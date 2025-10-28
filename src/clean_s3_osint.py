#!/usr/bin/env python3
"""
S3 Cleaner: reads raw objects from s3://<bucket>/<raw_prefix>, cleans them, and writes JSONL to s3://<bucket>/<clean_prefix>.
- No data in bucket? -> exits cleanly (no-op).
- Formats: .jsonl / .ndjson / .json (list of dicts) / .csv / .txt (one record per line). Optional .gz suffix supported.
- Outputs: newline-delimited JSON (.jsonl), UTF-8, gz optional.
- Idempotent: skips if clean/<same_key>.jsonl(.gz) exists unless --overwrite.
- Dedupe: per-batch + global manifest (state/dedupe-manifest.json) using SHA256 of normalized text.
"""

import argparse, csv, gzip, io, json, os, re, sys, hashlib, time
from datetime import datetime, timezone
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

# ---------- Config defaults ----------
DEFAULT_RAW_PREFIX = "raw/"
DEFAULT_CLEAN_PREFIX = "clean/"
DEFAULT_STATE_KEY = "state/dedupe-manifest.json"
DEFAULT_OUTPUT_GZIP = True

s3 = boto3.client("s3")

# ---------- Utilities ----------
URL_RE = re.compile(r"https?://[^\s)>\]}]+", re.IGNORECASE)
HTML_TAG_RE = re.compile(r"<[^>]+>")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:(?!-)[A-Z0-9-]{1,63}(?<!-)\.)+[A-Z]{2,63}\b", re.IGNORECASE)
WS_RE = re.compile(r"[ \t]+")

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256(text: str) -> str:
    h = hashlib.sha256()
    h.update(text.encode("utf-8", errors="ignore"))
    return h.hexdigest()

def s3_exists(bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise

def list_objects(bucket: str, prefix: str) -> Iterator[Dict]:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["Key"].endswith("/") or obj["Size"] == 0:
                continue
            yield obj

def get_obj_stream(bucket: str, key: str) -> io.BytesIO:
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    return io.BytesIO(body)

def open_text_reader(buf: io.BytesIO, key: str) -> io.TextIOBase:
    if key.endswith(".gz"):
        return io.TextIOWrapper(gzip.GzipFile(fileobj=buf), encoding="utf-8", errors="ignore")
    return io.TextIOWrapper(buf, encoding="utf-8", errors="ignore")

def detect_format(key: str) -> str:
    k = key.lower()
    if k.endswith(".jsonl") or k.endswith(".ndjson") or k.endswith(".jsonl.gz") or k.endswith(".ndjson.gz"):
        return "jsonl"
    if k.endswith(".json") or k.endswith(".json.gz"):
        return "json"
    if k.endswith(".csv") or k.endswith(".csv.gz"):
        return "csv"
    if k.endswith(".txt") or k.endswith(".txt.gz"):
        return "txt"
    return "unknown"

# ---------- Cleaning primitives ----------
def strip_html(text: str) -> str:
    # quick & safe-ish: nuke tags, collapse whitespace
    text = HTML_TAG_RE.sub(" ", text)
    return WS_RE.sub(" ", text).strip()

def normalize_whitespace(text: str) -> str:
    text = text.replace("\r", " ").replace("\n", " ").replace("\u00A0", " ")
    return WS_RE.sub(" ", text).strip()

def extract_iocs(text: str) -> Dict[str, List[str]]:
    urls = sorted(set(URL_RE.findall(text)))
    ipv4 = sorted(set(IPV4_RE.findall(text)))
    domains = sorted(set( d for d in DOMAIN_RE.findall(text) if not d.endswith((".png",".jpg",".gif",".svg")) ))
    return {"urls": urls, "ipv4": ipv4, "domains": domains}

def mask_pii(text: str) -> str:
    text = EMAIL_RE.sub("[EMAIL_REDACTED]", text)
    text = PHONE_RE.sub("[PHONE_REDACTED]", text)
    return text

def lang_filter_basic(text: str, min_alpha_ratio: float = 0.6) -> bool:
    # Very lightweight heuristic to pass mostly-English text without external deps.
    if not text:
        return False
    letters = sum(ch.isalpha() for ch in text)
    total = sum((ch.isalpha() or ch.isdigit()) for ch in text) + 1
    return (letters / total) >= min_alpha_ratio

def clean_text(raw: str) -> Tuple[str, Dict[str, List[str]]]:
    if raw is None:
        raw = ""
    base = normalize_whitespace(raw)
    base = strip_html(base)
    iocs = extract_iocs(base)
    # Remove URLs for modeling text, keep in iocs
    base = URL_RE.sub(" ", base)
    base = mask_pii(base)
    base = normalize_whitespace(base)
    return base, iocs

# ---------- Parsing ----------
def records_from_jsonl(reader: io.TextIOBase) -> Iterator[Dict]:
    for line in reader:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            # Try forgiving parse
            continue

def records_from_json(reader: io.TextIOBase) -> Iterator[Dict]:
    try:
        blob = json.load(reader)
        if isinstance(blob, dict):
            yield blob
        elif isinstance(blob, list):
            for item in blob:
                if isinstance(item, dict):
                    yield item
    except json.JSONDecodeError:
        return

def records_from_csv(reader: io.TextIOBase) -> Iterator[Dict]:
    sniffer = csv.Sniffer()
    try:
        sample = reader.read(4096)
        reader.seek(0)
        dialect = sniffer.sniff(sample)
    except Exception:
        reader.seek(0)
        dialect = csv.excel
    dr = csv.DictReader(reader, dialect=dialect)
    for row in dr:
        yield row

def records_from_txt(reader: io.TextIOBase) -> Iterator[Dict]:
    for i, line in enumerate(reader):
        t = line.strip()
        if t:
            yield {"text": t, "line_num": i + 1}

def iter_records_for_key(bucket: str, key: str) -> Iterator[Dict]:
    buf = get_obj_stream(bucket, key)
    reader = open_text_reader(buf, key)
    fmt = detect_format(key)
    if fmt == "jsonl":
        yield from records_from_jsonl(reader)
    elif fmt == "json":
        yield from records_from_json(reader)
    elif fmt == "csv":
        yield from records_from_csv(reader)
    elif fmt == "txt":
        yield from records_from_txt(reader)
    else:
        # Best-effort: treat as jsonl
        yield from records_from_jsonl(reader)

# ---------- Dedupe state ----------
def load_manifest(bucket: str, state_key: str) -> Dict[str, str]:
    if not s3_exists(bucket, state_key):
        return {}
    buf = get_obj_stream(bucket, state_key)
    try:
        return json.loads(buf.read().decode("utf-8", errors="ignore"))
    except Exception:
        return {}

def save_manifest(bucket: str, state_key: str, manifest: Dict[str, str]) -> None:
    data = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    s3.put_object(Bucket=bucket, Key=state_key, Body=data, ContentType="application/json; charset=utf-8")

# ---------- Writer ----------
def put_jsonl(bucket: str, key: str, rows: Iterable[Dict], gzip_out: bool) -> int:
    out = io.BytesIO()
    raw_stream: io.BufferedIOBase
    if gzip_out:
        gz = gzip.GzipFile(fileobj=out, mode="wb")
        raw_stream = gz
    else:
        raw_stream = out

    count = 0
    try:
        for row in rows:
            line = (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            raw_stream.write(line)
            count += 1
    finally:
        raw_stream.close()

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=out.getvalue(),
        ContentType="application/x-ndjson" + ("; charset=utf-8" if not gzip_out else ""),
        ContentEncoding=("gzip" if gzip_out else None) or "",
    )
    return count

# ---------- Cleaning pipeline ----------
def clean_record(rec: Dict, source_key: str) -> Optional[Dict]:
    # Normalize common fields; tolerate messy inputs
    title = str(rec.get("title") or rec.get("headline") or rec.get("name") or "").strip()
    text = rec.get("text") or rec.get("content") or rec.get("body") or ""
    text = str(text)

    cleaned_text, iocs = clean_text(text)
    if not cleaned_text or not lang_filter_basic(cleaned_text):
        return None

    out = {
        "id": rec.get("id") or rec.get("_id") or sha256((title + "\n" + cleaned_text)[:2000]),
        "title": title or None,
        "text": cleaned_text,
        "iocs": iocs,
        "url": rec.get("url") or rec.get("link") or None,
        "source_key": source_key,
        "collected_at": rec.get("collected_at") or rec.get("timestamp") or now_iso(),
        "tags": sorted(set(rec.get("tags") or [])),
    }
    return out

def target_clean_key(clean_prefix: str, raw_key: str) -> str:
    # Replace leading raw/ with clean/ and force .jsonl(.gz)
    base = raw_key
    if "/" in base:
        parts = base.split("/")
        if parts[0] == "raw":
            parts[0] = "clean"
            base = "/".join(parts)
    base = re.sub(r"\.(jsonl|ndjson|json|csv|txt)(\.gz)?$", "", base, flags=re.IGNORECASE)
    return f"{clean_prefix}{'/'.join(base.split('/')[1:])}.jsonl"  # ensure under clean/

def run(bucket: str, raw_prefix: str, clean_prefix: str, state_key: str, overwrite: bool, gzip_out: bool) -> None:
    manifest = load_manifest(bucket, state_key)
    batch_seen = set()
    total_in, total_out, total_skipped = 0, 0, 0

    objs = list(list_objects(bucket, raw_prefix))
    if not objs:
        print(f"[OK] No objects under s3://{bucket}/{raw_prefix} — nothing to do.")
        return

    for obj in objs:
        raw_key = obj["Key"]
        out_key = target_clean_key(clean_prefix, raw_key)

        if s3_exists(bucket, out_key) and not overwrite:
            print(f"[SKIP] Output exists: s3://{bucket}/{out_key}")
            total_skipped += 1
            continue

        def gen_rows():
            nonlocal total_in, total_out
            for rec in iter_records_for_key(bucket, raw_key):
                total_in += 1
                cleaned = clean_record(rec, raw_key)
                if not cleaned:
                    continue
                # dedupe by normalized text hash
                h = sha256(cleaned["text"])
                if h in batch_seen or h in manifest:
                    continue
                batch_seen.add(h)
                manifest[h] = cleaned["id"]
                yield cleaned
                total_out += 1

        # write
        target_key = out_key + (".gz" if gzip_out else "")
        count = put_jsonl(bucket, target_key, gen_rows(), gzip_out=gzip_out)
        print(f"[WRITE] s3://{bucket}/{target_key} -> {count} rows")

    # persist manifest
    save_manifest(bucket, state_key, manifest)
    print(f"[DONE] in={total_in} out={total_out} skipped_files={total_skipped} manifest_size={len(manifest)}")

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="Clean raw OSINT-like data from S3 and write cleaned JSONL back to S3.")
    p.add_argument("--bucket", required=True, help="S3 bucket name")
    p.add_argument("--raw-prefix", default=DEFAULT_RAW_PREFIX, help="Prefix for raw inputs (default: raw/)")
    p.add_argument("--clean-prefix", default=DEFAULT_CLEAN_PREFIX, help="Prefix for cleaned outputs (default: clean/)")
    p.add_argument("--state-key", default=DEFAULT_STATE_KEY, help="Key for dedupe manifest JSON")
    p.add_argument("--overwrite", action="store_true", help="Overwrite existing cleaned files")
    p.add_argument("--no-gzip", action="store_true", help="Disable gzip for outputs")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run(
        bucket=args.bucket,
        raw_prefix=args.raw_prefix if args.raw_prefix.endswith("/") else args.raw_prefix + "/",
        clean_prefix=args.clean_prefix if args.clean_prefix.endswith("/") else args.clean_prefix + "/",
        state_key=args.state_key,
        overwrite=args.overwrite,
        gzip_out=not args.no_gzip,
    )
