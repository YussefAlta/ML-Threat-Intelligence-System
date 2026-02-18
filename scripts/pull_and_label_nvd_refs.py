#!/usr/bin/env python3
"""
Pull NVD CVE records from S3 and label them using heuristic rules.

Loads 1228 CVE records from the NIST ingestion pipeline, builds rich text
documents from each CVE's description + reference URLs + tags + CWE data,
then labels them across the 6 threat intelligence taxonomy categories.
"""

import hashlib
import json
import os
import re
import sys
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from dotenv import load_dotenv
    load_dotenv()
    load_dotenv(".env.local")
except ImportError:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env.local")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    os.environ.setdefault(key.strip(), val.strip())

import boto3
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

BUCKET = os.getenv("S3_BUCKET_NAME", "avint-scraper-bucket-raw")
REGION = os.getenv("AWS_REGION", "us-east-1")
MAX_DOCS = 200


def get_s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=REGION,
    )


def load_cve_data(s3):
    """Load the NIST CVE data from S3."""
    key = "nist/cve/2025/11/06/nist_cve_20251113_163622.json"
    logger.info(f"Loading CVE data from s3://{BUCKET}/{key}")
    resp = s3.get_object(Bucket=BUCKET, Key=key)
    return json.loads(resp["Body"].read().decode("utf-8"))


def load_cwe_enrichment(s3):
    """Load CWE enrichment data if available."""
    cwe_data = {}
    try:
        resp = s3.list_objects_v2(Bucket=BUCKET, Prefix="enriched/cve/cwe/", MaxKeys=100)
        for obj in resp.get("Contents", []):
            if obj["Key"].endswith(".json") and obj["Size"] > 500:
                data = json.loads(
                    s3.get_object(Bucket=BUCKET, Key=obj["Key"])["Body"].read().decode("utf-8")
                )
                for rec in data.get("enriched_records", []):
                    cve_id = rec.get("cve_id")
                    if cve_id:
                        cwe_data[cve_id] = rec
    except Exception as e:
        logger.warning(f"Failed to load CWE enrichment: {e}")
    return cwe_data


def extract_cve_description(cve_obj):
    """Extract the English description from a CVE object."""
    descriptions = cve_obj.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def extract_references(cve_obj):
    """Extract reference URLs and tags."""
    refs = cve_obj.get("references", [])
    result = []
    for r in refs:
        result.append({
            "url": r.get("url", ""),
            "tags": r.get("tags", []),
            "source": r.get("source", ""),
        })
    return result


def extract_cvss_info(cve_obj):
    """Extract CVSS score and severity from metrics."""
    metrics = cve_obj.get("metrics", {})
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            m = metric_list[0]
            cvss_data = m.get("cvssData", {})
            return {
                "score": cvss_data.get("baseScore"),
                "severity": cvss_data.get("baseSeverity", m.get("baseSeverity")),
                "vector": cvss_data.get("vectorString"),
                "exploitability_score": m.get("exploitabilityScore"),
                "impact_score": m.get("impactScore"),
            }
    return None


def build_document_from_cve(vuln_record, cwe_data):
    """Build a rich text document from a CVE record."""
    cve_obj = vuln_record.get("cve", {})
    cve_id = cve_obj.get("id", "UNKNOWN")
    description = extract_cve_description(cve_obj)
    references = extract_references(cve_obj)
    cvss = extract_cvss_info(cve_obj)
    weaknesses = cve_obj.get("weaknesses", [])

    # Build rich text content
    parts = [f"CVE Identifier: {cve_id}", ""]

    if description:
        parts.append(description)
        parts.append("")

    if cvss:
        severity_str = f"CVSS Score: {cvss['score']}"
        if cvss.get("severity"):
            severity_str += f" ({cvss['severity']})"
        if cvss.get("vector"):
            severity_str += f" Vector: {cvss['vector']}"
        parts.append(severity_str)
        if cvss.get("exploitability_score"):
            parts.append(f"Exploitability Score: {cvss['exploitability_score']}")
        parts.append("")

    # CWE info
    cwe_ids = []
    for w in weaknesses:
        for wd in w.get("description", []):
            cwe_val = wd.get("value", "")
            if cwe_val.startswith("CWE-"):
                cwe_ids.append(cwe_val)
    if cwe_ids:
        parts.append(f"Weakness: {', '.join(cwe_ids)}")

    cwe_enriched = cwe_data.get(cve_id, {})
    cwe_details = cwe_enriched.get("cwe_details", {})
    for cwe_id_num, detail in cwe_details.items():
        name = detail.get("Name", "")
        desc = detail.get("Description", "")
        if name:
            parts.append(f"CWE-{cwe_id_num}: {name}")
        if desc:
            parts.append(desc)
    parts.append("")

    # References
    if references:
        parts.append("References:")
        for ref in references:
            tag_str = f" [{', '.join(ref['tags'])}]" if ref["tags"] else ""
            parts.append(f"  - {ref['url']}{tag_str}")
        parts.append("")

    ref_tags_flat = []
    for ref in references:
        ref_tags_flat.extend(ref.get("tags", []))

    content = "\n".join(parts)
    url_hash = hashlib.sha256(cve_id.encode()).hexdigest()[:8]

    title_parts = [f"{cve_id}"]
    if cvss and cvss.get("severity"):
        title_parts.append(f"({cvss['severity']})")
    if description:
        short_desc = description[:100].split(".")[0]
        title_parts.append(f"- {short_desc}")

    return {
        "id": f"nvd_cve_{cve_id}_{url_hash}",
        "title": " ".join(title_parts),
        "content": content,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "source": "nvd_ref",
        "source_category_hint": "vulnerability",
        "published_at": cve_obj.get("published"),
        "collected_at": cve_obj.get("lastModified"),
        "metadata": {
            "cve_id": cve_id,
            "cvss": cvss,
            "cwe_ids": cwe_ids,
            "ref_count": len(references),
            "ref_tags": list(set(ref_tags_flat)),
            "source_identifier": cve_obj.get("sourceIdentifier"),
        },
    }


# ---------------------------------------------------------------------------
# Labeling
# ---------------------------------------------------------------------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
APT_RE = re.compile(r"\b(APT\d+|UNC\d+|FIN\d+|TA\d+)\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

VULN_KW = ["vulnerability", "advisory", "patch", "security update", "cwe-", "affected versions",
            "cvss", "remediation", "buffer overflow", "injection", "cross-site", "denial of service",
            "privilege escalation", "authentication bypass", "information disclosure", "out-of-bounds"]
EXPLOIT_KW = ["proof of concept", "poc", "exploit code", "metasploit", "rce exploit", "shellcode",
              "0day", "zero-day", "weaponized", "exploitation", "exploit", "remote code execution",
              "arbitrary code", "code execution"]
PHISHING_KW = ["phishing", "credential harvesting", "spoofed", "lure", "phishing kit",
               "fake login", "social engineering", "spear-phishing"]
RANSOM_KW = ["ransomware", "ransom", "encrypt", "decryptor", "double extortion",
             "data leak", "ransom note", "file encryption"]
RANSOM_FAMILIES = ["lockbit", "blackcat", "alphv", "conti", "revil", "clop", "hive",
                   "royal", "akira", "play", "8base", "medusa", "blackbasta", "rhysida"]
ACTOR_KW = ["threat actor", "threat group", "attributed to", "nation-state", "espionage",
            "campaign", "intrusion set", "state-sponsored"]
ACTOR_NAMES = ["lazarus", "cozy bear", "fancy bear", "sandworm", "turla", "kimsuky",
               "mustang panda", "charming kitten", "hafnium", "nobelium"]
IOC_KW = ["indicator of compromise", "ioc", "c2", "command and control", "beacon", "callback"]


def kw_count(text_lower, keywords):
    return sum(1 for kw in keywords if kw in text_lower)


def label_document(doc):
    """Apply heuristic labeling across 6 categories."""
    text = (doc.get("content") or "").lower()
    title = (doc.get("title") or "").lower()
    combined = title + " " + text
    meta = doc.get("metadata", {})
    ref_tags = [t.lower() for t in meta.get("ref_tags", [])]
    cvss = meta.get("cvss") or {}
    labels = {}

    # Vulnerability
    vuln_score = 0.0
    vuln_signals = []
    if CVE_RE.search(combined):
        vuln_score += 0.3
        vuln_signals.append("cve_pattern")
    kc = kw_count(combined, VULN_KW)
    if kc >= 1:
        vuln_score += min(kc * 0.08, 0.5)
        vuln_signals.append(f"vuln_keywords({kc})")
    if "cwe-" in combined:
        vuln_score += 0.1
        vuln_signals.append("cwe_present")
    if cvss.get("score"):
        vuln_score += 0.1
        vuln_signals.append(f"cvss_{cvss['score']}")
    if any(t in ref_tags for t in ["vendor advisory", "patch"]):
        vuln_score += 0.1
        vuln_signals.append("advisory_tags")
    if vuln_score >= 0.3:
        labels["vulnerability"] = {"confidence": min(vuln_score, 1.0), "signals": vuln_signals}

    # Exploit
    exp_score = 0.0
    exp_signals = []
    kc = kw_count(combined, EXPLOIT_KW)
    if kc >= 1:
        exp_score += min(kc * 0.12, 0.8)
        exp_signals.append(f"exploit_keywords({kc})")
    if any(t in ref_tags for t in ["exploit", "third party advisory"]):
        exp_score += 0.2
        exp_signals.append("exploit_tag")
    if "exploit-db" in combined or "github.com" in combined and "exploit" in combined:
        exp_score += 0.2
        exp_signals.append("exploit_url")
    if cvss and cvss.get("exploitability_score") and cvss["exploitability_score"] >= 3.0:
        exp_score += 0.15
        exp_signals.append(f"high_exploitability({cvss['exploitability_score']})")
    if cvss and cvss.get("severity") == "CRITICAL":
        exp_score += 0.1
        exp_signals.append("critical_severity")
    if exp_score >= 0.3:
        labels["exploit"] = {"confidence": min(exp_score, 1.0), "signals": exp_signals}

    # Phishing
    ph_score = 0.0
    ph_signals = []
    kc = kw_count(combined, PHISHING_KW)
    if kc >= 1:
        ph_score += min(kc * 0.2, 0.9)
        ph_signals.append(f"phishing_keywords({kc})")
    if ph_score >= 0.3:
        labels["phishing"] = {"confidence": min(ph_score, 1.0), "signals": ph_signals}

    # Ransomware
    rs_score = 0.0
    rs_signals = []
    kc = kw_count(combined, RANSOM_KW)
    if kc >= 1:
        rs_score += min(kc * 0.15, 0.9)
        rs_signals.append(f"ransom_keywords({kc})")
    fam_matches = [f for f in RANSOM_FAMILIES if f in combined]
    if fam_matches:
        rs_score += len(fam_matches) * 0.25
        rs_signals.append(f"families({','.join(fam_matches)})")
    if rs_score >= 0.3:
        labels["ransomware"] = {"confidence": min(rs_score, 1.0), "signals": rs_signals}

    # Threat Actor
    ta_score = 0.0
    ta_signals = []
    if APT_RE.search(combined):
        ta_score += 0.4
        ta_signals.append("apt_pattern")
    kc = kw_count(combined, ACTOR_KW)
    if kc >= 1:
        ta_score += min(kc * 0.12, 0.5)
        ta_signals.append(f"actor_keywords({kc})")
    name_matches = [n for n in ACTOR_NAMES if n in combined]
    if name_matches:
        ta_score += len(name_matches) * 0.25
        ta_signals.append(f"actors({','.join(name_matches)})")
    if ta_score >= 0.3:
        labels["threat_actor"] = {"confidence": min(ta_score, 1.0), "signals": ta_signals}

    # IOC
    ioc_score = 0.0
    ioc_signals = []
    ip_count = len(IPV4_RE.findall(text))
    if ip_count > 3:
        ioc_score += 0.4
        ioc_signals.append(f"ip_density({ip_count})")
    hash_count = len(HASH_MD5.findall(text)) + len(HASH_SHA1.findall(text)) + len(HASH_SHA256.findall(text))
    if hash_count > 2:
        ioc_score += 0.3
        ioc_signals.append(f"hash_density({hash_count})")
    kc = kw_count(combined, IOC_KW)
    if kc >= 1:
        ioc_score += min(kc * 0.12, 0.5)
        ioc_signals.append(f"ioc_keywords({kc})")
    if ioc_score >= 0.3:
        labels["ioc"] = {"confidence": min(ioc_score, 1.0), "signals": ioc_signals}

    return labels


def main():
    s3 = get_s3_client()

    data = load_cve_data(s3)
    vulns = data.get("vulnerabilities", [])
    logger.info(f"Loaded {len(vulns)} CVE records")

    cwe_data = load_cwe_enrichment(s3)
    logger.info(f"Loaded CWE enrichment for {len(cwe_data)} CVEs")

    random.seed(42)
    if len(vulns) > MAX_DOCS:
        sampled = random.sample(vulns, MAX_DOCS)
    else:
        sampled = vulns[:MAX_DOCS]
    logger.info(f"Sampled {len(sampled)} CVE records for labeling")

    docs = []
    for i, vuln in enumerate(sampled):
        doc = build_document_from_cve(vuln, cwe_data)
        if len(doc["content"].strip()) < 50:
            continue
        doc["_labels"] = label_document(doc)
        docs.append(doc)

    logger.info(f"Built and labeled {len(docs)} documents")

    labeled_output = []
    for doc in docs:
        label_map = doc["_labels"]
        label_names = sorted(label_map.keys(), key=lambda k: label_map[k]["confidence"], reverse=True)
        primary = label_names[0] if label_names else "unknown"
        primary_conf = label_map[primary]["confidence"] if primary != "unknown" else 0.0

        labeled_output.append({
            "id": doc["id"],
            "title": doc["title"],
            "url": doc["url"],
            "source": doc["source"],
            "cve_id": doc["metadata"].get("cve_id"),
            "cvss_score": (doc["metadata"].get("cvss") or {}).get("score"),
            "cvss_severity": (doc["metadata"].get("cvss") or {}).get("severity"),
            "ref_count": doc["metadata"].get("ref_count", 0),
            "ref_tags": doc["metadata"].get("ref_tags", []),
            "content_length": len(doc["content"]),
            "labels": label_names,
            "primary_label": primary,
            "primary_confidence": round(primary_conf, 2),
            "label_details": {
                k: {"confidence": round(v["confidence"], 2), "signals": v["signals"]}
                for k, v in label_map.items()
            },
            "content_preview": doc["content"][:400].replace("\n", " "),
        })

    os.makedirs("data/gold", exist_ok=True)
    os.makedirs("data/corpus", exist_ok=True)

    corpus_path = "data/corpus/nvd_cves_200.jsonl"
    with open(corpus_path, "w") as f:
        for doc in docs:
            out = {k: v for k, v in doc.items() if k != "_labels"}
            f.write(json.dumps(out, ensure_ascii=False) + "\n")
    logger.info(f"Saved corpus to {corpus_path}")

    labeled_path = "data/gold/nvd_cves_labeled_200.jsonl"
    with open(labeled_path, "w") as f:
        for item in labeled_output:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    logger.info(f"Saved labeled docs to {labeled_path}")

    # Print summary
    from collections import Counter
    label_counts = Counter()
    multi_label_combos = Counter()
    severity_counts = Counter()
    for item in labeled_output:
        for lbl in item["labels"]:
            label_counts[lbl] += 1
        combo = "+".join(sorted(item["labels"]))
        multi_label_combos[combo] += 1
        sev = item.get("cvss_severity") or "N/A"
        severity_counts[sev] += 1

    print(f"\n{'='*70}")
    print(f"NVD CVE Labeling Summary -- {len(labeled_output)} documents")
    print(f"{'='*70}")

    print(f"\nLabel distribution (multi-label counts):")
    print(f"  {'Category':<20s} {'Count':>5s}  {'%':>6s}")
    print(f"  {'-'*20} {'-'*5}  {'-'*6}")
    for lbl, cnt in label_counts.most_common():
        pct = cnt / len(labeled_output) * 100
        print(f"  {lbl:<20s} {cnt:>5d}  {pct:5.1f}%")

    multi = sum(1 for item in labeled_output if len(item["labels"]) > 1)
    print(f"\n  Multi-label docs:    {multi} ({multi/len(labeled_output)*100:.1f}%)")
    single = sum(1 for item in labeled_output if len(item["labels"]) == 1)
    print(f"  Single-label docs:   {single} ({single/len(labeled_output)*100:.1f}%)")

    print(f"\nCVSS Severity distribution:")
    for sev, cnt in severity_counts.most_common():
        print(f"  {sev:<12s} {cnt:>5d}")

    print(f"\nTop label combinations:")
    for combo, cnt in multi_label_combos.most_common(10):
        print(f"  {combo:<45s} {cnt:>4d}")

    print(f"\nSample labeled documents:")
    for item in labeled_output[:5]:
        labels_str = ", ".join(f"{l}({item['label_details'][l]['confidence']})" for l in item["labels"])
        cvss_str = f"CVSS {item['cvss_score']} {item['cvss_severity']}" if item.get("cvss_score") else "No CVSS"
        print(f"\n  {item['cve_id']} | {cvss_str}")
        print(f"    Labels: {labels_str}")
        print(f"    Title:  {item['title'][:90]}")

    print(f"\n{'='*70}")
    print(f"Output files:")
    print(f"  Corpus (JSONL):  {corpus_path}")
    print(f"  Labels (JSONL):  {labeled_path}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
