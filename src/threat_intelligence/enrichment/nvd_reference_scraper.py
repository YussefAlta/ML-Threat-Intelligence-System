"""
NVD Reference URL Scraping Enricher.

Fetches reference URLs from NIST CVE records, classifies them, extracts and
cleans content (with GitHub-specific extractors), scores quality, and stores
raw/clean/meta under enriched/cve/ref_links/(date ingested)/.

All reference types are scraped (including GitHub advisories, commits, issues).
Media URLs (YouTube, Vimeo, etc.) are skipped by default (metadata-only).
"""

from __future__ import annotations

import hashlib
import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urlunparse, parse_qs

import requests
from charset_normalizer import from_bytes as detect_encoding_bytes

from ..core.config import Config
from ..utils.api_client import RateLimiter, retry_with_backoff
from .content_cleaner import ContentCleaner
from .reference_classifier import (
    classify_url,
    classify_with_content_hint,
    MEDIA, CODE,
    GITHUB_ADVISORY, GITHUB_COMMIT, GITHUB_ISSUE,
)
from ..storage.reference_storage import ReferenceStorage

logger = logging.getLogger(__name__)

TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "ref", "source", "campaign", "mc_cid", "mc_eid",
})

_USER_AGENTS = [
    "ML-Threat-Intelligence-System/1.0",
    "Mozilla/5.0 (compatible; SecurityResearchBot/1.0)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
]


class NVDReferenceScraperEnricher:
    """
    Enricher that scrapes, classifies, cleans, and stores reference URLs
    from NVD CVE records.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.storage = ReferenceStorage(self.config)
        self.cleaner = ContentCleaner(
            max_chunk_size=getattr(self.config, "NVD_REF_MAX_CHUNK_SIZE", 1_048_576)
        )

        self.rate_limiter = RateLimiter(
            max_requests=self.config.NVD_REF_RATE_LIMIT_REQUESTS,
            window_seconds=self.config.NVD_REF_RATE_LIMIT_WINDOW,
        )
        self.timeout = self.config.NVD_REF_TIMEOUT
        self.max_retries = self.config.NVD_REF_MAX_RETRIES
        self.max_size_bytes = self.config.NVD_REF_MAX_SIZE_MB * 1024 * 1024
        self.dedupe_ttl_days = self.config.NVD_REF_DEDUPE_TTL_DAYS
        self.skip_media = getattr(self.config, "NVD_REF_SKIP_MEDIA", True)
        self.min_useful_text = getattr(self.config, "NVD_REF_MIN_USEFUL_TEXT_LENGTH", 50)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": getattr(self.config, "NVD_REF_USER_AGENT", _USER_AGENTS[0]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_cves(self, cve_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process CVE records: classify, fetch, clean, store reference URLs.

        Returns summary dict with urls_processed, urls_succeeded, urls_failed,
        urls_skipped_media.
        """
        if not getattr(self.config, "NVD_REF_SCRAPE_ENABLED", True):
            logger.info("NVD reference scraping is disabled")
            return {"urls_processed": 0, "urls_succeeded": 0, "urls_failed": 0, "urls_skipped_media": 0}

        urls_processed = 0
        urls_succeeded = 0
        urls_failed = 0
        urls_skipped_media = 0

        for cve_record in cve_records:
            refs = self._extract_references(cve_record)
            if not refs:
                continue

            cve_id = (cve_record.get("cve") or {}).get("id")
            if not cve_id:
                continue

            for ref_index, ref in enumerate(refs):
                url = ref.get("url")
                if not url or not isinstance(url, str):
                    continue

                ref_type = classify_url(url)

                # Skip media URLs (metadata-only)
                if self.skip_media and ref_type == MEDIA:
                    urls_skipped_media += 1
                    self._store_metadata_only(url, cve_id, ref_index, ref_type, "skipped_media")
                    continue

                urls_processed += 1
                try:
                    result = self._fetch_and_store(url, cve_id, ref_index, ref_type)
                    if result and result.get("saved"):
                        urls_succeeded += 1
                    else:
                        urls_failed += 1
                except Exception as e:
                    logger.warning(f"Failed to process reference {url} for {cve_id}: {e}")
                    urls_failed += 1

        summary = {
            "urls_processed": urls_processed,
            "urls_succeeded": urls_succeeded,
            "urls_failed": urls_failed,
            "urls_skipped_media": urls_skipped_media,
        }
        logger.info(f"NVDReferenceScraper.enrich_cves summary: {summary}")
        return summary

    # ------------------------------------------------------------------
    # Reference extraction (NVD 2.0 + legacy)
    # ------------------------------------------------------------------

    def _extract_references(self, cve_record: Dict[str, Any]) -> List[Dict[str, Any]]:
        cve_data = cve_record.get("cve", {}) or {}
        references = cve_data.get("references")
        if isinstance(references, list):
            ref_data = references
        elif isinstance(references, dict):
            ref_data = references.get("reference_data") if references else []
        else:
            ref_data = []
        if not isinstance(ref_data, list):
            return []
        return [r for r in ref_data if isinstance(r, dict) and r.get("url")]

    # ------------------------------------------------------------------
    # URL normalization & hashing
    # ------------------------------------------------------------------

    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower() if parsed.scheme else "https"
            netloc = parsed.netloc.lower() if parsed.netloc else ""
            query_parts = []
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=False)
                filtered = {k: v for k, v in params.items() if k.lower() not in TRACKING_PARAMS}
                sorted_items = sorted(filtered.items())
                query_parts = [
                    f"{k}={v[0]}" if len(v) == 1 else f"{k}={','.join(v)}"
                    for k, v in sorted_items
                ]
            query = "&".join(query_parts)
            path = parsed.path.rstrip("/") or "/"
            return urlunparse((scheme, netloc, path, parsed.params, query, ""))
        except Exception as e:
            logger.debug(f"URL normalization failed for {url}: {e}")
            return url

    def _generate_url_hash(self, url: str, length: int = 8) -> str:
        normalized = self._normalize_url(url)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:length]

    # ------------------------------------------------------------------
    # Content type detection
    # ------------------------------------------------------------------

    def _determine_content_type(self, response: requests.Response) -> str:
        ct = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ct:
            return ct
        content = response.content[:512]
        if content.startswith(b"%PDF"):
            return "application/pdf"
        if content.lstrip().startswith(b"{"):
            return "application/json"
        if content.lstrip().startswith(b"<"):
            return "text/html"
        return "application/octet-stream"

    # ------------------------------------------------------------------
    # Encoding detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_encoding(content: bytes, content_type_header: str) -> str:
        """
        Detect encoding from Content-Type charset, falling back to
        charset-normalizer auto-detection, then UTF-8.
        """
        # 1. Parse charset from header
        for part in content_type_header.split(";"):
            part = part.strip().lower()
            if part.startswith("charset="):
                charset = part.split("=", 1)[1].strip().strip("'\"")
                if charset:
                    return charset

        # 2. Auto-detect via charset-normalizer
        if content:
            try:
                result = detect_encoding_bytes(content[:8192])
                best = result.best()
                if best and best.encoding:
                    return best.encoding
            except Exception:
                pass

        return "utf-8"

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _check_dedupe(self, url_hash: str, cve_id: str, ref_index: int) -> bool:
        fetch_date = datetime.now(timezone.utc)
        meta_key = self.storage.generate_s3_key(
            cve_id, ref_index, url_hash, "application/json", fetch_date, "meta"
        )
        if not self.storage.check_exists(meta_key):
            return False
        last_mod = self.storage.get_object_last_modified(meta_key)
        if not last_mod:
            return False
        if last_mod.tzinfo is None:
            last_mod = last_mod.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - last_mod) <= timedelta(days=self.dedupe_ttl_days)

    # ------------------------------------------------------------------
    # Metadata-only storage (for media or skipped URLs)
    # ------------------------------------------------------------------

    def _store_metadata_only(
        self, url: str, cve_id: str, ref_index: int, ref_type: str, reason: str,
    ) -> None:
        normalized = self._normalize_url(url)
        url_hash = self._generate_url_hash(url)
        fetch_date = datetime.now(timezone.utc)
        meta_key = self.storage.generate_s3_key(
            cve_id, ref_index, url_hash, "application/json", fetch_date, "meta"
        )
        metadata = {
            "cve_id": cve_id,
            "ref_index": ref_index,
            "original_url": url,
            "normalized_url": normalized,
            "ref_type": ref_type,
            "fetch_timestamp": fetch_date.isoformat() + "Z",
            "skipped": reason,
            "s3_keys": {"meta": meta_key},
        }
        self.storage.save_reference_metadata(metadata, meta_key)
        logger.info(
            f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} "
            f"normalized_url={normalized} ref_type={ref_type} skipped={reason}"
        )

    # ------------------------------------------------------------------
    # Main fetch-and-store pipeline
    # ------------------------------------------------------------------

    def _fetch_and_store(
        self, url: str, cve_id: str, ref_index: int, ref_type: str,
    ) -> Optional[Dict[str, Any]]:
        url_hash = self._generate_url_hash(url)

        if self._check_dedupe(url_hash, cve_id, ref_index):
            normalized = self._normalize_url(url)
            logger.info(
                f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} "
                f"normalized_url={normalized} skipped=dedupe"
            )
            return {"saved": False, "skipped": "dedupe"}

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            normalized = self._normalize_url(url)
            logger.info(
                f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} "
                f"normalized_url={normalized} skipped=scheme"
            )
            return {"saved": False, "skipped": "scheme"}

        # Rotate User-Agent
        self.session.headers["User-Agent"] = random.choice(_USER_AGENTS)

        fetch_date = datetime.now(timezone.utc)
        content_truncated = False

        @retry_with_backoff(
            max_retries=self.max_retries,
            initial_delay=1.0,
            backoff_multiplier=2.0,
            exceptions=(requests.RequestException,),
        )
        def do_fetch() -> requests.Response:
            nonlocal content_truncated
            self.rate_limiter.wait_if_needed()
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True, stream=True)
            body = b""
            for chunk in resp.iter_content(chunk_size=65536):
                body += chunk
                if len(body) > self.max_size_bytes:
                    content_truncated = True
                    logger.warning(f"Content truncated at {self.max_size_bytes} bytes for {url}")
                    break
            resp._content = body
            return resp

        normalized = self._normalize_url(url)

        try:
            response = do_fetch()
        except requests.RequestException as e:
            error_detail = f"{type(e).__name__}: {e}"
            logger.info(
                f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} "
                f"normalized_url={normalized} fetch_error={error_detail}"
            )
            return {"saved": False, "error": error_detail, "http_error_detail": error_detail}

        redirects = [r.headers.get("Location", "") for r in response.history] if response.history else []
        final_url = response.url
        status_code = response.status_code

        if status_code >= 400:
            error_detail = f"{status_code} {requests.status_codes._codes.get(status_code, ('',))[0]}"
            logger.info(
                f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} "
                f"normalized_url={normalized} status_code={status_code}"
            )
            return {"saved": False, "status_code": status_code, "http_error_detail": error_detail}

        content = response.content
        content_type = self._determine_content_type(response)
        content_type_header = response.headers.get("Content-Type", "")
        detected_encoding = self._detect_encoding(content, content_type_header)
        content_hash = hashlib.sha256(content).hexdigest()

        # Decode using detected encoding
        def _decode(raw: bytes) -> str:
            try:
                return raw.decode(detected_encoding)
            except (UnicodeDecodeError, LookupError):
                return raw.decode("utf-8", errors="replace")

        # S3 keys
        raw_key = self.storage.generate_s3_key(cve_id, ref_index, url_hash, content_type, fetch_date, "raw")
        clean_key = self.storage.generate_s3_key(cve_id, ref_index, url_hash, content_type, fetch_date, "clean")
        meta_key = self.storage.generate_s3_key(cve_id, ref_index, url_hash, content_type, fetch_date, "meta")

        logger.info(
            f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} "
            f"normalized_url={normalized} ref_type={ref_type} status_code={status_code} "
            f"raw_key={raw_key} clean_key={clean_key} meta_key={meta_key}"
        )

        # Extract text and clean -- route by ref_type and content_type
        cleaned_text = ""
        extraction_success = False
        extracted_title: Optional[str] = None
        extracted_meta_desc: Optional[str] = None
        github_fields: Optional[Dict] = None

        base_type = content_type.split(";")[0].strip().lower()

        if ref_type == CODE:
            # Raw code: store as-is, no HTML cleaning
            cleaned_text = _decode(content)
            extraction_success = bool(cleaned_text.strip())
        elif "html" in base_type:
            raw_text = _decode(content)

            # Extract metadata (title, meta description)
            html_meta = ContentCleaner.extract_html_metadata(raw_text)
            extracted_title = html_meta.get("title")
            extracted_meta_desc = html_meta.get("meta_description")

            # GitHub-specific extractors
            if ref_type == GITHUB_ADVISORY:
                github_fields = ContentCleaner.extract_github_advisory(raw_text)
                cleaned_text = github_fields.get("description") or ""
                if not cleaned_text and github_fields.get("title"):
                    cleaned_text = github_fields["title"]
            elif ref_type == GITHUB_COMMIT:
                github_fields = ContentCleaner.extract_github_commit(raw_text)
                cleaned_text = github_fields.get("commit_message") or ""
            elif ref_type == GITHUB_ISSUE:
                github_fields = ContentCleaner.extract_github_issue(raw_text)
                cleaned_text = github_fields.get("body") or github_fields.get("title") or ""
            else:
                extracted = ContentCleaner.extract_text_from_html(raw_text)
                cleaned_text = self.cleaner.clean_text(extracted, content_type)

            extraction_success = bool(cleaned_text.strip())

            # Refine classification with content hints
            if ref_type not in (GITHUB_ADVISORY, GITHUB_COMMIT, GITHUB_ISSUE):
                ref_type = classify_with_content_hint(url, extracted_title, cleaned_text[:300])
        elif "pdf" in base_type:
            extracted = ContentCleaner.extract_text_from_pdf(content)
            if extracted:
                cleaned_text = self.cleaner.clean_text(extracted, content_type)
                extraction_success = bool(cleaned_text.strip())
        elif "json" in base_type:
            cleaned_text = self.cleaner.clean_text(_decode(content), content_type)
            extraction_success = True
        elif "text" in base_type or "xml" in base_type:
            cleaned_text = self.cleaner.clean_text(_decode(content), content_type)
            extraction_success = True

        language = self.cleaner.detect_language(cleaned_text) if cleaned_text else "unknown"
        quality = ContentCleaner.assess_quality(cleaned_text, self.min_useful_text)

        metadata: Dict[str, Any] = {
            "cve_id": cve_id,
            "ref_index": ref_index,
            "original_url": url,
            "normalized_url": normalized,
            "final_url": final_url,
            "ref_type": ref_type,
            "fetch_timestamp": fetch_date.isoformat() + "Z",
            "status_code": status_code,
            "content_type": content_type,
            "detected_encoding": detected_encoding,
            "content_length": len(content),
            "content_truncated": content_truncated,
            "content_hash_sha256": content_hash,
            "extraction_success": extraction_success,
            "language": language,
            "cleaned_text_length": len(cleaned_text),
            "redirect_count": len(redirects),
            "redirects": redirects,
            "quality": quality,
            "extracted_title": extracted_title,
            "extracted_meta_description": extracted_meta_desc,
            "error": None,
            "http_error_detail": None,
            "s3_keys": {
                "raw": raw_key,
                "clean": clean_key if quality["label"] != "empty" else None,
                "meta": meta_key,
            },
        }

        if github_fields:
            metadata["github_extracted"] = github_fields

        # Save to S3 -- skip clean file for empty quality
        raw_ok = self.storage.save_reference_raw(content, raw_key, content_type)
        clean_ok = True
        if cleaned_text and quality["label"] != "empty":
            clean_ok = self.storage.save_reference_clean(cleaned_text, clean_key)
        meta_ok = self.storage.save_reference_metadata(metadata, meta_key)

        saved = raw_ok and meta_ok
        if not raw_ok or not meta_ok:
            logger.warning(f"Failed to save artifacts for {url} (raw_ok={raw_ok} meta_ok={meta_ok})")

        return {"saved": saved, "metadata": metadata}
