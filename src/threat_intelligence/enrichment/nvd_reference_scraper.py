"""
NVD Reference URL Scraping Enricher.

Fetches reference URLs from NIST CVE records (the "Reference URLs" on each NVD
detail page, e.g. https://nvd.nist.gov/vuln/detail/CVE-2021-44228). Stores raw
content, cleaned text, and metadata in S3 under enrichments/nvd_references/.

GitHub URLs are skipped by default (NVD_REF_SKIP_GITHUB=True); NIST often
includes GitHub repo links that yield minimal CVE value. Only non-GitHub
reference articles (advisories, writeups, vendor pages) are scraped.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import requests

from ..core.config import Config
from ..utils.api_client import RateLimiter, retry_with_backoff
from .content_cleaner import ContentCleaner
from ..storage.reference_storage import ReferenceStorage

logger = logging.getLogger(__name__)

# Tracking query params to remove (common analytics/tracking)
TRACKING_PARAMS = frozenset(
    {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "ref", "source", "campaign", "mc_cid", "mc_eid",
    }
)


class NVDReferenceScraperEnricher:
    """
    Enricher that scrapes and stores reference URLs from NVD CVE records.

    Fetches each reference URL, stores raw content and cleaned text in S3,
    with metadata for downstream processing.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.storage = ReferenceStorage(self.config)
        self.cleaner = ContentCleaner(
            max_chunk_size=getattr(
                self.config, "NVD_REF_MAX_CHUNK_SIZE", 1_048_576
            )
        )

        self.rate_limiter = RateLimiter(
            max_requests=self.config.NVD_REF_RATE_LIMIT_REQUESTS,
            window_seconds=self.config.NVD_REF_RATE_LIMIT_WINDOW,
        )
        self.timeout = self.config.NVD_REF_TIMEOUT
        self.max_retries = self.config.NVD_REF_MAX_RETRIES
        self.max_size_bytes = self.config.NVD_REF_MAX_SIZE_MB * 1024 * 1024
        self.dedupe_ttl_days = self.config.NVD_REF_DEDUPE_TTL_DAYS
        self.user_agent = self.config.NVD_REF_USER_AGENT
        self.skip_github = getattr(self.config, "NVD_REF_SKIP_GITHUB", True)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

    def enrich_cves(self, cve_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process CVE records: extract references, fetch URLs, store content.

        Args:
            cve_records: List of NIST CVE records

        Returns:
            Summary dict: urls_processed, urls_succeeded, urls_failed
        """
        if not getattr(self.config, "NVD_REF_SCRAPE_ENABLED", True):
            logger.info("NVD reference scraping is disabled")
            return {"urls_processed": 0, "urls_succeeded": 0, "urls_failed": 0}

        urls_processed = 0
        urls_succeeded = 0
        urls_failed = 0

        for cve_record in cve_records:
            refs = self._extract_references(cve_record)
            if not refs:
                continue

            cve_data = cve_record.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
                continue

            for ref_index, ref in enumerate(refs):
                url = ref.get("url")
                if not url or not isinstance(url, str):
                    continue

                # Skip GitHub URLs: repos from NIST refs often lack useful CVE content
                if self.skip_github and self._is_github_url(url):
                    normalized_url = self._normalize_url(url)
                    logger.info(
                        f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} "
                        f"normalized_url={normalized_url} skipped=github"
                    )
                    continue

                urls_processed += 1
                try:
                    result = self._fetch_url(url, cve_id, ref_index)
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
        }
        logger.info(f"NVDReferenceScraper.enrich_cves summary: {summary}")
        print(f"NVDReferenceScraper.enrich_cves summary: {summary}")
        return summary

    def _extract_references(self, cve_record: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract reference URLs from a CVE record.

        Supports:
        - NVD API 2.0: cve.references is an array of { url, source?, tags? }.
        - Legacy (e.g. 5.0): cve.references is an object with reference_data array.

        Paths:
        - 2.0: cve.references[]  (each item has "url")
        - Legacy: cve.references.reference_data[]  (each item has "url")
        """
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

        result = []
        for ref in ref_data:
            if isinstance(ref, dict) and ref.get("url"):
                result.append(ref)
        return result

    def _is_github_url(self, url: str) -> bool:
        """Return True if URL is a GitHub host (repos, gists, raw)."""
        try:
            parsed = urlparse(url)
            netloc = (parsed.netloc or "").lower()
            if not netloc:
                return False
            # Strip optional port and www
            host = netloc.split(":")[0].lstrip("www.")
            return host in (
                "github.com",
                "raw.githubusercontent.com",
                "gist.github.com",
            )
        except Exception:
            return False

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication: remove fragments, sort params, etc."""
        try:
            parsed = urlparse(url)
            # Normalize scheme and host to lowercase
            scheme = parsed.scheme.lower() if parsed.scheme else "https"
            netloc = parsed.netloc.lower() if parsed.netloc else ""

            # Remove fragment
            fragment = ""

            # Sort and filter query params (remove tracking)
            query_parts = []
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=False)
                filtered = {
                    k: v for k, v in params.items()
                    if k.lower() not in TRACKING_PARAMS
                }
                sorted_items = sorted(filtered.items())
                query_parts = [f"{k}={v[0]}" if len(v) == 1 else f"{k}={','.join(v)}"
                              for k, v in sorted_items]
            query = "&".join(query_parts) if query_parts else ""

            # Remove trailing slash from path (except for root)
            path = parsed.path.rstrip("/") or "/"

            rebuilt = urlunparse((scheme, netloc, path, parsed.params, query, fragment))
            return rebuilt
        except Exception as e:
            logger.debug(f"URL normalization failed for {url}: {e}")
            return url

    def _generate_url_hash(self, url: str, length: int = 8) -> str:
        """Generate short deterministic hash of normalized URL."""
        normalized = self._normalize_url(url)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        return digest[:length]

    def _determine_content_type(self, response: requests.Response) -> str:
        """Determine content type from response headers or content."""
        ct = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ct:
            return ct

        # Sniff from content
        content = response.content[:512]
        if content.startswith(b"%PDF"):
            return "application/pdf"
        if content.lstrip().startswith(b"{"):
            return "application/json"
        if content.lstrip().startswith(b"<"):
            return "text/html"
        return "application/octet-stream"

    def _check_dedupe(self, url: str, url_hash: str, cve_id: str, ref_index: int) -> bool:
        """
        Check if we should skip fetch (content already exists within TTL).

        Returns True if we should skip (content exists and is recent).
        """
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
        now = datetime.now(timezone.utc)
        age = now - last_mod
        return age <= timedelta(days=self.dedupe_ttl_days)

    def _fetch_url(self, url: str, cve_id: str, ref_index: int) -> Optional[Dict[str, Any]]:
        """
        Fetch URL, extract content, save raw/clean/meta to S3.

        Returns metadata dict if saved, None otherwise.
        """
        url_hash = self._generate_url_hash(url)

        # Deduplication check
        if self._check_dedupe(url, url_hash, cve_id, ref_index):
            normalized_url = self._normalize_url(url)
            logger.info(f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} normalized_url={normalized_url} skipped=dedupe")
            return {"saved": False, "skipped": "dedupe"}

        # Validate URL scheme
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            normalized_url = self._normalize_url(url)
            logger.info(f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} normalized_url={normalized_url} skipped=scheme")
            return {"saved": False, "skipped": "scheme"}

        fetch_date = datetime.now(timezone.utc)
        redirects: List[str] = []

        @retry_with_backoff(
            max_retries=self.max_retries,
            initial_delay=1.0,
            backoff_multiplier=2.0,
            exceptions=(requests.RequestException,),
        )
        def do_fetch() -> requests.Response:
            self.rate_limiter.wait_if_needed()
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,
            )
            # Read body with size limit
            content = b""
            for chunk in resp.iter_content(chunk_size=65536):
                content += chunk
                if len(content) > self.max_size_bytes:
                    logger.warning(f"Content exceeds {self.max_size_bytes} bytes for {url}")
                    break
            resp._content = content
            return resp

        try:
            response = do_fetch()
        except requests.RequestException as e:
            normalized_url = self._normalize_url(url)
            logger.info(f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} normalized_url={normalized_url} status_code=N/A fetch_error={e}")
            return {"saved": False, "error": str(e)}

        if response.history:
            redirects = [r.headers.get("Location", "") for r in response.history]

        final_url = response.url
        status_code = response.status_code

        normalized_url = self._normalize_url(url)
        if status_code >= 400:
            logger.info(f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} normalized_url={normalized_url} status_code={status_code}")
            return {"saved": False, "status_code": status_code}

        content = response.content
        content_type = self._determine_content_type(response)
        content_hash = hashlib.sha256(content).hexdigest()

        # Generate S3 keys
        raw_key = self.storage.generate_s3_key(
            cve_id, ref_index, url_hash, content_type, fetch_date, "raw"
        )
        clean_key = self.storage.generate_s3_key(
            cve_id, ref_index, url_hash, content_type, fetch_date, "clean"
        )
        meta_key = self.storage.generate_s3_key(
            cve_id, ref_index, url_hash, content_type, fetch_date, "meta"
        )
        logger.info(
            f"NVDReferenceScraper: cve_id={cve_id} ref_index={ref_index} normalized_url={normalized_url} status_code={status_code} "
            f"raw_key={raw_key} clean_key={clean_key} meta_key={meta_key}"
        )

        # Extract text and clean
        cleaned_text = ""
        extraction_success = False

        base_type = content_type.split(";")[0].strip().lower()
        if "html" in base_type:
            try:
                raw_text = content.decode("utf-8", errors="replace")
                extracted = ContentCleaner.extract_text_from_html(raw_text)
                cleaned_text = self.cleaner.clean_text(extracted, content_type)
                extraction_success = bool(cleaned_text.strip())
            except Exception as e:
                logger.debug(f"HTML extraction failed for {url}: {e}")
        elif "pdf" in base_type:
            extracted = ContentCleaner.extract_text_from_pdf(content)
            if extracted:
                cleaned_text = self.cleaner.clean_text(extracted, content_type)
                extraction_success = bool(cleaned_text.strip())
        elif "json" in base_type:
            try:
                raw_text = content.decode("utf-8", errors="replace")
                cleaned_text = self.cleaner.clean_text(raw_text, content_type)
                extraction_success = True
            except Exception:
                pass
        elif "text" in base_type or "xml" in base_type:
            try:
                raw_text = content.decode("utf-8", errors="replace")
                cleaned_text = self.cleaner.clean_text(raw_text, content_type)
                extraction_success = True
            except Exception:
                pass

        language = self.cleaner.detect_language(cleaned_text) if cleaned_text else "unknown"

        metadata = {
            "cve_id": cve_id,
            "ref_index": ref_index,
            "original_url": url,
            "final_url": final_url,
            "fetch_timestamp": fetch_date.isoformat() + "Z",
            "status_code": status_code,
            "content_type": content_type,
            "content_length": len(content),
            "content_hash_sha256": content_hash,
            "extraction_success": extraction_success,
            "language": language,
            "cleaned_text_length": len(cleaned_text),
            "redirects": redirects,
            "error": None,
            "s3_keys": {
                "raw": raw_key,
                "clean": clean_key,
                "meta": meta_key,
            },
        }

        # Save to S3
        raw_ok = self.storage.save_reference_raw(content, raw_key, content_type)
        clean_ok = self.storage.save_reference_clean(cleaned_text, clean_key) if cleaned_text else True
        meta_ok = self.storage.save_reference_metadata(metadata, meta_key)

        saved = raw_ok and meta_ok
        if not raw_ok or not meta_ok:
            logger.warning(f"Failed to save some artifacts for {url} (raw_ok={raw_ok} meta_ok={meta_ok})")

        return {"saved": saved, "metadata": metadata}
