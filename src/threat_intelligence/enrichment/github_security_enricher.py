import json
import time
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

from threat_intelligence.core.config import Config
from threat_intelligence.enrichment.content_cleaner import ContentCleaner
from threat_intelligence.storage.reference_storage import ReferenceStorage

logger = logging.getLogger(__name__)


@dataclass
class GitHubItem:
    item_type: str  # repo | issue | pr
    url: str
    payload: Dict


class GitHubSecurityEnricher:
    """
    GitHub CVE enrichment.
    Stores into:
      enrichments/github_references/raw
      enrichments/github_references/clean
      enrichments/github_references/meta
    """

    ROOT_PREFIX = "enrichments/github_references"

    def __init__(self, storage: ReferenceStorage, cleaner: ContentCleaner):
        self.storage = storage
        self.cleaner = cleaner

        self.enabled = getattr(Config, "GITHUB_ENABLED", True)
        self.token = getattr(Config, "GITHUB_TOKEN", None)
        self.max_items = int(getattr(Config, "GITHUB_MAX_ITEMS_PER_CVE", 10))
        self.rpm = int(getattr(Config, "GITHUB_RATE_LIMIT_RPM", 20))
        self.timeout = int(getattr(Config, "GITHUB_SEARCH_TIMEOUT", 20))
        self.max_retries = int(getattr(Config, "GITHUB_MAX_RETRIES", 3))

        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "User-Agent": "ML-Threat-Intelligence-System/1.0",
        })

        if self.token:
            self.session.headers.update({
                "Authorization": f"Bearer {self.token}"
            })

        self._last_req_ts = 0.0

    # =====================================================
    # MAIN
    # =====================================================

    def enrich_cves(self, cve_records: List[Dict]) -> Dict:

        if not self.enabled:
            logger.info("GitHubSecurityEnricher disabled.")
            return {"items_processed": 0, "items_succeeded": 0, "items_failed": 0}

        if not self.token:
            logger.warning("GITHUB_TOKEN missing.")
            return {"items_processed": 0, "items_succeeded": 0, "items_failed": 0}

        processed = succeeded = failed = 0

        for cve in cve_records:

            cve_id = self._extract_cve_id(cve)
            if not cve_id:
                continue

            items = self._collect_items_for_cve(cve_id)[: self.max_items]
            fetch_date = datetime.now(timezone.utc)

            for idx, item in enumerate(items):
                processed += 1
                try:
                    if self._store_item(cve_id, idx, item, fetch_date):
                        succeeded += 1
                    else:
                        failed += 1
                except Exception as e:
                    failed += 1
                    logger.error(f"GitHub error: {e}", exc_info=True)

        summary = {
            "items_processed": processed,
            "items_succeeded": succeeded,
            "items_failed": failed,
        }

        logger.info(summary)
        print(summary)
        return summary

    # =====================================================
    # COLLECTION
    # =====================================================

    def _collect_items_for_cve(self, cve_id: str):

        query = f'"{cve_id}"'

        repos = self._search("repositories", query)
        issues = self._search("issues", query)

        items = []

        for r in repos:
            url = r.get("html_url")
            if url:
                items.append(GitHubItem("repo", url, r))

        for i in issues:
            url = i.get("html_url")
            if url:
                itype = "pr" if "pull_request" in i else "issue"
                items.append(GitHubItem(itype, url, i))

        return items

    def _search(self, kind, query):

        url = f"https://api.github.com/search/{kind}"
        params = {
            "q": query,
            "per_page": 20,
            "sort": "updated",
            "order": "desc",
        }

        for attempt in range(self.max_retries):

            self._rate_limit()

            r = self.session.get(url, params=params, timeout=self.timeout)

            if r.status_code == 200:
                return (r.json() or {}).get("items", [])

            if r.status_code in (403, 429):
                time.sleep(2 ** attempt)
                continue

            logger.warning(f"GitHub search failed: {r.status_code}")
            return []

        return []

    def _rate_limit(self):
        if self.rpm <= 0:
            return

        interval = 60.0 / float(self.rpm)
        now = time.time()

        if now - self._last_req_ts < interval:
            time.sleep(interval - (now - self._last_req_ts))

        self._last_req_ts = time.time()

    # =====================================================
    # STORAGE
    # =====================================================

    def _store_item(self, cve_id, idx, item, fetch_date):

        normalized = self._normalize_url(item.url)
        url_hash = self._short_hash(normalized)

        raw_bytes = json.dumps(item.payload).encode()
        clean_text = self.cleaner.clean_text(
            self._to_clean_text(item),
            content_type="application/json",
        )

        # 🔥 ONLY raw/clean/meta (NOT full paths)
        raw_key = self.storage.generate_s3_key(
            cve_id, idx, url_hash,
            "application/json",
            fetch_date,
            folder="raw",
            root_prefix=self.ROOT_PREFIX
        )

        clean_key = self.storage.generate_s3_key(
            cve_id, idx, url_hash,
            "text/plain",
            fetch_date,
            folder="clean",
            root_prefix=self.ROOT_PREFIX
        )

        meta_key = self.storage.generate_s3_key(
            cve_id, idx, url_hash,
            "application/json",
            fetch_date,
            folder="meta",
            root_prefix=self.ROOT_PREFIX
        )

        if self.storage.check_exists(raw_key):
            return True

        ok_raw = self.storage.save_reference_raw(raw_bytes, raw_key, "application/json")
        ok_clean = self.storage.save_reference_clean(clean_text, clean_key)

        metadata = {
            "source": "github",
            "cve_id": cve_id,
            "item_type": item.item_type,
            "original_url": item.url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "s3_keys": {
                "raw": raw_key,
                "clean": clean_key,
                "meta": meta_key,
            },
        }

        ok_meta = self.storage.save_reference_metadata(metadata, meta_key)

        logger.info(f"GitHub stored: {raw_key}")

        return bool(ok_raw and ok_clean and ok_meta)

    # =====================================================
    # HELPERS
    # =====================================================

    def _to_clean_text(self, item):

        p = item.payload

        if item.item_type == "repo":
            return "\n".join([
                f"URL: {p.get('html_url','')}",
                f"Repo: {p.get('full_name','')}",
                f"Description: {p.get('description','')}",
            ])

        return "\n".join([
            f"URL: {p.get('html_url','')}",
            f"Title: {p.get('title','')}",
            f"Body: {p.get('body','')}",
        ])

    def _extract_cve_id(self, record):

        for path in [
            ("cve_id",),
            ("id",),
            ("cve","id"),
            ("cve","CVE_data_meta","ID"),
        ]:
            cur = record
            for k in path:
                if not isinstance(cur, dict) or k not in cur:
                    break
                cur = cur[k]
            else:
                if isinstance(cur, str) and cur.startswith("CVE-"):
                    return cur

        return None

    def _normalize_url(self, url):
        return (url or "").strip()

    def _short_hash(self, s):
        return hashlib.sha256(s.encode()).hexdigest()[:10]
