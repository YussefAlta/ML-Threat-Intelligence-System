"""
PhishTank phishing feed ingester.
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List

import requests

logger = logging.getLogger(__name__)


class PhishTankIngester:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ML-Threat-Intelligence-System/1.0 (https://github.com)'
        })

    def ingest(self, max_records: int = 200) -> List[Dict]:
        docs = []
        url = self.config.PHISHTANK_FEED_URL
        params = {}
        if getattr(self.config, 'PHISHTANK_API_KEY', None):
            params['app_key'] = self.config.PHISHTANK_API_KEY

        try:
            resp = self.session.get(url, params=params if params else None, timeout=60)
            resp.raise_for_status()
            records = resp.json()
        except requests.RequestException as e:
            logger.error("Failed to fetch PhishTank feed: %s", e)
            return []
        except ValueError as e:
            logger.error("Invalid JSON from PhishTank feed: %s", e)
            return []

        if not isinstance(records, list):
            logger.error("PhishTank feed is not a JSON array")
            return []

        for i, record in enumerate(records[:max_records]):
            try:
                doc = self._to_unified_doc(record)
                if doc:
                    docs.append(doc)
            except Exception as e:
                logger.warning("Skipping PhishTank record %s: %s", record.get('phish_id'), e)
                continue

        logger.info("PhishTank ingester: collected %d documents (max=%d)", len(docs), max_records)
        return docs

    def _to_unified_doc(self, record: Dict) -> Dict:
        phish_id = record.get('phish_id')
        raw_url = record.get('url', '')
        if not phish_id and not raw_url:
            return None

        hash8 = hashlib.sha256(f"{phish_id}{raw_url}".encode()).hexdigest()[:8]
        doc_id = f"phishtank_{phish_id}_{hash8}"

        target = record.get('target', 'Unknown')
        title = f"Phishing: {target} - {raw_url[:80]}" if raw_url else f"Phishing: {target}"

        verified = record.get('verified', 'unknown')
        submission_time = record.get('submission_time', '')
        detail_url = record.get('phish_detail_url', '')

        parts = [f"Phishing URL: {raw_url}"]
        if target:
            parts.append(f"Target brand: {target}")
        if submission_time:
            parts.append(f"Submitted: {submission_time}")
        parts.append(f"Verified: {verified}")
        if detail_url:
            parts.append(f"Details: {detail_url}")
        content = ". ".join(parts)

        return {
            "id": doc_id,
            "title": title,
            "content": content,
            "url": detail_url or raw_url,
            "source": "phishtank",
            "source_category_hint": "phishing",
            "published_at": submission_time if submission_time else None,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "phish_id": phish_id,
                "target": target,
                "verified": verified,
                "original_url": raw_url,
            },
        }
