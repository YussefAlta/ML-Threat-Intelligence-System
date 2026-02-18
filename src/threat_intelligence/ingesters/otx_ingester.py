"""
AlienVault OTX pulse ingester.

Fetches threat intelligence pulses from OTX (subscribed or public activity feed)
and produces unified documents with IOC summaries.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List

import requests

logger = logging.getLogger(__name__)


class OTXIngester:
    """
    Ingests threat intelligence pulses from AlienVault OTX.
    Produces unified documents with descriptions and IOC type summaries.
    """

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        headers = {'User-Agent': 'ML-Threat-Intelligence-System/1.0'}
        api_key = getattr(self.config, 'OTX_API_KEY', None)
        if api_key:
            headers['X-OTX-API-KEY'] = api_key
        self.session.headers.update(headers)

    def ingest(self, max_records: int = 100) -> List[Dict]:
        base_url = getattr(self.config, 'OTX_API_BASE_URL', 'https://otx.alienvault.com/api/v1/')
        base_url = base_url.rstrip('/') + '/'
        if getattr(self.config, 'OTX_API_KEY', None):
            endpoint = f"{base_url}pulses/subscribed"
        else:
            endpoint = f"{base_url}pulses/activity"

        docs = []
        page = 1
        limit = 50
        fetched = 0
        url_to_use = endpoint
        params_to_use = {'limit': limit, 'page': page}

        while fetched < max_records:
            try:
                resp = self.session.get(
                    url_to_use,
                    params=params_to_use,
                    timeout=60,
                )
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                logger.error("Failed to fetch OTX pulses (page=%d): %s", page, e)
                break
            except ValueError as e:
                logger.error("Invalid JSON from OTX: %s", e)
                break

            results = data.get('results')
            if not results:
                break

            for pulse in results:
                if fetched >= max_records:
                    break
                try:
                    doc = self._to_unified_doc(pulse)
                    if doc:
                        docs.append(doc)
                        fetched += 1
                except Exception as e:
                    logger.warning("Skipping OTX pulse %s: %s", pulse.get('id'), e)

            if fetched % 50 == 0 and fetched > 0:
                logger.info("OTX ingester: collected %d documents...", fetched)

            if len(results) < limit:
                break
            next_url = data.get('next')
            if next_url:
                url_to_use = next_url
                params_to_use = None
            else:
                page += 1
                url_to_use = endpoint
                params_to_use = {'limit': limit, 'page': page}

        logger.info(
            "OTX ingester: collected %d documents (max=%d)",
            len(docs),
            max_records,
        )
        return docs

    def _to_unified_doc(self, pulse: Dict) -> Dict:
        pulse_id = pulse.get('id') or pulse.get('name', '')
        name = pulse.get('name') or 'Untitled Pulse'
        description = (pulse.get('description') or '').strip()
        tags = pulse.get('tags') or []
        indicators = pulse.get('indicators') or []
        created = pulse.get('created')
        author_name = pulse.get('author_name') or pulse.get('author', {}).get('username', '')
        references = pulse.get('references') or []

        indicator_types = {}
        for ind in indicators:
            itype = ind.get('type') if isinstance(ind, dict) else getattr(ind, 'type', 'Unknown')
            indicator_types[itype] = indicator_types.get(itype, 0) + 1

        tag_str = ', '.join(tags) if tags else ''
        ind_summary_parts = []
        for itype, count in sorted(indicator_types.items()):
            ind_summary_parts.append(f"{itype}: {count}")
        ind_summary = '; '.join(ind_summary_parts) if ind_summary_parts else "No indicators"

        ref_str = ''
        if references:
            ref_list = [r.get('url', r) if isinstance(r, dict) else str(r) for r in references[:5]]
            ref_str = ' '.join(ref_list)

        parts = []
        if description:
            parts.append(description)
        if tag_str:
            parts.append(f"Tags: {tag_str}.")
        parts.append(f"Indicator summary: {ind_summary}.")
        if ref_str:
            parts.append(f"References: {ref_str}")
        content = ' '.join(parts)

        raw_id = f"{pulse_id}{name}{created}"
        hash8 = hashlib.sha256(raw_id.encode()).hexdigest()[:8]
        doc_id = f"otx_{pulse_id}_{hash8}"

        doc_url = f"https://otx.alienvault.com/pulse/{pulse_id}"

        return {
            "id": doc_id,
            "title": name,
            "content": content,
            "url": doc_url,
            "source": "otx",
            "source_category_hint": "ioc",
            "published_at": created,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "pulse_id": pulse_id,
                "author": author_name,
                "tags": tags,
                "indicator_count": len(indicators),
                "indicator_types": indicator_types,
            },
        }
