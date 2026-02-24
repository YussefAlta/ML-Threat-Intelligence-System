"""
Abuse.ch ThreatFox IOC ingester.

Fetches recent IOCs from ThreatFox's public JSON export and produces
unified documents grouped by malware family for richer NLP content.
No API key required.
"""

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class ThreatFoxIngester:
    """
    Ingests IOCs from Abuse.ch ThreatFox public JSON export.
    Groups IOCs by malware family to produce documents with enough
    text content for NLP classification and entity extraction.
    """

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ML-Threat-Intelligence-System/1.0",
            "Accept": "application/json",
        })

    def ingest(self, max_records: int = 200) -> List[Dict]:
        url = getattr(
            self.config, "THREATFOX_EXPORT_URL",
            "https://threatfox.abuse.ch/export/json/recent/",
        )

        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            raw_data = resp.json()
        except requests.RequestException as e:
            logger.error("Failed to fetch ThreatFox IOCs: %s", e)
            return []
        except ValueError as e:
            logger.error("Invalid JSON from ThreatFox: %s", e)
            return []

        if not isinstance(raw_data, dict):
            logger.warning("ThreatFox returned unexpected data type: %s", type(raw_data))
            return []

        # Flatten: each key maps to a list containing one IOC entry
        all_iocs: List[Dict] = []
        for entry_id, entries in raw_data.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict):
                    entry["_threatfox_id"] = entry_id
                    all_iocs.append(entry)

        if not all_iocs:
            logger.warning("ThreatFox returned no IOC entries")
            return []

        logger.info("ThreatFox: fetched %d raw IOC entries", len(all_iocs))

        # Group by malware family for richer documents
        by_malware: Dict[str, List[Dict]] = defaultdict(list)
        for ioc in all_iocs:
            family = ioc.get("malware_printable") or ioc.get("malware") or "Unknown"
            by_malware[family].append(ioc)

        docs: List[Dict] = []
        for family, iocs in sorted(by_malware.items(), key=lambda x: -len(x[1])):
            if len(docs) >= max_records:
                break
            doc = self._group_to_unified_doc(family, iocs)
            if doc:
                docs.append(doc)

        logger.info(
            "ThreatFox ingester: collected %d documents from %d IOCs (max=%d)",
            len(docs), len(all_iocs), max_records,
        )
        return docs

    def _group_to_unified_doc(self, family: str, iocs: List[Dict]) -> Optional[Dict]:
        if not iocs:
            return None

        # Categorize IOCs by type
        domains: List[str] = []
        ips: List[str] = []
        urls: List[str] = []
        tags: set = set()
        references: set = set()
        reporters: set = set()
        threat_types: set = set()
        confidences: List[int] = []
        first_seen: Optional[str] = None

        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "")
            ioc_value = ioc.get("ioc_value", "")

            if "domain" in ioc_type:
                domains.append(ioc_value)
            elif "ip" in ioc_type:
                ips.append(ioc_value)
            elif "url" in ioc_type:
                urls.append(ioc_value)

            if ioc.get("tags"):
                for tag in str(ioc["tags"]).split(","):
                    tag = tag.strip()
                    if tag:
                        tags.add(tag)

            if ioc.get("reference"):
                references.add(str(ioc["reference"]))

            if ioc.get("reporter"):
                reporters.add(ioc["reporter"])

            if ioc.get("threat_type"):
                threat_types.add(ioc["threat_type"])

            conf = ioc.get("confidence_level")
            if conf is not None:
                try:
                    confidences.append(int(conf))
                except (ValueError, TypeError):
                    pass

            seen = ioc.get("first_seen_utc")
            if seen and (first_seen is None or seen < first_seen):
                first_seen = seen

        # Build content
        threat_str = ", ".join(sorted(threat_types)) if threat_types else "unknown"
        parts = [f"Threat intelligence: {family} ({threat_str})."]

        indicator_parts = []
        if domains:
            indicator_parts.append(f"{len(domains)} domains")
        if ips:
            indicator_parts.append(f"{len(ips)} IPs")
        if urls:
            indicator_parts.append(f"{len(urls)} URLs")
        if indicator_parts:
            parts.append(f"IOC indicators: {', '.join(indicator_parts)}.")

        if domains:
            parts.append(f"Malicious domains: {', '.join(domains[:20])}.")
        if ips:
            parts.append(f"Command and control IPs: {', '.join(ips[:20])}.")
        if urls:
            parts.append(f"Malicious URLs: {', '.join(urls[:10])}.")

        if tags:
            parts.append(f"Tags: {', '.join(sorted(tags))}.")

        avg_conf = round(sum(confidences) / len(confidences)) if confidences else 0
        parts.append(f"Confidence level: {avg_conf}.")

        if references:
            parts.append(f"References: {' '.join(sorted(references)[:5])}.")

        content = " ".join(parts)

        # Generate stable ID
        raw_id = f"threatfox_{family}_{first_seen or ''}"
        hash8 = hashlib.sha256(raw_id.encode()).hexdigest()[:8]
        doc_id = f"threatfox_{family.lower().replace(' ', '_')}_{hash8}"

        return {
            "id": doc_id,
            "title": f"ThreatFox IOCs: {family}",
            "content": content,
            "url": f"https://threatfox.abuse.ch/browse/malware/{family.replace(' ', '%20')}/",
            "source": "threatfox",
            "source_category_hint": "ioc",
            "published_at": first_seen,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "malware_family": family,
                "threat_types": sorted(threat_types),
                "ioc_count": len(iocs),
                "domain_count": len(domains),
                "ip_count": len(ips),
                "url_count": len(urls),
                "avg_confidence": avg_conf,
                "tags": sorted(tags),
                "reporters": sorted(reporters),
            },
        }
