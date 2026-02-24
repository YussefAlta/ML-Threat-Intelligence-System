"""
CISA Known Exploited Vulnerabilities (KEV) ingester.

Fetches the KEV catalog from CISA's public JSON feed and produces
unified documents. Each entry represents an actively exploited
vulnerability with vendor, product, description, and ransomware flags.
No API key required.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class CISAKEVIngester:
    """
    Ingests actively exploited vulnerabilities from the CISA KEV catalog.
    Produces unified documents enriched with vendor, product, required action,
    and ransomware campaign indicators.
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
            self.config, "CISA_KEV_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )

        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.error("Failed to fetch CISA KEV catalog: %s", e)
            return []
        except ValueError as e:
            logger.error("Invalid JSON from CISA KEV: %s", e)
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            logger.warning("CISA KEV 'vulnerabilities' is not a list")
            return []

        if not vulnerabilities:
            logger.warning("CISA KEV catalog is empty")
            return []

        # Sort by dateAdded descending so we get the most recent first
        vulnerabilities.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)

        docs: List[Dict] = []
        for entry in vulnerabilities[:max_records]:
            try:
                doc = self._to_unified_doc(entry)
                if doc:
                    docs.append(doc)
            except Exception as e:
                logger.warning("Skipping CISA KEV entry %s: %s", entry.get("cveID"), e)
                continue

        logger.info(
            "CISA KEV ingester: collected %d documents (max=%d, catalog_total=%d)",
            len(docs), max_records, len(vulnerabilities),
        )
        return docs

    def _to_unified_doc(self, entry: Dict) -> Optional[Dict]:
        cve_id = entry.get("cveID")
        if not cve_id:
            return None

        vendor = entry.get("vendorProject", "Unknown")
        product = entry.get("product", "Unknown")
        vuln_name = entry.get("vulnerabilityName", "")
        description = entry.get("shortDescription", "")
        required_action = entry.get("requiredAction", "")
        due_date = entry.get("dueDate", "")
        date_added = entry.get("dateAdded", "")
        ransomware_use = entry.get("knownRansomwareCampaignUse", "Unknown")
        notes = entry.get("notes", "")
        cwes = entry.get("cwes") or []

        # Build content
        parts = [f"CISA Known Exploited Vulnerability: {cve_id} - {vuln_name}."]
        parts.append(f"Vendor: {vendor}. Product: {product}.")

        if description:
            parts.append(description)

        if required_action:
            parts.append(f"Required action: {required_action}.")

        if due_date:
            parts.append(f"Remediation due date: {due_date}.")

        if ransomware_use and ransomware_use != "Unknown":
            parts.append(f"Known ransomware campaign use: {ransomware_use}.")

        if notes:
            parts.append(f"Notes: {notes}")

        content = " ".join(parts)

        # Determine category hint
        if ransomware_use == "Known":
            hint = "ransomware"
        else:
            hint = "vulnerability"

        # Generate stable ID
        raw_id = f"cisa_kev_{cve_id}"
        hash8 = hashlib.sha256(raw_id.encode()).hexdigest()[:8]
        doc_id = f"cisa_kev_{cve_id}_{hash8}"

        return {
            "id": doc_id,
            "title": f"CISA KEV: {cve_id} - {vendor} {product}",
            "content": content,
            "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "source": "cisa_kev",
            "source_category_hint": hint,
            "published_at": date_added if date_added else None,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "cve_id": cve_id,
                "vendor": vendor,
                "product": product,
                "ransomware_use": ransomware_use,
                "date_added": date_added,
                "due_date": due_date,
                "cwes": cwes,
            },
        }
