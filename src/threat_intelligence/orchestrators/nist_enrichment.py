"""
Phase 2: NIST CVE Enrichment Orchestrator.

This orchestrator:
- Takes CVE records (e.g., from the NIST ingestion pipeline)
- Enriches them with:
    - MITRE CWE weakness details
    - VulnCheck vulnerability intelligence
- Stores enriched results in S3 and/or local storage
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional

from ..core.config import Config
from ..storage.data_storage import DataStorage
from ..enrichment import CWEEnricher, VulnCheckEnricher

logger = logging.getLogger(__name__)


class NISTEnrichmentOrchestrator:
    """
    Orchestrates enrichment of NIST CVE data with CWE and VulnCheck.

    Typical usage:
        config = Config()
        orchestrator = NISTEnrichmentOrchestrator(config)
        enriched = orchestrator.enrich_cves(cve_records)
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.config.validate()

        self.storage = DataStorage(self.config)
        self.cwe_enricher = CWEEnricher(self.config)
        self.vulncheck_enricher = VulnCheckEnricher(self.config)

        logger.info("NIST Enrichment Orchestrator initialized")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_cves(
        self,
        cve_records: List[Dict],
        date_filter: Optional[str] = None,
        save_local: bool = True,
        run_cwe: bool = True,
        run_vulncheck: bool = True,
    ) -> Dict[str, Dict]:
        """
        Enrich CVEs with CWE and VulnCheck data.

        Args:
            cve_records: List of CVE records (from NISTCVEIngester or stored files)
            date_filter: Optional date for storage organization
            save_local: Whether to save enriched data locally as well as S3
            run_cwe: Whether to run CWE enrichment
            run_vulncheck: Whether to run VulnCheck enrichment

        Returns:
            Dict with keys "cwe" and "vulncheck" containing enrichment summaries.
        """
        results: Dict[str, Dict] = {
            "cwe": {"success": False, "records": 0, "s3_key": None},
            "vulncheck": {"success": False, "records": 0, "s3_key": None},
        }

        if not cve_records:
            logger.warning("No CVE records provided for enrichment")
            return results

        # Normalize date_filter (default = today's date)
        if not date_filter:
            date_filter = datetime.now().strftime("%Y-%m-%d")

        # ------------------------------------------------------------------
        # CWE enrichment
        # ------------------------------------------------------------------
        if run_cwe:
            try:
                logger.info("Starting CWE enrichment for CVEs...")
                cwe_enriched = self.cwe_enricher.enrich_cves(cve_records)
                if cwe_enriched:
                    s3_key = self.storage.save_enriched_cve_data(
                        cwe_enriched,
                        enrichment_source="cwe",
                        date_filter=date_filter,
                        save_local=save_local,
                    )
                    results["cwe"] = {
                        "success": True,
                        "records": len(cwe_enriched),
                        "s3_key": s3_key,
                    }
                else:
                    logger.info("No CWE enrichment records produced")
                    results["cwe"] = {
                        "success": True,
                        "records": 0,
                        "s3_key": None,
                    }
            except Exception as e:
                logger.error(f"CWE enrichment failed: {str(e)}", exc_info=True)
                results["cwe"] = {
                    "success": False,
                    "records": 0,
                    "s3_key": None,
                    "error": str(e),
                }

        # ------------------------------------------------------------------
        # VulnCheck enrichment
        # ------------------------------------------------------------------
        if run_vulncheck:
            try:
                logger.info("Starting VulnCheck enrichment for CVEs...")
                vuln_enriched = self.vulncheck_enricher.enrich_cves(cve_records)
                if vuln_enriched:
                    s3_key = self.storage.save_enriched_cve_data(
                        vuln_enriched,
                        enrichment_source="vulncheck",
                        date_filter=date_filter,
                        save_local=save_local,
                    )
                    results["vulncheck"] = {
                        "success": True,
                        "records": len(vuln_enriched),
                        "s3_key": s3_key,
                    }
                else:
                    logger.info("No VulnCheck enrichment records produced")
                    results["vulncheck"] = {
                        "success": True,
                        "records": 0,
                        "s3_key": None,
                    }
            except Exception as e:
                logger.error(f"VulnCheck enrichment failed: {str(e)}", exc_info=True)
                results["vulncheck"] = {
                    "success": False,
                    "records": 0,
                    "s3_key": None,
                    "error": str(e),
                }

        return results


