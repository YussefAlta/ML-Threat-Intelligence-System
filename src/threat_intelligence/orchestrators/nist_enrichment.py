"""
Phase 2: NIST CVE Enrichment Orchestrator.

This orchestrator:
- Takes CVE records (e.g., from the NIST ingestion pipeline)
- Enriches them with:
    - NVD Reference URL scraping (raw/clean/meta)
    - GitHub security evidence (raw/clean/meta)
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
from ..enrichment import (
    CWEEnricher,
    VulnCheckEnricher,
    NVDReferenceScraperEnricher,
    GitHubSecurityEnricher,
)

logger = logging.getLogger(__name__)


class NISTEnrichmentOrchestrator:
    """
    Orchestrates enrichment of NIST CVE data with:
      - NVD reference scraping
      - GitHub evidence
      - CWE
      - VulnCheck

    Typical usage:
        config = Config()
        orchestrator = NISTEnrichmentOrchestrator(config)
        results = orchestrator.enrich_cves(cve_records)
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.config.validate()

        self.storage = DataStorage(self.config)

        # Enrichment stages
        self.ref_scraper = NVDReferenceScraperEnricher(self.config)
        self.github_enricher = GitHubSecurityEnricher(self.config)
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
        run_reference_scrape: bool = True,
        run_github: bool = True,
        run_cwe: bool = True,
        run_vulncheck: bool = True,
    ) -> Dict[str, Dict]:
        """
        Enrich CVEs with NVD reference scraping, GitHub, CWE, and VulnCheck data.

        Args:
            cve_records: List of CVE records (from NISTCVEIngester or stored files)
            date_filter: Optional date for storage organization
            save_local: Whether to save enriched data locally as well as S3
            run_reference_scrape: Whether to run NVD reference URL scraping enrichment
            run_github: Whether to run GitHub enrichment
            run_cwe: Whether to run CWE enrichment
            run_vulncheck: Whether to run VulnCheck enrichment

        Returns:
            Dict with keys:
              - "reference_scrape"
              - "github"
              - "cwe"
              - "vulncheck"
        """
        results: Dict[str, Dict] = {
            "reference_scrape": {"success": False, "urls_processed": 0, "urls_succeeded": 0, "urls_failed": 0},
            "github": {"success": False, "items_processed": 0, "items_succeeded": 0, "items_failed": 0},
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
        # 1) NVD Reference scraping enrichment (first)
        # ------------------------------------------------------------------
        if run_reference_scrape:
            try:
                logger.info("Starting NVD reference scraping enrichment...")
                ref_enriched = self.ref_scraper.enrich_cves(cve_records)
                results["reference_scrape"] = {
                    "success": True,
                    "urls_processed": ref_enriched.get("urls_processed", 0),
                    "urls_succeeded": ref_enriched.get("urls_succeeded", 0),
                    "urls_failed": ref_enriched.get("urls_failed", 0),
                }
            except Exception as e:
                logger.error(f"Reference scraping enrichment failed: {str(e)}", exc_info=True)
                results["reference_scrape"] = {
                    "success": False,
                    "error": str(e),
                }

        # ------------------------------------------------------------------
        # 2) GitHub enrichment (second)
        # ------------------------------------------------------------------
        if run_github:
            try:
                logger.info("Starting GitHub enrichment for CVEs...")
                gh = self.github_enricher.enrich_cves(cve_records)
                results["github"] = {
                    "success": True,
                    "items_processed": gh.get("items_processed", 0),
                    "items_succeeded": gh.get("items_succeeded", 0),
                    "items_failed": gh.get("items_failed", 0),
                }
            except Exception as e:
                logger.error(f"GitHub enrichment failed: {str(e)}", exc_info=True)
                results["github"] = {
                    "success": False,
                    "error": str(e),
                }

        # ------------------------------------------------------------------
        # 3) CWE enrichment
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
        # 4) VulnCheck enrichment
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
