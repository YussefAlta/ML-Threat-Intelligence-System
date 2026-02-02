#!/usr/bin/env python3
"""
Test script for Phase 2 enrichment:
- Fetches a small sample of recent CVEs from NIST
- Runs CWE and VulnCheck enrichment
- Stores enriched results via DataStorage
"""

import sys
import os
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_intelligence.core.config import Config
from threat_intelligence.ingesters.nist_cve_ingester import NISTCVEIngester
from threat_intelligence.storage.data_storage import DataStorage
from threat_intelligence.orchestrators.nist_enrichment import NISTEnrichmentOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    logger.info("=" * 70)
    logger.info("Phase 2 Enrichment Test")
    logger.info("=" * 70)

    config = Config()
    config.validate()

    # 1) Load CVEs from the most recent NIST CVE file stored in S3, falling back to local/live only if needed
    storage = DataStorage(config)
    sample_cves = []
    latest_s3_key = storage.get_latest_nist_cve_s3_key()
    if latest_s3_key:
        logger.info(f"Loading CVEs from latest NIST CVE object in S3: {latest_s3_key}")
        try:
            data = storage.load_json_from_s3(latest_s3_key)
            if isinstance(data, dict):
                sample_cves = data.get("vulnerabilities", [])
                # Use a smaller sample for testing (3 CVEs to avoid long wait times)
                sample_cves = sample_cves[:3]
                logger.info(
                    f"Loaded {len(sample_cves)} CVEs from S3 for enrichment test"
                )
                logger.info(
                    "Note: Enrichment may take a few minutes due to API rate limiting. "
                    "This is normal and expected."
                )
        except Exception as e:
            logger.error(f"Failed to load NIST CVEs from S3: {str(e)}")

    if not sample_cves:
        logger.error(
            "No CVEs loaded from S3; please ensure Phase 1 NIST ingestion has "
            "stored CVEs in S3 under 'nist/cve/'."
        )
        return 1

    if not sample_cves:
        logger.error("No CVEs available; cannot run enrichment test")
        return 1

    # 2) Run enrichment
    logger.info(f"Starting enrichment for {len(sample_cves)} CVEs...")
    logger.info("This may take a few minutes due to API rate limiting.")
    
    orchestrator = NISTEnrichmentOrchestrator(config)
    results = orchestrator.enrich_cves(
        sample_cves,
        save_local=True,
        run_cwe=True,
        run_vulncheck=True,
    )

    logger.info("=" * 70)
    logger.info("Enrichment Results")
    logger.info("=" * 70)

    cwe_res = results.get("cwe", {})
    vc_res = results.get("vulncheck", {})

    logger.info(
        "CWE Enrichment: success=%s, records=%s, s3_key=%s",
        cwe_res.get("success"),
        cwe_res.get("records"),
        cwe_res.get("s3_key"),
    )
    logger.info(
        "VulnCheck Enrichment: success=%s, records=%s, s3_key=%s",
        vc_res.get("success"),
        vc_res.get("records"),
        vc_res.get("s3_key"),
    )

    overall_success = cwe_res.get("success") and vc_res.get("success")
    if overall_success:
        logger.info("🎉 Phase 2 enrichment test completed successfully!")
        return 0

    logger.warning("⚠️ Phase 2 enrichment test completed with some failures")
    return 1


if __name__ == "__main__":
    sys.exit(main())


