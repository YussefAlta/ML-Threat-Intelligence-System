#!/usr/bin/env python3
"""
Simple test script for Phase 2 enrichment with a single CVE:
- Loads ONE CVE from S3
- Tests CWE and VulnCheck enrichment
- Shows progress logs
"""

import sys
import os
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_intelligence.core.config import Config
from threat_intelligence.storage.data_storage import DataStorage
from threat_intelligence.orchestrators.nist_enrichment import NISTEnrichmentOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    logger.info("=" * 70)
    logger.info("Simple Phase 2 Enrichment Test (1 CVE)")
    logger.info("=" * 70)

    config = Config()
    config.validate()

    # Load ONE CVE from S3
    storage = DataStorage(config)
    latest_s3_key = storage.get_latest_nist_cve_s3_key()
    if not latest_s3_key:
        logger.error("No CVE files found in S3!")
        return 1

    logger.info(f"Loading from: {latest_s3_key}")
    data = storage.load_json_from_s3(latest_s3_key)
    
    if not isinstance(data, dict):
        logger.error("Invalid data format")
        return 1
        
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        logger.error("No vulnerabilities found in file")
        return 1
    
    # Take just the first CVE
    test_cve = vulnerabilities[0]
    cve_id = test_cve.get("cve", {}).get("id", "UNKNOWN")
    logger.info(f"Testing enrichment for: {cve_id}")
    
    # Run enrichment
    logger.info("Starting enrichment...")
    orchestrator = NISTEnrichmentOrchestrator(config)
    
    try:
        results = orchestrator.enrich_cves(
            [test_cve],  # Just one CVE
            save_local=True,
            run_cwe=True,
            run_vulncheck=True,
        )
        
        logger.info("=" * 70)
        logger.info("Results:")
        logger.info(f"CWE: {results.get('cwe', {})}")
        logger.info(f"VulnCheck: {results.get('vulncheck', {})}")
        logger.info("=" * 70)
        
        cwe_success = results.get("cwe", {}).get("success", False)
        vc_success = results.get("vulncheck", {}).get("success", False)
        
        if cwe_success and vc_success:
            logger.info("✅ Test passed!")
            return 0
        else:
            logger.warning("⚠️ Test completed with some issues")
            return 1
            
    except KeyboardInterrupt:
        logger.error("Test interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Test failed with error: {str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

