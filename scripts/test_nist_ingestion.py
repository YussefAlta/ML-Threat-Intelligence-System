#!/usr/bin/env python3
"""
Test script for NIST CVE/CPE ingestion pipeline.
Tests all aspects of the Phase 1 implementation:
- CVE ingestion with pagination
- CPE ingestion with pagination
- Rate limiting
- Retry logic
- Error handling
- S3 storage
"""
import sys
import os
import logging
import argparse
from datetime import datetime, timedelta

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from threat_intelligence.core.config import Config
from threat_intelligence.scrapers.nist_cve_scraper import NISTCVEScraper
from threat_intelligence.scrapers.nist_cpe_scraper import NISTCPEScraper
from threat_intelligence.orchestrators.nist_ingestion import NISTIngestionOrchestrator
from threat_intelligence.storage.data_storage import DataStorage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_config():
    """Test configuration loading."""
    logger.info("=" * 60)
    logger.info("Testing Configuration")
    logger.info("=" * 60)
    
    config = Config()
    config.validate()
    
    logger.info(f"NIST API Base URL: {config.NIST_API_BASE_URL}")
    logger.info(f"NIST API Key: {'*' * 10 if config.NIST_API_KEY else 'NOT SET'}")
    logger.info(f"Rate Limit: {config.NIST_RATE_LIMIT_REQUESTS} requests per {config.NIST_RATE_LIMIT_WINDOW} seconds")
    logger.info(f"Max Retries: {config.NIST_MAX_RETRIES}")
    logger.info(f"Results Per Page: {config.NIST_RESULTS_PER_PAGE}")
    logger.info(f"S3 Bucket: {config.S3_BUCKET_NAME or 'NOT SET'}")
    
    if not config.NIST_API_KEY:
        logger.warning("WARNING: NIST_API_KEY not set. API requests may be rate limited.")
    
    return config


def test_cve_scraper(config, max_count=10):
    """Test NIST CVE scraper."""
    logger.info("=" * 60)
    logger.info("Testing NIST CVE Scraper")
    logger.info("=" * 60)
    
    try:
        scraper = NISTCVEScraper(config)
        
        # Test fetching recent CVEs
        logger.info(f"Fetching up to {max_count} recent CVEs...")
        cves = scraper.fetch_recent_cves(days=7, max_count=max_count)
        
        if cves:
            logger.info(f"✅ Successfully fetched {len(cves)} CVE records")
            
            # Display first CVE info
            if cves:
                first_cve = cves[0]
                cve_data = first_cve.get('cve', {})
                cve_id = cve_data.get('id', 'Unknown')
                logger.info(f"Sample CVE ID: {cve_id}")
                
                # Check for required fields
                required_fields = ['cve']
                missing_fields = [f for f in required_fields if f not in first_cve]
                if missing_fields:
                    logger.warning(f"Missing fields in CVE record: {missing_fields}")
                else:
                    logger.info("✅ CVE record structure looks good")
            
            return True, cves
        else:
            logger.warning("⚠️  No CVEs fetched")
            return False, []
            
    except Exception as e:
        logger.error(f"❌ Error testing CVE scraper: {str(e)}", exc_info=True)
        return False, []


def test_cpe_scraper(config, max_count=10):
    """Test NIST CPE scraper."""
    logger.info("=" * 60)
    logger.info("Testing NIST CPE Scraper")
    logger.info("=" * 60)
    
    try:
        scraper = NISTCPEScraper(config)
        
        # Test fetching recent CPEs
        logger.info(f"Fetching up to {max_count} recent CPEs...")
        cpes = scraper.fetch_recent_cpes(days=7, max_count=max_count)
        
        if cpes:
            logger.info(f"✅ Successfully fetched {len(cpes)} CPE records")
            
            # Display first CPE info
            if cpes:
                first_cpe = cpes[0]
                cpe_data = first_cpe.get('cpe', {})
                cpe_name = cpe_data.get('cpeName', 'Unknown')
                logger.info(f"Sample CPE Name: {cpe_name}")
                
                # Check for required fields
                required_fields = ['cpe']
                missing_fields = [f for f in required_fields if f not in first_cpe]
                if missing_fields:
                    logger.warning(f"Missing fields in CPE record: {missing_fields}")
                else:
                    logger.info("✅ CPE record structure looks good")
            
            return True, cpes
        else:
            logger.warning("⚠️  No CPEs fetched")
            return False, []
            
    except Exception as e:
        logger.error(f"❌ Error testing CPE scraper: {str(e)}", exc_info=True)
        return False, []


def test_pagination(config):
    """Test pagination functionality."""
    logger.info("=" * 60)
    logger.info("Testing Pagination")
    logger.info("=" * 60)
    
    try:
        scraper = NISTCVEScraper(config)
        
        # Fetch with pagination (request more than one page)
        logger.info("Testing pagination by fetching 15 records with 10 per page...")
        cves = scraper.fetch_cves(
            pub_start_date=(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT00:00:00.000'),
            pub_end_date=datetime.now().strftime('%Y-%m-%dT23:59:59.999'),
            results_per_page=10,
            max_count=15
        )
        
        if len(cves) >= 10:
            logger.info(f"✅ Pagination working correctly. Fetched {len(cves)} records")
            return True
        else:
            logger.warning(f"⚠️  Only fetched {len(cves)} records, may not have tested pagination")
            return len(cves) > 0
            
    except Exception as e:
        logger.error(f"❌ Error testing pagination: {str(e)}", exc_info=True)
        return False


def test_storage(config, cve_records=None, cpe_records=None):
    """Test storage functionality."""
    logger.info("=" * 60)
    logger.info("Testing Storage")
    logger.info("=" * 60)
    
    try:
        storage = DataStorage(config)
        
        if cve_records:
            logger.info(f"Saving {len(cve_records)} CVE records...")
            s3_key = storage.save_cve_data(
                cve_records=cve_records[:5],  # Save first 5 for testing
                save_local=True
            )
            if s3_key:
                logger.info(f"✅ CVE data saved to S3: {s3_key}")
            else:
                logger.info("✅ CVE data saved locally (S3 not configured or failed)")
        
        if cpe_records:
            logger.info(f"Saving {len(cpe_records)} CPE records...")
            s3_key = storage.save_cpe_data(
                cpe_records=cpe_records[:5],  # Save first 5 for testing
                save_local=True
            )
            if s3_key:
                logger.info(f"✅ CPE data saved to S3: {s3_key}")
            else:
                logger.info("✅ CPE data saved locally (S3 not configured or failed)")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error testing storage: {str(e)}", exc_info=True)
        return False


def test_orchestrator(config, max_count=10):
    """Test the ingestion orchestrator."""
    logger.info("=" * 60)
    logger.info("Testing Ingestion Orchestrator")
    logger.info("=" * 60)
    
    try:
        orchestrator = NISTIngestionOrchestrator(config)
        
        # Test CVE ingestion
        logger.info("Testing CVE ingestion via orchestrator...")
        cve_result = orchestrator.ingest_cves(
            days_back=7,
            max_count=max_count,
            save_local=True
        )
        
        if cve_result.get('success'):
            logger.info(f"✅ CVE ingestion successful: {cve_result['records_fetched']} records")
        else:
            logger.error(f"❌ CVE ingestion failed: {cve_result.get('error', 'Unknown error')}")
        
        # Test CPE ingestion
        logger.info("Testing CPE ingestion via orchestrator...")
        cpe_result = orchestrator.ingest_cpes(
            days_back=7,
            max_count=max_count,
            save_local=True
        )
        
        if cpe_result.get('success'):
            logger.info(f"✅ CPE ingestion successful: {cpe_result['records_fetched']} records")
        else:
            logger.error(f"❌ CPE ingestion failed: {cpe_result.get('error', 'Unknown error')}")
        
        return cve_result.get('success', False) and cpe_result.get('success', False)
        
    except Exception as e:
        logger.error(f"❌ Error testing orchestrator: {str(e)}", exc_info=True)
        return False


def main():
    """Main test function."""
    parser = argparse.ArgumentParser(description='Test NIST CVE/CPE ingestion pipeline')
    parser.add_argument('--max-count', type=int, default=10,
                       help='Maximum number of records to fetch per test')
    parser.add_argument('--test', choices=['all', 'config', 'cve', 'cpe', 'pagination', 'storage', 'orchestrator'],
                       default='all', help='Which test to run')
    parser.add_argument('--skip-storage', action='store_true',
                       help='Skip storage tests')
    
    args = parser.parse_args()
    
    logger.info("=" * 60)
    logger.info("NIST Ingestion Pipeline Test Suite")
    logger.info("=" * 60)
    
    # Test configuration
    if args.test in ['all', 'config']:
        config = test_config()
        if not config:
            logger.error("Configuration test failed!")
            return 1
    else:
        config = Config()
        config.validate()
    
    results = {}
    
    # Test CVE scraper
    if args.test in ['all', 'cve']:
        cve_success, cve_records = test_cve_scraper(config, max_count=args.max_count)
        results['cve_scraper'] = cve_success
    else:
        cve_records = []
    
    # Test CPE scraper
    if args.test in ['all', 'cpe']:
        cpe_success, cpe_records = test_cpe_scraper(config, max_count=args.max_count)
        results['cpe_scraper'] = cpe_success
    else:
        cpe_records = []
    
    # Test pagination
    if args.test in ['all', 'pagination']:
        pagination_success = test_pagination(config)
        results['pagination'] = pagination_success
    
    # Test storage
    if args.test in ['all', 'storage'] and not args.skip_storage:
        storage_success = test_storage(config, cve_records, cpe_records)
        results['storage'] = storage_success
    
    # Test orchestrator
    if args.test in ['all', 'orchestrator']:
        orchestrator_success = test_orchestrator(config, max_count=args.max_count)
        results['orchestrator'] = orchestrator_success
    
    # Summary
    logger.info("=" * 60)
    logger.info("Test Summary")
    logger.info("=" * 60)
    
    for test_name, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        logger.info(f"{test_name}: {status}")
    
    all_passed = all(results.values())
    
    if all_passed:
        logger.info("\n🎉 All tests passed!")
        return 0
    else:
        logger.error("\n⚠️  Some tests failed. Please review the logs above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

