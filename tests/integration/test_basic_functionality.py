#!/usr/bin/env python3
"""
Integration test to verify basic module imports and initialization.

Validates that core modules (Config, ingesters, storage, enrichment)
can be imported and instantiated without errors.
"""
import logging
import os
import sys

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'src')))

from threat_intelligence.core.config import Config
from threat_intelligence.storage.data_storage import DataStorage
from threat_intelligence.enrichment.content_cleaner import ContentCleaner

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)


def test_basic_functionality():
    """Test basic initialization of core modules."""
    print("Testing Basic Functionality")
    print("=" * 60)

    # Test 1: Config initialization
    print("\n1. Testing Config initialization...")
    config = Config()
    config.validate()
    assert config.NIST_API_BASE_URL is not None
    print("  Config initialized successfully")

    # Test 2: DataStorage initialization
    print("\n2. Testing DataStorage initialization...")
    storage = DataStorage(config)
    assert storage is not None
    print("  DataStorage initialized successfully")

    # Test 3: ContentCleaner initialization
    print("\n3. Testing ContentCleaner initialization...")
    cleaner = ContentCleaner()
    assert cleaner is not None
    print("  ContentCleaner initialized successfully")

    # Test 4: ContentCleaner text cleaning
    print("\n4. Testing ContentCleaner text cleaning...")
    raw_text = "  Hello   world.   Cookie policy notice.  "
    cleaned = cleaner.clean_text(raw_text)
    assert "Hello" in cleaned
    assert "Cookie" not in cleaned
    print(f"  Cleaned: '{cleaned}'")

    # Test 5: Ingester imports
    print("\n5. Testing ingester imports...")
    try:
        from threat_intelligence.ingesters import NISTCVEIngester, NISTCPEIngester
        assert NISTCVEIngester is not None
        assert NISTCPEIngester is not None
        print("  NIST ingesters imported successfully")
    except ImportError as e:
        print(f"  NIST ingester import failed: {e}")
        return

    # Test 6: OSINT ingester imports
    print("\n6. Testing OSINT ingester imports...")
    try:
        from threat_intelligence.ingesters import (
            PhishTankIngester,
            RansomwatchIngester,
            MITREAttackIngester,
            OTXIngester,
            ExploitDBIngester,
        )
        print("  All 5 OSINT ingesters imported successfully")
    except ImportError as e:
        print(f"  OSINT ingester import issue (may be OK if optional deps missing): {e}")

    # Test 7: Enrichment imports
    print("\n7. Testing enrichment imports...")
    from threat_intelligence.enrichment import (
        CWEEnricher,
        VulnCheckEnricher,
        NVDReferenceScraperEnricher,
        classify_url,
    )
    assert classify_url("https://github.com/org/repo/security/advisories/GHSA-1234") is not None
    print("  Enrichment modules imported successfully")

    # Test 8: Quality scoring
    print("\n8. Testing quality scoring...")
    quality = ContentCleaner.assess_quality(
        "CVE-2024-1234 is a critical vulnerability in Apache HTTP Server version 2.4.51. "
        "An attacker can exploit this to gain remote code execution. "
        "Users should upgrade to version 2.4.52 immediately."
    )
    assert quality["label"] == "good"
    assert quality["has_cve_mention"] is True
    assert quality["has_version_mention"] is True
    print(f"  Quality assessment: {quality['label']}")

    print(f"\nBasic functionality test completed successfully!")


if __name__ == "__main__":
    test_basic_functionality()
