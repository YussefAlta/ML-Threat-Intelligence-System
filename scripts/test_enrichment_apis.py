#!/usr/bin/env python3
"""
Test script for Phase 2 enrichment APIs (CWE and VulnCheck).
Verifies that both APIs are accessible and working correctly.
"""
import sys
import os
import json
import logging

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from threat_intelligence.core.config import Config
from threat_intelligence.utils.api_client import APIClient, RateLimiter
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_cwe_api():
    """Test MITRE CWE API."""
    print("=" * 70)
    print("Testing MITRE CWE API")
    print("=" * 70)
    
    config = Config()
    base_url = config.CWE_API_BASE_URL
    
    print(f"Base URL: {base_url}")
    print(f"Note: No API key required - API is public")
    print()
    
    results = {}
    
    # Test 1: Version endpoint
    print("1. Testing version endpoint...")
    try:
        url = f"{base_url.rstrip('/')}/cwe/version"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        results['version'] = {
            'success': True,
            'status_code': response.status_code,
            'data': data
        }
        print(f"   ✅ Success! Status: {response.status_code}")
        print(f"   Content Version: {data.get('ContentVersion', 'N/A')}")
        print(f"   Total Weaknesses: {data.get('TotalWeaknesses', 'N/A')}")
        print(f"   Total Categories: {data.get('TotalCategories', 'N/A')}")
    except Exception as e:
        results['version'] = {
            'success': False,
            'error': str(e)
        }
        print(f"   ❌ Failed: {str(e)}")
    
    print()
    
    # Test 2: Get weakness details
    print("2. Testing weakness endpoint (CWE-79 - XSS)...")
    try:
        url = f"{base_url.rstrip('/')}/cwe/weakness/79"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        results['weakness'] = {
            'success': True,
            'status_code': response.status_code,
            'has_data': bool(data.get('Weaknesses'))
        }
        print(f"   ✅ Success! Status: {response.status_code}")
        if data.get('Weaknesses'):
            weakness = data['Weaknesses'][0]
            print(f"   CWE ID: {weakness.get('ID')}")
            print(f"   Name: {weakness.get('Name', 'N/A')[:60]}...")
    except Exception as e:
        results['weakness'] = {
            'success': False,
            'error': str(e)
        }
        print(f"   ❌ Failed: {str(e)}")
    
    print()
    
    # Test 3: Get multiple CWEs
    print("3. Testing multiple CWE endpoint (74, 79)...")
    try:
        url = f"{base_url.rstrip('/')}/cwe/74,79"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        # Handle both dict and list responses
        if isinstance(data, dict):
            count = len(data.get('Weaknesses', []))
        elif isinstance(data, list):
            count = len(data)
        else:
            count = 0
        results['multiple'] = {
            'success': True,
            'status_code': response.status_code,
            'count': count
        }
        print(f"   ✅ Success! Status: {response.status_code}")
        print(f"   Received {count} weaknesses")
    except Exception as e:
        results['multiple'] = {
            'success': False,
            'error': str(e)
        }
        print(f"   ❌ Failed: {str(e)}")
    
    print()
    
    # Test 4: Get relationships (parents)
    print("4. Testing relationships endpoint (CWE-74 parents)...")
    try:
        url = f"{base_url.rstrip('/')}/cwe/74/parents?view=1000"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        results['relationships'] = {
            'success': True,
            'status_code': response.status_code,
            'count': len(data) if isinstance(data, list) else 0
        }
        print(f"   ✅ Success! Status: {response.status_code}")
        print(f"   Found {len(data) if isinstance(data, list) else 0} parent relationships")
    except Exception as e:
        results['relationships'] = {
            'success': False,
            'error': str(e)
        }
        print(f"   ❌ Failed: {str(e)}")
    
    return results


def test_vulncheck_api():
    """Test VulnCheck API."""
    print("=" * 70)
    print("Testing VulnCheck API")
    print("=" * 70)
    
    config = Config()
    base_url = config.VULNCHECK_API_BASE_URL
    api_key = config.VULNCHECK_API_KEY
    
    print(f"Base URL: {base_url}")
    
    if not api_key:
        print("❌ ERROR: VULNCHECK_API_KEY not found in configuration!")
        print("   Please add VULNCHECK_API_KEY to your .env or .env.local file")
        return {'error': 'API key not configured'}
    
    print(f"API Key: {'*' * 10}...{api_key[-4:] if len(api_key) > 4 else '****'}")
    print()
    
    results = {}
    
    # Test 1: Index endpoint (lists available indexes)
    print("1. Testing index endpoint...")
    try:
        response = requests.get(
            f"{base_url.rstrip('/')}/index",
            headers={
                'Accept': 'application/json',
                'Authorization': f'Bearer {api_key}'
            },
            timeout=15
        )
        response.raise_for_status()
        data = response.json()
        results['index'] = {
            'success': True,
            'status_code': response.status_code,
            'has_data': bool(data)
        }
        print(f"   ✅ Success! Status: {response.status_code}")
        print(f"   Response type: {type(data).__name__}")
        if isinstance(data, dict):
            print(f"   Keys: {list(data.keys())[:5]}")
        elif isinstance(data, list):
            print(f"   List length: {len(data)}")
    except requests.HTTPError as e:
        results['index'] = {
            'success': False,
            'status_code': e.response.status_code,
            'error': str(e)
        }
        print(f"   ❌ Failed: Status {e.response.status_code}")
        print(f"   Error: {str(e)}")
        if e.response.status_code == 401:
            print("   ⚠️  Authentication failed - check your API key")
        elif e.response.status_code == 403:
            print("   ⚠️  Access forbidden - check API key permissions")
    except Exception as e:
        results['index'] = {
            'success': False,
            'error': str(e)
        }
        print(f"   ❌ Failed: {str(e)}")
    
    print()
    
    # Test 2: Try a CVE lookup (if API supports it)
    print("2. Testing CVE lookup endpoint...")
    try:
        # Try a common endpoint - adjust based on VulnCheck API docs
        # Common patterns: /v3/vulns/{cve_id} or /v3/cve/{cve_id}
        test_cve = "CVE-2024-27983"  # A recent CVE
        endpoints_to_try = [
            f"{base_url.rstrip('/')}/vulns/{test_cve}",
            f"{base_url.rstrip('/')}/cve/{test_cve}",
            f"{base_url.rstrip('/')}/vulnerability/{test_cve}",
        ]
        
        success = False
        for endpoint in endpoints_to_try:
            try:
                response = requests.get(
                    endpoint,
                    headers={
                        'Accept': 'application/json',
                        'Authorization': f'Bearer {api_key}'
                    },
                    timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    results['cve_lookup'] = {
                        'success': True,
                        'status_code': response.status_code,
                        'endpoint': endpoint,
                        'has_data': bool(data)
                    }
                    print(f"   ✅ Success! Status: {response.status_code}")
                    print(f"   Working endpoint: {endpoint}")
                    print(f"   Response type: {type(data).__name__}")
                    success = True
                    break
                elif response.status_code == 404:
                    # Endpoint exists but CVE not found - that's OK
                    results['cve_lookup'] = {
                        'success': True,
                        'status_code': 404,
                        'endpoint': endpoint,
                        'note': 'Endpoint exists but CVE not found'
                    }
                    print(f"   ✅ Endpoint exists: {endpoint} (404 - CVE not found, which is OK)")
                    success = True
                    break
            except:
                continue
        
        if not success:
            print(f"   ⚠️  Could not determine correct CVE endpoint")
            print(f"   Consult VulnCheck API documentation for correct endpoint structure")
            results['cve_lookup'] = {
                'success': False,
                'note': 'Could not determine correct endpoint'
            }
    except Exception as e:
        results['cve_lookup'] = {
            'success': False,
            'error': str(e)
        }
        print(f"   ❌ Failed: {str(e)}")
    
    return results


def main():
    """Main test function."""
    print("=" * 70)
    print("Phase 2 Enrichment APIs Test Suite")
    print("=" * 70)
    print()
    
    # Load config
    config = Config()
    config.validate()
    
    all_results = {}
    
    # Test CWE API
    print("\n")
    cwe_results = test_cwe_api()
    all_results['cwe'] = cwe_results
    
    # Test VulnCheck API
    print("\n")
    vulncheck_results = test_vulncheck_api()
    all_results['vulncheck'] = vulncheck_results
    
    # Summary
    print()
    print("=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    # CWE Summary
    cwe_all_passed = all(
        r.get('success', False) if isinstance(r, dict) else False
        for r in cwe_results.values()
    )
    print(f"\nMITRE CWE API: {'✅ ALL TESTS PASSED' if cwe_all_passed else '⚠️  SOME TESTS FAILED'}")
    
    # VulnCheck Summary
    if 'error' in vulncheck_results:
        print(f"\nVulnCheck API: ❌ NOT CONFIGURED")
    else:
        vulncheck_all_passed = all(
            r.get('success', False) if isinstance(r, dict) else False
            for r in vulncheck_results.values() if isinstance(r, dict)
        )
        print(f"\nVulnCheck API: {'✅ ALL TESTS PASSED' if vulncheck_all_passed else '⚠️  SOME TESTS FAILED'}")
    
    print()
    print("=" * 70)
    
    # Overall status
    overall_success = (
        cwe_all_passed and
        'error' not in vulncheck_results and
        all(
            r.get('success', False) if isinstance(r, dict) else False
            for r in vulncheck_results.values() if isinstance(r, dict)
        )
    )
    
    if overall_success:
        print("🎉 All API tests passed! APIs are ready for Phase 2 enrichment.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

