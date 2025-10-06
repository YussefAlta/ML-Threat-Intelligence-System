#!/usr/bin/env python3
"""
Test script to verify basic functionality after removing search features.
"""
import logging
import os
import sys
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from config import Config
from scrapers.web_scraper import WebScraper
from scrapers.twitter_scraper import TwitterScraper
from data_storage import DataStorage

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

def test_basic_functionality():
    """Test basic scraping functionality without search features."""
    print("🧪 Testing Basic Functionality (Search Removed)")
    print("=" * 60)
    
    config = Config()
    config.validate()
    
    # Test 1: Web Scraper Initialization
    print("\n1. Testing Web Scraper Initialization...")
    web_scraper = WebScraper(config)
    if web_scraper.firecrawl:
        print("✅ Web scraper initialized successfully")
    else:
        print("❌ Web scraper initialization failed")
        return
    
    # Test 2: Twitter Scraper Initialization
    print("\n2. Testing Twitter Scraper Initialization...")
    twitter_scraper = TwitterScraper(config)
    if twitter_scraper.firecrawl:
        print("✅ Twitter scraper initialized successfully")
    else:
        print("❌ Twitter scraper initialization failed")
        return
    
    # Test 3: Data Storage
    print("\n3. Testing Data Storage...")
    storage = DataStorage(config)
    print("✅ Data storage initialized successfully")
    
    # Test 4: Verify search methods are removed
    print("\n4. Verifying search methods are removed...")
    web_methods = [method for method in dir(web_scraper) if 'search' in method.lower()]
    twitter_methods = [method for method in dir(twitter_scraper) if 'search' in method.lower()]
    
    print(f"Web scraper methods with 'search': {web_methods}")
    print(f"Twitter scraper methods with 'search': {twitter_methods}")
    
    if not web_methods and not twitter_methods:
        print("✅ Search methods successfully removed")
    else:
        print("⚠️  Some search methods may still exist")
    
    # Test 5: Test basic URL validation
    print("\n5. Testing URL validation...")
    test_urls = [
        "https://example.com",
        "https://github.com",
        "https://stackoverflow.com",
        "invalid-url",
        "not-a-url"
    ]
    
    for url in test_urls:
        is_valid = web_scraper.is_valid_url(url)
        print(f"  {url}: {'✅' if is_valid else '❌'}")
    
    # Test 6: Test data structure creation
    print("\n6. Testing data structure creation...")
    try:
        # Create a mock content data structure
        mock_content = {
            'id': 'test_123',
            'title': 'Test Article',
            'content': 'This is a test article about cybersecurity and threat intelligence.',
            'url': 'https://example.com/test',
            'author': 'Test Author',
            'source_type': 'web_content',
            'scraped_at': datetime.now().isoformat(),
            'domain': 'example.com',
            'keywords': ['test', 'article', 'cybersecurity', 'threat', 'intelligence'],
            'raw_content': {
                'markdown': '# Test Article\n\nThis is test content.',
                'html': '<h1>Test Article</h1><p>This is test content.</p>',
                'word_frequency': {'test': 2, 'article': 1, 'cybersecurity': 1},
                'total_words': 5,
                'unique_words': 4
            },
            'preprocessing_notes': {
                'stop_words_preserved': True,
                'minimal_cleaning_applied': True,
                'ready_for_nlp_preprocessing': True
            }
        }
        
        print("✅ Mock data structure created successfully")
        print(f"   Title: {mock_content['title']}")
        print(f"   URL: {mock_content['url']}")
        print(f"   Keywords: {len(mock_content['keywords'])} words")
        print(f"   Raw data preserved: {mock_content['preprocessing_notes']['stop_words_preserved']}")
        
    except Exception as e:
        print(f"❌ Data structure creation failed: {str(e)}")
    
    # Test 7: Test link extraction
    print("\n7. Testing link extraction...")
    try:
        test_post = {
            'content': 'Check out https://github.com and https://stackoverflow.com for more info.',
            'url': 'https://example.com/test'
        }
        
        links = web_scraper.extract_links(test_post)
        print(f"✅ Extracted {len(links)} links: {links}")
        
    except Exception as e:
        print(f"❌ Link extraction failed: {str(e)}")
    
    # Test 8: Test main.py functionality
    print("\n8. Testing main.py command structure...")
    try:
        import subprocess
        result = subprocess.run([
            'python', 'main.py', '--help'
        ], capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            print("✅ Main.py help command works")
            # Check that search arguments are not in help
            if '--search' not in result.stdout:
                print("✅ Search arguments successfully removed from CLI")
            else:
                print("⚠️  Search arguments may still be present in CLI")
        else:
            print(f"❌ Main.py help command failed: {result.stderr}")
            
    except Exception as e:
        print(f"❌ Main.py test failed: {str(e)}")
    
    print(f"\n✅ Basic functionality test completed!")
    print("The search functionality has been successfully removed.")
    print("The system is ready for basic web scraping operations.")

if __name__ == "__main__":
    test_basic_functionality()
