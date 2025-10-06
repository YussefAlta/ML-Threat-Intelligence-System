"""
Base scraper class for threat intelligence data collection.
"""
import os
import json
import time
import requests
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaseScraper(ABC):
    """Base class for all social media scrapers."""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    @abstractmethod
    def scrape_posts(self, source: str, max_posts: int = None) -> List[Dict]:
        """Scrape posts from a specific source."""
        pass
    
    @abstractmethod
    def extract_links(self, post: Dict) -> List[str]:
        """Extract links from a post."""
        pass
    
    def follow_links(self, links: List[str], max_depth: int = 2) -> List[Dict]:
        """Follow links and extract content from linked pages."""
        if not self.config.FOLLOW_LINKS:
            return []
        
        linked_content = []
        for link in links:
            try:
                content = self._extract_page_content(link)
                if content:
                    linked_content.append({
                        'url': link,
                        'title': content.get('title', ''),
                        'content': content.get('content', ''),
                        'timestamp': datetime.now().isoformat(),
                        'source_type': 'linked_content'
                    })
                    logger.info(f"Successfully extracted content from: {link}")
                
                # Add delay to be respectful
                time.sleep(self.config.REQUEST_DELAY)
                
            except Exception as e:
                logger.error(f"Error extracting content from {link}: {str(e)}")
                continue
        
        return linked_content
    
    def _extract_page_content(self, url: str) -> Optional[Dict]:
        """Extract content from a web page."""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Extract title
            title = soup.find('title')
            title_text = title.get_text().strip() if title else ""
            
            # Extract main content - try different selectors
            content_selectors = [
                'article',
                'main',
                '.content',
                '.post-content',
                '.entry-content',
                'div[role="main"]'
            ]
            
            content_text = ""
            for selector in content_selectors:
                content_elem = soup.select_one(selector)
                if content_elem:
                    content_text = content_elem.get_text(separator=' ', strip=True)
                    break
            
            # If no specific content found, get body text
            if not content_text:
                body = soup.find('body')
                if body:
                    content_text = body.get_text(separator=' ', strip=True)
            
            # Clean up the text
            content_text = ' '.join(content_text.split())
            
            return {
                'title': title_text,
                'content': content_text,
                'url': url
            }
            
        except Exception as e:
            logger.error(f"Error extracting content from {url}: {str(e)}")
            return None
    
    def save_data(self, data: List[Dict], source: str, data_type: str = "posts") -> str:
        """Save scraped data to local storage."""
        # Create data directory if it doesn't exist
        os.makedirs(self.config.RAW_DATA_DIR, exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{source}_{data_type}_{timestamp}.json"
        filepath = os.path.join(self.config.RAW_DATA_DIR, filename)
        
        # Save data
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved {len(data)} {data_type} to {filepath}")
        return filepath
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and safe to scrape."""
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and parsed.scheme in ['http', 'https']
        except:
            return False
    
    def clean_text(self, text: str) -> str:
        """Clean and normalize text content."""
        if not text:
            return ""
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Remove common unwanted characters
        text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
        
        return text.strip()
