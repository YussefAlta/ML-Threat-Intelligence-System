"""
General web scraper for blogs, news articles, and other web content using Firecrawl API.
"""
import re
import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import logging
from datetime import datetime
from bs4 import BeautifulSoup

from .base_scraper import BaseScraper

logger = logging.getLogger(__name__)

class WebScraper(BaseScraper):
    """
    General web scraper for blogs, news articles, and other web content using Firecrawl API.
    """
    
    def __init__(self, config, storage=None):
        """
        Initialize WebScraper.
        
        Args:
            config: Configuration object
            storage: Optional DataStorage instance for direct S3 uploads
        """
        super().__init__(config)
        self.firecrawl = self._initialize_firecrawl()
        self.storage = storage
    
    def _initialize_firecrawl(self):
        """Initialize Firecrawl API client."""
        try:
            from firecrawl import FirecrawlApp
            
            if not self.config.FIRECRAWL_API_KEY:
                logger.error("Firecrawl API key not configured")
                return None
            
            firecrawl = FirecrawlApp(api_key=self.config.FIRECRAWL_API_KEY)
            logger.info("Firecrawl API initialized successfully")
            return firecrawl
            
        except ImportError:
            logger.error("Firecrawl package not installed. Run: pip install firecrawl-py")
            return None
        except Exception as e:
            logger.error(f"Failed to initialize Firecrawl API: {str(e)}")
            return None
    
    def scrape_posts(self, source: str, max_posts: int = None, save_to_s3: bool = True) -> List[Dict]:
        """
        Scrape content from a web URL or search for content.
        
        Args:
            source: URL to scrape or search query
            max_posts: Maximum number of posts to scrape (not used for single URL)
            save_to_s3: Whether to automatically save raw metadata to S3 (default: True)
        
        Returns:
            List of scraped content dictionaries
        """
        if not self.firecrawl:
            logger.error("Firecrawl API not initialized")
            return []
        
        # Check if source is a URL
        if self.is_valid_url(source):
            posts = self._scrape_from_url(source)
        else:
            # Treat as search query - Firecrawl doesn't support search, so return empty
            logger.warning(f"Source '{source}' is not a valid URL. WebScraper only supports URL-based scraping.")
            posts = []
        
        # Save full raw data directly to S3 if storage is available and save_to_s3 is True
        if posts and save_to_s3 and self.storage:
            try:
                # Save full raw post data (not just metadata subset)
                s3_key = self.storage.save_posts_to_s3_direct(
                    posts, 
                    source, 
                    data_type="raw_data",
                    save_local=False
                )
                if s3_key:
                    logger.info(f"Raw data saved directly to S3: {s3_key}")
            except Exception as e:
                logger.error(f"Failed to save raw data to S3: {str(e)}")
        
        return posts
    
    def _scrape_from_url(self, url: str) -> List[Dict]:
        """Scrape content from a specific URL using Firecrawl API."""
        try:
            logger.info(f"Scraping web content from URL: {url}")
            
            # Use Firecrawl to scrape the page
            scrape_result = self.firecrawl.scrape(
                url=url,
                formats=['markdown', 'html'],
                only_main_content=True,
                wait_for=3000,  # Wait 3 seconds for content to load
                timeout=30000   # 30 second timeout
            )
            
            if not scrape_result:
                logger.error(f"Firecrawl scraping failed for {url}")
                return []
            
            # Extract content from Firecrawl result
            markdown_content = getattr(scrape_result, 'markdown', '') or ''
            html_content = getattr(scrape_result, 'html', '') or ''
            
            # Parse the scraped content
            content = self._parse_web_content(markdown_content, html_content, url)
            
            return [content] if content else []
            
        except Exception as e:
            logger.error(f"Error scraping from URL {url} with Firecrawl: {str(e)}")
            return []
    
    def _parse_web_content(self, markdown_content: str, html_content: str, url: str) -> Optional[Dict]:
        """Parse web content from Firecrawl result."""
        try:
            # Extract title from markdown (usually the first # heading)
            title = ""
            if markdown_content:
                title_match = re.search(r'^#\s+(.+)$', markdown_content, re.MULTILINE)
                if title_match:
                    title = title_match.group(1).strip()
            
            # If no title from markdown, try to extract from HTML
            if not title and html_content:
                soup = BeautifulSoup(html_content, 'html.parser')
                title_elem = soup.find('title') or soup.find('h1')
                if title_elem:
                    title = title_elem.get_text().strip()
            
            # Extract metadata from HTML if available
            metadata = self._extract_metadata(html_content)
            
            # Clean and process content
            content_text = self._clean_content(markdown_content or html_content)
            
            # Extract author, publication date, and other metadata
            author = metadata.get('author', '')
            published_date = metadata.get('published_date', '')
            description = metadata.get('description', '')
            
            # Extract keywords and tags
            keywords, word_frequency = self._extract_keywords(content_text)
            
            # Create structured content with maximum raw data preservation
            content_data = {
                'id': f"web_{hash(url)}",
                'title': title,
                'content': content_text,  # Minimally cleaned content
                'url': url,
                'author': author,
                'published_date': published_date,
                'description': description,
                'keywords': keywords,  # All words including stop words
                'source_type': 'web_content',
                'scraped_at': datetime.now().isoformat(),
                'domain': urlparse(url).netloc,
                'metadata': metadata,
                'raw_content': {
                    'markdown': markdown_content,  # Original markdown
                    'html': html_content,          # Original HTML
                    'raw_text': markdown_content or html_content,  # Completely unprocessed text
                    'word_frequency': word_frequency,  # Word frequency data
                    'total_words': len(keywords),
                    'unique_words': len(set(keywords))
                },
                'preprocessing_notes': {
                    'stop_words_preserved': True,
                    'minimal_cleaning_applied': True,
                    'ready_for_nlp_preprocessing': True
                }
            }
            
            return content_data
            
        except Exception as e:
            logger.error(f"Error parsing web content from {url}: {str(e)}")
            return None
    
    def _extract_metadata(self, html_content: str) -> Dict:
        """Extract metadata from HTML content."""
        metadata = {}
        
        if not html_content:
            return metadata
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                name = meta.get('name', '').lower()
                property_attr = meta.get('property', '').lower()
                content = meta.get('content', '')
                
                if name == 'author' or property_attr == 'article:author':
                    metadata['author'] = content
                elif name == 'description' or property_attr == 'og:description':
                    metadata['description'] = content
                elif name == 'keywords':
                    metadata['keywords'] = content
                elif property_attr == 'article:published_time':
                    metadata['published_date'] = content
                elif property_attr == 'og:title':
                    metadata['og_title'] = content
                elif property_attr == 'og:type':
                    metadata['content_type'] = content
            
            # Extract structured data (JSON-LD)
            json_scripts = soup.find_all('script', type='application/ld+json')
            for script in json_scripts:
                try:
                    data = json.loads(script.string)
                    if isinstance(data, dict):
                        if data.get('@type') == 'Article':
                            metadata['article_type'] = 'Article'
                            if 'author' in data:
                                metadata['author'] = data['author'].get('name', '')
                            if 'datePublished' in data:
                                metadata['published_date'] = data['datePublished']
                except:
                    continue
            
        except Exception as e:
            logger.error(f"Error extracting metadata: {str(e)}")
        
        return metadata
    
    def _extract_keywords(self, content: str) -> Tuple[List[str], Dict[str, int]]:
        """Extract all words from content for raw data collection (no stop word filtering)."""
        if not content:
            return [], {}
        
        # Extract all words (including stop words) for raw data collection
        words = re.findall(r'\b[a-zA-Z]+\b', content.lower())
        
        # Count word frequency (including stop words)
        word_count = {}
        for word in words:
            word_count[word] = word_count.get(word, 0) + 1
        
        # Return both the list of words and the frequency dictionary
        # This preserves all raw data for later preprocessing
        all_words = sorted(word_count.items(), key=lambda x: x[1], reverse=True)
        word_list = [word for word, count in all_words]
        
        return word_list, word_count
    
    def _clean_content(self, content: str) -> str:
        """Minimal content cleaning to preserve raw data for preprocessing."""
        if not content:
            return ""
        
        # Only normalize whitespace - preserve all text content including stop words
        # Remove excessive whitespace but keep single spaces
        content = re.sub(r'\s+', ' ', content)
        
        # Keep all text content including:
        # - Stop words (the, and, or, etc.)
        # - Punctuation and special characters
        # - Numbers and symbols
        # - All formatting that might be meaningful
        
        return content.strip()
    
    def extract_links(self, post: Dict) -> List[str]:
        """Extract links from a web post."""
        links = []
        
        # Extract URL from the post
        if post.get('url') and self.is_valid_url(post['url']):
            links.append(post['url'])
        
        # Extract URLs from content using regex
        content = post.get('content', '')
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        found_urls = re.findall(url_pattern, content)
        
        for url in found_urls:
            if self.is_valid_url(url) and url not in links:
                links.append(url)
        
        return links
    
    def scrape_article(self, url: str, save_to_s3: bool = True) -> Optional[Dict]:
        """Scrape a single article from URL."""
        results = self._scrape_from_url(url)
        
        # Save full raw data directly to S3 if storage is available
        if results and save_to_s3 and self.storage:
            try:
                s3_key = self.storage.save_posts_to_s3_direct(
                    results,
                    url,
                    data_type="raw_data",
                    save_local=False
                )
                if s3_key:
                    logger.info(f"Raw data saved directly to S3: {s3_key}")
            except Exception as e:
                logger.error(f"Failed to save raw data to S3: {str(e)}")
        
        return results[0] if results else None
    
    def _extract_raw_metadata(self, post: Dict) -> Dict:
        """
        Extract raw metadata from a post for S3 storage.
        This preserves all raw data including HTML, markdown, and metadata.
        """
        return {
            'id': post.get('id'),
            'url': post.get('url'),
            'title': post.get('title'),
            'scraped_at': post.get('scraped_at'),
            'domain': post.get('domain'),
            'raw_content': post.get('raw_content', {}),
            'metadata': post.get('metadata', {}),
            'preprocessing_notes': post.get('preprocessing_notes', {})
        }
