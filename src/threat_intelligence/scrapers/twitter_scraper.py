"""
Twitter/X scraper for threat intelligence data collection using Firecrawl API.
"""
import re
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse, quote
import logging
from datetime import datetime, timedelta

from .base_scraper import BaseScraper

logger = logging.getLogger(__name__)

class TwitterScraper(BaseScraper):
    """Twitter/X scraper implementation using Firecrawl API for reliable scraping."""
    
    def __init__(self, config):
        super().__init__(config)
        self.firecrawl = self._initialize_firecrawl()
    
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
    
    def scrape_posts(self, source: str, max_posts: int = None) -> List[Dict]:
        """Scrape tweets from a specific Twitter account using Firecrawl API."""
        max_posts = max_posts or self.config.MAX_POSTS_PER_SOURCE
        
        if not self.firecrawl:
            logger.error("Firecrawl API not initialized")
            return []
        
        try:
            # Check if source is a Twitter URL
            if self._is_twitter_url(source):
                posts = self._scrape_from_url_firecrawl(source)
            else:
                # For username, construct profile URL
                profile_url = f"https://x.com/{source}"
                posts = self._scrape_from_url_firecrawl(profile_url)
            
            logger.info(f"Scraped {len(posts)} tweets from {source}")
            return posts
            
        except Exception as e:
            logger.error(f"Error scraping tweets from {source}: {str(e)}")
            return []
    
    def _is_twitter_url(self, source: str) -> bool:
        """Check if the source is a Twitter URL."""
        return 'twitter.com' in source or 'x.com' in source
    
    def _scrape_from_url_firecrawl(self, url: str) -> List[Dict]:
        """Scrape tweets from a specific Twitter URL using Firecrawl API."""
        try:
            logger.info(f"Scraping from Twitter URL with Firecrawl: {url}")
            
            # Use Firecrawl to scrape the page
            scrape_result = self.firecrawl.scrape(
                url=url,
                formats=['markdown', 'html'],
                only_main_content=True,
                wait_for=3000,  # Wait 3 seconds for content to load
                timeout=30000  # 30 second timeout
            )
            
            if not scrape_result:
                logger.error(f"Firecrawl scraping failed for {url}")
                return []
            
            # Extract content from Firecrawl result (v2 returns Document object)
            markdown_content = getattr(scrape_result, 'markdown', '') or ''
            html_content = getattr(scrape_result, 'html', '') or ''
            
            # Parse the scraped content
            tweets = self._parse_firecrawl_content(markdown_content, html_content, url)
            
            return tweets
            
        except Exception as e:
            logger.error(f"Error scraping from URL {url} with Firecrawl: {str(e)}")
            return []
    
    def _parse_firecrawl_content(self, markdown_content: str, html_content: str, url: str) -> List[Dict]:
        """Parse content scraped by Firecrawl to extract tweet data."""
        tweets = []
        
        try:
            # Extract username from URL
            username = url.split('/')[-1] if '/' in url else 'unknown_user'
            
            # Try to extract tweet content from markdown
            if markdown_content:
                tweets = self._extract_tweets_from_markdown(markdown_content, url, username)
            
            # If no tweets found in markdown, try HTML
            if not tweets and html_content:
                tweets = self._extract_tweets_from_html_firecrawl(html_content, url, username)
            
            # If still no tweets, create a tweet from available content
            if not tweets:
                tweets = self._create_tweet_from_content(markdown_content or html_content, url, username)
            
            return tweets
            
        except Exception as e:
            logger.error(f"Error parsing Firecrawl content: {str(e)}")
            return []
    
    def _extract_tweets_from_markdown(self, markdown_content: str, url: str, username: str) -> List[Dict]:
        """Extract tweets from markdown content."""
        tweets = []
        
        try:
            # Look for tweet patterns in markdown
            lines = markdown_content.split('\n')
            current_tweet = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Check if this looks like a tweet (has @mentions, #hashtags, or is substantial text)
                if (len(line) > 20 and 
                    ('@' in line or '#' in line or 'http' in line or 
                     any(word in line.lower() for word in ['threat', 'security', 'cyber', 'malware', 'attack']))):
                    current_tweet.append(line)
                elif current_tweet:
                    # End of current tweet, process it
                    tweet_text = ' '.join(current_tweet)
                    if len(tweet_text) > 10:  # Only process substantial tweets
                        tweet_data = self._create_tweet_data(tweet_text, url, username)
                        tweets.append(tweet_data)
                    current_tweet = []
            
            # Process any remaining tweet
            if current_tweet:
                tweet_text = ' '.join(current_tweet)
                if len(tweet_text) > 10:
                    tweet_data = self._create_tweet_data(tweet_text, url, username)
                    tweets.append(tweet_data)
            
            return tweets
            
        except Exception as e:
            logger.error(f"Error extracting tweets from markdown: {str(e)}")
            return []
    
    def _extract_tweets_from_html_firecrawl(self, html_content: str, url: str, username: str) -> List[Dict]:
        """Extract tweets from HTML content scraped by Firecrawl."""
        tweets = []
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Look for tweet containers
            tweet_containers = soup.find_all(['article', 'div'], attrs={'data-testid': re.compile(r'tweet|status')})
            
            if not tweet_containers:
                # Try alternative selectors
                tweet_containers = soup.find_all(['article', 'div'], class_=re.compile(r'tweet|status'))
            
            for i, container in enumerate(tweet_containers[:5]):  # Limit to 5 tweets
                try:
                    # Extract text content
                    text_elem = container.find(['div', 'p'], class_=re.compile(r'text|content|tweet-text'))
                    text = text_elem.get_text(strip=True) if text_elem else ""
                    
                    if text and len(text) > 10:
                        tweet_data = self._create_tweet_data(text, url, username)
                        tweets.append(tweet_data)
                        
                except Exception as e:
                    logger.warning(f"Error parsing tweet container {i}: {str(e)}")
                    continue
            
            return tweets
            
        except Exception as e:
            logger.error(f"Error extracting tweets from HTML: {str(e)}")
            return []
    
    def _create_tweet_from_content(self, content: str, url: str, username: str) -> List[Dict]:
        """Create a tweet from available content when no specific tweets are found."""
        try:
            # Extract meaningful content
            lines = content.split('\n')
            meaningful_lines = [line.strip() for line in lines if len(line.strip()) > 20]
            
            if meaningful_lines:
                tweet_text = ' '.join(meaningful_lines[:3])  # Take first 3 meaningful lines
            else:
                tweet_text = f"Content from {url}"
            
            tweet_data = self._create_tweet_data(tweet_text, url, username)
            return [tweet_data]
            
        except Exception as e:
            logger.error(f"Error creating tweet from content: {str(e)}")
            return []
    
    def _create_tweet_data(self, text: str, url: str, username: str) -> Dict:
        """Create structured tweet data with maximum raw data preservation."""
        # Extract all words including stop words for raw data collection
        all_words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
        word_frequency = {}
        for word in all_words:
            word_frequency[word] = word_frequency.get(word, 0) + 1
        
        return {
            'id': f'firecrawl_tweet_{hash(text) % 10000}',
            'text': text,  # Raw text with all stop words preserved
            'author': username,
            'author_name': username.title(),
            'created_at': datetime.now().isoformat(),
            'source_type': 'twitter',
            'url': url,
            'retweet_count': 0,
            'favorite_count': 0,
            'reply_count': 0,
            'quote_count': 0,
            'is_quote_status': False,
            'in_reply_to_status_id': None,
            'in_reply_to_user_id': None,
            'in_reply_to_screen_name': None,
            'hashtags': self._extract_hashtags(text),
            'mentions': self._extract_mentions(text),
            'urls': self._extract_urls_from_text(text),
            'media': [],
            'raw_data': {
                'id': f'firecrawl_tweet_{hash(text) % 10000}',
                'content': text,  # Raw content
                'user': {
                    'username': username,
                    'displayname': username.title(),
                    'id': f'user_{hash(username) % 10000}'
                },
                'date': datetime.now().isoformat(),
                'retweetCount': 0,
                'likeCount': 0,
                'replyCount': 0,
                'quoteCount': 0,
                'extraction_method': 'firecrawl',
                'word_frequency': word_frequency,  # All words including stop words
                'total_words': len(all_words),
                'unique_words': len(set(all_words))
            },
            'preprocessing_notes': {
                'stop_words_preserved': True,
                'minimal_cleaning_applied': True,
                'ready_for_nlp_preprocessing': True
            }
        }
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from tweet text using regex."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return [url for url in urls if self.is_valid_url(url)]
    
    def _extract_hashtags(self, text: str) -> List[str]:
        """Extract hashtags from tweet text."""
        hashtag_pattern = r'#(\w+)'
        hashtags = re.findall(hashtag_pattern, text)
        return hashtags
    
    def _extract_mentions(self, text: str) -> List[str]:
        """Extract mentions from tweet text."""
        mention_pattern = r'@(\w+)'
        mentions = re.findall(mention_pattern, text)
        return mentions
    
    def extract_links(self, post: Dict) -> List[str]:
        """Extract links from a Twitter post."""
        links = []
        
        # Extract URLs from the post
        if 'urls' in post and post['urls']:
            for url in post['urls']:
                if self.is_valid_url(url):
                    links.append(url)
        
        # Also extract URLs from the text using regex
        text = post.get('text', '')
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        found_urls = re.findall(url_pattern, text)
        
        for url in found_urls:
            if self.is_valid_url(url) and url not in links:
                links.append(url)
        
        return links
