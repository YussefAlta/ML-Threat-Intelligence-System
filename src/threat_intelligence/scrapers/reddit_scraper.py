"""
Reddit scraper for threat intelligence data collection.
"""
import re
import praw
from typing import Dict, List, Optional
import logging

from .base_scraper import BaseScraper

logger = logging.getLogger(__name__)

class RedditScraper(BaseScraper):
    """Reddit scraper implementation."""
    
    def __init__(self, config):
        super().__init__(config)
        self.reddit = self._initialize_reddit()
    
    def _initialize_reddit(self):
        """Initialize Reddit API client."""
        try:
            reddit = praw.Reddit(
                client_id=self.config.REDDIT_CLIENT_ID,
                client_secret=self.config.REDDIT_CLIENT_SECRET,
                user_agent=self.config.REDDIT_USER_AGENT
            )
            
            # Test the connection
            reddit.user.me()
            logger.info("Reddit API initialized successfully")
            
            return reddit
            
        except Exception as e:
            logger.error(f"Failed to initialize Reddit API: {str(e)}")
            raise
    
    def scrape_posts(self, source: str, max_posts: int = None) -> List[Dict]:
        """Scrape posts from a specific subreddit or user."""
        if not self.reddit:
            logger.error("Reddit API not initialized")
            return []
        
        max_posts = max_posts or self.config.MAX_POSTS_PER_SOURCE
        
        try:
            posts = []
            
            # Check if source is a subreddit (starts with r/ or is a subreddit name)
            if source.startswith('r/') or not source.startswith('u/'):
                subreddit_name = source.replace('r/', '')
                posts = self._scrape_subreddit(subreddit_name, max_posts)
            else:
                # Scrape user posts
                username = source.replace('u/', '')
                posts = self._scrape_user_posts(username, max_posts)
            
            logger.info(f"Scraped {len(posts)} posts from {source}")
            return posts
            
        except Exception as e:
            logger.error(f"Error scraping posts from {source}: {str(e)}")
            return []
    
    def _scrape_subreddit(self, subreddit_name: str, max_posts: int) -> List[Dict]:
        """Scrape posts from a subreddit."""
        try:
            subreddit = self.reddit.subreddit(subreddit_name)
            posts = []
            
            for submission in subreddit.hot(limit=max_posts):
                post_data = self._process_submission(submission)
                if post_data:
                    posts.append(post_data)
            
            return posts
            
        except Exception as e:
            logger.error(f"Error scraping subreddit r/{subreddit_name}: {str(e)}")
            return []
    
    def _scrape_user_posts(self, username: str, max_posts: int) -> List[Dict]:
        """Scrape posts from a specific user."""
        try:
            user = self.reddit.redditor(username)
            posts = []
            
            for submission in user.submissions.new(limit=max_posts):
                post_data = self._process_submission(submission)
                if post_data:
                    posts.append(post_data)
            
            return posts
            
        except Exception as e:
            logger.error(f"Error scraping user u/{username}: {str(e)}")
            return []
    
    def _process_submission(self, submission) -> Optional[Dict]:
        """Process a Reddit submission into our standard format."""
        try:
            post_data = {
                'id': submission.id,
                'title': submission.title,
                'text': submission.selftext,
                'author': str(submission.author) if submission.author else '[deleted]',
                'subreddit': str(submission.subreddit),
                'created_at': submission.created_utc,
                'source_type': 'reddit',
                'url': f"https://reddit.com{submission.permalink}",
                'score': submission.score,
                'upvote_ratio': submission.upvote_ratio,
                'num_comments': submission.num_comments,
                'is_self': submission.is_self,
                'is_video': submission.is_video,
                'over_18': submission.over_18,
                'spoiler': submission.spoiler,
                'locked': submission.locked,
                'stickied': submission.stickied,
                'link_flair_text': submission.link_flair_text,
                'domain': submission.domain,
                'url_external': submission.url if not submission.is_self else None,
                'raw_data': {
                    'id': submission.id,
                    'title': submission.title,
                    'selftext': submission.selftext,
                    'author': str(submission.author) if submission.author else None,
                    'subreddit': str(submission.subreddit),
                    'created_utc': submission.created_utc,
                    'score': submission.score,
                    'upvote_ratio': submission.upvote_ratio,
                    'num_comments': submission.num_comments,
                    'url': submission.url,
                    'permalink': submission.permalink
                }
            }
            
            return post_data
            
        except Exception as e:
            logger.error(f"Error processing submission {submission.id}: {str(e)}")
            return None
    
    def extract_links(self, post: Dict) -> List[str]:
        """Extract links from a Reddit post."""
        links = []
        
        # Extract external URL if present
        if post.get('url_external') and self.is_valid_url(post['url_external']):
            links.append(post['url_external'])
        
        # Extract URLs from text content using regex
        text_content = f"{post.get('title', '')} {post.get('text', '')}"
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        found_urls = re.findall(url_pattern, text_content)
        
        for url in found_urls:
            if self.is_valid_url(url) and url not in links:
                links.append(url)
        
        return links
    
    def search_posts(self, query: str, subreddit: str = None, max_posts: int = 100) -> List[Dict]:
        """Search for posts containing specific keywords."""
        try:
            posts = []
            
            if subreddit:
                # Search within specific subreddit
                subreddit_obj = self.reddit.subreddit(subreddit)
                for submission in subreddit_obj.search(query, sort='new', limit=max_posts):
                    post_data = self._process_submission(submission)
                    if post_data:
                        posts.append(post_data)
            else:
                # Search across all of Reddit
                for submission in self.reddit.subreddit('all').search(query, sort='new', limit=max_posts):
                    post_data = self._process_submission(submission)
                    if post_data:
                        posts.append(post_data)
            
            logger.info(f"Found {len(posts)} Reddit posts for query: {query}")
            return posts
            
        except Exception as e:
            logger.error(f"Error searching Reddit posts for query '{query}': {str(e)}")
            return []
    
    def get_subreddit_info(self, subreddit_name: str) -> Optional[Dict]:
        """Get information about a subreddit."""
        try:
            subreddit = self.reddit.subreddit(subreddit_name)
            
            subreddit_info = {
                'name': subreddit.display_name,
                'title': subreddit.title,
                'description': subreddit.description,
                'public_description': subreddit.public_description,
                'subscribers': subreddit.subscribers,
                'active_users': subreddit.active_user_count,
                'created_utc': subreddit.created_utc,
                'over18': subreddit.over18,
                'lang': subreddit.lang,
                'url': f"https://reddit.com/r/{subreddit_name}"
            }
            
            return subreddit_info
            
        except Exception as e:
            logger.error(f"Error getting subreddit info for r/{subreddit_name}: {str(e)}")
            return None
