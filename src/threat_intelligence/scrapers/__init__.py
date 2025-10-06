"""Web scrapers for various platforms."""

from .base_scraper import BaseScraper
from .web_scraper import WebScraper
from .twitter_scraper import TwitterScraper
from .reddit_scraper import RedditScraper

__all__ = [
    'BaseScraper',
    'WebScraper', 
    'TwitterScraper',
    'RedditScraper'
]