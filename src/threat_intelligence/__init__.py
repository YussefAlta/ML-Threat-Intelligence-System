"""
Threat Intelligence Web Scraping System

A comprehensive system for collecting threat intelligence data from various sources
including web content, social media platforms, and other open sources.
"""

__version__ = "1.0.0"
__author__ = "AVINT Project"

# Core imports
from .core.config import Config
from .storage.data_storage import DataStorage

# Scraper imports
from .scrapers.base_scraper import BaseScraper
from .scrapers.web_scraper import WebScraper
from .scrapers.twitter_scraper import TwitterScraper
from .scrapers.reddit_scraper import RedditScraper

__all__ = [
    'Config',
    'DataStorage',
    'BaseScraper',
    'WebScraper',
    'TwitterScraper',
    'RedditScraper'
]
