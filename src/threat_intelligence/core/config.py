"""
Configuration management for the threat intelligence webscraper.
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env and .env.local files
load_dotenv()  # Loads .env
load_dotenv('.env.local')  # Loads .env.local (overrides .env)

class Config:
    """Configuration class for the webscraper."""
    
    # Main API Key
    API_KEY = os.getenv('API_KEY')
    
    # Reddit API Configuration
    REDDIT_CLIENT_ID = os.getenv('REDDIT_CLIENT_ID')
    REDDIT_CLIENT_SECRET = os.getenv('REDDIT_CLIENT_SECRET')
    REDDIT_USER_AGENT = os.getenv('REDDIT_USER_AGENT', 'ThreatIntelligenceBot/1.0')
    
    # Firecrawl API Configuration (for Twitter/X scraping)
    FIRECRAWL_API_KEY = os.getenv('FIRECRAWL_API_KEY', 'FIRECRAWL_API_KEY_REDACTED')
    
    # NIST API Configuration
    NIST_API_KEY = os.getenv('NIST_API_KEY')
    NIST_API_BASE_URL = os.getenv('NIST_API_BASE_URL', 'https://services.nvd.nist.gov/rest/json/')
    NIST_RATE_LIMIT_REQUESTS = int(os.getenv('NIST_RATE_LIMIT_REQUESTS', '5'))  # Requests per window
    NIST_RATE_LIMIT_WINDOW = int(os.getenv('NIST_RATE_LIMIT_WINDOW', '30'))  # Seconds
    NIST_MAX_RETRIES = int(os.getenv('NIST_MAX_RETRIES', '5'))
    NIST_RETRY_BACKOFF = float(os.getenv('NIST_RETRY_BACKOFF', '2.0'))  # Exponential backoff multiplier
    NIST_RESULTS_PER_PAGE = int(os.getenv('NIST_RESULTS_PER_PAGE', '2000'))  # Max is 2000, default 2000 (best practice)
    
    # AWS S3 Configuration
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
    S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
    
    # Scraping Configuration
    MAX_POSTS_PER_SOURCE = int(os.getenv('MAX_POSTS_PER_SOURCE', '100'))
    FOLLOW_LINKS = os.getenv('FOLLOW_LINKS', 'True').lower() == 'true'
    MAX_LINK_DEPTH = int(os.getenv('MAX_LINK_DEPTH', '2'))
    REQUEST_DELAY = float(os.getenv('REQUEST_DELAY', '1.0'))
    
    # Data Storage
    DATA_DIR = os.getenv('DATA_DIR', 'data')
    RAW_DATA_DIR = os.path.join(DATA_DIR, 'raw')
    
    @classmethod
    def validate(cls):
        """Validate that required configuration is present."""
        # Twitter uses snscrape - no API credentials needed
        # Only Reddit requires API credentials
        required_reddit = [
            cls.REDDIT_CLIENT_ID,
            cls.REDDIT_CLIENT_SECRET
        ]
        
        if not all(required_reddit):
            print("Warning: Reddit API credentials not fully configured")
        
        return True
