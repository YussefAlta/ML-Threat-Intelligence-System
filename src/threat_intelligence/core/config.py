"""
Configuration management for the ML Threat Intelligence System.
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env and .env.local files
load_dotenv()  # Loads .env
load_dotenv('.env.local')  # Loads .env.local (overrides .env)

class Config:
    """Configuration class for the threat intelligence system."""
    
    # NIST API Configuration
    NIST_API_KEY = os.getenv('NIST_API_KEY')
    NIST_API_BASE_URL = os.getenv('NIST_API_BASE_URL', 'https://services.nvd.nist.gov/rest/json/')
    NIST_RATE_LIMIT_REQUESTS = int(os.getenv('NIST_RATE_LIMIT_REQUESTS', '5'))  # Requests per window
    NIST_RATE_LIMIT_WINDOW = int(os.getenv('NIST_RATE_LIMIT_WINDOW', '30'))  # Seconds
    NIST_MAX_RETRIES = int(os.getenv('NIST_MAX_RETRIES', '5'))
    NIST_RETRY_BACKOFF = float(os.getenv('NIST_RETRY_BACKOFF', '2.0'))  # Exponential backoff multiplier
    NIST_RESULTS_PER_PAGE = int(os.getenv('NIST_RESULTS_PER_PAGE', '2000'))  # Max is 2000, default 2000 (best practice)
    
    # MITRE CWE API Configuration
    CWE_API_BASE_URL = os.getenv('CWE_API_BASE_URL', 'https://cwe-api.mitre.org/api/v1/')
    CWE_RATE_LIMIT_REQUESTS = int(os.getenv('CWE_RATE_LIMIT_REQUESTS', '10'))  # Requests per window (conservative)
    CWE_RATE_LIMIT_WINDOW = int(os.getenv('CWE_RATE_LIMIT_WINDOW', '60'))  # Seconds
    CWE_MAX_RETRIES = int(os.getenv('CWE_MAX_RETRIES', '5'))
    
    # VulnCheck API Configuration
    VULNCHECK_API_KEY = os.getenv('VULNCHECK_API_KEY')
    VULNCHECK_API_BASE_URL = os.getenv('VULNCHECK_API_BASE_URL', 'https://api.vulncheck.com/v3/')
    VULNCHECK_RATE_LIMIT_REQUESTS = int(os.getenv('VULNCHECK_RATE_LIMIT_REQUESTS', '10'))
    VULNCHECK_RATE_LIMIT_WINDOW = int(os.getenv('VULNCHECK_RATE_LIMIT_WINDOW', '60'))
    VULNCHECK_MAX_RETRIES = int(os.getenv('VULNCHECK_MAX_RETRIES', '5'))
    
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
        # No validation required for NIST API (optional API key)
        return True
