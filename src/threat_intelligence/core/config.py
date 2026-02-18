"""
Configuration management for the ML Threat Intelligence System.
"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
    load_dotenv('.env.local')
except ImportError:
    _env_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '.env.local')
    if os.path.exists(_env_path):
        with open(_env_path) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _k, _, _v = _line.partition('=')
                    os.environ.setdefault(_k.strip(), _v.strip())

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
    
    # Data Storage
    DATA_DIR = os.getenv('DATA_DIR', 'data')
    RAW_DATA_DIR = os.path.join(DATA_DIR, 'raw')

    # NVD Reference Scraping Configuration
    NVD_REF_SCRAPE_ENABLED = os.getenv('NVD_REF_SCRAPE_ENABLED', 'True').lower() == 'true'
    NVD_REF_RATE_LIMIT_REQUESTS = int(os.getenv('NVD_REF_RATE_LIMIT_REQUESTS', '10'))
    NVD_REF_RATE_LIMIT_WINDOW = int(os.getenv('NVD_REF_RATE_LIMIT_WINDOW', '60'))
    NVD_REF_TIMEOUT = int(os.getenv('NVD_REF_TIMEOUT', '30'))
    NVD_REF_MAX_RETRIES = int(os.getenv('NVD_REF_MAX_RETRIES', '3'))
    NVD_REF_MAX_SIZE_MB = int(os.getenv('NVD_REF_MAX_SIZE_MB', '10'))
    NVD_REF_DEDUPE_TTL_DAYS = int(os.getenv('NVD_REF_DEDUPE_TTL_DAYS', '30'))
    NVD_REF_MAX_CHUNK_SIZE = int(os.getenv('NVD_REF_MAX_CHUNK_SIZE', '1048576'))  # 1MB
    NVD_REF_USER_AGENT = os.getenv('NVD_REF_USER_AGENT', 'ML-Threat-Intelligence-System/1.0')
    NVD_REF_SKIP_MEDIA = os.getenv('NVD_REF_SKIP_MEDIA', 'True').lower() == 'true'
    NVD_REF_MIN_USEFUL_TEXT_LENGTH = int(os.getenv('NVD_REF_MIN_USEFUL_TEXT_LENGTH', '50'))

    # OSINT Corpus Configuration
    OSINT_CORPUS_S3_PREFIX = os.getenv('OSINT_CORPUS_S3_PREFIX', 'osint/corpus')
    OSINT_CORPUS_LOCAL_DIR = os.path.join(DATA_DIR, 'corpus')

    # PhishTank Configuration
    PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY')
    PHISHTANK_FEED_URL = os.getenv('PHISHTANK_FEED_URL', 'http://data.phishtank.com/data/online-valid.json')
    PHISHTANK_RATE_LIMIT_REQUESTS = int(os.getenv('PHISHTANK_RATE_LIMIT_REQUESTS', '5'))
    PHISHTANK_RATE_LIMIT_WINDOW = int(os.getenv('PHISHTANK_RATE_LIMIT_WINDOW', '60'))

    # Ransomwatch Configuration
    RANSOMWATCH_FEED_URL = os.getenv('RANSOMWATCH_FEED_URL', 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json')
    RANSOMWATCH_GROUPS_URL = os.getenv('RANSOMWATCH_GROUPS_URL', 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json')

    # MITRE ATT&CK Configuration
    MITRE_ATTACK_URL = os.getenv('MITRE_ATTACK_URL', 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')

    # AlienVault OTX Configuration
    OTX_API_KEY = os.getenv('OTX_API_KEY')
    OTX_API_BASE_URL = os.getenv('OTX_API_BASE_URL', 'https://otx.alienvault.com/api/v1/')
    OTX_RATE_LIMIT_REQUESTS = int(os.getenv('OTX_RATE_LIMIT_REQUESTS', '10'))
    OTX_RATE_LIMIT_WINDOW = int(os.getenv('OTX_RATE_LIMIT_WINDOW', '60'))
    OTX_PULSE_LIMIT = int(os.getenv('OTX_PULSE_LIMIT', '100'))

    # ExploitDB Configuration
    EXPLOITDB_CSV_URL = os.getenv('EXPLOITDB_CSV_URL', 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv')
    EXPLOITDB_BASE_URL = os.getenv('EXPLOITDB_BASE_URL', 'https://www.exploit-db.com/')
    EXPLOITDB_RATE_LIMIT_REQUESTS = int(os.getenv('EXPLOITDB_RATE_LIMIT_REQUESTS', '5'))
    EXPLOITDB_RATE_LIMIT_WINDOW = int(os.getenv('EXPLOITDB_RATE_LIMIT_WINDOW', '60'))

    # NLP Configuration
    NLP_ENRICHED_S3_PREFIX = os.getenv('NLP_ENRICHED_S3_PREFIX', 'nlp/enriched')
    SECUREBERT_MODEL_NAME = os.getenv('SECUREBERT_MODEL_NAME', 'cisco-ai/SecureBERT2.0-base')
    SECUREBERT_NER_MODEL_NAME = os.getenv('SECUREBERT_NER_MODEL_NAME', 'cisco-ai/SecureBERT2.0-NER')
    SECUREBERT_MAX_TOKENS = int(os.getenv('SECUREBERT_MAX_TOKENS', '7500'))

    # Legacy (only for scrapers.base_scraper; not used by current pipeline)
    FOLLOW_LINKS = os.getenv('FOLLOW_LINKS', 'False').lower() == 'true'
    REQUEST_DELAY = float(os.getenv('REQUEST_DELAY', '1.0'))

    @classmethod
    def validate(cls):
        """Validate that required configuration is present."""
        # No validation required for NIST API (optional API key)
        return True
