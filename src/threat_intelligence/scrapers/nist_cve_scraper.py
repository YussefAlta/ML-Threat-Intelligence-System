"""
NIST CVE (Common Vulnerabilities and Exposures) scraper.
Fetches CVE data from NIST NVD API with pagination, rate limiting, and error handling.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from .base_scraper import BaseScraper
from ..utils.api_client import APIClient, RateLimiter

logger = logging.getLogger(__name__)


class NISTCVEScraper(BaseScraper):
    """
    Scraper for NIST CVE data from the National Vulnerability Database (NVD).
    
    Supports:
    - Pagination for large datasets
    - Rate limiting (respects API quotas)
    - Retry logic with exponential backoff
    - Incremental updates (by publication date)
    - CVE JSON 5.0 schema
    """
    
    def __init__(self, config, storage=None):
        """
        Initialize NIST CVE scraper.
        
        Args:
            config: Configuration object
            storage: Optional DataStorage instance for saving data
        """
        super().__init__(config)
        self.storage = storage
        
        # Initialize rate limiter
        rate_limiter = RateLimiter(
            max_requests=config.NIST_RATE_LIMIT_REQUESTS,
            window_seconds=config.NIST_RATE_LIMIT_WINDOW
        )
        
        # Initialize API client
        self.api_client = APIClient(
            base_url=config.NIST_API_BASE_URL,
            api_key=config.NIST_API_KEY,
            rate_limiter=rate_limiter,
            max_retries=config.NIST_MAX_RETRIES,
            backoff_multiplier=config.NIST_RETRY_BACKOFF,
            timeout=60
        )
        
        # CVE API endpoint (using 2.0 version)
        self.cve_endpoint = "cves/2.0"
        
        logger.info("NIST CVE scraper initialized")
    
    def scrape_posts(self, source: str = "cve", max_posts: Optional[int] = None) -> List[Dict]:
        """
        Scrape CVE data from NIST API.
        
        Note: This method signature matches BaseScraper but 'source' and 'max_posts'
        have different meanings for CVE data:
        - source: Not used (kept for interface compatibility)
        - max_posts: Maximum number of CVEs to fetch (None = fetch all)
        
        Args:
            source: Not used (for interface compatibility)
            max_posts: Maximum number of CVEs to fetch
            
        Returns:
            List of CVE records
        """
        return self.fetch_cves(max_count=max_posts)
    
    def extract_links(self, post: Dict) -> List[str]:
        """
        Extract links from a CVE record.
        
        Args:
            post: CVE record dictionary
            
        Returns:
            List of URLs found in the CVE record
        """
        links = []
        
        # Extract references from CVE
        cve_data = post.get('cve', {})
        references = cve_data.get('references', [])
        
        for ref in references:
            url = ref.get('url')
            if url:
                links.append(url)
        
        return links
    
    def fetch_cves(
        self,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        results_per_page: Optional[int] = None,
        max_count: Optional[int] = None,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None
    ) -> List[Dict]:
        """
        Fetch CVE data from NIST API with pagination support.
        
        Args:
            pub_start_date: Publication start date (YYYY-MM-DDTHH:MM:SS.mmm) or (YYYY-MM-DD)
            pub_end_date: Publication end date (YYYY-MM-DDTHH:MM:SS.mmm) or (YYYY-MM-DD)
            results_per_page: Number of results per page (max 2000, default from config)
            max_count: Maximum number of CVEs to fetch (None = fetch all)
            last_mod_start_date: Last modification start date (for incremental updates)
            last_mod_end_date: Last modification end date (for incremental updates)
            
        Returns:
            List of CVE vulnerability records
        """
        if results_per_page is None:
            results_per_page = min(self.config.NIST_RESULTS_PER_PAGE, 2000)
        
        all_cves = []
        start_index = 0
        total_results = None
        
        logger.info(f"Starting CVE fetch. Max count: {max_count}, Results per page: {results_per_page}")
        
        while True:
            # Check if we've reached the max count
            if max_count and len(all_cves) >= max_count:
                logger.info(f"Reached max count ({max_count}). Stopping fetch.")
                break
            
            # Calculate how many results to fetch in this batch
            remaining = max_count - len(all_cves) if max_count else None
            if remaining and remaining < results_per_page:
                results_per_page = remaining
            
            # Fetch batch
            logger.info(f"Fetching CVEs: start_index={start_index}, results_per_page={results_per_page}")
            
            try:
                batch = self._fetch_cve_batch(
                    start_index=start_index,
                    results_per_page=results_per_page,
                    pub_start_date=pub_start_date,
                    pub_end_date=pub_end_date,
                    last_mod_start_date=last_mod_start_date,
                    last_mod_end_date=last_mod_end_date
                )
                
                if not batch:
                    logger.info("No more CVEs to fetch.")
                    break
                
                cves = batch.get('vulnerabilities', [])
                if not cves:
                    logger.info("No CVEs in response. Stopping.")
                    break
                
                all_cves.extend(cves)
                logger.info(f"Fetched {len(cves)} CVEs. Total: {len(all_cves)}")
                
                # Get total results from first response
                if total_results is None:
                    total_results = batch.get('totalResults', 0)
                    logger.info(f"Total CVEs available: {total_results}")
                
                # Check if there are more results
                if len(all_cves) >= total_results:
                    logger.info("Fetched all available CVEs.")
                    break
                
                # Update start index for next batch
                start_index += len(cves)
                
                # Check if we've reached max count
                if max_count and len(all_cves) >= max_count:
                    # Truncate to exact max_count
                    all_cves = all_cves[:max_count]
                    logger.info(f"Reached max count ({max_count}). Stopping fetch.")
                    break
                
            except Exception as e:
                logger.error(f"Error fetching CVE batch at start_index {start_index}: {str(e)}")
                raise
        
        logger.info(f"Successfully fetched {len(all_cves)} CVEs")
        return all_cves
    
    def _fetch_cve_batch(
        self,
        start_index: int,
        results_per_page: int,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None
    ) -> Dict:
        """
        Fetch a single batch of CVEs from NIST API.
        
        Args:
            start_index: Starting index for pagination
            results_per_page: Number of results to fetch
            pub_start_date: Publication start date
            pub_end_date: Publication end date
            last_mod_start_date: Last modification start date
            last_mod_end_date: Last modification end date
            
        Returns:
            API response dictionary
        """
        params = {
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }
        
        # Add date filters if provided
        if pub_start_date:
            params['pubStartDate'] = pub_start_date
        if pub_end_date:
            params['pubEndDate'] = pub_end_date
        if last_mod_start_date:
            params['lastModStartDate'] = last_mod_start_date
        if last_mod_end_date:
            params['lastModEndDate'] = last_mod_end_date
        
        try:
            response = self.api_client.get(self.cve_endpoint, params=params)
            return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch CVE batch: {str(e)}")
            raise
    
    def fetch_recent_cves(self, days: int = 7, max_count: Optional[int] = None) -> List[Dict]:
        """
        Fetch recently published CVEs.
        
        Args:
            days: Number of days to look back
            max_count: Maximum number of CVEs to fetch
            
        Returns:
            List of recent CVE records
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        pub_start_date = start_date.strftime('%Y-%m-%dT00:00:00.000')
        pub_end_date = end_date.strftime('%Y-%m-%dT23:59:59.999')
        
        logger.info(f"Fetching CVEs published between {pub_start_date} and {pub_end_date}")
        
        return self.fetch_cves(
            pub_start_date=pub_start_date,
            pub_end_date=pub_end_date,
            max_count=max_count
        )
    
    def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            
        Returns:
            CVE record if found, None otherwise
        """
        try:
            response = self.api_client.get(f"{self.cve_endpoint}/{cve_id}")
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                return vulnerabilities[0]
            return None
        except Exception as e:
            logger.error(f"Failed to fetch CVE {cve_id}: {str(e)}")
            return None

