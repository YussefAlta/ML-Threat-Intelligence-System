"""
NIST CPE (Common Platform Enumeration) scraper.
Fetches CPE data from NIST NVD API with pagination, rate limiting, and error handling.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .base_scraper import BaseScraper
from ..utils.api_client import APIClient, RateLimiter

logger = logging.getLogger(__name__)


class NISTCPEScraper(BaseScraper):
    """
    Scraper for NIST CPE data from the National Vulnerability Database (NVD).
    
    Supports:
    - Pagination for large datasets
    - Rate limiting (respects API quotas)
    - Retry logic with exponential backoff
    - Incremental updates (by last modification date)
    - CPE matching for vulnerability analysis
    """
    
    def __init__(self, config, storage=None):
        """
        Initialize NIST CPE scraper.
        
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
        
        # CPE API endpoints (using 2.3 version)
        self.cpe_endpoint = "cpes/2.0"
        
        logger.info("NIST CPE scraper initialized")
    
    def scrape_posts(self, source: str = "cpe", max_posts: Optional[int] = None) -> List[Dict]:
        """
        Scrape CPE data from NIST API.
        
        Note: This method signature matches BaseScraper but 'source' and 'max_posts'
        have different meanings for CPE data:
        - source: Not used (kept for interface compatibility)
        - max_posts: Maximum number of CPEs to fetch (None = fetch all)
        
        Args:
            source: Not used (for interface compatibility)
            max_posts: Maximum number of CPEs to fetch
            
        Returns:
            List of CPE records
        """
        return self.fetch_cpes(max_count=max_posts)
    
    def extract_links(self, post: Dict) -> List[str]:
        """
        Extract links from a CPE record.
        
        Args:
            post: CPE record dictionary
            
        Returns:
            List of URLs found in the CPE record (typically empty for CPEs)
        """
        links = []
        
        # CPE records may have reference links
        cpe_item = post.get('cpe', {})
        references = cpe_item.get('references', [])
        
        for ref in references:
            url = ref.get('ref', '')
            if url:
                links.append(url)
        
        return links
    
    def fetch_cpes(
        self,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None,
        results_per_page: Optional[int] = None,
        max_count: Optional[int] = None,
        cpe_match_string: Optional[str] = None,
        keyword_exact_match: Optional[bool] = None,
        keyword_search: Optional[str] = None
    ) -> List[Dict]:
        """
        Fetch CPE data from NIST API with pagination support.
        
        Args:
            last_mod_start_date: Last modification start date (YYYY-MM-DDTHH:MM:SS.mmm)
            last_mod_end_date: Last modification end date (YYYY-MM-DDTHH:MM:SS.mmm)
            results_per_page: Number of results per page (max 2000, default from config)
            max_count: Maximum number of CPEs to fetch (None = fetch all)
            cpe_match_string: CPE match string for filtering (format: cpe:2.3:...)
            keyword_exact_match: Exact match for keyword search
            keyword_search: Keyword to search for
            
        Returns:
            List of CPE records
        """
        if results_per_page is None:
            results_per_page = min(self.config.NIST_RESULTS_PER_PAGE, 2000)
        
        all_cpes = []
        start_index = 0
        total_results = None
        
        logger.info(f"Starting CPE fetch. Max count: {max_count}, Results per page: {results_per_page}")
        
        while True:
            # Check if we've reached the max count
            if max_count and len(all_cpes) >= max_count:
                logger.info(f"Reached max count ({max_count}). Stopping fetch.")
                break
            
            # Calculate how many results to fetch in this batch
            remaining = max_count - len(all_cpes) if max_count else None
            if remaining and remaining < results_per_page:
                results_per_page = remaining
            
            # Fetch batch
            logger.info(f"Fetching CPEs: start_index={start_index}, results_per_page={results_per_page}")
            
            try:
                batch = self._fetch_cpe_batch(
                    start_index=start_index,
                    results_per_page=results_per_page,
                    last_mod_start_date=last_mod_start_date,
                    last_mod_end_date=last_mod_end_date,
                    cpe_match_string=cpe_match_string,
                    keyword_exact_match=keyword_exact_match,
                    keyword_search=keyword_search
                )
                
                if not batch:
                    logger.info("No more CPEs to fetch.")
                    break
                
                cpes = batch.get('products', [])
                if not cpes:
                    logger.info("No CPEs in response. Stopping.")
                    break
                
                all_cpes.extend(cpes)
                logger.info(f"Fetched {len(cpes)} CPEs. Total: {len(all_cpes)}")
                
                # Get total results from first response
                if total_results is None:
                    total_results = batch.get('totalResults', 0)
                    logger.info(f"Total CPEs available: {total_results}")
                
                # Check if there are more results
                if len(all_cpes) >= total_results:
                    logger.info("Fetched all available CPEs.")
                    break
                
                # Update start index for next batch
                start_index += len(cpes)
                
                # Check if we've reached max count
                if max_count and len(all_cpes) >= max_count:
                    # Truncate to exact max_count
                    all_cpes = all_cpes[:max_count]
                    logger.info(f"Reached max count ({max_count}). Stopping fetch.")
                    break
                
            except Exception as e:
                logger.error(f"Error fetching CPE batch at start_index {start_index}: {str(e)}")
                raise
        
        logger.info(f"Successfully fetched {len(all_cpes)} CPEs")
        return all_cpes
    
    def _fetch_cpe_batch(
        self,
        start_index: int,
        results_per_page: int,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None,
        cpe_match_string: Optional[str] = None,
        keyword_exact_match: Optional[bool] = None,
        keyword_search: Optional[str] = None
    ) -> Dict:
        """
        Fetch a single batch of CPEs from NIST API.
        
        Args:
            start_index: Starting index for pagination
            results_per_page: Number of results to fetch
            last_mod_start_date: Last modification start date
            last_mod_end_date: Last modification end date
            cpe_match_string: CPE match string filter
            keyword_exact_match: Exact match for keyword
            keyword_search: Keyword to search
            
        Returns:
            API response dictionary
        """
        params = {
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }
        
        # Add date filters if provided
        if last_mod_start_date:
            params['lastModStartDate'] = last_mod_start_date
        if last_mod_end_date:
            params['lastModEndDate'] = last_mod_end_date
        
        # Add CPE match string if provided
        if cpe_match_string:
            params['cpeMatchString'] = cpe_match_string
        
        # Add keyword search if provided
        if keyword_search:
            params['keywordSearch'] = keyword_search
            if keyword_exact_match is not None:
                params['keywordExactMatch'] = str(keyword_exact_match).lower()
        
        try:
            response = self.api_client.get(self.cpe_endpoint, params=params)
            return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch CPE batch: {str(e)}")
            raise
    
    def fetch_recent_cpes(self, days: int = 7, max_count: Optional[int] = None) -> List[Dict]:
        """
        Fetch recently modified CPEs.
        
        Args:
            days: Number of days to look back
            max_count: Maximum number of CPEs to fetch
            
        Returns:
            List of recent CPE records
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        last_mod_start_date = start_date.strftime('%Y-%m-%dT00:00:00.000')
        last_mod_end_date = end_date.strftime('%Y-%m-%dT23:59:59.999')
        
        logger.info(f"Fetching CPEs modified between {last_mod_start_date} and {last_mod_end_date}")
        
        return self.fetch_cpes(
            last_mod_start_date=last_mod_start_date,
            last_mod_end_date=last_mod_end_date,
            max_count=max_count
        )
    
    def fetch_cpe_by_match_string(self, cpe_match_string: str, max_count: Optional[int] = None) -> List[Dict]:
        """
        Fetch CPEs matching a specific CPE match string.
        
        Args:
            cpe_match_string: CPE match string (format: cpe:2.3:...)
            max_count: Maximum number of CPEs to fetch
            
        Returns:
            List of matching CPE records
        """
        logger.info(f"Fetching CPEs matching: {cpe_match_string}")
        
        return self.fetch_cpes(
            cpe_match_string=cpe_match_string,
            max_count=max_count
        )
    
    def fetch_cpes_by_keyword(self, keyword: str, exact_match: bool = False, max_count: Optional[int] = None) -> List[Dict]:
        """
        Fetch CPEs by keyword search.
        
        Args:
            keyword: Keyword to search for
            exact_match: Whether to use exact match
            max_count: Maximum number of CPEs to fetch
            
        Returns:
            List of matching CPE records
        """
        logger.info(f"Searching CPEs for keyword: '{keyword}' (exact_match={exact_match})")
        
        return self.fetch_cpes(
            keyword_search=keyword,
            keyword_exact_match=exact_match,
            max_count=max_count
        )

