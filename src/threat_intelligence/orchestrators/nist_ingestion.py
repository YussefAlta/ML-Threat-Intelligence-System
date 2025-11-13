"""
Main orchestrator for NIST CVE/CPE data ingestion pipeline.
Handles scheduling, incremental updates, and coordination between CVE and CPE scrapers.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from ..core.config import Config
from ..scrapers.nist_cve_scraper import NISTCVEScraper
from ..scrapers.nist_cpe_scraper import NISTCPEScraper
from ..storage.data_storage import DataStorage

logger = logging.getLogger(__name__)


class NISTIngestionOrchestrator:
    """
    Orchestrates NIST CVE and CPE data ingestion.
    
    Features:
    - Coordinated CVE and CPE ingestion
    - Incremental updates by date
    - Error handling and recovery
    - Progress tracking
    - Idempotent operations
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize NIST ingestion orchestrator.
        
        Args:
            config: Optional Config instance (creates new if not provided)
        """
        self.config = config or Config()
        self.config.validate()
        
        # Initialize storage
        self.storage = DataStorage(self.config)
        
        # Initialize scrapers
        self.cve_scraper = NISTCVEScraper(self.config, storage=self.storage)
        self.cpe_scraper = NISTCPEScraper(self.config, storage=self.storage)
        
        logger.info("NIST Ingestion Orchestrator initialized")
    
    def ingest_cves(
        self,
        days_back: Optional[int] = None,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        max_count: Optional[int] = None,
        save_local: bool = True
    ) -> Dict:
        """
        Ingest CVE data from NIST API.
        
        Args:
            days_back: Number of days to look back (used if dates not provided)
            pub_start_date: Publication start date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS.mmm)
            pub_end_date: Publication end date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS.mmm)
            max_count: Maximum number of CVEs to fetch
            save_local: Whether to save locally as well as S3
            
        Returns:
            Dictionary with ingestion results
        """
        logger.info("Starting CVE ingestion...")
        
        try:
            # Determine date range
            if not pub_start_date or not pub_end_date:
                if days_back:
                    end_date = datetime.now()
                    start_date = end_date - timedelta(days=days_back)
                    pub_start_date = start_date.strftime('%Y-%m-%dT00:00:00.000')
                    pub_end_date = end_date.strftime('%Y-%m-%dT23:59:59.999')
                else:
                    # Use recent CVEs default (last 7 days)
                    end_date = datetime.now()
                    start_date = end_date - timedelta(days=7)
                    pub_start_date = start_date.strftime('%Y-%m-%dT00:00:00.000')
                    pub_end_date = end_date.strftime('%Y-%m-%dT23:59:59.999')
            
            logger.info(f"Fetching CVEs from {pub_start_date} to {pub_end_date}")
            
            # Fetch CVEs
            cve_records = self.cve_scraper.fetch_cves(
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
                max_count=max_count
            )
            
            if not cve_records:
                logger.warning("No CVE records fetched")
                return {
                    'success': False,
                    'records_fetched': 0,
                    'records_saved': 0,
                    's3_key': None,
                    'error': 'No records fetched'
                }
            
            logger.info(f"Fetched {len(cve_records)} CVE records")
            
            # Save to storage
            date_filter = pub_start_date.split('T')[0] if 'T' in pub_start_date else pub_start_date
            s3_key = self.storage.save_cve_data(
                cve_records=cve_records,
                date_filter=date_filter,
                save_local=save_local
            )
            
            result = {
                'success': True,
                'records_fetched': len(cve_records),
                'records_saved': len(cve_records),
                's3_key': s3_key,
                'date_range': {
                    'start': pub_start_date,
                    'end': pub_end_date
                }
            }
            
            logger.info(f"Successfully ingested {len(cve_records)} CVE records")
            return result
            
        except Exception as e:
            logger.error(f"Error during CVE ingestion: {str(e)}", exc_info=True)
            return {
                'success': False,
                'records_fetched': 0,
                'records_saved': 0,
                's3_key': None,
                'error': str(e)
            }
    
    def ingest_cpes(
        self,
        days_back: Optional[int] = None,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None,
        max_count: Optional[int] = None,
        save_local: bool = True
    ) -> Dict:
        """
        Ingest CPE data from NIST API.
        
        Args:
            days_back: Number of days to look back (used if dates not provided)
            last_mod_start_date: Last modification start date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS.mmm)
            last_mod_end_date: Last modification end date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS.mmm)
            max_count: Maximum number of CPEs to fetch
            save_local: Whether to save locally as well as S3
            
        Returns:
            Dictionary with ingestion results
        """
        logger.info("Starting CPE ingestion...")
        
        try:
            # Determine date range
            if not last_mod_start_date or not last_mod_end_date:
                if days_back:
                    end_date = datetime.now()
                    start_date = end_date - timedelta(days=days_back)
                    last_mod_start_date = start_date.strftime('%Y-%m-%dT00:00:00.000')
                    last_mod_end_date = end_date.strftime('%Y-%m-%dT23:59:59.999')
                else:
                    # Use recent CPEs default (last 7 days)
                    end_date = datetime.now()
                    start_date = end_date - timedelta(days=7)
                    last_mod_start_date = start_date.strftime('%Y-%m-%dT00:00:00.000')
                    last_mod_end_date = end_date.strftime('%Y-%m-%dT23:59:59.999')
            
            logger.info(f"Fetching CPEs modified from {last_mod_start_date} to {last_mod_end_date}")
            
            # Fetch CPEs
            cpe_records = self.cpe_scraper.fetch_cpes(
                last_mod_start_date=last_mod_start_date,
                last_mod_end_date=last_mod_end_date,
                max_count=max_count
            )
            
            if not cpe_records:
                logger.warning("No CPE records fetched")
                return {
                    'success': False,
                    'records_fetched': 0,
                    'records_saved': 0,
                    's3_key': None,
                    'error': 'No records fetched'
                }
            
            logger.info(f"Fetched {len(cpe_records)} CPE records")
            
            # Save to storage
            date_filter = last_mod_start_date.split('T')[0] if 'T' in last_mod_start_date else last_mod_start_date
            s3_key = self.storage.save_cpe_data(
                cpe_records=cpe_records,
                date_filter=date_filter,
                save_local=save_local
            )
            
            result = {
                'success': True,
                'records_fetched': len(cpe_records),
                'records_saved': len(cpe_records),
                's3_key': s3_key,
                'date_range': {
                    'start': last_mod_start_date,
                    'end': last_mod_end_date
                }
            }
            
            logger.info(f"Successfully ingested {len(cpe_records)} CPE records")
            return result
            
        except Exception as e:
            logger.error(f"Error during CPE ingestion: {str(e)}", exc_info=True)
            return {
                'success': False,
                'records_fetched': 0,
                'records_saved': 0,
                's3_key': None,
                'error': str(e)
            }
    
    def ingest_all(
        self,
        days_back: int = 7,
        max_cve_count: Optional[int] = None,
        max_cpe_count: Optional[int] = None,
        save_local: bool = True
    ) -> Dict:
        """
        Ingest both CVE and CPE data.
        
        Args:
            days_back: Number of days to look back
            max_cve_count: Maximum number of CVEs to fetch
            max_cpe_count: Maximum number of CPEs to fetch
            save_local: Whether to save locally as well as S3
            
        Returns:
            Dictionary with combined ingestion results
        """
        logger.info(f"Starting full NIST ingestion (last {days_back} days)...")
        
        results = {
            'started_at': datetime.now().isoformat(),
            'cve_ingestion': None,
            'cpe_ingestion': None,
            'overall_success': False
        }
        
        # Ingest CVEs
        try:
            cve_result = self.ingest_cves(
                days_back=days_back,
                max_count=max_cve_count,
                save_local=save_local
            )
            results['cve_ingestion'] = cve_result
        except Exception as e:
            logger.error(f"CVE ingestion failed: {str(e)}", exc_info=True)
            results['cve_ingestion'] = {
                'success': False,
                'error': str(e)
            }
        
        # Ingest CPEs
        try:
            cpe_result = self.ingest_cpes(
                days_back=days_back,
                max_count=max_cpe_count,
                save_local=save_local
            )
            results['cpe_ingestion'] = cpe_result
        except Exception as e:
            logger.error(f"CPE ingestion failed: {str(e)}", exc_info=True)
            results['cpe_ingestion'] = {
                'success': False,
                'error': str(e)
            }
        
        # Determine overall success
        results['overall_success'] = (
            results['cve_ingestion'] and results['cve_ingestion'].get('success', False) and
            results['cpe_ingestion'] and results['cpe_ingestion'].get('success', False)
        )
        results['completed_at'] = datetime.now().isoformat()
        
        # Log summary
        total_records = (
            (results['cve_ingestion'].get('records_fetched', 0) if results['cve_ingestion'] else 0) +
            (results['cpe_ingestion'].get('records_fetched', 0) if results['cpe_ingestion'] else 0)
        )
        
        logger.info(
            f"Completed NIST ingestion. Total records: {total_records}. "
            f"Overall success: {results['overall_success']}"
        )
        
        return results

