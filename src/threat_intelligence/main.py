"""
Main script for threat intelligence data collection.
Note: Social media scraping (Twitter/Reddit) has been removed.
Use NIST orchestrators for CVE/CPE ingestion and enrichment.
"""
import logging
from typing import Dict
from .core.config import Config
from .storage.data_storage import DataStorage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatIntelligenceScraper:
    """
    Main orchestrator for threat intelligence data collection.
    
    Note: Social media scraping has been removed. This class is kept
    for backward compatibility but is deprecated. Use NIST orchestrators
    for CVE/CPE ingestion and enrichment.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.storage = DataStorage(config)
    
    def get_data_summary(self) -> Dict:
        """Get summary of all stored data."""
        return self.storage.get_data_summary()


def main():
    """Main entry point."""
    logger.warning(
        "Social media scraping has been removed. "
        "Use NIST orchestrators for CVE/CPE ingestion and enrichment. "
        "See scripts/test_nist_ingestion.py and scripts/test_phase2_enrichment.py"
    )
    return 0

if __name__ == "__main__":
    exit(main())
