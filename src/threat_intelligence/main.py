"""
Main script for threat intelligence webscraping.
"""
import argparse
import logging
from typing import List, Dict
from .core.config import Config
from .scrapers import TwitterScraper, RedditScraper, WebScraper
from .storage.data_storage import DataStorage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatIntelligenceScraper:
    """Main orchestrator for threat intelligence scraping."""
    
    def __init__(self, config: Config):
        self.config = config
        self.storage = DataStorage(config)
        self.scrapers = {}
    
    def scrape_source(self, platform: str, source: str, max_posts: int = None) -> Dict:
        """Scrape data from a specific source."""
        # Initialize scraper if not already done
        if platform not in self.scrapers:
            if platform == 'twitter':
                self.scrapers[platform] = TwitterScraper(self.config)
            elif platform == 'reddit':
                self.scrapers[platform] = RedditScraper(self.config)
            elif platform == 'web':
                # Pass storage instance to WebScraper for direct S3 uploads
                self.scrapers[platform] = WebScraper(self.config, storage=self.storage)
            else:
                raise ValueError(f"Unsupported platform: {platform}")
        
        scraper = self.scrapers[platform]
        max_posts = max_posts or self.config.MAX_POSTS_PER_SOURCE
        
        logger.info(f"Starting scrape of {platform}:{source} (max {max_posts} posts)")
        
        # Scrape posts
        posts = scraper.scrape_posts(source, max_posts)
        
        if not posts:
            logger.warning(f"No posts found for {platform}:{source}")
            return {'posts': [], 'linked_content': []}
        
        # Extract and follow links
        all_links = []
        for post in posts:
            links = scraper.extract_links(post)
            all_links.extend(links)
        
        # Remove duplicates while preserving order
        unique_links = list(dict.fromkeys(all_links))
        
        logger.info(f"Found {len(unique_links)} unique links to follow")
        
        # Follow links and extract content
        linked_content = []
        if unique_links and self.config.FOLLOW_LINKS:
            linked_content = scraper.follow_links(unique_links, self.config.MAX_LINK_DEPTH)
            logger.info(f"Extracted content from {len(linked_content)} linked pages")
        
        # Save data (only save locally, raw data already saved to S3 by scraper)
        posts_file = None
        linked_file = None
        # Only save locally for backup - raw data is already in S3
        if platform == 'web':
            # Web scraper already saved raw data to S3, skip processed data saving
            logger.info("Raw data already saved to S3 by web scraper, skipping processed data save")
        else:
            # For other platforms, save locally
            posts_file = self.storage.save_posts(posts, f"{platform}_{source}", "posts")
            if linked_content:
                linked_file = self.storage.save_linked_content(linked_content, f"{platform}_{source}")
        
        return {
            'posts': posts,
            'linked_content': linked_content,
            'posts_file': posts_file,
            'linked_file': linked_file,
            'total_links_found': len(unique_links),
            'links_processed': len(linked_content)
        }
    
    def scrape_multiple_sources(self, sources: List[Dict]) -> Dict:
        """Scrape data from multiple sources."""
        results = {}
        
        for source_config in sources:
            platform = source_config['platform']
            source = source_config['source']
            max_posts = source_config.get('max_posts', self.config.MAX_POSTS_PER_SOURCE)
            
            try:
                result = self.scrape_source(platform, source, max_posts)
                results[f"{platform}_{source}"] = result
                
                logger.info(f"Successfully scraped {platform}:{source} - "
                          f"{len(result['posts'])} posts, "
                          f"{len(result['linked_content'])} linked pages")
                
            except Exception as e:
                logger.error(f"Failed to scrape {platform}:{source}: {str(e)}")
                results[f"{platform}_{source}"] = {'error': str(e)}
        
        return results
    
    def get_data_summary(self) -> Dict:
        """Get summary of all stored data."""
        return self.storage.get_data_summary()
    

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Threat Intelligence Webscraper')
    parser.add_argument('--platform', choices=['twitter', 'reddit', 'web'], required=True,
                       help='Platform to scrape from')
    parser.add_argument('--source', required=True,
                       help='Source to scrape (e.g., username, subreddit, or Twitter URL)')
    parser.add_argument('--max-posts', type=int, default=None,
                       help='Maximum number of posts to scrape')
    parser.add_argument('--follow-links', action='store_true', default=True,
                       help='Follow links in posts to extract additional content')
    parser.add_argument('--no-follow-links', dest='follow_links', action='store_false',
                       help='Disable following links in posts')
    parser.add_argument('--summary', action='store_true',
                       help='Show data summary instead of scraping')
    
    
    args = parser.parse_args()
    
    # Load configuration
    config = Config()
    config.validate()
    
    # Override config with command line arguments
    if args.max_posts:
        config.MAX_POSTS_PER_SOURCE = args.max_posts
    config.FOLLOW_LINKS = args.follow_links
    
    # Initialize scraper
    scraper = ThreatIntelligenceScraper(config)
    
    if args.summary:
        # Show data summary
        summary = scraper.get_data_summary()
        print("\n=== Data Summary ===")
        print(f"Total files: {summary['total_files']}")
        print(f"Total posts: {summary['total_posts']}")
        print(f"Sources: {list(summary['sources'].keys())}")
        print(f"Data types: {list(summary['data_types'].keys())}")
        
        for source, count in summary['sources'].items():
            print(f"  {source}: {count} posts")
        
        for data_type, count in summary['data_types'].items():
            print(f"  {data_type}: {count} items")
    else:
        # Perform scraping
        try:
            result = scraper.scrape_source(args.platform, args.source, args.max_posts)
            
            print(f"\n=== Scraping Results ===")
            print(f"Platform: {args.platform}")
            print(f"Source: {args.source}")
            print(f"Posts scraped: {len(result['posts'])}")
            print(f"Links found: {result['total_links_found']}")
            print(f"Linked content extracted: {result['links_processed']}")
            print(f"Posts saved to: {result['posts_file']}")
            if result['linked_file']:
                print(f"Linked content saved to: {result['linked_file']}")
            
        except Exception as e:
            logger.error(f"Scraping failed: {str(e)}")
            return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
