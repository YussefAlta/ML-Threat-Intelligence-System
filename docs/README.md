# ML Threat Intelligence System - Webscraper

A modular webscraping system for collecting threat intelligence data from social media platforms and following links to extract additional context.

## Features

- **Multi-platform Support**: Twitter/X, Reddit, and general web scrapers with extensible architecture
- **Universal Web Scraping**: Extract content from any website, blog, or news article using Firecrawl API
- **Link Following**: Automatically follows links in posts to extract additional content
- **Flexible Storage**: Local storage with S3 compatibility for future cloud deployment
- **Modular Design**: Easy to add new social media platforms and content sources
- **Raw Data Collection**: Preserves unstructured data for downstream ML/NLP processing
- **Advanced Content Parsing**: Extracts metadata, keywords, and structured content from web pages

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ML-Threat-Intelligence-System
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure API credentials:
```bash
cp .env.example .env
# Edit .env with your API credentials
```

## Configuration

Create a `.env` file with the following variables:

### Twitter/X (No API Required)
Twitter scraping uses snscrape - no API credentials needed!

### Reddit API
```
REDDIT_CLIENT_ID=your_client_id_here
REDDIT_CLIENT_SECRET=your_client_secret_here
REDDIT_USER_AGENT=your_user_agent_here
```

### Firecrawl API (for web scraping)
```
FIRECRAWL_API_KEY=your_firecrawl_api_key_here
```

### Optional: AWS S3 (for future use)
```
AWS_ACCESS_KEY_ID=your_aws_access_key_here
AWS_SECRET_ACCESS_KEY=your_aws_secret_key_here
AWS_REGION=us-east-1
S3_BUCKET_NAME=your_bucket_name_here
```

## Usage

### Command Line Interface

#### Scrape Twitter
```bash
python main.py --platform twitter --source briankrebs --max-posts 50
```

#### Scrape Reddit
```bash
python main.py --platform reddit --source r/cybersecurity --max-posts 100
```

#### Scrape Web Content
```bash
python main.py --platform web --source "https://example.com/article" --max-posts 1
```

#### View Data Summary
```bash
python main.py --summary
```

### Programmatic Usage

```python
from config import Config
from scrapers import TwitterScraper, RedditScraper, WebScraper
from data_storage import DataStorage

# Initialize
config = Config()
twitter_scraper = TwitterScraper(config)
web_scraper = WebScraper(config)
storage = DataStorage(config)

# Scrape Twitter
posts = twitter_scraper.scrape_posts("briankrebs", max_posts=10)

# Scrape web content
web_content = web_scraper.scrape_posts("https://example.com/article")

# Extract and follow links
links = []
for post in posts:
    links.extend(twitter_scraper.extract_links(post))

linked_content = twitter_scraper.follow_links(links)

# Save data
storage.save_posts(posts, "twitter_briankrebs", "posts")
storage.save_posts(web_content, "web_example", "posts")
storage.save_linked_content(linked_content, "twitter_briankrebs")
```

## Architecture

### Core Components

1. **BaseScraper**: Abstract base class with common functionality
2. **TwitterScraper**: Twitter/X specific implementation
3. **RedditScraper**: Reddit specific implementation
4. **WebScraper**: Universal web content scraper using Firecrawl API
5. **DataStorage**: Handles local and S3 storage
6. **Config**: Centralized configuration management

### Data Flow

1. **Scrape Posts**: Collect posts from social media platforms and web content
2. **Extract Links**: Identify URLs in post content
3. **Follow Links**: Visit linked pages and extract content
4. **Parse Content**: Extract structured data, metadata, and keywords
5. **Store Data**: Save raw data in JSON format for ML processing

### Data Structure

#### Post Data
```json
{
  "id": "unique_post_id",
  "text": "post_content",
  "author": "username",
  "created_at": "2024-01-01T00:00:00",
  "source_type": "twitter|reddit|web_content",
  "url": "post_url",
  "urls": ["extracted_urls"],
  "raw_data": {...}
}
```

#### Web Content Data
```json
{
  "id": "web_12345",
  "title": "Article Title",
  "content": "Full article content...",
  "author": "Author Name",
  "published_date": "2025-10-06",
  "keywords": ["cybersecurity", "threat", "intelligence"],
  "source_type": "web_content",
  "domain": "example.com",
  "metadata": {...}
}
```

#### Linked Content
```json
{
  "url": "linked_url",
  "title": "page_title",
  "content": "page_content",
  "timestamp": "2024-01-01T00:00:00",
  "source_type": "linked_content"
}
```

## Extending the System

### Adding New Platforms

1. Create a new scraper class inheriting from `BaseScraper`
2. Implement required methods: `scrape_posts()`, `extract_links()`
3. Add the scraper to the main orchestrator

Example:
```python
class LinkedInScraper(BaseScraper):
    def scrape_posts(self, source, max_posts=None):
        # Implementation here
        pass
    
    def extract_links(self, post):
        # Implementation here
        pass
```

## Data Storage

- **Local Storage**: Data saved to `data/raw/` directory
- **S3 Ready**: Configuration for future S3 deployment
- **JSON Format**: Structured data for easy ML processing

## Error Handling

- Comprehensive logging for debugging
- Graceful handling of API rate limits
- Robust error recovery for link following

## Recent Updates

### October 6, 2025 - Major Enhancement
- ✅ **Added Universal Web Scraper**: Can now extract content from any website, blog, or news article
- ✅ **Integrated Firecrawl API**: Professional web scraping service for complex websites
- ✅ **Enhanced Content Parsing**: Extracts metadata, keywords, and structured content
- ✅ **System Cleanup**: Removed redundant files and streamlined codebase
- ✅ **Real-world Testing**: Successfully tested with OSINT threat intelligence content

## Future Enhancements

- Additional social media platforms (LinkedIn, Mastodon, etc.)
- Real-time streaming data collection
- Advanced content extraction (images, videos)
- Integration with threat intelligence platforms
- Automated threat classification pipeline
- Enhanced search capabilities for web content
- AI-powered content analysis and prioritization

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]