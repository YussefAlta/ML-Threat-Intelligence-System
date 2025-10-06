# Setup Guide

## Quick Start

1. **Install Dependencies**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure API Credentials**
   Create a `.env` file in the project root with your API credentials:
   ```bash
   cp .env.template .env
   # Edit .env with your actual credentials
   ```

3. **Test the Installation**
   ```bash
   python test_scraper.py
   python demo.py
   ```

## API Credentials Setup

### Twitter/X (No API Required)
Twitter scraping uses snscrape - no API credentials needed! The scraper will work out of the box.

### Reddit API
1. Go to [Reddit App Preferences](https://www.reddit.com/prefs/apps)
2. Create a new app (script type)
3. Note the client ID and secret
4. Add to `.env` file:
   ```
   REDDIT_CLIENT_ID=your_client_id_here
   REDDIT_CLIENT_SECRET=your_client_secret_here
   REDDIT_USER_AGENT=ThreatIntelligenceBot/1.0
   ```

## Usage Examples

### Command Line
```bash
# Scrape Twitter
python main.py --platform twitter --source briankrebs --max-posts 50

# Scrape Reddit
python main.py --platform reddit --source r/cybersecurity --max-posts 100

# View data summary
python main.py --summary
```

### Programmatic Usage
```python
from config import Config
from scrapers import TwitterScraper, RedditScraper
from data_storage import DataStorage

config = Config()
twitter_scraper = TwitterScraper(config)
storage = DataStorage(config)

# Scrape and save data
posts = twitter_scraper.scrape_posts("briankrebs", max_posts=10)
storage.save_posts(posts, "twitter_briankrebs", "posts")
```

## Data Storage

- **Local Storage**: Data saved to `data/raw/` directory
- **S3 Ready**: Configure AWS credentials for cloud storage
- **Format**: JSON files with structured data for ML processing

## Troubleshooting

### Common Issues

1. **API Rate Limits**: The scrapers include built-in rate limiting
2. **Missing Credentials**: Check your `.env` file configuration
3. **Network Issues**: Ensure stable internet connection for link following

### Getting Help

- Check the logs for detailed error messages
- Run `python test_scraper.py` to verify installation
- Use `python demo.py` to see the system in action
