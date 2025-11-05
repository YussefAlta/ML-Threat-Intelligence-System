"""
Data storage utilities for threat intelligence data.
"""
import os
import json
import boto3
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class DataStorage:
    """Handles data storage for both local and S3 storage."""
    
    def __init__(self, config):
        self.config = config
        self.s3_client = None
        self._initialize_s3()
    
    def _initialize_s3(self):
        """Initialize S3 client if credentials are available."""
        if (self.config.AWS_ACCESS_KEY_ID and 
            self.config.AWS_SECRET_ACCESS_KEY and 
            self.config.S3_BUCKET_NAME):
            try:
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=self.config.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=self.config.AWS_SECRET_ACCESS_KEY,
                    region_name=self.config.AWS_REGION
                )
                logger.info("S3 client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {str(e)}")
                self.s3_client = None
        else:
            logger.info("S3 credentials not configured, using local storage only")
    
    def save_posts(self, posts: List[Dict], source: str, data_type: str = "posts") -> str:
        """Save posts data to storage."""
        # Create local data directory
        os.makedirs(self.config.RAW_DATA_DIR, exist_ok=True)
        
        # Sanitize source name for filename
        import re
        safe_source = re.sub(r'[^\w\-_\.]', '_', source)
        safe_source = safe_source[:50]  # Limit length
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_source}_{data_type}_{timestamp}.json"
        local_filepath = os.path.join(self.config.RAW_DATA_DIR, filename)
        
        # Save locally
        with open(local_filepath, 'w', encoding='utf-8') as f:
            json.dump(posts, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved {len(posts)} {data_type} locally to {local_filepath}")
        
        # Save to S3 if available
        if self.s3_client:
            try:
                s3_key = f"raw_data/{source}/{filename}"
                self.s3_client.upload_file(
                    local_filepath,
                    self.config.S3_BUCKET_NAME,
                    s3_key
                )
                logger.info(f"Uploaded {filename} to S3: s3://{self.config.S3_BUCKET_NAME}/{s3_key}")
            except Exception as e:
                logger.error(f"Failed to upload to S3: {str(e)}")
        
        return local_filepath
    
    def save_linked_content(self, linked_content: List[Dict], source: str) -> str:
        """Save linked content data to storage."""
        return self.save_posts(linked_content, source, "linked_content")
    
    def save_posts_to_s3_direct(self, posts: List[Dict], source: str, data_type: str = "posts", save_local: bool = False) -> Optional[str]:
        """
        Save posts directly to S3 without requiring local file creation first.
        
        Args:
            posts: List of post dictionaries to save
            source: Source identifier for the data
            data_type: Type of data (e.g., "posts", "linked_content", "raw_metadata")
            save_local: Whether to also save locally (default: False)
        
        Returns:
            S3 key path if successful, None otherwise
        """
        if not self.s3_client:
            logger.warning("S3 client not available, cannot save directly to S3")
            if save_local:
                return self.save_posts(posts, source, data_type)
            return None
        
        try:
            # Sanitize source name for filename
            import re
            safe_source = re.sub(r'[^\w\-_\.]', '_', source)
            safe_source = safe_source[:50]  # Limit length
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{safe_source}_{data_type}_{timestamp}.json"
            
            # Convert posts to JSON string
            json_data = json.dumps(posts, indent=2, ensure_ascii=False)
            
            # Upload directly to S3 - save directly under raw_data/ (no subfolders)
            s3_key = f"raw_data/{filename}"
            self.s3_client.put_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
                Body=json_data.encode('utf-8'),
                ContentType='application/json'
            )
            
            logger.info(f"Uploaded {len(posts)} {data_type} directly to S3: s3://{self.config.S3_BUCKET_NAME}/{s3_key}")
            
            # Optionally save locally as well
            if save_local:
                os.makedirs(self.config.RAW_DATA_DIR, exist_ok=True)
                local_filepath = os.path.join(self.config.RAW_DATA_DIR, filename)
                with open(local_filepath, 'w', encoding='utf-8') as f:
                    f.write(json_data)
                logger.info(f"Also saved locally to {local_filepath}")
            
            return s3_key
            
        except Exception as e:
            logger.error(f"Failed to upload directly to S3: {str(e)}")
            # Fallback to local save if S3 fails
            if save_local:
                logger.info("Falling back to local storage")
                return self.save_posts(posts, source, data_type)
            return None
    
    def load_posts(self, filepath: str) -> List[Dict]:
        """Load posts from a JSON file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                posts = json.load(f)
            logger.info(f"Loaded {len(posts)} posts from {filepath}")
            return posts
        except Exception as e:
            logger.error(f"Error loading posts from {filepath}: {str(e)}")
            return []
    
    def list_data_files(self, source: str = None) -> List[str]:
        """List all data files in the raw data directory."""
        if not os.path.exists(self.config.RAW_DATA_DIR):
            return []
        
        files = []
        for filename in os.listdir(self.config.RAW_DATA_DIR):
            if filename.endswith('.json'):
                if source is None or filename.startswith(source):
                    files.append(os.path.join(self.config.RAW_DATA_DIR, filename))
        
        return sorted(files)
    
    def get_data_summary(self) -> Dict:
        """Get a summary of stored data."""
        files = self.list_data_files()
        
        summary = {
            'total_files': len(files),
            'total_posts': 0,
            'sources': {},
            'data_types': {}
        }
        
        for filepath in files:
            try:
                posts = self.load_posts(filepath)
                filename = os.path.basename(filepath)
                
                # Parse filename to extract source and data type
                parts = filename.replace('.json', '').split('_')
                if len(parts) >= 3:
                    source = parts[0]
                    data_type = parts[1]
                    
                    summary['total_posts'] += len(posts)
                    
                    if source not in summary['sources']:
                        summary['sources'][source] = 0
                    summary['sources'][source] += len(posts)
                    
                    if data_type not in summary['data_types']:
                        summary['data_types'][data_type] = 0
                    summary['data_types'][data_type] += len(posts)
                    
            except Exception as e:
                logger.error(f"Error processing file {filepath}: {str(e)}")
        
        return summary
