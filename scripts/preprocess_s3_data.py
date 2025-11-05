#!/usr/bin/env python3
"""
Preprocessing script to convert raw HTML to readable content.
Reads from S3, processes the data, and saves back to S3.

This script preserves ALL original data while adding processed versions.
"""
import sys
import os
import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.threat_intelligence.core.config import Config
from src.threat_intelligence.storage.data_storage import DataStorage
from src.threat_intelligence.utils.preprocessor import HTMLPreprocessor
from typing import List, Optional, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def list_raw_data_files(storage: DataStorage, limit: int = 100) -> List[str]:
    """
    List all raw data files in S3.
    
    Args:
        storage: DataStorage instance
        limit: Maximum number of files to return
        
    Returns:
        List of S3 keys
    """
    if not storage.s3_client:
        logger.error("S3 client not available")
        return []
    
    try:
        response = storage.s3_client.list_objects_v2(
            Bucket=storage.config.S3_BUCKET_NAME,
            Prefix='raw_data/',
            MaxKeys=limit
        )
        
        if 'Contents' in response:
            # Filter for JSON files only
            files = [obj['Key'] for obj in response['Contents'] 
                    if obj['Key'].endswith('.json')]
            return files
        return []
    except Exception as e:
        logger.error(f"Error listing S3 files: {str(e)}")
        return []


def load_post_from_s3(storage: DataStorage, s3_key: str) -> Optional[List[Dict]]:
    """
    Load a post file from S3.
    
    Args:
        storage: DataStorage instance
        s3_key: S3 key path
        
    Returns:
        List of post dictionaries or None
    """
    if not storage.s3_client:
        return None
    
    try:
        response = storage.s3_client.get_object(
            Bucket=storage.config.S3_BUCKET_NAME,
            Key=s3_key
        )
        data = json.loads(response['Body'].read())
        return data if isinstance(data, list) else [data]
    except Exception as e:
        logger.error(f"Error loading {s3_key} from S3: {str(e)}")
        return None


def save_processed_to_s3(storage: DataStorage, posts: List[Dict], original_key: str) -> Optional[str]:
    """
    Save processed posts to S3.
    
    Args:
        storage: DataStorage instance
        posts: List of processed post dictionaries
        original_key: Original S3 key (for reference)
        
    Returns:
        S3 key of saved file or None
    """
    if not storage.s3_client:
        return None
    
    try:
        # Generate filename for processed data
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"processed_{timestamp}.json"
        s3_key = f"processed_data/{filename}"
        
        # Convert to JSON
        json_data = json.dumps(posts, indent=2, ensure_ascii=False)
        
        # Upload to S3
        storage.s3_client.put_object(
            Bucket=storage.config.S3_BUCKET_NAME,
            Key=s3_key,
            Body=json_data.encode('utf-8'),
            ContentType='application/json',
            Metadata={
                'original_key': original_key,
                'processed_at': datetime.now().isoformat(),
                'post_count': str(len(posts))
            }
        )
        
        logger.info(f"Saved processed data to S3: s3://{storage.config.S3_BUCKET_NAME}/{s3_key}")
        return s3_key
        
    except Exception as e:
        logger.error(f"Error saving processed data to S3: {str(e)}")
        return None


def preprocess_file(storage: DataStorage, preprocessor: HTMLPreprocessor, s3_key: str) -> bool:
    """
    Preprocess a single file from S3.
    
    Args:
        storage: DataStorage instance
        preprocessor: HTMLPreprocessor instance
        s3_key: S3 key of file to process
        
    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Processing file: {s3_key}")
    
    # Load data from S3
    posts = load_post_from_s3(storage, s3_key)
    if not posts:
        logger.warning(f"No data found in {s3_key}")
        return False
    
    logger.info(f"Loaded {len(posts)} post(s) from {s3_key}")
    
    # Preprocess posts
    processed_posts = preprocessor.preprocess_batch(posts)
    
    # Save processed data back to S3
    processed_key = save_processed_to_s3(storage, processed_posts, s3_key)
    
    if processed_key:
        logger.info(f"Successfully processed {len(processed_posts)} post(s)")
        return True
    else:
        logger.error(f"Failed to save processed data for {s3_key}")
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Preprocess raw HTML data from S3')
    parser.add_argument('--file', type=str, help='Specific S3 key to process')
    parser.add_argument('--all', action='store_true', help='Process all raw data files')
    parser.add_argument('--limit', type=int, default=10, help='Maximum number of files to process (default: 10)')
    parser.add_argument('--dry-run', action='store_true', help='List files without processing')
    
    args = parser.parse_args()
    
    # Load configuration
    config = Config()
    storage = DataStorage(config)
    preprocessor = HTMLPreprocessor()
    
    if not storage.s3_client:
        logger.error("S3 client not available. Check your AWS credentials.")
        return 1
    
    if args.file:
        # Process specific file
        success = preprocess_file(storage, preprocessor, args.file)
        return 0 if success else 1
    
    elif args.all or args.dry_run:
        # List and process files
        files = list_raw_data_files(storage, limit=args.limit)
        
        if not files:
            logger.info("No raw data files found in S3")
            return 0
        
        logger.info(f"Found {len(files)} raw data file(s)")
        
        if args.dry_run:
            print("\nFiles that would be processed:")
            for f in files:
                print(f"  - {f}")
            return 0
        
        # Process each file
        success_count = 0
        for s3_key in files:
            if preprocess_file(storage, preprocessor, s3_key):
                success_count += 1
        
        logger.info(f"\n=== Processing Complete ===")
        logger.info(f"Processed: {success_count}/{len(files)} files")
        return 0 if success_count == len(files) else 1
    
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    exit(main())

