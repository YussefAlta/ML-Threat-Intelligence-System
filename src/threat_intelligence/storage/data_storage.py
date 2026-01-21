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

    # ------------------------------------------------------------------
    # S3 helpers for NIST CVE/CPE data
    # ------------------------------------------------------------------

    def list_s3_objects(self, prefix: str) -> List[Dict]:
        """
        List objects in S3 under a given prefix.

        Returns:
            List of dicts with at least 'Key' and 'LastModified'
        """
        if not self.s3_client:
            logger.warning("S3 client not available; cannot list S3 objects")
            return []

        objects: List[Dict] = []
        continuation_token = None

        try:
            while True:
                kwargs = {
                    "Bucket": self.config.S3_BUCKET_NAME,
                    "Prefix": prefix,
                    "MaxKeys": 1000,
                }
                if continuation_token:
                    kwargs["ContinuationToken"] = continuation_token

                response = self.s3_client.list_objects_v2(**kwargs)
                contents = response.get("Contents", [])
                objects.extend(contents)

                if not response.get("IsTruncated"):
                    break
                continuation_token = response.get("NextContinuationToken")

            logger.info(
                f"Listed {len(objects)} objects from S3 with prefix '{prefix}'"
            )
            return objects
        except Exception as e:
            logger.error(f"Error listing S3 objects for prefix '{prefix}': {str(e)}")
            return []

    def load_json_from_s3(self, key: str) -> Optional[Dict]:
        """
        Load a JSON object from S3.

        Args:
            key: S3 object key

        Returns:
            Parsed JSON dict or None if error
        """
        if not self.s3_client:
            logger.warning("S3 client not available; cannot load from S3")
            return None

        try:
            response = self.s3_client.get_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=key,
            )
            body = response["Body"].read().decode("utf-8")
            data = json.loads(body)
            logger.info(
                f"Loaded JSON from S3: s3://{self.config.S3_BUCKET_NAME}/{key}"
            )
            return data
        except Exception as e:
            logger.error(
                f"Error loading JSON from S3 key '{key}': {str(e)}"
            )
            return None

    def get_latest_nist_cve_s3_key(self) -> Optional[str]:
        """
        Get the latest NIST CVE object key from S3.

        Keys are expected under: nist/cve/YYYY/MM/DD/nist_cve_*.json
        """
        objects = self.list_s3_objects("nist/cve/")
        if not objects:
            logger.warning("No NIST CVE objects found in S3 under 'nist/cve/'")
            return None

        # Pick the most recently modified object
        latest_obj = max(objects, key=lambda o: o.get("LastModified"))
        key = latest_obj.get("Key")
        logger.info(
            f"Latest NIST CVE S3 object: s3://{self.config.S3_BUCKET_NAME}/{key}"
        )
        return key

    def get_latest_nist_cpe_s3_key(self) -> Optional[str]:
        """
        Get the latest NIST CPE object key from S3.

        Keys are expected under: nist/cpe/YYYY/MM/DD/nist_cpe_*.json
        """
        objects = self.list_s3_objects("nist/cpe/")
        if not objects:
            logger.warning("No NIST CPE objects found in S3 under 'nist/cpe/'")
            return None

        latest_obj = max(objects, key=lambda o: o.get("LastModified"))
        key = latest_obj.get("Key")
        logger.info(
            f"Latest NIST CPE S3 object: s3://{self.config.S3_BUCKET_NAME}/{key}"
        )
        return key

    # ------------------------------------------------------------------
    # Enriched data storage
    # ------------------------------------------------------------------

    def save_enriched_cve_data(
        self,
        enriched_records: List[Dict],
        enrichment_source: str,
        date_filter: Optional[str] = None,
        save_local: bool = True,
    ) -> Optional[str]:
        """
        Save enriched CVE data to S3 with clear organization.

        Args:
            enriched_records: List of enrichment dicts (one per CVE)
            enrichment_source: Source of enrichment (e.g., "cwe", "vulncheck")
            date_filter: Optional date (YYYY-MM-DD) for organization
            save_local: Whether to also save locally

        Returns:
            S3 key path if successful, None otherwise
        """
        if not enriched_records:
            logger.warning("No enriched CVE records to save")
            return None

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"enriched_cve_{enrichment_source}_{timestamp}.json"

            data = {
                "source": enrichment_source,
                "data_type": "cve_enrichment",
                "record_count": len(enriched_records),
                "ingested_at": datetime.now().isoformat(),
                "date_filter": date_filter,
                "enriched_records": enriched_records,
            }

            json_data = json.dumps(data, indent=2, ensure_ascii=False)

            # S3 key structure: enriched/cve/<source>/YYYY/MM/DD/filename
            if date_filter:
                date_parts = date_filter.split("-")
                if len(date_parts) == 3:
                    year, month, day = date_parts
                    s3_key = f"enriched/cve/{enrichment_source}/{year}/{month}/{day}/{filename}"
                else:
                    s3_key = f"enriched/cve/{enrichment_source}/{filename}"
            else:
                year = datetime.now().strftime("%Y")
                month = datetime.now().strftime("%m")
                day = datetime.now().strftime("%d")
                s3_key = f"enriched/cve/{enrichment_source}/{year}/{month}/{day}/{filename}"

            if self.s3_client:
                try:
                    self.s3_client.put_object(
                        Bucket=self.config.S3_BUCKET_NAME,
                        Key=s3_key,
                        Body=json_data.encode("utf-8"),
                        ContentType="application/json",
                        Metadata={
                            "record_count": str(len(enriched_records)),
                            "data_type": "cve_enrichment",
                            "source": enrichment_source,
                        },
                    )
                    logger.info(
                        f"Uploaded {len(enriched_records)} enriched CVE records "
                        f"to S3: s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to upload enriched CVE data to S3 ({enrichment_source}): {str(e)}"
                    )
                    return None

            if save_local:
                os.makedirs(self.config.RAW_DATA_DIR, exist_ok=True)
                local_filepath = os.path.join(self.config.RAW_DATA_DIR, filename)
                with open(local_filepath, "w", encoding="utf-8") as f:
                    f.write(json_data)
                logger.info(f"Also saved enriched CVE data locally to {local_filepath}")

            return s3_key if self.s3_client else None

        except Exception as e:
            logger.error(f"Error saving enriched CVE data ({enrichment_source}): {str(e)}")
            return None
    
    def save_cve_data(self, cve_records: List[Dict], date_filter: Optional[str] = None, save_local: bool = True) -> Optional[str]:
        """
        Save CVE data to S3 with proper organization.
        
        Args:
            cve_records: List of CVE vulnerability records
            date_filter: Optional date filter string (YYYY-MM-DD) for organizing by date
            save_local: Whether to also save locally
            
        Returns:
            S3 key path if successful, None otherwise
        """
        if not cve_records:
            logger.warning("No CVE records to save")
            return None
        
        try:
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nist_cve_{timestamp}.json"
            
            # Prepare data with metadata
            data = {
                'source': 'nist_nvd',
                'data_type': 'cve',
                'record_count': len(cve_records),
                'ingested_at': datetime.now().isoformat(),
                'date_filter': date_filter,
                'vulnerabilities': cve_records
            }
            
            # Convert to JSON
            json_data = json.dumps(data, indent=2, ensure_ascii=False)
            
            # Determine S3 key with date-based organization
            if date_filter:
                # Organize by date: nist/cve/YYYY/MM/DD/filename
                date_parts = date_filter.split('-')
                if len(date_parts) == 3:
                    year, month, day = date_parts
                    s3_key = f"nist/cve/{year}/{month}/{day}/{filename}"
                else:
                    s3_key = f"nist/cve/{filename}"
            else:
                # Organize by ingestion date
                year = datetime.now().strftime("%Y")
                month = datetime.now().strftime("%m")
                day = datetime.now().strftime("%d")
                s3_key = f"nist/cve/{year}/{month}/{day}/{filename}"
            
            # Save to S3 if available
            if self.s3_client:
                try:
                    self.s3_client.put_object(
                        Bucket=self.config.S3_BUCKET_NAME,
                        Key=s3_key,
                        Body=json_data.encode('utf-8'),
                        ContentType='application/json',
                        Metadata={
                            'record_count': str(len(cve_records)),
                            'data_type': 'cve',
                            'source': 'nist_nvd'
                        }
                    )
                    logger.info(
                        f"Uploaded {len(cve_records)} CVE records to S3: "
                        f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
                    )
                except Exception as e:
                    logger.error(f"Failed to upload CVE data to S3: {str(e)}")
                    return None
            
            # Optionally save locally
            if save_local:
                os.makedirs(self.config.RAW_DATA_DIR, exist_ok=True)
                local_filepath = os.path.join(self.config.RAW_DATA_DIR, filename)
                with open(local_filepath, 'w', encoding='utf-8') as f:
                    f.write(json_data)
                logger.info(f"Also saved locally to {local_filepath}")
            
            return s3_key if self.s3_client else None
            
        except Exception as e:
            logger.error(f"Error saving CVE data: {str(e)}")
            return None
    
    def save_cpe_data(self, cpe_records: List[Dict], date_filter: Optional[str] = None, save_local: bool = True) -> Optional[str]:
        """
        Save CPE data to S3 with proper organization.
        
        Args:
            cpe_records: List of CPE product records
            date_filter: Optional date filter string (YYYY-MM-DD) for organizing by date
            save_local: Whether to also save locally
            
        Returns:
            S3 key path if successful, None otherwise
        """
        if not cpe_records:
            logger.warning("No CPE records to save")
            return None
        
        try:
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nist_cpe_{timestamp}.json"
            
            # Prepare data with metadata
            data = {
                'source': 'nist_nvd',
                'data_type': 'cpe',
                'record_count': len(cpe_records),
                'ingested_at': datetime.now().isoformat(),
                'date_filter': date_filter,
                'products': cpe_records
            }
            
            # Convert to JSON
            json_data = json.dumps(data, indent=2, ensure_ascii=False)
            
            # Determine S3 key with date-based organization
            if date_filter:
                # Organize by date: nist/cpe/YYYY/MM/DD/filename
                date_parts = date_filter.split('-')
                if len(date_parts) == 3:
                    year, month, day = date_parts
                    s3_key = f"nist/cpe/{year}/{month}/{day}/{filename}"
                else:
                    s3_key = f"nist/cpe/{filename}"
            else:
                # Organize by ingestion date
                year = datetime.now().strftime("%Y")
                month = datetime.now().strftime("%m")
                day = datetime.now().strftime("%d")
                s3_key = f"nist/cpe/{year}/{month}/{day}/{filename}"
            
            # Save to S3 if available
            if self.s3_client:
                try:
                    self.s3_client.put_object(
                        Bucket=self.config.S3_BUCKET_NAME,
                        Key=s3_key,
                        Body=json_data.encode('utf-8'),
                        ContentType='application/json',
                        Metadata={
                            'record_count': str(len(cpe_records)),
                            'data_type': 'cpe',
                            'source': 'nist_nvd'
                        }
                    )
                    logger.info(
                        f"Uploaded {len(cpe_records)} CPE records to S3: "
                        f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
                    )
                except Exception as e:
                    logger.error(f"Failed to upload CPE data to S3: {str(e)}")
                    return None
            
            # Optionally save locally
            if save_local:
                os.makedirs(self.config.RAW_DATA_DIR, exist_ok=True)
                local_filepath = os.path.join(self.config.RAW_DATA_DIR, filename)
                with open(local_filepath, 'w', encoding='utf-8') as f:
                    f.write(json_data)
                logger.info(f"Also saved locally to {local_filepath}")
            
            return s3_key if self.s3_client else None
            
        except Exception as e:
            logger.error(f"Error saving CPE data: {str(e)}")
            return None