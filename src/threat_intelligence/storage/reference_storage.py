"""
S3 storage utilities for NVD reference content.

Stores raw fetched content, cleaned text, and metadata for CVE reference URLs
in the enrichments/nvd_references/ prefix.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, Optional

from ..core.config import Config

logger = logging.getLogger(__name__)

# Content type to file extension mapping
CONTENT_TYPE_EXT = {
    "text/html": ".html",
    "application/pdf": ".pdf",
    "application/json": ".json",
    "text/plain": ".txt",
    "text/xml": ".xml",
    "application/xml": ".xml",
}

DEFAULT_EXT = ".bin"
ROOT_PREFIX = "enrichments/nvd_references"


class ReferenceStorage:
    """S3 storage utilities for reference content."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.s3_client = None
        self._initialize_s3()

    def _initialize_s3(self) -> None:
        """Initialize S3 client if credentials are available."""
        import boto3

        if (
            self.config.AWS_ACCESS_KEY_ID
            and self.config.AWS_SECRET_ACCESS_KEY
            and self.config.S3_BUCKET_NAME
        ):
            try:
                self.s3_client = boto3.client(
                    "s3",
                    aws_access_key_id=self.config.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=self.config.AWS_SECRET_ACCESS_KEY,
                    region_name=self.config.AWS_REGION,
                )
                logger.debug("Reference storage S3 client initialized")
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {str(e)}")
                self.s3_client = None
        else:
            logger.info("S3 credentials not configured for reference storage")

    def generate_s3_key(
        self,
        cve_id: str,
        ref_index: int,
        url_hash: str,
        content_type: str,
        fetch_date: datetime,
        folder: str,
    ) -> str:
        """
        Generate S3 key for reference content.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-12345)
            ref_index: Zero-based index of reference in NVD list
            url_hash: Short hash of normalized URL
            content_type: MIME type for extension selection
            fetch_date: Date of fetch for path organization
            folder: One of 'raw', 'clean', 'meta'

        Returns:
            S3 key path
        """
        year = fetch_date.strftime("%Y")
        month = fetch_date.strftime("%m")
        day = fetch_date.strftime("%d")
        ref_str = f"{ref_index:03d}"

        if folder == "raw":
            ext = self._get_extension_for_content_type(content_type)
            return f"{ROOT_PREFIX}/raw/{cve_id}/{year}/{month}/{day}/{ref_str}_{url_hash}{ext}"
        elif folder == "clean":
            return f"{ROOT_PREFIX}/clean/{cve_id}/{year}/{month}/{day}/{ref_str}_{url_hash}.txt"
        elif folder == "meta":
            return f"{ROOT_PREFIX}/meta/{cve_id}/{year}/{month}/{day}/{ref_str}_{url_hash}.json"
        else:
            raise ValueError(f"Unknown folder: {folder}")

    def _get_extension_for_content_type(self, content_type: str) -> str:
        """Map content type to file extension."""
        if not content_type:
            return DEFAULT_EXT
        base_type = content_type.split(";")[0].strip().lower()
        return CONTENT_TYPE_EXT.get(base_type, DEFAULT_EXT)

    def save_reference_raw(
        self, content: bytes, s3_key: str, content_type: str = "application/octet-stream"
    ) -> bool:
        """
        Save raw reference content to S3.

        Args:
            content: Raw bytes to store
            s3_key: Full S3 key path
            content_type: MIME type of content

        Returns:
            True if successful, False otherwise
        """
        if not self.s3_client:
            s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
            logger.warning(f"ReferenceStorage.save_reference_raw: failure (no S3 client), intended {s3_uri}")
            return False

        s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
        try:
            self.s3_client.put_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
                Body=content,
                ContentType=content_type,
                Metadata={"content_type": content_type[:256]},
            )
            logger.info(f"ReferenceStorage.save_reference_raw: success, wrote {s3_uri}")
            return True
        except Exception as e:
            logger.error(f"ReferenceStorage.save_reference_raw: failure, {s3_uri} - {e}")
            return False

    def save_reference_clean(self, text: str, s3_key: str) -> bool:
        """
        Save cleaned text to S3.

        Args:
            text: Cleaned plain text
            s3_key: Full S3 key path

        Returns:
            True if successful, False otherwise
        """
        if not self.s3_client:
            s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
            logger.warning(f"ReferenceStorage.save_reference_clean: failure (no S3 client), intended {s3_uri}")
            return False

        s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
        try:
            self.s3_client.put_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
                Body=text.encode("utf-8"),
                ContentType="text/plain; charset=utf-8",
            )
            logger.info(f"ReferenceStorage.save_reference_clean: success, wrote {s3_uri}")
            return True
        except Exception as e:
            logger.error(f"ReferenceStorage.save_reference_clean: failure, {s3_uri} - {e}")
            return False

    def save_reference_metadata(self, metadata: Dict, s3_key: str) -> bool:
        """
        Save metadata JSON to S3.

        Args:
            metadata: Metadata dictionary (JSON-serializable)
            s3_key: Full S3 key path

        Returns:
            True if successful, False otherwise
        """
        if not self.s3_client:
            s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
            logger.warning(f"ReferenceStorage.save_reference_metadata: failure (no S3 client), intended {s3_uri}")
            return False

        s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
        try:
            json_data = json.dumps(metadata, indent=2, ensure_ascii=False)
            self.s3_client.put_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
                Body=json_data.encode("utf-8"),
                ContentType="application/json",
            )
            logger.info(f"ReferenceStorage.save_reference_metadata: success, wrote {s3_uri}")
            return True
        except Exception as e:
            logger.error(f"ReferenceStorage.save_reference_metadata: failure, {s3_uri} - {e}")
            return False

    def check_exists(self, s3_key: str) -> bool:
        """
        Check if an S3 object exists.

        Args:
            s3_key: Full S3 key path

        Returns:
            True if object exists, False otherwise
        """
        if not self.s3_client:
            return False

        try:
            self.s3_client.head_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
            )
            return True
        except Exception:
            return False

    def get_object_last_modified(self, s3_key: str) -> Optional[datetime]:
        """
        Get the LastModified timestamp of an S3 object if it exists.

        Args:
            s3_key: Full S3 key path

        Returns:
            LastModified datetime or None if object doesn't exist
        """
        if not self.s3_client:
            return None

        try:
            response = self.s3_client.head_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
            )
            return response.get("LastModified")
        except Exception:
            return None
