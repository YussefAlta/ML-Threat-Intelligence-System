"""
S3 storage utilities for reference content.

Stores raw fetched content, cleaned text, and metadata for CVE reference URLs.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Dict, Optional

from ..core.config import Config

logger = logging.getLogger(__name__)

# Content type → extension map
CONTENT_TYPE_EXT = {
    "text/html": ".html",
    "application/pdf": ".pdf",
    "application/json": ".json",
    "text/plain": ".txt",
    "text/xml": ".xml",
    "application/xml": ".xml",
}

DEFAULT_EXT = ".bin"


class ReferenceStorage:
    """
    Handles S3 storage for enrichment reference content.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.s3_client = None
        self._initialize_s3()

    # -----------------------------------------------------
    # S3 INIT
    # -----------------------------------------------------

    def _initialize_s3(self):
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
                logger.info("ReferenceStorage S3 initialized")
            except Exception as e:
                logger.error(f"S3 init failed: {e}")
                self.s3_client = None
        else:
            logger.warning("S3 credentials not configured")

    # -----------------------------------------------------
    # KEY GENERATION
    # -----------------------------------------------------

    def generate_s3_key(
        self,
        cve_id: str,
        ref_index: int,
        url_hash: str,
        content_type: str,
        fetch_date: datetime,
        folder: str,
        root_prefix: str = "enrichments/nvd_references",
    ) -> str:
        """
        Generate consistent S3 key.
        """

        year = fetch_date.strftime("%Y")
        month = fetch_date.strftime("%m")
        day = fetch_date.strftime("%d")
        ref_str = f"{ref_index:03d}"

        if folder == "raw":
            ext = self._get_extension(content_type)
            return (
                f"{root_prefix}/raw/"
                f"{cve_id}/{year}/{month}/{day}/"
                f"{ref_str}_{url_hash}{ext}"
            )

        if folder == "clean":
            return (
                f"{root_prefix}/clean/"
                f"{cve_id}/{year}/{month}/{day}/"
                f"{ref_str}_{url_hash}.txt"
            )

        if folder == "meta":
            return (
                f"{root_prefix}/meta/"
                f"{cve_id}/{year}/{month}/{day}/"
                f"{ref_str}_{url_hash}.json"
            )

        raise ValueError(f"Unknown folder: {folder}")

    def _get_extension(self, content_type: str) -> str:
        if not content_type:
            return DEFAULT_EXT
        base = content_type.split(";")[0].strip().lower()
        return CONTENT_TYPE_EXT.get(base, DEFAULT_EXT)

    # -----------------------------------------------------
    # SAVE METHODS
    # -----------------------------------------------------

    def save_reference_raw(
        self, content: bytes, s3_key: str, content_type: str
    ) -> bool:

        if not self.s3_client:
            logger.warning("No S3 client (raw)")
            return False

        try:
            self.s3_client.put_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
                Body=content,
                ContentType=content_type,
            )
            logger.info(f"Saved raw: {s3_key}")
            return True
        except Exception as e:
            logger.error(f"Raw save failed: {e}")
            return False

    def save_reference_clean(self, text: str, s3_key: str) -> bool:

        if not self.s3_client:
            logger.warning("No S3 client (clean)")
            return False

        try:
            self.s3_client.put_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
                Body=text.encode("utf-8"),
                ContentType="text/plain; charset=utf-8",
            )
            logger.info(f"Saved clean: {s3_key}")
            return True
        except Exception as e:
            logger.error(f"Clean save failed: {e}")
            return False

    def save_reference_metadata(self, metadata: Dict, s3_key: str) -> bool:

        if not self.s3_client:
            logger.warning("No S3 client (meta)")
            return False

        try:
            body = json.dumps(metadata, indent=2).encode("utf-8")
            self.s3_client.put_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
                Body=body,
                ContentType="application/json",
            )
            logger.info(f"Saved meta: {s3_key}")
            return True
        except Exception as e:
            logger.error(f"Meta save failed: {e}")
            return False

    # -----------------------------------------------------
    # HELPERS
    # -----------------------------------------------------

    def check_exists(self, s3_key: str) -> bool:

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
