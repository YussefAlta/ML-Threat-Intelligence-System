"""
S3 storage utilities for unified OSINT corpus documents.

Stores and loads corpus documents (unified schema) as JSONL files under
osint/corpus/{YYYY}/{MM}/{DD}/, with optional local mirroring.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..core.config import Config

logger = logging.getLogger(__name__)

# Gold set path relative to DATA_DIR
GOLD_SET_FILENAME = "gold_100.jsonl"
GOLD_SET_S3_KEY_SUFFIX = "gold/gold_100.jsonl"


class CorpusStorage:
    """S3 storage utilities for unified OSINT corpus documents."""

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
                logger.debug("Corpus storage S3 client initialized")
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {str(e)}")
                self.s3_client = None
        else:
            logger.info("S3 credentials not configured for corpus storage")

    def save_corpus_batch(
        self,
        documents: List[Dict[str, Any]],
        source: str,
        save_local: bool = True,
        upload_to_s3: bool = True,
    ) -> Optional[str]:
        """
        Save a list of corpus documents (unified schema dicts) as a JSONL file to S3.

        Args:
            documents: List of corpus document dicts (unified schema).
            source: Source identifier (e.g. nvd_ref, phishtank, ransomwatch).
            save_local: If True, also save to config.OSINT_CORPUS_LOCAL_DIR.
            upload_to_s3: If True and S3 client exists, upload to S3.

        Returns:
            S3 key if successful, None on failure.
        """
        if not documents:
            logger.warning("CorpusStorage.save_corpus_batch: empty documents list, nothing to save")
            return None

        now = datetime.utcnow()
        ts = now.strftime("%Y%m%d_%H%M%S")
        s3_key = (
            f"{self.config.OSINT_CORPUS_S3_PREFIX}/"
            f"{now.year:04d}/{now.month:02d}/{now.day:02d}/"
            f"{source}_corpus_{ts}.jsonl"
        )

        lines = []
        for doc in documents:
            line = json.dumps(doc, ensure_ascii=False, indent=None)
            lines.append(line)

        body = "\n".join(lines).encode("utf-8")

        if self.s3_client and upload_to_s3:
            s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
            try:
                self.s3_client.put_object(
                    Bucket=self.config.S3_BUCKET_NAME,
                    Key=s3_key,
                    Body=body,
                    ContentType="application/x-ndjson",
                )
                logger.info(f"CorpusStorage.save_corpus_batch: S3 success, wrote {s3_uri}")
            except Exception as e:
                logger.error(f"CorpusStorage.save_corpus_batch: S3 failure, {s3_uri} - {e}")
                return None
        else:
            logger.warning(
                f"CorpusStorage.save_corpus_batch: no S3 client, skipping S3 write for {s3_key}"
            )

        # Optionally save locally
        if save_local:
            local_dir = self.config.OSINT_CORPUS_LOCAL_DIR
            date_dir = os.path.join(
                local_dir,
                f"{now.year:04d}",
                f"{now.month:02d}",
                f"{now.day:02d}",
            )
            os.makedirs(date_dir, exist_ok=True)
            local_path = os.path.join(date_dir, f"{source}_corpus_{ts}.jsonl")
            try:
                with open(local_path, "w", encoding="utf-8") as f:
                    f.write(body.decode("utf-8"))
                logger.info(f"CorpusStorage.save_corpus_batch: local success, wrote {local_path}")
            except Exception as e:
                logger.error(f"CorpusStorage.save_corpus_batch: local failure, {local_path} - {e}")

        return s3_key

    def load_corpus_batch(self, s3_key: str) -> List[Dict[str, Any]]:
        """
        Load a JSONL file from S3 given an S3 key.

        Args:
            s3_key: Full S3 key path to the JSONL file.

        Returns:
            List of corpus document dicts, or empty list on failure.
        """
        if not self.s3_client:
            logger.warning(
                "CorpusStorage.load_corpus_batch: no S3 client, cannot load from S3"
            )
            return []

        s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
        try:
            response = self.s3_client.get_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=s3_key,
            )
            content = response["Body"].read().decode("utf-8")
            documents = []
            for line in content.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                documents.append(json.loads(line))
            logger.info(f"CorpusStorage.load_corpus_batch: loaded {len(documents)} docs from {s3_uri}")
            return documents
        except Exception as e:
            logger.error(f"CorpusStorage.load_corpus_batch: failure, {s3_uri} - {e}")
            return []

    def list_corpus_files(self) -> List[Dict[str, Any]]:
        """
        List all corpus JSONL files in S3 under the corpus prefix.

        Returns:
            List of S3 object dicts (Key, LastModified, Size, etc.), or empty list on failure.
        """
        if not self.s3_client:
            logger.warning(
                "CorpusStorage.list_corpus_files: no S3 client, cannot list S3"
            )
            return []

        prefix = f"{self.config.OSINT_CORPUS_S3_PREFIX}/"
        objects: List[Dict[str, Any]] = []

        try:
            paginator = self.s3_client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.config.S3_BUCKET_NAME, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj.get("Key", "")
                    if key.endswith(".jsonl"):
                        objects.append(obj)
            logger.info(f"CorpusStorage.list_corpus_files: found {len(objects)} corpus files")
            return objects
        except Exception as e:
            logger.error(f"CorpusStorage.list_corpus_files: failure - {e}")
            return []

    def load_all_corpus(self) -> List[Dict[str, Any]]:
        """
        Load ALL corpus documents across all JSONL files in S3 under the corpus prefix.

        Returns:
            Flat list of all corpus document dicts, or empty list on failure.
        """
        objects = self.list_corpus_files()
        if not objects:
            return []

        all_documents: List[Dict[str, Any]] = []
        for obj in objects:
            key = obj.get("Key", "")
            if not key:
                continue
            docs = self.load_corpus_batch(key)
            all_documents.extend(docs)

        logger.info(f"CorpusStorage.load_all_corpus: loaded {len(all_documents)} total documents")
        return all_documents

    def save_gold_set(self, documents: List[Dict[str, Any]]) -> bool:
        """
        Save the gold evaluation set JSONL to both S3 and local at data/gold/gold_100.jsonl.

        Args:
            documents: List of gold document dicts.

        Returns:
            True if at least one save succeeded, False otherwise.
        """
        lines = []
        for doc in documents:
            line = json.dumps(doc, ensure_ascii=False, indent=None)
            lines.append(line)

        body = "\n".join(lines).encode("utf-8")

        # Local path: data/gold/gold_100.jsonl
        gold_local_dir = os.path.join(self.config.DATA_DIR, "gold")
        local_path = os.path.join(gold_local_dir, GOLD_SET_FILENAME)

        local_ok = False
        try:
            os.makedirs(gold_local_dir, exist_ok=True)
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(body.decode("utf-8"))
            logger.info(f"CorpusStorage.save_gold_set: local success, wrote {local_path}")
            local_ok = True
        except Exception as e:
            logger.error(f"CorpusStorage.save_gold_set: local failure, {local_path} - {e}")

        # S3
        s3_key = f"{self.config.OSINT_CORPUS_S3_PREFIX}/{GOLD_SET_S3_KEY_SUFFIX}"
        s3_ok = False
        if self.s3_client:
            s3_uri = f"s3://{self.config.S3_BUCKET_NAME}/{s3_key}"
            try:
                self.s3_client.put_object(
                    Bucket=self.config.S3_BUCKET_NAME,
                    Key=s3_key,
                    Body=body,
                    ContentType="application/x-ndjson",
                )
                logger.info(f"CorpusStorage.save_gold_set: S3 success, wrote {s3_uri}")
                s3_ok = True
            except Exception as e:
                logger.error(f"CorpusStorage.save_gold_set: S3 failure, {s3_uri} - {e}")
        else:
            logger.warning("CorpusStorage.save_gold_set: no S3 client, skipping S3 write")

        return local_ok or s3_ok

    def load_gold_set(self) -> Optional[List[Dict[str, Any]]]:
        """
        Load the gold set from local file first, falling back to S3.

        Returns:
            List of gold document dicts, or None on failure.
        """
        # Try local first
        local_path = os.path.join(self.config.DATA_DIR, "gold", GOLD_SET_FILENAME)
        if os.path.isfile(local_path):
            try:
                documents = []
                with open(local_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        documents.append(json.loads(line))
                logger.info(f"CorpusStorage.load_gold_set: loaded {len(documents)} docs from local {local_path}")
                return documents
            except Exception as e:
                logger.error(f"CorpusStorage.load_gold_set: local failure, {local_path} - {e}")

        # Fallback to S3
        s3_key = f"{self.config.OSINT_CORPUS_S3_PREFIX}/{GOLD_SET_S3_KEY_SUFFIX}"
        docs = self.load_corpus_batch(s3_key)
        if docs:
            logger.info(f"CorpusStorage.load_gold_set: loaded {len(docs)} docs from S3 fallback")
            return docs

        logger.warning("CorpusStorage.load_gold_set: could not load gold set from local or S3")
        return None
