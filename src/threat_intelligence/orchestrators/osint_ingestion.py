"""
OSINT Corpus Ingestion Orchestrator.

Composes all OSINT source ingesters to build a unified threat intelligence
corpus. Also normalizes existing NVD reference content into the same schema.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..core.config import Config
from ..ingesters.exploitdb_ingester import ExploitDBIngester
from ..ingesters.mitre_attack_ingester import MITREAttackIngester
from ..ingesters.otx_ingester import OTXIngester
from ..ingesters.phishtank_ingester import PhishTankIngester
from ..ingesters.ransomwatch_ingester import RansomwatchIngester
from ..storage.corpus_storage import CorpusStorage
from ..storage.data_storage import DataStorage

logger = logging.getLogger(__name__)

AVAILABLE_SOURCES = [
    "phishtank",
    "ransomwatch",
    "mitre_attack",
    "otx",
    "exploitdb",
    "nvd_refs",
]



class OSINTIngestionOrchestrator:
    """
    Orchestrates OSINT corpus ingestion from multiple sources.
    Composes ingesters and normalizes NVD reference content into unified documents.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.config.validate()
        self.corpus_storage = CorpusStorage(self.config)
        self.data_storage = DataStorage(self.config)
        self.phishtank = PhishTankIngester(self.config)
        self.ransomwatch = RansomwatchIngester(self.config)
        self.mitre_attack = MITREAttackIngester(self.config)
        self.otx = OTXIngester(self.config)
        self.exploitdb = ExploitDBIngester(self.config)
        logger.info("OSINT Ingestion Orchestrator initialized")

    def run_all(
        self,
        max_per_source: int = 200,
        save_local: bool = True,
        sources: Optional[List[str]] = None,
        upload_to_s3: bool = True,
    ) -> Dict[str, Any]:
        """
        Run ingestion for all or specified sources.

        Args:
            max_per_source: Maximum records per source.
            save_local: Whether to save locally.
            sources: List of source keys to run; if None, run all.
            upload_to_s3: Whether to upload to S3 (False for local-only).

        Returns:
            Results dict with per-source status and totals.
        """
        to_run = sources if sources is not None else AVAILABLE_SOURCES
        results: Dict[str, Any] = {}
        total_documents = 0
        sources_succeeded = 0
        sources_failed = 0

        for source in to_run:
            if source not in AVAILABLE_SOURCES:
                logger.warning("Unknown source %s, skipping", source)
                continue

            try:
                if source == "nvd_refs":
                    docs = self._collect_nvd_refs(max_records=max_per_source)
                else:
                    ingester = getattr(self, source, None)
                    if ingester is None:
                        raise ValueError(f"No ingester for source: {source}")
                    max_records = min(100, max_per_source) if source == "otx" else max_per_source
                    docs = ingester.ingest(max_records=max_records)

                if not docs:
                    results[source] = {"success": True, "count": 0, "s3_key": None}
                    sources_succeeded += 1
                    continue

                s3_key = self.corpus_storage.save_corpus_batch(
                    documents=docs,
                    source=source,
                    save_local=save_local,
                    upload_to_s3=upload_to_s3,
                )
                count = len(docs)
                total_documents += count
                sources_succeeded += 1
                results[source] = {"success": True, "count": count, "s3_key": s3_key}

            except Exception as e:
                logger.exception("Source %s failed: %s", source, e)
                results[source] = {"success": False, "count": 0, "s3_key": None, "error": str(e)}
                sources_failed += 1

        results["total_documents"] = total_documents
        results["sources_succeeded"] = sources_succeeded
        results["sources_failed"] = sources_failed
        return results

    def _collect_nvd_refs(self, max_records: int = 200) -> List[Dict[str, Any]]:
        """
        Collect NVD reference documents from S3 into unified corpus schema.
        """
        prefix = "enriched/cve/ref_links/"
        objects = self.data_storage.list_s3_objects(prefix)
        meta_keys = [o["Key"] for o in objects if "/meta/" in o["Key"] and o["Key"].endswith(".json")]
        meta_keys.sort()

        docs: List[Dict[str, Any]] = []
        for meta_key in meta_keys:
            if len(docs) >= max_records:
                break

            meta = self.data_storage.load_json_from_s3(meta_key)
            if not meta:
                continue

            clean_key = meta_key.replace("/meta/", "/clean/").replace(".json", ".txt")
            content = self._load_text_from_s3(clean_key)
            if not content or not content.strip():
                continue

            cve_id = meta.get("cve_id", "unknown")
            filename = meta_key.split("/")[-1]
            url_hash = filename.split("_")[-1].replace(".json", "") if "_" in filename else "unknown"
            extracted_title = meta.get("extracted_title")
            title = extracted_title if extracted_title else f"NVD Reference: {cve_id}"
            original_url = meta.get("original_url", "")
            fetch_ts = meta.get("fetch_timestamp", "")
            ref_type = meta.get("ref_type", "")
            quality = meta.get("quality", {})
            language = meta.get("language", "")

            doc = {
                "id": f"nvd_ref_{cve_id}_{url_hash}",
                "title": title,
                "content": content.strip(),
                "url": original_url,
                "source": "nvd_ref",
                "source_category_hint": "vulnerability",
                "published_at": fetch_ts,
                "metadata": {
                    "cve_id": cve_id,
                    "ref_type": ref_type,
                    "quality": quality,
                    "language": language,
                },
            }
            docs.append(doc)

        logger.info("NVD refs: collected %d documents (max=%d)", len(docs), max_records)
        return docs

    def _load_text_from_s3(self, key: str) -> Optional[str]:
        if not self.data_storage.s3_client:
            return None
        try:
            response = self.data_storage.s3_client.get_object(
                Bucket=self.config.S3_BUCKET_NAME,
                Key=key,
            )
            return response["Body"].read().decode("utf-8")
        except Exception as e:
            logger.debug("Failed to load text from %s: %s", key, e)
            return None
