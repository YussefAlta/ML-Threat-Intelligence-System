"""
NLP Enrichment Orchestrator.

Loads corpus documents, runs NLP enrichment (labeling, entity extraction,
normalization, relation extraction, risk scoring), evaluates against the
gold set, and stores results to S3 and local filesystem.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..core.config import Config
from ..nlp.nlp_enricher import NLPEnricher, deduplicate_corpus
from ..nlp.evaluation import evaluate_labels, generate_report, load_gold_set
from ..storage.corpus_storage import CorpusStorage

logger = logging.getLogger(__name__)


class NLPEnrichmentOrchestrator:
    """
    Orchestrates the full NLP enrichment pipeline:
    1. Load corpus (from local JSONL or S3)
    2. Deduplicate
    3. Run NLP enrichment (labeling, entities, relations, risk)
    4. Save enriched output to S3 and local
    5. Evaluate against gold set
    """

    def __init__(self, config: Optional[Config] = None, use_securebert: bool = True):
        self.config = config or Config()
        self.config.validate()
        self.corpus_storage = CorpusStorage(self.config)
        self.enricher = NLPEnricher(config=self.config, use_securebert=use_securebert)
        logger.info("NLP Enrichment Orchestrator initialized")

    def run(
        self,
        corpus_path: Optional[str] = None,
        gold_path: Optional[str] = None,
        output_path: Optional[str] = None,
        report_path: Optional[str] = None,
        upload_to_s3: bool = True,
        save_local: bool = True,
    ) -> Dict[str, Any]:
        """
        Run the full NLP enrichment pipeline.

        Args:
            corpus_path: Local JSONL corpus path. If None, loads from S3.
            gold_path: Path to gold set JSONL. Defaults to data/gold/gold_100.jsonl.
            output_path: Local path for enriched output JSONL.
            report_path: Local path for evaluation report text.
            upload_to_s3: Whether to upload enriched output to S3.
            save_local: Whether to save enriched output locally.

        Returns:
            Dict with keys: success, corpus_size, enriched_count, dedup_removed,
            evaluation, s3_key, output_path, report_path
        """
        results: Dict[str, Any] = {
            "started_at": datetime.now().isoformat(),
            "success": False,
            "corpus_size": 0,
            "dedup_removed": 0,
            "enriched_count": 0,
            "evaluation": None,
            "s3_key": None,
            "output_path": None,
            "report_path": None,
        }

        # 1. Load corpus
        try:
            if corpus_path and os.path.isfile(corpus_path):
                documents = self._load_local_corpus(corpus_path)
                logger.info("Loaded %d corpus documents from %s", len(documents), corpus_path)
            else:
                documents = self.corpus_storage.load_all_corpus()
                logger.info("Loaded %d corpus documents from S3", len(documents))

            if not documents:
                logger.error("No corpus documents loaded")
                results["error"] = "No corpus documents found"
                return results

            results["corpus_size"] = len(documents)
        except Exception as e:
            logger.error("Failed to load corpus: %s", e)
            results["error"] = str(e)
            return results

        # 2. Deduplicate
        unique_docs = deduplicate_corpus(documents)
        results["dedup_removed"] = len(documents) - len(unique_docs)
        if results["dedup_removed"] > 0:
            logger.info(
                "Deduplication: %d -> %d docs (%d removed)",
                len(documents), len(unique_docs), results["dedup_removed"],
            )

        # 3. Run NLP enrichment
        try:
            enriched = self.enricher.enrich_corpus(unique_docs)
            results["enriched_count"] = len(enriched)
            logger.info("Enriched %d documents", len(enriched))
        except Exception as e:
            logger.error("NLP enrichment failed: %s", e)
            results["error"] = str(e)
            return results

        # 4. Save enriched output locally
        if save_local:
            if output_path is None:
                os.makedirs(os.path.join(self.config.DATA_DIR, "processed"), exist_ok=True)
                output_path = os.path.join(
                    self.config.DATA_DIR, "processed",
                    f"nlp_enriched_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl",
                )
            try:
                self.enricher.save_enriched(enriched, output_path)
                results["output_path"] = output_path
                logger.info("Saved enriched output to %s", output_path)
            except Exception as e:
                logger.error("Failed to save enriched locally: %s", e)

        # 5. Save enriched output to S3
        if upload_to_s3:
            try:
                s3_key = self.enricher.save_enriched_to_s3(enriched, self.corpus_storage)
                results["s3_key"] = s3_key
            except Exception as e:
                logger.error("Failed to save enriched to S3: %s", e)

        # 6. Evaluate against gold set
        if gold_path is None:
            gold_path = os.path.join(self.config.DATA_DIR, "gold", "gold_100.jsonl")

        if os.path.isfile(gold_path):
            try:
                if report_path is None:
                    os.makedirs(os.path.join(self.config.DATA_DIR, "processed"), exist_ok=True)
                    report_path = os.path.join(
                        self.config.DATA_DIR, "processed",
                        f"eval_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    )

                gold_set = load_gold_set(gold_path)
                eval_results = evaluate_labels(enriched, gold_set)
                report = generate_report(eval_results, output_path=report_path)

                results["evaluation"] = eval_results
                results["report_path"] = report_path

                macro_f1 = eval_results.get("macro_avg", {}).get("f1", 0)
                logger.info(
                    "Evaluation macro F1: %.2f (%s)",
                    macro_f1, "PASS" if macro_f1 >= 0.70 else "FAIL",
                )
                logger.info("Evaluation report:\n%s", report)
            except Exception as e:
                logger.error("Evaluation failed: %s", e)
                results["evaluation_error"] = str(e)
        else:
            logger.warning("Gold set not found at %s, skipping evaluation", gold_path)

        results["success"] = True
        results["completed_at"] = datetime.now().isoformat()
        return results

    def _load_local_corpus(self, path: str) -> List[Dict]:
        """Load corpus from a local JSONL file."""
        documents: List[Dict] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    documents.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return documents
