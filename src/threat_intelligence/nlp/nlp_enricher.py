"""
NLP enrichment pipeline for threat intelligence documents.

Orchestrates the full NLP processing flow: weak supervision labeling,
entity extraction (rule-based + SecureBERT NER), risk scoring, and
output generation. Produces nlp_enriched JSON for each document.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class NLPEnricher:
    """
    Orchestrates classification, entity extraction, and risk scoring
    to produce enriched JSON output per document.
    """

    def __init__(self, config: Optional[Any] = None, use_securebert: bool = True) -> None:
        self._config = config
        self._use_securebert = use_securebert
        self._securebert_available = False
        self._securebert_extractor: Any = None
        self._majority_vote = None
        self._entity_extractor = None
        self._risk_scorer = None
        self._merge_entities = None
        self._init_components()

    def _init_components(self) -> None:
        from .labeling_functions import majority_vote
        from .entity_extractor import RuleBasedEntityExtractor
        from .risk_scorer import RiskScorer

        self._majority_vote = majority_vote
        self._entity_extractor = RuleBasedEntityExtractor()
        self._risk_scorer = RiskScorer()

        if self._use_securebert:
            try:
                from .securebert_ner import SecureBERTNERExtractor, merge_entities
                if SecureBERTNERExtractor.is_available():
                    self._securebert_extractor = SecureBERTNERExtractor(config=self._config)
                    self._merge_entities = merge_entities
                    self._securebert_available = True
            except Exception as e:
                logger.warning("SecureBERT NER not available, using regex-only entities: %s", e)

    def enrich_document(self, doc: Dict) -> Dict:
        """
        Run full NLP enrichment on a single document.

        Args:
            doc: Document dict with id, content, title, source, etc.

        Returns:
            Enriched dict with domain_labels, entities, entity_summary,
            risk_assessment, and metadata.
        """
        text = doc.get("content", "") or ""
        labels = self._majority_vote(doc)

        rule_entities = self._entity_extractor.extract_entities(text)
        rule_summary = self._entity_extractor.extract_entity_summary(text)

        merged_entities = list(rule_entities)
        entity_extraction_methods = ["regex"]

        if self._securebert_available and self._securebert_extractor and self._merge_entities:
            try:
                ner_entities = self._securebert_extractor.extract_entities(text)
                merged_entities = self._merge_entities(rule_entities, ner_entities)
                entity_extraction_methods.append("securebert_ner")
            except Exception as e:
                logger.warning("SecureBERT NER failed for doc %s: %s", doc.get("id"), e)

        risk_result = self._risk_scorer.score_document(labels, rule_summary, text)

        return {
            "id": doc["id"],
            "source": doc.get("source"),
            "title": doc.get("title"),
            "domain_labels": labels,
            "entities": merged_entities,
            "entity_summary": rule_summary,
            "risk_assessment": risk_result,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "enrichment_version": "1.0.0",
            "methods": {
                "classification": "weak_supervision_majority_vote",
                "entity_extraction": entity_extraction_methods,
                "risk_scoring": "rule_based_v1",
            },
        }

    def enrich_corpus(
        self,
        documents: List[Dict],
        progress_interval: int = 50,
    ) -> List[Dict]:
        """
        Process each document through the enrichment pipeline.

        Args:
            documents: List of document dicts
            progress_interval: Log progress every N documents

        Returns:
            List of enriched document dicts; failed docs are skipped with a log
        """
        enriched: List[Dict] = []
        for i, doc in enumerate(documents):
            try:
                out = self.enrich_document(doc)
                enriched.append(out)
            except Exception as e:
                logger.warning("Enrichment failed for doc %s: %s", doc.get("id"), e)
                continue
            if (i + 1) % progress_interval == 0:
                logger.info("Enriched %d / %d documents", i + 1, len(documents))
        return enriched

    def save_enriched(self, enriched_docs: List[Dict], output_path: str) -> None:
        """
        Write enriched documents to a JSONL file.

        Args:
            enriched_docs: List of enriched document dicts
            output_path: Path to output JSONL file
        """
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for doc in enriched_docs:
                f.write(json.dumps(doc, ensure_ascii=False) + "\n")
