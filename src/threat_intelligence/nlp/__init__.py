"""
NLP enrichment modules for threat intelligence document analysis.

Includes weak supervision labeling, entity extraction, classification,
risk scoring, relation extraction, normalization, and evaluation.
"""

from .labeling_functions import (
    majority_vote,
    label_corpus,
    apply_labeling_functions,
    get_all_labeling_functions,
    LABEL_NAMES,
)
from .entity_extractor import RuleBasedEntityExtractor
from .risk_scorer import RiskScorer
from .prelabeler import CorpusPreLabeler
from .evaluation import evaluate_labels, generate_report, run_evaluation
from .relation_extractor import RelationExtractor
from .normalizer import EntityNormalizer
from .nlp_enricher import NLPEnricher

__all__ = [
    "majority_vote",
    "label_corpus",
    "apply_labeling_functions",
    "get_all_labeling_functions",
    "LABEL_NAMES",
    "RuleBasedEntityExtractor",
    "RiskScorer",
    "CorpusPreLabeler",
    "evaluate_labels",
    "generate_report",
    "run_evaluation",
    "RelationExtractor",
    "EntityNormalizer",
    "NLPEnricher",
]

try:
    from .securebert_ner import SecureBERTNERExtractor, merge_entities
    from .classifier import SecureBERTClassifier

    __all__ += [
        "SecureBERTNERExtractor",
        "merge_entities",
        "SecureBERTClassifier",
    ]
except ImportError:
    pass
