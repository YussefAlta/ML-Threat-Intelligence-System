"""
SecureBERT 2.0 NER integration for soft entity extraction.

Uses Cisco's pre-trained SecureBERT2.0-NER model (cisco-ai/SecureBERT2.0-NER)
for inference-only extraction of: threat actors, malware families, organizations,
systems/platforms, and vulnerability mentions. No fine-tuning required.

The model uses ModernBERT architecture with 8,192 token context window.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from ..core.config import Config

logger = logging.getLogger(__name__)

ENTITY_GROUP_MAP = {
    "Malware": "malware",
    "Organization": "organization",
    "ORG": "organization",
    "System": "system",
    "Indicator": "indicator",
    "Vulnerability": "vulnerability",
}

CHARS_PER_TOKEN_APPROX = 4

# Minimum confidence score for NER entities
NER_CONFIDENCE_THRESHOLD = 0.70

# Minimum character length for a valid entity
NER_MIN_ENTITY_LENGTH = 4

# Values that are never valid entities (common NER noise)
_NOISE_VALUES = frozenset({
    # Punctuation
    ".", ",", "-", ";", ":", "(", ")", "[", "]", "{", "}", "/", "\\",
    "|", "_", "](", "=", "+", "*", "#", "@", "!", "?", "'", '"',
    # Stop words
    "the", "that", "this", "with", "from", "for", "and", "but", "not",
    "are", "was", "were", "been", "have", "has", "had", "will", "would",
    "can", "could", "may", "might", "shall", "should", "its", "their",
    "which", "when", "where", "what", "some", "also", "into", "over",
    # Sub-word fragments
    "ing", "tion", "ware", "ment", "ness", "ity", "ous", "ble",
    "xml.", "xml", "org", "com", "net", "oit", "expl",
    # Generic nouns NER misclassifies as entities
    "malware", "exploit", "tools", "system", "cloud", "cloud services",
    "industries", "organizations", "entities", "victims", "customer",
    "products", "versions", "open", "account", "product",
    "government sectors", "government entities", "remote access tools",
    "associated malware", "find", "triage",
})


def _get_config_max_tokens(config: Optional["Config"] = None) -> int:
    if config is not None:
        return getattr(config, "SECUREBERT_MAX_TOKENS", 7500)
    try:
        from ..core.config import Config
        return getattr(Config, "SECUREBERT_MAX_TOKENS", 7500)
    except ImportError:
        return 7500


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


class SecureBERTNERExtractor:
    """
    Extracts soft entities (threat actors, malware, organizations, etc.) from
    threat intelligence text using SecureBERT 2.0 NER model.
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        config: Optional["Config"] = None,
        device: Optional[str] = None,
    ) -> None:
        if config is not None and model_name is None:
            model_name = getattr(config, "SECUREBERT_NER_MODEL_NAME", "cisco-ai/SecureBERT2.0-NER")
        self.model_name = model_name or "cisco-ai/SecureBERT2.0-NER"
        self._config = config
        self._device = self._resolve_device(device)
        self._pipeline: Any = None

    def _resolve_device(self, device: Optional[str]) -> str:
        if device is not None:
            return device
        try:
            import torch
            if torch.cuda.is_available():
                return "cuda"
            if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
                return "mps"
        except ImportError:
            pass
        return "cpu"

    def _load_pipeline(self) -> None:
        try:
            from transformers import pipeline
        except ImportError as e:
            logger.warning("transformers not installed; SecureBERT NER unavailable: %s", e)
            raise
        try:
            device_arg = -1 if self._device == "cpu" else self._device
            self._pipeline = pipeline(
                "token-classification",
                model=self.model_name,
                device=device_arg,
                aggregation_strategy="simple",
            )
            logger.info("SecureBERT NER model loaded: %s (device=%s)", self.model_name, self._device)
        except Exception as e:
            logger.error("Failed to load SecureBERT NER model %s: %s", self.model_name, e)
            raise

    @property
    def pipeline(self) -> Any:
        if self._pipeline is None:
            self._load_pipeline()
        return self._pipeline

    def _normalize_type(self, entity_group: str) -> str:
        return ENTITY_GROUP_MAP.get(entity_group, entity_group.lower())

    def _merge_adjacent(self, entities: List[Dict[str, Any]], text: str) -> List[Dict[str, Any]]:
        """
        Merge adjacent entities of the same type with contiguous spans.

        Some NER models tag every sub-word token as B- instead of I-,
        producing fragments like ("C", "VE", "-", "2024") instead of
        "CVE-2024-1234". This method stitches them back together.
        """
        if not entities:
            return entities

        sorted_ents = sorted(entities, key=lambda e: e.get("start", 0))
        merged: List[Dict[str, Any]] = [dict(sorted_ents[0])]

        for ent in sorted_ents[1:]:
            prev = merged[-1]
            gap = ent["start"] - prev["end"]
            same_type = ent["type"] == prev["type"]

            if same_type and gap <= 0:
                # Contiguous or overlapping — merge
                prev["value"] = text[prev["start"]:ent["end"]].strip()
                prev["end"] = ent["end"]
                prev["score"] = max(prev.get("score", 0), ent.get("score", 0))
            else:
                merged.append(dict(ent))

        # Clean up leading/trailing whitespace in values
        for e in merged:
            e["value"] = e["value"].strip()

        return [e for e in merged if e["value"]]

    def _dedupe_entities(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        best: Dict[tuple, Dict[str, Any]] = {}
        for e in entities:
            key = (e["type"], e["value"])
            if key not in best or e["score"] > best[key]["score"]:
                best[key] = e
        return list(best.values())

    def extract_entities(
        self,
        text: str,
        max_length: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Extract named entities from threat intelligence text.

        Args:
            text: Input text to analyze.
            max_length: Approximate max characters (from token limit).
                Defaults to config.SECUREBERT_MAX_TOKENS * 4 or 30000.

        Returns:
            List of entity dicts with type, value, start, end, score, method.
        """
        if max_length is None:
            max_tokens = _get_config_max_tokens(self._config)
            max_length = max_tokens * CHARS_PER_TOKEN_APPROX
        truncated = text[:max_length] if len(text) > max_length else text

        try:
            raw = self.pipeline(truncated)
        except Exception as e:
            logger.error("SecureBERT NER inference failed: %s", e)
            return []

        entities: List[Dict[str, Any]] = []
        for item in raw:
            entity_group = item.get("entity_group", item.get("entity", ""))
            score = float(item.get("score", 0.0))
            if score < NER_CONFIDENCE_THRESHOLD:
                continue

            normalized_type = self._normalize_type(entity_group)
            value = (item.get("word") or "").strip()
            if not value:
                continue

            start = int(item.get("start", 0))
            end = int(item.get("end", start + len(value)))

            entities.append({
                "type": normalized_type,
                "value": value,
                "start": start,
                "end": end,
                "score": score,
                "method": "securebert_ner",
            })

        entities = self._merge_adjacent(entities, truncated)
        entities = self._filter_noise(entities)
        return self._dedupe_entities(entities)

    @staticmethod
    def _filter_noise(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove sub-word fragments, punctuation, and common stop words."""
        filtered: List[Dict[str, Any]] = []
        for e in entities:
            value = e.get("value", "").strip().rstrip(".")
            if len(value) < NER_MIN_ENTITY_LENGTH:
                continue
            if value.lower() in _NOISE_VALUES:
                continue
            # Skip if all punctuation/digits
            if not any(c.isalpha() for c in value):
                continue
            e["value"] = value
            filtered.append(e)
        return filtered

    def extract_entity_summary(self, text: str) -> Dict[str, Any]:
        """
        Extract entities and return a structured summary with counts and grouping.

        Returns:
            Dict with entities, counts, total, and by_type.
        """
        entities = self.extract_entities(text)
        counts: Dict[str, int] = {}
        by_type: Dict[str, List[Dict[str, Any]]] = {}

        for e in entities:
            t = e["type"]
            counts[t] = counts.get(t, 0) + 1
            by_type.setdefault(t, []).append({"value": e["value"], "score": e["score"]})

        return {
            "entities": entities,
            "counts": counts,
            "total": len(entities),
            "by_type": by_type,
        }

    @staticmethod
    def is_available() -> bool:
        """Check if transformers and torch are available."""
        try:
            import transformers
            import torch
            return True
        except ImportError:
            logger.warning("SecureBERT NER unavailable: transformers or torch not installed")
            return False


def merge_entities(
    rule_entities: List[Dict[str, Any]],
    ner_entities: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Merge entities from rule-based and NER extraction, deduplicating overlapping spans.

    Rule-based entities take priority for structured types (cve_id, ipv4, sha256, etc.)
    since regex is higher precision for those. NER entities fill in soft types.
    """
    rule_spans = [(e.get("start", 0), e.get("end", 0)) for e in rule_entities]
    filtered_ner: List[Dict[str, Any]] = []

    for ne in ner_entities:
        ns, ne_end = ne.get("start", 0), ne.get("end", 0)
        overlaps = any(_spans_overlap(ns, ne_end, rs, re) for rs, re in rule_spans)
        if not overlaps:
            filtered_ner.append(ne)

    merged = rule_entities + filtered_ner
    merged.sort(key=lambda e: e.get("start", 0))
    return merged
