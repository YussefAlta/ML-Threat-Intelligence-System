"""
Rule-based relation extraction for threat intelligence documents.

Extracts semantic relationships between entities: exploit-vulnerability links,
actor-malware associations, actor-target mappings, and malware-vulnerability
connections. Uses pattern matching on text surrounding entity mentions.
"""

import re
from typing import Dict, List, Any, Optional


class RelationExtractor:
    """
    Extracts semantic relations between entities using rule-based pattern matching.
    """

    PROXIMITY_WINDOW = 200

    def __init__(self) -> None:
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._exploits_triggers = [
            re.compile(r"(?P<entity>\S+(?:\s+\S+){0,3})\s+exploits\s+(?P<cve>CVE-\d{4}-\d{4,7})", re.IGNORECASE),
            re.compile(r"exploit\s+for\s+(?P<cve>CVE-\d{4}-\d{4,7})", re.IGNORECASE),
            re.compile(r"(?P<cve>CVE-\d{4}-\d{4,7})\s+exploited\s+by\s+(?P<entity>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"PoC\s+for\s+(?P<cve>CVE-\d{4}-\d{4,7})", re.IGNORECASE),
            re.compile(r"(?P<cve>CVE-\d{4}-\d{4,7})[^.]{0,80}remote\s+code\s+execution", re.IGNORECASE | re.DOTALL),
        ]
        self._uses_triggers = [
            re.compile(r"(?P<actor>\S+(?:\s+\S+){0,3})\s+uses\s+(?P<malware>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"(?P<actor>\S+(?:\s+\S+){0,3})\s+deployed\s+(?P<malware>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"(?P<malware>\S+(?:\s+\S+){0,3})\s+attributed\s+to\s+(?P<actor>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"(?P<actor>\S+(?:\s+\S+){0,3})\s+leverages\s+(?P<tool>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"(?P<actor>\S+(?:\s+\S+){0,3})[^.]{0,50}associated\s+with[^.]{0,50}(?P<malware>\S+(?:\s+\S+){0,3})", re.IGNORECASE | re.DOTALL),
        ]
        self._targets_triggers = [
            re.compile(r"(?P<actor>\S+(?:\s+\S+){0,3})\s+targets\s+(?P<target>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"(?P<actor>\S+(?:\s+\S+){0,3})\s+targeting\s+(?P<target>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"campaign\s+against\s+(?P<target>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"attacks?\s+on\s+(?P<target>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
        ]
        self._drops_triggers = [
            re.compile(r"(?P<m1>\S+(?:\s+\S+){0,3})\s+drops\s+(?P<m2>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"(?P<m1>\S+(?:\s+\S+){0,3})\s+delivers\s+(?P<m2>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"(?P<m1>\S+(?:\s+\S+){0,3})\s+downloads\s+(?P<m2>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
        ]
        self._affects_triggers = [
            re.compile(r"(?P<cve>CVE-\d{4}-\d{4,7})\s+affects\s+(?P<product>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
            re.compile(r"(?P<product>\S+(?:\s+\S+){0,3})\s+vulnerable\s+to\s+(?P<cve>CVE-\d{4}-\d{4,7})", re.IGNORECASE),
            re.compile(r"(?P<cve>CVE-\d{4}-\d{4,7})\s+in\s+(?P<product>\S+(?:\s+\S+){0,3})", re.IGNORECASE),
        ]

    def extract_relations(self, text: str, entities: List[Dict]) -> List[Dict]:
        """
        Extract semantic relations between entities in the document text.

        Args:
            text: Document text.
            entities: List of entity dicts with type, value, start, end.

        Returns:
            List of relation dicts with type, source, source_type, target, target_type,
            evidence, confidence, and method.
        """
        entities_with_spans = [e for e in entities if "start" in e and "end" in e]
        if not entities_with_spans:
            return []

        relations: List[Dict[str, Any]] = []
        seen: set = set()

        for e1 in entities_with_spans:
            nearby = self._find_nearby_entities(
                entities_with_spans,
                e1.get("start", 0),
                e1.get("end", 0),
                self.PROXIMITY_WINDOW,
            )
            for e2 in nearby:
                if e1 is e2:
                    continue
                rel = self._try_extract_relation(text, entities_with_spans, e1, e2)
                if rel is not None:
                    key = (rel["type"], rel["source"], rel["target"])
                    if key not in seen:
                        seen.add(key)
                        relations.append(rel)

        for e in entities_with_spans:
            rel = self._try_exploits_implicit(text, entities_with_spans, e)
            if rel is not None:
                key = (rel["type"], rel["source"], rel["target"])
                if key not in seen:
                    seen.add(key)
                    relations.append(rel)

        for e in entities_with_spans:
            rel = self._try_targets_implicit(text, entities_with_spans, e)
            if rel is not None:
                key = (rel["type"], rel["source"], rel["target"])
                if key not in seen:
                    seen.add(key)
                    relations.append(rel)

        return relations

    def _try_extract_relation(
        self,
        text: str,
        entities: List[Dict],
        e1: Dict,
        e2: Dict,
    ) -> Optional[Dict[str, Any]]:
        start = min(e1["start"], e2["start"])
        end = max(e1["end"], e2["end"])
        window_start = max(0, start - self.PROXIMITY_WINDOW)
        window_end = min(len(text), end + self.PROXIMITY_WINDOW)
        window = text[window_start:window_end]

        t1, t2 = e1.get("type", ""), e2.get("type", "")

        if t1 == "cve_id" and t2 in ("malware", "organization", "system"):
            rel = self._extract_exploits(text, window, window_start, e1, e2)
            if rel:
                return rel

        if t2 == "cve_id" and t1 in ("malware", "organization", "system"):
            rel = self._extract_exploits(text, window, window_start, e2, e1)
            if rel:
                return rel

        if t1 == "organization" and t2 == "malware":
            rel = self._extract_uses(text, window, window_start, e1, e2)
            if rel:
                return rel

        if t2 == "organization" and t1 == "malware":
            rel = self._extract_uses(text, window, window_start, e2, e1)
            if rel:
                return rel

        if t1 == "organization" and t2 in ("organization", "system"):
            rel = self._extract_targets(text, window, window_start, e1, e2)
            if rel:
                return rel

        if t2 == "organization" and t1 in ("organization", "system"):
            rel = self._extract_targets(text, window, window_start, e2, e1)
            if rel:
                return rel

        if t1 == "malware" and t2 == "malware":
            rel = self._extract_drops(text, window, window_start, e1, e2)
            if rel:
                return rel

        if t1 == "cve_id" and t2 in ("organization", "system"):
            rel = self._extract_affects(text, window, window_start, e1, e2)
            if rel:
                return rel

        if t2 == "cve_id" and t1 in ("organization", "system"):
            rel = self._extract_affects(text, window, window_start, e2, e1)
            if rel:
                return rel

        return None

    def _extract_exploits(
        self,
        text: str,
        window: str,
        window_start: int,
        cve_ent: Dict,
        other_ent: Dict,
    ) -> Optional[Dict[str, Any]]:
        for i, pat in enumerate(self._exploits_triggers):
            m = pat.search(window)
            if m is None:
                continue
            cve_val = cve_ent.get("value", "")
            other_val = other_ent.get("value", "")
            if cve_val.lower() not in window.lower() or other_val.lower() not in window.lower():
                continue
            sent_start, sent_end = self._get_sentence_span(text, cve_ent["start"], cve_ent["end"])
            if other_ent["start"] < sent_start or other_ent["end"] > sent_end:
                continue
            if i in (1, 3, 4):
                confidence = 0.6
            else:
                confidence = 0.9
            evidence = self._get_sentence(text, cve_ent["start"], cve_ent["end"])
            return {
                "type": "exploits",
                "source": other_val,
                "source_type": other_ent.get("type", ""),
                "target": cve_val,
                "target_type": "cve_id",
                "evidence": evidence,
                "confidence": confidence,
                "method": "rule_based",
            }
        if (
            "exploit" in window.lower() or "exploited" in window.lower() or "poc" in window.lower()
        ) and cve_ent.get("value", "").lower() in window.lower():
            sent_start, sent_end = self._get_sentence_span(text, cve_ent["start"], cve_ent["end"])
            if other_ent["start"] < sent_start or other_ent["end"] > sent_end:
                return None
            evidence = self._get_sentence(text, cve_ent["start"], cve_ent["end"])
            return {
                "type": "exploits",
                "source": other_ent.get("value", ""),
                "source_type": other_ent.get("type", ""),
                "target": cve_ent.get("value", ""),
                "target_type": "cve_id",
                "evidence": evidence,
                "confidence": 0.5,
                "method": "rule_based",
            }
        return None

    def _extract_uses(
        self,
        text: str,
        window: str,
        window_start: int,
        actor_ent: Dict,
        malware_ent: Dict,
    ) -> Optional[Dict[str, Any]]:
        actor_val = actor_ent.get("value", "")
        malware_val = malware_ent.get("value", "")
        for i, pat in enumerate(self._uses_triggers):
            m = pat.search(window)
            if m is None:
                continue
            if actor_val.lower() not in window.lower() or malware_val.lower() not in window.lower():
                continue
            confidence = 0.85 if i < 4 else 0.7
            evidence = self._get_sentence(text, actor_ent["start"], malware_ent["end"])
            return {
                "type": "uses",
                "source": actor_val,
                "source_type": actor_ent.get("type", ""),
                "target": malware_val,
                "target_type": "malware",
                "evidence": evidence,
                "confidence": confidence,
                "method": "rule_based",
            }
        if any(
            t in window.lower()
            for t in ("uses", "deployed", "attributed", "leverages", "associated with")
        ):
            evidence = self._get_sentence(text, actor_ent["start"], malware_ent["end"])
            return {
                "type": "uses",
                "source": actor_val,
                "source_type": actor_ent.get("type", ""),
                "target": malware_val,
                "target_type": "malware",
                "evidence": evidence,
                "confidence": 0.5,
                "method": "rule_based",
            }
        return None

    def _extract_targets(
        self,
        text: str,
        window: str,
        window_start: int,
        actor_ent: Dict,
        target_ent: Dict,
    ) -> Optional[Dict[str, Any]]:
        actor_val = actor_ent.get("value", "")
        target_val = target_ent.get("value", "")
        for pat in self._targets_triggers:
            m = pat.search(window)
            if m is None:
                continue
            if actor_val.lower() not in window.lower() or target_val.lower() not in window.lower():
                continue
            evidence = self._get_sentence(text, actor_ent["start"], target_ent["end"])
            return {
                "type": "targets",
                "source": actor_val,
                "source_type": actor_ent.get("type", ""),
                "target": target_val,
                "target_type": target_ent.get("type", ""),
                "evidence": evidence,
                "confidence": 0.85,
                "method": "rule_based",
            }
        if any(t in window.lower() for t in ("targets", "targeting", "campaign against", "attacks on")):
            evidence = self._get_sentence(text, actor_ent["start"], target_ent["end"])
            return {
                "type": "targets",
                "source": actor_val,
                "source_type": actor_ent.get("type", ""),
                "target": target_val,
                "target_type": target_ent.get("type", ""),
                "evidence": evidence,
                "confidence": 0.5,
                "method": "rule_based",
            }
        return None

    def _extract_drops(
        self,
        text: str,
        window: str,
        window_start: int,
        m1_ent: Dict,
        m2_ent: Dict,
    ) -> Optional[Dict[str, Any]]:
        v1 = m1_ent.get("value", "")
        v2 = m2_ent.get("value", "")
        for pat in self._drops_triggers:
            m = pat.search(window)
            if m is None:
                continue
            if v1.lower() not in window.lower() or v2.lower() not in window.lower():
                continue
            evidence = self._get_sentence(text, m1_ent["start"], m2_ent["end"])
            return {
                "type": "drops",
                "source": v1,
                "source_type": "malware",
                "target": v2,
                "target_type": "malware",
                "evidence": evidence,
                "confidence": 0.9,
                "method": "rule_based",
            }
        return None

    def _extract_affects(
        self,
        text: str,
        window: str,
        window_start: int,
        cve_ent: Dict,
        product_ent: Dict,
    ) -> Optional[Dict[str, Any]]:
        cve_val = cve_ent.get("value", "")
        product_val = product_ent.get("value", "")
        sent_start, sent_end = self._get_sentence_span(text, cve_ent["start"], cve_ent["end"])
        for pat in self._affects_triggers:
            m = pat.search(window)
            if m is None:
                continue
            if cve_val.lower() not in window.lower() or product_val.lower() not in window.lower():
                continue
            if product_ent["start"] < sent_start or product_ent["end"] > sent_end:
                continue
            evidence = self._get_sentence(text, cve_ent["start"], product_ent["end"])
            return {
                "type": "affects",
                "source": cve_val,
                "source_type": "cve_id",
                "target": product_val,
                "target_type": product_ent.get("type", ""),
                "evidence": evidence,
                "confidence": 0.85,
                "method": "rule_based",
            }
        if any(t in window.lower() for t in ("affects", "vulnerable to", " in ")):
            if product_ent["start"] < sent_start or product_ent["end"] > sent_end:
                return None
            evidence = self._get_sentence(text, cve_ent["start"], product_ent["end"])
            return {
                "type": "affects",
                "source": cve_val,
                "source_type": "cve_id",
                "target": product_val,
                "target_type": product_ent.get("type", ""),
                "evidence": evidence,
                "confidence": 0.5,
                "method": "rule_based",
            }
        return None

    def _try_exploits_implicit(
        self,
        text: str,
        entities: List[Dict],
        cve_ent: Dict,
    ) -> Optional[Dict[str, Any]]:
        if cve_ent.get("type") != "cve_id":
            return None
        cve_val = cve_ent.get("value", "")
        window_start = max(0, cve_ent["start"] - self.PROXIMITY_WINDOW)
        window_end = min(len(text), cve_ent["end"] + self.PROXIMITY_WINDOW)
        window = text[window_start:window_end]
        for pat in [self._exploits_triggers[1], self._exploits_triggers[3], self._exploits_triggers[4]]:
            if pat.search(window) is None:
                continue
            nearby = self._find_nearby_entities(entities, cve_ent["start"], cve_ent["end"], self.PROXIMITY_WINDOW)
            sent_start, sent_end = self._get_sentence_span(text, cve_ent["start"], cve_ent["end"])
            for n in nearby:
                if (
                    n.get("type") in ("malware", "organization", "system")
                    and n is not cve_ent
                    and n.get("value")
                    and n["start"] >= sent_start
                    and n["end"] <= sent_end
                ):
                    evidence = self._get_sentence(text, cve_ent["start"], cve_ent["end"])
                    return {
                        "type": "exploits",
                        "source": n.get("value", ""),
                        "source_type": n.get("type", ""),
                        "target": cve_val,
                        "target_type": "cve_id",
                        "evidence": evidence,
                        "confidence": 0.6,
                        "method": "rule_based",
                    }
        return None

    def _try_targets_implicit(
        self,
        text: str,
        entities: List[Dict],
        target_ent: Dict,
    ) -> Optional[Dict[str, Any]]:
        if target_ent.get("type") not in ("organization", "system"):
            return None
        window_start = max(0, target_ent["start"] - self.PROXIMITY_WINDOW)
        window_end = min(len(text), target_ent["end"] + self.PROXIMITY_WINDOW)
        window = text[window_start:window_end]
        if not re.search(r"campaign\s+against|attacks?\s+on", window, re.IGNORECASE):
            return None
        nearby = self._find_nearby_entities(
            entities, target_ent["start"], target_ent["end"], self.PROXIMITY_WINDOW
        )
        for n in nearby:
            if n.get("type") == "organization" and n is not target_ent and n.get("value"):
                evidence = self._get_sentence(text, n["start"], target_ent["end"])
                return {
                    "type": "targets",
                    "source": n.get("value", ""),
                    "source_type": n.get("type", ""),
                    "target": target_ent.get("value", ""),
                    "target_type": target_ent.get("type", ""),
                    "evidence": evidence,
                    "confidence": 0.6,
                    "method": "rule_based",
                }
        return None

    def _get_sentence_span(self, text: str, start: int, end: int) -> tuple:
        sent_start = start
        for i in range(start - 1, -1, -1):
            if text[i] in ".!?\n":
                sent_start = i + 1
                break
            if i == 0:
                sent_start = 0
                break

        sent_end = end
        for i in range(end, len(text)):
            if text[i] in ".!?\n":
                sent_end = i + 1
                break
            if i == len(text) - 1:
                sent_end = len(text)
                break

        return (sent_start, sent_end)

    def _get_sentence(self, text: str, start: int, end: int) -> str:
        """
        Extract the sentence containing the given span.

        Args:
            text: Full document text.
            start: Start offset of span.
            end: End offset of span.

        Returns:
            The sentence containing the span, or a substring around the span if no clear sentence.
        """
        sent_start, sent_end = self._get_sentence_span(text, start, end)
        return text[sent_start:sent_end].strip()

    def _find_nearby_entities(
        self,
        entities: List[Dict],
        center_start: int,
        center_end: int,
        max_distance: int = 200,
    ) -> List[Dict]:
        """
        Return entities within max_distance characters of the center span.

        Args:
            entities: List of entity dicts with start, end.
            center_start: Start of center span.
            center_end: End of center span.
            max_distance: Maximum character distance from center.

        Returns:
            List of entities within the proximity window.
        """
        result: List[Dict] = []
        for e in entities:
            s = e.get("start", 0)
            end = e.get("end", 0)
            dist_before = center_start - end if end < center_start else 0
            dist_after = s - center_end if s > center_end else 0
            if dist_before <= max_distance and dist_after <= max_distance:
                result.append(e)
        return result
