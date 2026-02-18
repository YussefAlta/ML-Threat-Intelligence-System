"""
Risk scoring for threat intelligence documents.

Assigns a risk tier (Critical, High, Medium, Low) based on signals extracted
during classification and entity extraction. Produces a structured risk
assessment with contributing signals and overall confidence.
"""

import re
from typing import Dict, List, Optional


_RE_EXPLOIT_AVAILABLE = re.compile(
    r"\b(proof of concept|PoC|exploit code|weaponized)\b",
    re.IGNORECASE,
)
_RE_ACTIVELY_EXPLOITED = re.compile(
    r"\b(actively exploited|in the wild|exploitation observed|known exploited)\b",
    re.IGNORECASE,
)
_RE_CRITICAL_SEVERITY = re.compile(
    r"\b(critical)\b.{0,80}\b(severity|vulnerability)\b|\b(severity|vulnerability)\b.{0,80}\b(critical)\b",
    re.IGNORECASE | re.DOTALL,
)


class RiskScorer:
    """
    Assigns risk tier and score to documents based on classification labels,
    entity summary, and text-derived signals.
    """

    def __init__(self) -> None:
        pass

    def score_document(
        self,
        labels: Dict[str, float],
        entity_summary: Dict,
        text: str,
    ) -> Dict:
        """
        Compute risk tier, score, signals, and contributing factors.

        Args:
            labels: Output of majority_vote, e.g. {"vulnerability": 0.8, "exploit": 0.6}
            entity_summary: Output of entity extractor's extract_entity_summary
            text: Raw document text for additional signal extraction

        Returns:
            Dict with risk_tier, risk_score, signals, contributing_factors
        """
        signals = self._extract_signals(labels, entity_summary, text)
        risk_score = self._compute_score(signals)
        risk_tier = self._compute_tier(signals)
        contributing_factors = self._build_factors(signals, risk_tier)
        return {
            "risk_tier": risk_tier,
            "risk_score": round(risk_score, 4),
            "signals": signals,
            "contributing_factors": contributing_factors,
        }

    def _extract_signals(
        self,
        labels: Dict[str, float],
        entity_summary: Dict,
        text: str,
    ) -> Dict:
        exploit_available = (
            labels.get("exploit", 0) >= 0.3 or bool(_RE_EXPLOIT_AVAILABLE.search(text))
        )
        actively_exploited = bool(_RE_ACTIVELY_EXPLOITED.search(text))
        severity_critical = bool(_RE_CRITICAL_SEVERITY.search(text))
        ransomware_mentioned = labels.get("ransomware", 0) >= 0.3

        cvss_scores = entity_summary.get("cvss_scores") or []
        max_cvss = max(cvss_scores) if cvss_scores else None
        if max_cvss is not None and max_cvss >= 9.0:
            severity_critical = True
        high_cvss = max_cvss is not None and max_cvss >= 7.0

        unique_ips = entity_summary.get("unique_ips") or []
        unique_domains = entity_summary.get("unique_domains") or []
        unique_hashes = entity_summary.get("unique_hashes") or {}
        hash_count = sum(
            len(unique_hashes.get(k, [])) for k in ("md5", "sha1", "sha256")
        )
        ioc_total = len(unique_ips) + len(unique_domains) + hash_count
        if ioc_total > 10:
            ioc_density = "high"
        elif ioc_total > 3:
            ioc_density = "medium"
        elif ioc_total > 0:
            ioc_density = "low"
        else:
            ioc_density = "none"

        cve_count = entity_summary.get("counts", {}).get("cve_id", 0) or len(
            entity_summary.get("unique_cves") or []
        )
        vulnerability_in_labels = labels.get("vulnerability", 0) >= 0.3

        return {
            "exploit_available": exploit_available,
            "actively_exploited": actively_exploited,
            "severity_critical": severity_critical,
            "ransomware_mentioned": ransomware_mentioned,
            "high_cvss": high_cvss,
            "cvss_score": max_cvss,
            "ioc_density": ioc_density,
            "cve_count": cve_count,
            "hash_count": hash_count,
            "vulnerability_in_labels": vulnerability_in_labels,
        }

    def _compute_score(self, signals: Dict) -> float:
        score = 0.0
        weights = {
            "exploit_available": 0.15,
            "actively_exploited": 0.2,
            "severity_critical": 0.15,
            "ransomware_mentioned": 0.15,
            "high_cvss": 0.1,
            "ioc_density": 0.1,
            "cve_count": 0.05,
            "hash_count": 0.05,
        }
        ioc_density_values = {"none": 0, "low": 0.05, "medium": 0.1, "high": 0.15}
        for k, w in weights.items():
            if k == "ioc_density":
                score += ioc_density_values.get(signals.get(k, "none"), 0)
            elif k == "cve_count":
                cnt = signals.get(k, 0)
                score += min(0.05 * min(cnt, 3), 0.15)
            elif k == "hash_count":
                cnt = signals.get(k, 0)
                score += min(0.02 * min(cnt, 5), 0.1)
            elif signals.get(k, False):
                score += w
        return min(score, 1.0)

    def _compute_tier(self, signals: Dict) -> str:
        exploit_available = signals.get("exploit_available", False)
        actively_exploited = signals.get("actively_exploited", False)
        severity_critical = signals.get("severity_critical", False)
        ransomware_mentioned = signals.get("ransomware_mentioned", False)
        ioc_density = signals.get("ioc_density", "none")
        cve_count = signals.get("cve_count", 0)
        if (
            actively_exploited
            and (exploit_available or severity_critical)
        ) or (ransomware_mentioned and exploit_available):
            return "critical"
        if (
            exploit_available
            or severity_critical
            or ransomware_mentioned
            or actively_exploited
        ):
            return "high"
        if (
            signals.get("vulnerability_in_labels", False)
            or ioc_density in ("medium", "high")
            or cve_count > 0
        ):
            return "medium"
        return "low"

    def _build_factors(self, signals: Dict, risk_tier: str) -> List[str]:
        factors: List[str] = []
        if signals.get("exploit_available"):
            factors.append("Exploit code or PoC available")
        if signals.get("actively_exploited"):
            factors.append("Actively exploited in the wild")
        if signals.get("severity_critical"):
            cvss = signals.get("cvss_score")
            if cvss is not None:
                factors.append(f"Critical severity (CVSS {cvss})")
            else:
                factors.append("Critical severity mentioned")
        if signals.get("ransomware_mentioned"):
            factors.append("Ransomware activity mentioned")
        cvss = signals.get("cvss_score")
        if signals.get("high_cvss") and cvss is not None and cvss < 9.0:
            factors.append(f"High CVSS score ({cvss})")
        ioc_density = signals.get("ioc_density", "none")
        if ioc_density in ("medium", "high"):
            factors.append(f"Moderate to high IOC density ({ioc_density})")
        if signals.get("cve_count", 0) > 0:
            factors.append(f"{signals['cve_count']} CVE(s) referenced")
        if signals.get("hash_count", 0) > 0:
            factors.append(f"{signals['hash_count']} file hash(es) present")
        if not factors:
            factors.append("No high-impact signals detected")
        return factors
