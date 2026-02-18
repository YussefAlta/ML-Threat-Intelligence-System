"""
Heuristic pre-labeling for gold evaluation set creation.

Applies the same rules that will become weak supervision labeling functions
to auto-label a stratified sample of corpus documents. Outputs pre-labeled
documents for human review.
"""

import csv
import json
import logging
import re
from collections import defaultdict
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

LABEL_THRESHOLD = 0.3
CONFIDENCE_THRESHOLD = 0.5
MAX_PREDICTED_LABELS = 3


class CorpusPreLabeler:
    """
    Heuristic pre-labeler for stratified corpus sampling and auto-labeling.
    """

    def __init__(self) -> None:
        self._cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        self._apt_pattern = re.compile(
            r"APT\d+|APT-\d+|UNC\d+|FIN\d+|TA\d+", re.IGNORECASE
        )
        self._ip_pattern = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )
        self._md5_pattern = re.compile(r"\b[a-fA-F0-9]{32}\b")
        self._sha1_pattern = re.compile(r"\b[a-fA-F0-9]{40}\b")
        self._sha256_pattern = re.compile(r"\b[a-fA-F0-9]{64}\b")
        self._domain_pattern = re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
        )

        self._vuln_keywords = [
            "vulnerability",
            "advisory",
            "patch",
            "security update",
            "CWE-",
            "affected versions",
            "CVSS",
        ]
        self._exploit_keywords = [
            r"proof of concept",
            r"PoC",
            r"exploit code",
            r"Metasploit",
            r"RCE exploit",
            r"shellcode",
            r"payload",
            r"exploit-db",
            r"0day",
            r"zero-day",
        ]
        self._phishing_keywords = [
            "phishing",
            "credential harvesting",
            "spoofed",
            "lure",
            "phishing kit",
            "fake login",
            "social engineering",
            "spear-phishing",
        ]
        self._ransomware_keywords = [
            "ransomware",
            "ransom",
            "encrypt",
            "decryptor",
            "double extortion",
            "data leak",
            "ransom note",
        ]
        self._ransomware_families = [
            "LockBit",
            "BlackCat",
            "ALPHV",
            "Conti",
            "REvil",
            "Clop",
            "Hive",
            "Royal",
            "Akira",
            "Play",
            "8Base",
            "Medusa",
            "BlackBasta",
            "Rhysida",
        ]
        self._threat_actor_keywords = [
            "threat actor",
            "threat group",
            "attributed to",
            "suspected",
            "nation-state",
            "espionage",
            "campaign",
            "intrusion set",
        ]
        self._threat_actor_groups = [
            "Lazarus",
            "Cozy Bear",
            "Fancy Bear",
            "Equation Group",
            "Sandworm",
            "Turla",
            "Kimsuky",
            "Mustang Panda",
        ]
        self._ioc_keywords = [
            "indicator",
            "C2",
            "command and control",
            "beacon",
            "callback",
            "IOC",
            "indicators of compromise",
        ]

        self._vuln_re = [re.compile(re.escape(k), re.IGNORECASE) for k in self._vuln_keywords]
        self._exploit_re = [
            re.compile(k, re.IGNORECASE) for k in self._exploit_keywords
        ]
        self._phishing_re = [
            re.compile(re.escape(k), re.IGNORECASE) for k in self._phishing_keywords
        ]
        self._ransomware_re = [
            re.compile(re.escape(k), re.IGNORECASE) for k in self._ransomware_keywords
        ]
        self._ransomware_fam_re = [
            re.compile(re.escape(k), re.IGNORECASE) for k in self._ransomware_families
        ]
        self._threat_actor_re = [
            re.compile(re.escape(k), re.IGNORECASE) for k in self._threat_actor_keywords
        ]
        self._threat_actor_grp_re = [
            re.compile(re.escape(k), re.IGNORECASE) for k in self._threat_actor_groups
        ]
        self._ioc_re = [
            re.compile(re.escape(k), re.IGNORECASE) for k in self._ioc_keywords
        ]

    def _score_vulnerability(self, text: str, title: str) -> Tuple[float, List[str]]:
        score = 0.0
        rules: List[str] = []
        combined = f"{title}\n{text}"

        if self._cve_pattern.search(combined):
            score += 0.4
            rules.append("cve_pattern")

        kw_score = 0.0
        for pat in self._vuln_re:
            if pat.search(combined):
                kw_score += 0.1
        if kw_score > 0:
            rules.append("advisory_keywords")
        score += min(kw_score, 0.5)

        return (min(score, 1.0), rules)

    def _score_exploit(self, text: str, title: str) -> Tuple[float, List[str]]:
        score = 0.0
        rules: List[str] = []
        combined = f"{title}\n{text}"

        has_poc = False
        for pat in self._exploit_re:
            if pat.search(combined):
                score += 0.15
                has_poc = True
        if has_poc:
            rules.append("poc_keywords")

        if re.search(r"github\.com[^\s]*", combined, re.IGNORECASE) and re.search(
            r"exploit|poc", combined, re.IGNORECASE
        ):
            score += 0.3
            rules.append("github_exploit_url")

        return (min(score, 1.0), rules)

    def _score_phishing(
        self, text: str, title: str, source_category_hint: str = ""
    ) -> Tuple[float, List[str]]:
        score = 0.0
        rules: List[str] = []
        combined = f"{title}\n{text}"

        if source_category_hint and str(source_category_hint).lower() == "phishing":
            score += 0.3
            rules.append("source_category_hint")

        for pat in self._phishing_re:
            if pat.search(combined):
                score += 0.15
        if any(pat.search(combined) for pat in self._phishing_re):
            rules.append("phishing_keywords")

        return (min(score, 1.0), rules)

    def _score_ransomware(self, text: str, title: str) -> Tuple[float, List[str]]:
        score = 0.0
        rules: List[str] = []
        combined = f"{title}\n{text}"

        for pat in self._ransomware_re:
            if pat.search(combined):
                score += 0.15
        if any(pat.search(combined) for pat in self._ransomware_re):
            rules.append("ransomware_keywords")
        for pat in self._ransomware_fam_re:
            if pat.search(combined):
                score += 0.2
        if any(pat.search(combined) for pat in self._ransomware_fam_re):
            rules.append("ransomware_family")

        return (min(score, 1.0), rules)

    def _score_threat_actor(self, text: str, title: str) -> Tuple[float, List[str]]:
        score = 0.0
        rules: List[str] = []
        combined = f"{title}\n{text}"

        if self._apt_pattern.search(combined):
            score += 0.4
            rules.append("apt_pattern")

        for pat in self._threat_actor_re:
            if pat.search(combined):
                score += 0.1
        if any(pat.search(combined) for pat in self._threat_actor_re):
            rules.append("threat_actor_keywords")
        for pat in self._threat_actor_grp_re:
            if pat.search(combined):
                score += 0.2
        if any(pat.search(combined) for pat in self._threat_actor_grp_re):
            rules.append("threat_actor_group")

        return (min(score, 1.0), rules)

    def _score_ioc(self, text: str, title: str) -> Tuple[float, List[str]]:
        score = 0.0
        rules: List[str] = []
        combined = f"{title}\n{text}"

        ip_count = len(self._ip_pattern.findall(combined))
        if ip_count > 3:
            score += 0.4
            rules.append("ip_density")

        hash_count = (
            len(self._md5_pattern.findall(combined))
            + len(self._sha1_pattern.findall(combined))
            + len(self._sha256_pattern.findall(combined))
        )
        if hash_count > 2:
            score += 0.3
            rules.append("hash_density")

        domain_count = len(self._domain_pattern.findall(combined))
        if domain_count > 3:
            score += 0.2
            rules.append("domain_density")

        for pat in self._ioc_re:
            if pat.search(combined):
                score += 0.1
        if any(pat.search(combined) for pat in self._ioc_re):
            rules.append("ioc_keywords")

        return (min(score, 1.0), rules)

    def prelabel_document(self, doc: Dict) -> Dict:
        """
        Pre-label a single corpus document using heuristic rules.

        Args:
            doc: Unified corpus document with id, title, content, source, source_category_hint.

        Returns:
            Pre-label result with predicted_labels, label_signals, confidence, and needs_review.
        """
        content = doc.get("content", "") or ""
        title = doc.get("title", "") or ""
        source_category_hint = doc.get("source_category_hint", "") or ""

        content_preview = content[:500] if content else ""

        label_signals: Dict[str, Dict] = {}
        scorers = [
            ("vulnerability", lambda: self._score_vulnerability(content, title)),
            ("exploit", lambda: self._score_exploit(content, title)),
            (
                "phishing",
                lambda: self._score_phishing(
                    content, title, source_category_hint
                ),
            ),
            ("ransomware", lambda: self._score_ransomware(content, title)),
            ("threat_actor", lambda: self._score_threat_actor(content, title)),
            ("ioc", lambda: self._score_ioc(content, title)),
        ]

        for label, fn in scorers:
            score, matched_rules = fn()
            label_signals[label] = {"score": round(score, 2), "matched_rules": matched_rules}

        predicted_labels = [
            lbl for lbl, sig in label_signals.items()
            if sig["score"] >= LABEL_THRESHOLD
        ]

        pred_scores = [
            label_signals[lbl]["score"]
            for lbl in predicted_labels
        ]
        confidence = (
            round(sum(pred_scores) / len(pred_scores), 2)
            if pred_scores
            else 0.0
        )

        max_score = max(s["score"] for s in label_signals.values())
        needs_review = (
            max_score < CONFIDENCE_THRESHOLD
            or len(predicted_labels) > MAX_PREDICTED_LABELS
            or len(predicted_labels) == 0
        )

        return {
            "id": doc["id"],
            "title": title,
            "content_preview": content_preview,
            "source": doc.get("source", ""),
            "source_category_hint": source_category_hint,
            "predicted_labels": predicted_labels,
            "label_signals": label_signals,
            "confidence": confidence,
            "needs_review": needs_review,
        }

    def prelabel_corpus(
        self, documents: List[Dict], sample_size: int = 100
    ) -> List[Dict]:
        """
        Stratified sample and pre-label corpus documents.

        Args:
            documents: List of unified corpus documents.
            sample_size: Target number of documents to sample.

        Returns:
            List of pre-label results, sorted by needs_review first, then confidence ascending.
        """
        if not documents:
            return []

        by_hint: Dict[str, List[Dict]] = defaultdict(list)
        for d in documents:
            hint = d.get("source_category_hint") or "unknown"
            by_hint[str(hint)].append(d)

        num_categories = len(by_hint)
        per_category = max(1, sample_size // num_categories)

        sampled: List[Dict] = []
        for hint, docs in by_hint.items():
            take = min(per_category, len(docs))
            if take >= len(docs):
                sampled.extend(docs)
            else:
                step = max(1, len(docs) // take)
                for i in range(0, len(docs), step):
                    if len(sampled) >= sample_size:
                        break
                    sampled.append(docs[i])

        while len(sampled) < sample_size:
            added = False
            for hint, docs in by_hint.items():
                for d in docs:
                    if d not in sampled:
                        sampled.append(d)
                        added = True
                        break
                if len(sampled) >= sample_size:
                    break
            if not added:
                break

        prelabeled = [self.prelabel_document(d) for d in sampled[:sample_size]]

        prelabeled.sort(
            key=lambda x: (not x["needs_review"], x["confidence"])
        )

        return prelabeled

    def save_prelabeled(
        self, prelabeled: List[Dict], output_path: str
    ) -> None:
        """
        Write pre-labeled results to JSONL file.

        Args:
            prelabeled: List of pre-label result dicts.
            output_path: Path to output JSONL file.
        """
        with open(output_path, "w", encoding="utf-8") as f:
            for item in prelabeled:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        logger.info(
            "Saved %d pre-labeled documents to %s", len(prelabeled), output_path
        )

    def save_for_review(
        self, prelabeled: List[Dict], output_path: str
    ) -> None:
        """
        Write pre-labeled results to a human-friendly TSV for review.

        Args:
            prelabeled: List of pre-label result dicts.
            output_path: Path to output TSV file.
        """
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(
                [
                    "id",
                    "title",
                    "source",
                    "predicted_labels",
                    "confidence",
                    "needs_review",
                    "content_preview",
                ]
            )
            for item in prelabeled:
                writer.writerow(
                    [
                        item.get("id", ""),
                        item.get("title", ""),
                        item.get("source", ""),
                        "|".join(item.get("predicted_labels", [])),
                        item.get("confidence", 0),
                        item.get("needs_review", False),
                        item.get("content_preview", ""),
                    ]
                )
        logger.info(
            "Saved %d pre-labeled documents for review to %s",
            len(prelabeled),
            output_path,
        )
