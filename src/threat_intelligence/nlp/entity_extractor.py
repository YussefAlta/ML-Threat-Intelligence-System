"""
Rule-based entity extraction for structured threat intelligence entities.

Extracts high-precision entities using regex patterns: CVE IDs, IP addresses,
domains, URLs, file hashes (MD5/SHA1/SHA256), email addresses, and CVSS scores.
These complement model-based extraction (SecureBERT 2.0 NER) for soft entities.
"""

import re
from typing import Dict, List, Set, Any


class RuleBasedEntityExtractor:
    def __init__(self) -> None:
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

        ipv4_octet = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        self._ipv4_pattern = re.compile(
            rf"(?<!\d)(?<!\\.){ipv4_octet}\.{ipv4_octet}\.{ipv4_octet}\.{ipv4_octet}(?!\.\d)"
        )

        ipv6_part = r"[0-9a-fA-F]{1,4}"
        self._ipv6_pattern = re.compile(
            rf"\b(?:{ipv6_part}:){{2,7}}{ipv6_part}\b"
        )

        tlds = r"com|net|org|io|gov|edu|ru|cn|uk|de|fr|info|biz|xyz|top|onion"
        self._domain_pattern = re.compile(
            rf"(?<!/)\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+({tlds})\b",
            re.IGNORECASE,
        )

        self._url_pattern = re.compile(
            r"https?://[^\s<>\"'\)\]}\|]+(?:\s|$|[\"'\)\]}\|])?",
        )

        self._md5_pattern = re.compile(r"\b[a-fA-F0-9]{32}\b")

        self._sha1_pattern = re.compile(r"\b[a-fA-F0-9]{40}\b")

        self._sha256_pattern = re.compile(r"\b[a-fA-F0-9]{64}\b")

        self._email_pattern = re.compile(
            rf"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{{2,}}(?:\.[a-zA-Z]{{2,}})*\b"
        )

        self._cvss_patterns = [
            re.compile(r"CVSS[:\s]*(\d+\.\d+)", re.IGNORECASE),
            re.compile(r"CVSS:3\.\d/AV:[^/]+/AC:[^/]+/PR:[^/]+/UI:[^/]+/S:[^/]+/C:[^/]+/I:[^/]+/A:[^/]+[^\s]*"),
            re.compile(r"severity[:\s]+(\d+\.\d+)", re.IGNORECASE),
            re.compile(r"score[:\s]+(\d+\.\d+)", re.IGNORECASE),
            re.compile(r"(\d+\.\d+)\s*/\s*10(?:\s|$|[,.\)])"),
        ]

        self._version_prefix = re.compile(r"(?i)(?:version|v)\s*\d*\s*$")

    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        entities: List[Dict[str, Any]] = []
        seen: Set[tuple] = set()

        extractors = [
            self._extract_cves,
            self._extract_ipv4,
            self._extract_ipv6,
            self._extract_domains,
            self._extract_urls,
            self._extract_md5,
            self._extract_sha1,
            self._extract_sha256,
            self._extract_emails,
            self._extract_cvss,
        ]

        for extract_fn in extractors:
            for ent in extract_fn(text):
                key = (ent["type"], ent["value"].lower() if ent["value"] else ent["value"])
                if key not in seen:
                    seen.add(key)
                    entities.append(ent)

        entities.sort(key=lambda e: e["start"])
        return entities

    def extract_entity_summary(self, text: str) -> Dict[str, Any]:
        entities = self.extract_entities(text)

        counts: Dict[str, int] = {}
        for ent in entities:
            t = ent["type"]
            counts[t] = counts.get(t, 0) + 1

        unique_cves = sorted(
            {e["value"] for e in entities if e["type"] == "cve_id"},
            key=str.upper,
        )
        unique_ips = sorted(
            {
                e["value"]
                for e in entities
                if e["type"] in ("ipv4", "ipv6")
            }
        )
        unique_hashes = {
            "md5": sorted({e["value"] for e in entities if e["type"] == "md5"}),
            "sha1": sorted({e["value"] for e in entities if e["type"] == "sha1"}),
            "sha256": sorted({e["value"] for e in entities if e["type"] == "sha256"}),
        }
        unique_domains = sorted(
            {e["value"] for e in entities if e["type"] == "domain"}
        )
        unique_urls = sorted(
            {e["value"] for e in entities if e["type"] == "url"}
        )
        unique_emails = sorted(
            {e["value"] for e in entities if e["type"] == "email"}
        )

        cvss_values: List[float] = []
        for e in entities:
            if e["type"] == "cvss_score" and e.get("value"):
                try:
                    v = float(e["value"])
                    if 0 <= v <= 10:
                        cvss_values.append(v)
                except (ValueError, TypeError):
                    pass
        cvss_scores = sorted(set(cvss_values))

        return {
            "entities": entities,
            "counts": counts,
            "total": len(entities),
            "unique_cves": unique_cves,
            "unique_ips": unique_ips,
            "unique_hashes": unique_hashes,
            "unique_domains": unique_domains,
            "unique_urls": unique_urls,
            "unique_emails": unique_emails,
            "cvss_scores": cvss_scores,
        }

    def _make_entity(
        self,
        etype: str,
        value: str,
        start: int,
        end: int,
    ) -> Dict[str, Any]:
        return {
            "type": etype,
            "value": value,
            "start": start,
            "end": end,
            "method": "regex",
        }

    def _extract_cves(self, text: str) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for m in self._cve_pattern.finditer(text):
            result.append(
                self._make_entity("cve_id", m.group(0), m.start(), m.end())
            )
        return result

    def _extract_ipv4(self, text: str) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for m in self._ipv4_pattern.finditer(text):
            value = m.group(0)
            prefix = text[max(0, m.start() - 20) : m.start()]
            if self._version_prefix.search(prefix):
                continue
            result.append(
                self._make_entity("ipv4", value, m.start(), m.end())
            )
        return result

    def _extract_ipv6(self, text: str) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for m in self._ipv6_pattern.finditer(text):
            result.append(
                self._make_entity("ipv6", m.group(0), m.start(), m.end())
            )
        return result

    def _extract_domains(self, text: str) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for m in self._domain_pattern.finditer(text):
            value = m.group(0)
            if "://" in text[max(0, m.start() - 10) : m.start()]:
                continue
            result.append(
                self._make_entity("domain", value, m.start(), m.end())
            )
        return result

    def _extract_urls(self, text: str) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for m in self._url_pattern.finditer(text):
            value = m.group(0).rstrip(' "\')]}|')
            result.append(
                self._make_entity("url", value, m.start(), m.start() + len(value))
            )
        return result

    def _extract_md5(self, text: str) -> List[Dict[str, Any]]:
        return self._extract_hashes_excluding_urls(
            text, self._md5_pattern, "md5"
        )

    def _extract_sha1(self, text: str) -> List[Dict[str, Any]]:
        return self._extract_hashes_excluding_urls(
            text, self._sha1_pattern, "sha1"
        )

    def _extract_sha256(self, text: str) -> List[Dict[str, Any]]:
        return self._extract_hashes_excluding_urls(
            text, self._sha256_pattern, "sha256"
        )

    def _extract_hashes_excluding_urls(
        self,
        text: str,
        pattern: re.Pattern[str],
        etype: str,
    ) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for m in pattern.finditer(text):
            chunk_start = max(0, m.start() - 100)
            chunk = text[chunk_start : m.end() + 1]
            if "://" in chunk:
                url_start = chunk.rfind("://")
                if url_start >= 0:
                    abs_url_start = chunk_start + url_start
                    url_end = m.end()
                    for term in ' \n\t<>"\')]}|':
                        idx = text.find(term, m.end())
                        if idx >= 0:
                            url_end = min(url_end, idx)
                    if m.start() >= abs_url_start and m.end() <= url_end:
                        continue
            result.append(
                self._make_entity(etype, m.group(0), m.start(), m.end())
            )
        return result

    def _extract_emails(self, text: str) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for m in self._email_pattern.finditer(text):
            result.append(
                self._make_entity("email", m.group(0), m.start(), m.end())
            )
        return result

    def _extract_cvss(self, text: str) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        seen_scores: Set[str] = set()

        for i, pattern in enumerate(self._cvss_patterns):
            for m in pattern.finditer(text):
                if i == 1:
                    result.append(
                        self._make_entity(
                            "cvss_score",
                            m.group(0),
                            m.start(),
                            m.end(),
                        )
                    )
                else:
                    g = m.group(1)
                    if g and g not in seen_scores:
                        seen_scores.add(g)
                        result.append(
                            self._make_entity(
                                "cvss_score",
                                g,
                                m.start(),
                                m.end(),
                            )
                        )
        return result
