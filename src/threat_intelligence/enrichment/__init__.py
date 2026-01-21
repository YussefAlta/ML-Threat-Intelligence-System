"""
Enrichment utilities for augmenting CVE/CPE data with additional context.

Phase 2 focuses on:
- CWE enrichment (MITRE CWE REST API)
- VulnCheck enrichment (exploit / threat intelligence)
"""

from .cwe_enricher import CWEEnricher
from .vulncheck_enricher import VulnCheckEnricher

__all__ = [
    "CWEEnricher",
    "VulnCheckEnricher",
]


