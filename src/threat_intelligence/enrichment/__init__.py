"""
Enrichment utilities for augmenting CVE/CPE data with additional context.

Phase 2 focuses on:
- NVD reference scraping (fetch and store reference URLs from CVE records)
- CWE enrichment (MITRE CWE REST API)
- VulnCheck enrichment (exploit / threat intelligence)
"""

from .cwe_enricher import CWEEnricher
from .vulncheck_enricher import VulnCheckEnricher
from .nvd_reference_scraper import NVDReferenceScraperEnricher

__all__ = [
    "CWEEnricher",
    "VulnCheckEnricher",
    "NVDReferenceScraperEnricher",
]


