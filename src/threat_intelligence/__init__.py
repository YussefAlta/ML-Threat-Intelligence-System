"""
ML Threat Intelligence System

A production-ready system for ingesting and enriching CVE (Common Vulnerabilities and Exposures)
data from NIST's National Vulnerability Database (NVD) API with detailed context from
MITRE CWE and VulnCheck APIs.
"""

__version__ = "1.0.0"
__author__ = "AVINT Project"

# Core imports
from .core.config import Config
from .storage.data_storage import DataStorage

# Ingester imports
from .ingesters.nist_cve_ingester import NISTCVEIngester
from .ingesters.nist_cpe_ingester import NISTCPEIngester

# Orchestrator imports
from .orchestrators.nist_ingestion import NISTIngestionOrchestrator
from .orchestrators.nist_enrichment import NISTEnrichmentOrchestrator

# Enrichment imports
from .enrichment.cwe_enricher import CWEEnricher
from .enrichment.vulncheck_enricher import VulnCheckEnricher

__all__ = [
    'Config',
    'DataStorage',
    'NISTCVEIngester',
    'NISTCPEIngester',
    'NISTIngestionOrchestrator',
    'NISTEnrichmentOrchestrator',
    'CWEEnricher',
    'VulnCheckEnricher'
]
