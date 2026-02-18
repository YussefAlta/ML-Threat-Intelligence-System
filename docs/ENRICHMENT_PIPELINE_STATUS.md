# Enrichment Pipeline Status

## Overview

This document describes the current state of the threat intelligence enrichment pipeline, which ingests CVE data and OSINT sources, enriches them with structured metadata, and prepares a unified corpus for NLP analysis.

## Pipeline Flow

```
NIST NVD API --> CVE/CPE Ingestion --> S3: nist/cve/, nist/cpe/
  |-> NVD Reference Scraping --> S3: enriched/cve/ref_links/{date}/{raw,clean,meta}/
  |-> CWE Enrichment         --> S3: enriched/cve/cwe/
  |-> VulnCheck Enrichment   --> S3: enriched/cve/vulncheck/

OSINT Sources (PhishTank, ransomwatch, MITRE ATT&CK, ExploitDB, AlienVault OTX)
  |-> OSINT Ingesters --> Unified Corpus --> S3: osint/corpus/

Unified Corpus (600 docs, 6 categories)
  |-> NLP Enrichment Pipeline --> S3: nlp/enriched/
        (labeling -> entity extraction -> NER -> relations -> risk scoring)
```

## Component Status

| # | Component | Class / Module | Status | Output |
|---|-----------|---------------|--------|--------|
| 1 | NIST CVE Ingestion | `NISTCVEIngester` | Operational | `nist/cve/` |
| 2 | NIST CPE Ingestion | `NISTCPEIngester` | Operational | `nist/cpe/` |
| 3 | CWE Enrichment | `CWEEnricher` | Operational | `enriched/cve/cwe/` |
| 4 | VulnCheck Enrichment | `VulnCheckEnricher` | Operational | `enriched/cve/vulncheck/` |
| 5 | NVD Reference Scraping | `NVDReferenceScraperEnricher` | Operational | `enriched/cve/ref_links/{date}/{raw,clean,meta}/` |
| 6 | OSINT - PhishTank | OSINT ingester | Operational | Phishing URLs with metadata |
| 7 | OSINT - ransomwatch | OSINT ingester | Operational | Ransomware group leak activity |
| 8 | OSINT - MITRE ATT&CK | OSINT ingester | Operational | Threat actor intrusion sets (techniques, malware, tools) |
| 9 | OSINT - ExploitDB | OSINT ingester | Operational | Exploit descriptions and metadata |
| 10 | OSINT - AlienVault OTX | OSINT ingester | Operational | Threat pulses with IOCs (requires API key) |
| 11 | Corpus Assembly | — | Operational | `data/corpus/combined_corpus.jsonl` (600 docs, 6 categories) |
| 12 | Gold Evaluation Set | — | Operational | `data/gold/gold_100.jsonl` (100 stratified labeled docs) |
| 13 | NLP Enrichment Pipeline | `src/threat_intelligence/nlp/` | Code Complete | `nlp/enriched/` (not yet run on full corpus) |

## Operational Components

### NIST CVE/CPE Ingestion

- **Components**: `NISTCVEIngester`, `NISTCPEIngester`
- **Source**: NIST NVD API
- **Output**: Raw CVE and CPE data in S3

### CWE Enrichment

- **Component**: `CWEEnricher`
- **Source**: MITRE CWE API
- **Enrichment**: Transforms CWE IDs into full weakness details (descriptions, consequences, mitigations, detection methods, hierarchy)
- **Output**: `enriched/cve/cwe/`

### VulnCheck Enrichment

- **Component**: `VulnCheckEnricher`
- **Source**: VulnCheck API
- **Enrichment**: Exploit availability, proof-of-concept data, threat context, vulnerability prioritization
- **Output**: `enriched/cve/vulncheck/`

### NVD Reference Scraping

- **Component**: `NVDReferenceScraperEnricher`
- **Function**: Fetches, classifies, and cleans reference URLs from CVE records
- **Output**: `enriched/cve/ref_links/{date}/{raw,clean,meta}/`

### OSINT Ingestion

Five sources, all operational:

| Source | Data Collected |
|--------|---------------|
| PhishTank | Phishing URLs with metadata |
| ransomwatch | Ransomware group leak site activity |
| MITRE ATT&CK | Threat actor intrusion sets with techniques, malware, tools |
| ExploitDB | Exploit descriptions and metadata |
| AlienVault OTX | Threat pulses with IOCs (requires API key) |

### Corpus Assembly and Gold Set

- **Corpus**: 600 unified documents across 6 categories in `data/corpus/combined_corpus.jsonl`
- **Gold Set**: 100 stratified labeled documents in `data/gold/gold_100.jsonl` for evaluation

## Code-Complete Components

### NLP Enrichment Pipeline

All modules are implemented in `src/threat_intelligence/nlp/` but have not yet been executed on the full corpus.

| Module | Description |
|--------|-------------|
| Weak supervision labeling | 17 labeling functions across 6 categories |
| Rule-based entity extraction | CVEs, IPs, hashes, domains |
| SecureBERT 2.0 NER | Threat actors, malware, organizations |
| Relation extraction | exploits, uses, targets relationships |
| Entity normalization | Deduplication and canonicalization |
| Risk scoring | Critical / High / Medium / Low classification |
| Evaluation utilities | Metrics against gold evaluation set |

## Next Steps

1. Run the NLP enrichment pipeline on the 600-document corpus
2. Evaluate weak supervision labels against the gold set (target F1 > 0.7)
3. Upload enriched outputs to S3 under `nlp/enriched/`
4. If F1 < 0.7, upgrade to Snorkel LabelModel or fine-tune SecureBERT 2.0
