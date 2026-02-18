# ML Threat Intelligence System

A production-grade threat intelligence pipeline that ingests vulnerability data from NIST NVD, collects OSINT from five external sources, and applies NLP enrichment for automated document classification, entity extraction, relation mapping, and risk scoring.

## Overview

This system provides an end-to-end pipeline for building a structured threat intelligence corpus:

- **Ingest** CVE/CPE records from the NIST National Vulnerability Database API
- **Enrich** CVE data with weakness details (MITRE CWE) and exploit intelligence (VulnCheck)
- **Scrape** NVD reference URLs for advisory content, patch notes, and write-ups
- **Collect** OSINT from PhishTank, ransomwatch, MITRE ATT&CK, ExploitDB, and AlienVault OTX
- **Classify** documents across six threat categories using weak supervision (Snorkel)
- **Extract** structured entities (CVEs, IPs, hashes, threat actors, malware) via regex and SecureBERT NER
- **Map** relationships between entities (exploits, uses, targets)
- **Score** risk with tier assignment (Critical / High / Medium / Low)
- **Store** all outputs in AWS S3 with date-based organization

## System Architecture

```
                          ┌──────────────────────────────────────┐
                          │     ML Threat Intelligence System     │
                          └──────────────────────────────────────┘

  Data Sources                  Pipeline                        Storage
 ─────────────────       ─────────────────────            ───────────────
 NIST NVD API ──────┐
                     ├──▶ NIST Ingesters ──────────────▶ S3: nist/cve/, nist/cpe/
 MITRE CWE API ─────┤
 VulnCheck API ─────┤
                     ├──▶ Enrichment Layer ────────────▶ S3: enriched/cve/cwe/
 NVD Reference URLs ┤                                       enriched/cve/vulncheck/
                     │                                       enriched/cve/ref_links/
 PhishTank ─────────┤
 ransomwatch ───────┤
 MITRE ATT&CK ─────┼──▶ OSINT Ingesters ──────────────▶ S3: osint/corpus/
 ExploitDB ─────────┤
 AlienVault OTX ────┘
                          │
                          ▼
                     NLP Pipeline
                     ├─ Weak Supervision (Snorkel LFs) ─▶ Document Labels
                     ├─ Entity Extraction (Regex + NER) ─▶ Structured Entities
                     ├─ Relation Extraction ─────────────▶ Entity Relationships
                     └─ Risk Scoring ────────────────────▶ S3: nlp/enriched/
```

## Key Components

### 1. NIST Data Ingestion (`ingesters/`)

- **NISTCVEIngester** -- fetches CVE records from NVD API with pagination, date filtering, and retry logic
- **NISTCPEIngester** -- fetches CPE records from NVD API

### 2. CVE Enrichment (`enrichment/`)

- **CWEEnricher** -- maps CWE IDs to full weakness details from MITRE (descriptions, mitigations, consequences, relationships)
- **VulnCheckEnricher** -- adds exploit intelligence, proof-of-concept availability, and active threat context
- **NVD Reference Scraper** -- fetches and classifies reference URLs from CVE records, extracts HTML/PDF content with quality scoring, stores raw text, cleaned text, and metadata under `enriched/cve/ref_links/`

### 3. OSINT Collection (`ingesters/`)

Five operational collectors that normalize output to a unified document schema:

| Source | Data Collected |
|---|---|
| **PhishTank** | Phishing URLs with target brand metadata |
| **ransomwatch** | Ransomware group leak site activity |
| **MITRE ATT&CK** | Threat actor intrusion sets with techniques and malware |
| **ExploitDB** | Exploit descriptions, platforms, and metadata |
| **AlienVault OTX** | Threat intelligence pulses with IOCs |

The assembled corpus contains approximately 600 documents across six categories (Vulnerability, Exploit, Phishing, Ransomware, Threat Actor, IOC).

### 4. NLP Enrichment (`nlp/`)

Sprint 1 of the NLP pipeline is code-complete and includes:

- **Weak Supervision** -- 17 labeling functions across 6 categories, aggregated via Snorkel's label model to produce probabilistic document labels
- **Entity Extraction** -- hybrid approach combining regex patterns for structured entities (CVE IDs, IP addresses, file hashes, URLs) with SecureBERT 2.0 NER for soft entities (threat actors, malware families, organizations)
- **Relation Extraction** -- rule-based extraction of typed relationships (exploits, uses, targets) between entity pairs
- **Entity Normalization** -- canonicalization of vendor names, threat actor aliases, and malware families
- **Risk Scoring** -- composite scoring with tier assignment (Critical / High / Medium / Low)
- **Evaluation** -- gold evaluation set of 100 stratified labeled documents with precision, recall, and F1 utilities per category

### 5. Orchestration (`orchestrators/`)

- **NISTIngestionOrchestrator** -- coordinates CVE/CPE ingestion workflows
- **NISTEnrichmentOrchestrator** -- coordinates CWE and VulnCheck enrichment
- **OSINTOrchestrator** -- coordinates OSINT collection across all five sources

### 6. Storage (`storage/`)

- **DataStorage** -- S3 and local storage with date-based organization, metadata tracking, and deduplication
- **ReferenceStorage** -- manages NVD reference scraping outputs
- **CorpusStorage** -- manages OSINT corpus storage and retrieval

### 7. Utilities (`utils/`)

- **APIClient** -- handles rate limiting, retries with exponential backoff, and error handling
- **RateLimiter** -- token bucket algorithm for API quota management

## Quick Start

### Prerequisites

- Python 3.8+
- AWS S3 bucket (optional; the system falls back to local storage)
- API keys listed below (some optional)

### Installation

```bash
git clone https://github.com/YussefAlta/ML-Threat-Intelligence-System.git
cd ML-Threat-Intelligence-System

python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Configuration

Create a `.env.local` file in the project root:

```bash
# NIST API (optional but recommended for higher rate limits)
NIST_API_KEY=your_nist_api_key_here

# MITRE CWE API (no key required)
CWE_API_BASE_URL=https://cwe-api.mitre.org/api/v1/

# VulnCheck API (required for VulnCheck enrichment)
VULNCHECK_API_KEY=your_vulncheck_api_key_here
VULNCHECK_API_BASE_URL=https://api.vulncheck.com/v3/

# AWS S3
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket-name

# OSINT Sources
PHISHTANK_API_KEY=your_phishtank_api_key  # optional
OTX_API_KEY=your_otx_api_key              # required for AlienVault OTX

# NLP Models
SECUREBERT_MODEL_NAME=jackaduma/SecBERT    # or custom checkpoint
SECUREBERT_NER_MODEL_NAME=jackaduma/SecBERT # or NER-specific checkpoint
```

### Basic Usage

#### Ingest CVE Data

```python
from src.threat_intelligence.core.config import Config
from src.threat_intelligence.orchestrators.nist_ingestion import NISTIngestionOrchestrator

config = Config()
orchestrator = NISTIngestionOrchestrator(config)

result = orchestrator.ingest_cves(days_back=7, max_count=100)
print(f"Ingested {result['records_fetched']} CVEs")
```

#### Enrich CVE Data

```python
from src.threat_intelligence.orchestrators.nist_enrichment import NISTEnrichmentOrchestrator
from src.threat_intelligence.storage.data_storage import DataStorage

config = Config()
storage = DataStorage(config)

latest_key = storage.get_latest_nist_cve_s3_key()
data = storage.load_json_from_s3(latest_key)
cves = data.get("vulnerabilities", [])[:10]

orchestrator = NISTEnrichmentOrchestrator(config)
results = orchestrator.enrich_cves(
    cve_records=cves,
    run_cwe=True,
    run_vulncheck=True
)

print(f"CWE enrichment: {results['cwe']['records']} records")
print(f"VulnCheck enrichment: {results['vulncheck']['records']} records")
```

#### Collect OSINT Corpus

```python
from src.threat_intelligence.orchestrators.osint_orchestrator import OSINTOrchestrator

config = Config()
orchestrator = OSINTOrchestrator(config)

results = orchestrator.collect_all()
for source, result in results.items():
    print(f"{source}: {result['documents']} documents")
```

## Testing

```bash
# NIST ingestion tests
python scripts/test_nist_ingestion.py --test all --max-count 10

# Enrichment pipeline tests
python scripts/test_phase2_enrichment.py

# Individual enrichment API tests
python scripts/test_enrichment_simple.py
```

## S3 Storage Layout

```
S3 Bucket/
├── nist/
│   ├── cve/YYYY/MM/DD/          # Raw CVE records from NVD
│   └── cpe/YYYY/MM/DD/          # Raw CPE records from NVD
├── enriched/cve/
│   ├── cwe/YYYY/MM/DD/          # CWE weakness details
│   ├── vulncheck/YYYY/MM/DD/    # VulnCheck exploit intelligence
│   └── ref_links/{date}/        # NVD reference URL content
│       ├── raw/                  #   Raw extracted text
│       ├── clean/                #   Cleaned text
│       └── meta/                 #   Classification and quality metadata
├── osint/corpus/YYYY/MM/DD/     # OSINT documents (unified schema)
└── nlp/enriched/{date}/         # NLP pipeline output
```

## Project Structure

```
ML-Threat-Intelligence-System/
├── src/threat_intelligence/
│   ├── core/              # Configuration management
│   ├── ingesters/         # NIST + OSINT ingesters (7 total)
│   ├── enrichment/        # CWE, VulnCheck, NVD reference scraping
│   ├── nlp/               # NLP pipeline (labeling, NER, relations, risk scoring)
│   ├── orchestrators/     # Workflow coordination (NIST + OSINT)
│   ├── storage/           # S3 storage (data, reference, corpus)
│   └── utils/             # API client, rate limiter
├── scripts/               # Run scripts and utilities
├── data/                  # Corpus and gold evaluation set
├── docs/                  # Documentation
├── tests/                 # Unit and integration tests
├── aws/                   # IAM policies
└── requirements.txt
```

## Dependencies

Key Python packages:

- `requests`, `feedparser` -- HTTP and RSS ingestion
- `boto3` -- AWS S3 storage
- `beautifulsoup4`, `langdetect`, `PyPDF2` -- content extraction and cleaning
- `transformers`, `torch` -- SecureBERT NER models
- `snorkel` -- weak supervision label aggregation
- `spacy`, `regex` -- NLP tokenization and pattern matching

See `requirements.txt` for the full list with pinned versions.

## Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) -- system architecture and design
- [Phase 1: NIST Ingestion](docs/PHASE1_NIST_INGESTION.md) -- CVE/CPE data ingestion
- [Phase 2: CVE Enrichment](docs/PHASE2_CVE_ENRICHMENT.md) -- CWE and VulnCheck enrichment
- [NVD Reference Enrichment](docs/NVD_REFERENCE_ENRICHMENT.md) -- NVD reference URL scraping
- [NLP Architecture Plan](docs/NLP_ARCHITECTURE_PLAN.md) -- NLP architecture and sprint roadmap
- [Enrichment Pipeline Status](docs/ENRICHMENT_PIPELINE_STATUS.md) -- pipeline status overview

## Next Steps

- Run the NLP pipeline end-to-end on the assembled OSINT corpus
- Evaluate classification and extraction quality against the gold evaluation set
- Tune Snorkel label model parameters based on evaluation metrics
- Explore fine-tuning SecureBERT NER on domain-specific labeled data
- Add real-time ingestion and streaming capabilities
- Build a dashboard for visualization and monitoring

## Contributing

This is a project for AVINT. For questions or issues, please contact the project maintainers.

## License

[Specify your license here]

## Acknowledgments

- **NIST NVD** -- comprehensive CVE/CPE vulnerability data
- **MITRE** -- CWE weakness enumeration and ATT&CK framework
- **VulnCheck** -- exploit intelligence
- **PhishTank** -- phishing URL intelligence
- **ransomwatch** -- ransomware leak site monitoring
- **ExploitDB** -- public exploit archive
- **AlienVault OTX** -- open threat intelligence exchange
