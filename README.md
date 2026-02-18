# ML Threat Intelligence System

A production-ready threat intelligence system that ingests CVE (Common Vulnerabilities and Exposures) and CPE (Common Platform Enumeration) data from NIST's National Vulnerability Database (NVD) API and enriches it with detailed context from MITRE CWE and VulnCheck APIs.

## 🎯 Overview

This system provides a comprehensive pipeline for:
- **Ingesting** CVE/CPE data from NIST NVD API
- **Enriching** CVE data with detailed weakness information (MITRE CWE)
- **Enriching** CVE data with exploit intelligence (VulnCheck)
- **Storing** all data in AWS S3 with organized date-based structure
- **Managing** rate limits, retries, and error handling automatically

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Threat Intelligence System                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────┐
│  NIST NVD API   │
│  (CVE/CPE Data) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│  NIST Ingesters │─────▶│  S3 Storage      │
│  (API Clients)  │      │  (Raw Data)      │
└─────────────────┘      └────────┬─────────┘
                                  │
                                  ▼
┌─────────────────┐      ┌──────────────────┐
│  Enrichment     │─────▶│  S3 Storage      │
│  Orchestrator   │      │  (Enriched Data)  │
└─────────────────┘      └──────────────────┘
         │
         ├─▶ MITRE CWE API (Weakness Details)
         └─▶ VulnCheck API (Exploit Intelligence)
```

## 📦 Key Components

### 1. **Data Ingestion** (`ingesters/`)
- **NISTCVEIngester**: Fetches CVE data from NIST NVD API
- **NISTCPEIngester**: Fetches CPE data from NIST NVD API
- Features: Pagination, rate limiting, retry logic, date filtering

### 2. **Data Enrichment** (`enrichment/`)
- **CWEEnricher**: Enriches CVEs with MITRE CWE weakness details
- **VulnCheckEnricher**: Adds exploit intelligence from VulnCheck
- Features: Caching, error handling, relationship mapping

### 3. **Orchestration** (`orchestrators/`)
- **NISTIngestionOrchestrator**: Coordinates CVE/CPE ingestion
- **NISTEnrichmentOrchestrator**: Coordinates enrichment workflow
- Features: Error isolation, progress tracking, batch processing

### 4. **Storage** (`storage/`)
- **DataStorage**: Manages S3 and local storage
- Features: Date-based organization, metadata tracking, deduplication

### 5. **Utilities** (`utils/`)
- **APIClient**: Handles rate limiting, retries, error handling
- **RateLimiter**: Token bucket algorithm for API quotas

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- AWS S3 bucket (optional, for cloud storage)
- API Keys (optional, for higher rate limits):
  - NIST API Key (optional, but recommended)
  - VulnCheck API Key (required for VulnCheck enrichment)

### Installation

```bash
# Clone the repository
git clone https://github.com/YussefAlta/ML-Threat-Intelligence-System.git
cd ML-Threat-Intelligence-System

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
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

# AWS S3 Configuration (required for cloud storage)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket-name
```

### Basic Usage

#### Ingest CVE Data

```python
from src.threat_intelligence.core.config import Config
from src.threat_intelligence.orchestrators.nist_ingestion import NISTIngestionOrchestrator

config = Config()
orchestrator = NISTIngestionOrchestrator(config)

# Ingest recent CVEs (last 7 days)
result = orchestrator.ingest_cves(days_back=7, max_count=100)
print(f"Ingested {result['records_fetched']} CVEs")
```

#### Enrich CVE Data

```python
from src.threat_intelligence.orchestrators.nist_enrichment import NISTEnrichmentOrchestrator
from src.threat_intelligence.storage.data_storage import DataStorage

config = Config()
storage = DataStorage(config)

# Load CVEs from S3
latest_key = storage.get_latest_nist_cve_s3_key()
data = storage.load_json_from_s3(latest_key)
cves = data.get("vulnerabilities", [])[:10]  # First 10 CVEs

# Enrich with CWE and VulnCheck
orchestrator = NISTEnrichmentOrchestrator(config)
results = orchestrator.enrich_cves(
    cve_records=cves,
    run_cwe=True,
    run_vulncheck=True
)

print(f"CWE enrichment: {results['cwe']['records']} records")
print(f"VulnCheck enrichment: {results['vulncheck']['records']} records")
```

## 📚 Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)**: Detailed system architecture and design
- **[Phase 1: NIST Ingestion](docs/PHASE1_NIST_INGESTION.md)**: CVE/CPE data ingestion implementation
- **[Phase 2: CVE Enrichment](docs/PHASE2_CVE_ENRICHMENT.md)**: CWE and VulnCheck enrichment implementation
- **[Enrichment Pipeline Status](docs/ENRICHMENT_PIPELINE_STATUS.md)**: Current pipeline status and data flow

## 🧪 Testing

```bash
# Test NIST ingestion
python scripts/test_nist_ingestion.py --test all --max-count 10

# Test enrichment pipeline
python scripts/test_phase2_enrichment.py

# Test individual enrichment APIs
python scripts/test_enrichment_simple.py
```

## 📊 Data Flow

### Ingestion Flow

1. **NISTCVEIngester** fetches CVE data from NIST NVD API
   - Handles pagination automatically
   - Respects rate limits (5 requests/30 seconds without API key)
   - Retries on failures with exponential backoff
   - Filters by publication date or modification date

2. **DataStorage** saves raw CVE data to S3
   - Organized by date: `nist/cve/YYYY/MM/DD/`
   - Includes metadata: source, record count, ingestion timestamp

### Enrichment Flow

1. **NISTEnrichmentOrchestrator** loads CVEs from S3
2. **CWEEnricher** extracts CWE IDs from CVEs and fetches full details from MITRE
   - Adds descriptions, mitigations, consequences, relationships
3. **VulnCheckEnricher** fetches exploit intelligence for each CVE
   - Handles 404s gracefully (not all CVEs exist in VulnCheck)
4. **DataStorage** saves enriched data to S3
   - Organized by date: `enriched/cve/cwe/YYYY/MM/DD/`
   - Organized by date: `enriched/cve/vulncheck/YYYY/MM/DD/`

## 🔑 Key Features

### Robust API Handling
- **Rate Limiting**: Automatic rate limit management for all APIs
- **Retry Logic**: Exponential backoff for transient failures
- **Error Handling**: Graceful handling of 404s, timeouts, and API errors
- **Caching**: In-memory caching to avoid duplicate API calls

### Scalable Storage
- **S3 Integration**: Cloud storage with date-based organization
- **Local Fallback**: Works without S3 (saves locally)
- **Metadata Tracking**: Full audit trail of ingestion and enrichment

### Production Ready
- **Comprehensive Logging**: Detailed logs for debugging and monitoring
- **Idempotent Operations**: Safe to re-run without duplicating data
- **Incremental Updates**: Fetch only new/modified records
- **Batch Processing**: Efficient handling of large datasets

### Future Enhancements 🚧
- **NVD Reference Scraping**: Fetches and classifies reference URLs from NIST CVE records (advisory, GitHub advisory/commit/issue, media, code, etc.); all types including GitHub are scraped; media URLs are skipped by default. **OSINT Enrichment** (In Development): Articles, social media, and other open sources
- Real-time ingestion and streaming
- ML-based vulnerability prioritization
- Dashboard and visualization tools

## 📁 Project Structure

```
ML-Threat-Intelligence-System/
├── src/threat_intelligence/
│   ├── core/              # Configuration management
│   ├── ingesters/         # NIST API clients (CVE/CPE)
│   ├── enrichment/        # CWE and VulnCheck enrichers
│   ├── orchestrators/     # Workflow coordination
│   ├── storage/           # S3 and local storage
│   └── utils/             # API client, rate limiter
├── scripts/               # Test and utility scripts
├── docs/                  # Documentation
├── tests/                 # Unit and integration tests
└── requirements.txt       # Python dependencies
```

## 🔧 Configuration Options

See `src/threat_intelligence/core/config.py` for all configuration options:

- **NIST API**: Rate limits, retries, results per page
- **CWE API**: Rate limits, retries
- **VulnCheck API**: Rate limits, retries
- **AWS S3**: Region, bucket name, credentials
- **Storage**: Local data directory paths

## 📈 What Gets Enriched?

### NIST Provides (Raw CVE Data)
- CVE ID, description, severity scores
- **CWE IDs only** (e.g., "CWE-79") - just the identifier
- Affected products (CPE references)
- References and advisories

### Our Enrichment Adds

**From MITRE CWE API:**
- Full weakness descriptions and extended descriptions
- Common consequences (impact analysis)
- Potential mitigations (how to fix/prevent)
- Demonstrative examples (real-world scenarios)
- Detection methods
- Parent/child relationships (weakness hierarchy)
- 20+ additional fields

**From VulnCheck API:**
- Exploit intelligence
- Proof-of-concept availability
- Active threat context
- Vulnerability prioritization data

**From OSINT Sources** 🚧 (In Development):
- Articles and blog posts mentioning CVEs
- Social media discussions (Twitter/X, Reddit, LinkedIn)
- Reference articles and advisories linked from NIST NVD (e.g. vendor advisories, writeups; GitHub repos are excluded)
- Security advisories and bulletins
- Community insights and analysis

## 🤝 Contributing

This is a project for AVINT. For questions or issues, please contact the project maintainers.

## 📄 License

[Specify your license here]

## 🙏 Acknowledgments

- **NIST NVD**: For providing comprehensive CVE/CPE data
- **MITRE**: For CWE weakness enumeration data
- **VulnCheck**: For exploit intelligence data
