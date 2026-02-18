# System Architecture

## Overview

The ML Threat Intelligence System is a modular pipeline for ingesting, enriching, and classifying threat intelligence data from multiple sources. It combines structured vulnerability data (NIST NVD) with open-source intelligence (OSINT) feeds, applies NLP-based enrichment (weak supervision labeling, entity extraction, risk scoring), and stores all outputs in S3 with date-partitioned organization.

## High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                        Threat Intelligence System                              │
└────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐  ┌───────────┐  ┌────────────┐  ┌──────────┐  ┌────────────┐
  │  NIST NVD    │  │ PhishTank │  │ ransomwatch│  │MITRE     │  │ AlienVault │
  │  API         │  │ (JSON)    │  │ (GitHub)   │  │ATT&CK    │  │ OTX API    │
  └──────┬───────┘  └─────┬─────┘  └─────┬──────┘  │(STIX)    │  └─────┬──────┘
         │                │              │         └─────┬────┘        │
         │                │              │               │             │
         │                └──────┬───────┴───────┬───────┘             │
         │                       │               │                     │
         ▼                       ▼               ▼                     ▼
  ┌──────────────┐     ┌────────────────────────────────────────────────────┐
  │ NIST         │     │            OSINT Ingestion Orchestrator            │
  │ Ingesters    │     │  PhishTank | ransomwatch | MITRE ATT&CK |        │
  │ (CVE + CPE)  │     │  OTX | ExploitDB | NVD Reference Normalizer      │
  └──────┬───────┘     └───────────────────────┬────────────────────────────┘
         │                                      │
         ▼                                      ▼
  ┌──────────────┐                    ┌──────────────────────┐
  │ DataStorage  │                    │   CorpusStorage      │
  │ (S3: nist/)  │                    │   (S3: osint/corpus/)│
  └──────┬───────┘                    └──────────┬───────────┘
         │                                       │
         ▼                                       ▼
  ┌──────────────────────┐             ┌──────────────────────────────────────┐
  │ NIST Enrichment      │             │         NLP Enrichment Pipeline      │
  │ Orchestrator         │             │  Labeling Functions (weak supervision)│
  └──────┬───────────────┘             │  Entity Extraction (regex + NER)     │
         │                             │  Relation Extraction                 │
         ├────────────┬──────────┐     │  Risk Scoring                        │
         │            │          │     └─────────────────┬────────────────────┘
         ▼            ▼          ▼                       │
  ┌──────────┐ ┌──────────┐ ┌─────────────┐             ▼
  │ CWE      │ │VulnCheck │ │NVD Ref      │   ┌──────────────────────┐
  │ Enricher │ │Enricher  │ │Scraper      │   │ S3: nlp/enriched/    │
  └──────────┘ └──────────┘ └─────────────┘   └──────────────────────┘
         │            │          │
         ▼            ▼          ▼
  ┌──────────────────────────────────────┐
  │ S3: enriched/cve/{cwe,vulncheck,    │
  │     ref_links}                       │
  └──────────────────────────────────────┘
```

## Project Structure

```
ML-Threat-Intelligence-System/
├── src/threat_intelligence/
│   ├── core/              # Configuration management
│   ├── ingesters/         # NIST + OSINT API clients
│   ├── enrichment/        # CWE, VulnCheck, NVD reference scraping
│   ├── nlp/               # NLP pipeline (labeling, NER, relations, risk)
│   ├── orchestrators/     # Workflow coordination (NIST + OSINT)
│   ├── storage/           # S3 storage (data, reference, corpus)
│   └── utils/             # API client, rate limiter
├── scripts/               # Run scripts
├── data/                  # Corpus and gold set outputs
│   ├── corpus/            # combined_corpus.jsonl (~600 documents)
│   └── gold/              # gold_100.jsonl (stratified evaluation set)
├── docs/                  # Documentation
├── tests/                 # Tests
├── aws/                   # IAM policies
└── requirements.txt
```

## Component Details

### 1. Core Configuration (`core/config.py`)

Centralized configuration management using environment variables.

**Responsibilities:**
- Load configuration from `.env` and `.env.local` files
- Provide default values for all settings
- Validate required configuration

**Key Settings:**
- API endpoints and keys (NIST, MITRE CWE, VulnCheck, AlienVault OTX)
- Rate limiting parameters
- Retry logic configuration
- AWS S3 credentials and bucket name
- Storage paths

### 2. NIST Data Ingestion (`ingesters/nist_cve_ingester.py`, `nist_cpe_ingester.py`)

API clients for fetching structured vulnerability data from NIST NVD.

#### NISTCVEIngester

**Purpose:** Fetch CVE data from NIST NVD API

**Key Methods:**
- `fetch_cves()`: Fetch CVEs with date filtering and pagination
- `fetch_recent_cves()`: Fetch CVEs from last N days
- `fetch_cve_by_id()`: Fetch a specific CVE

**Features:**
- Automatic pagination handling
- Date-based filtering (publication date, modification date)
- Rate limit compliance
- Retry logic with exponential backoff
- CVE JSON 5.0 schema support

#### NISTCPEIngester

**Purpose:** Fetch CPE data from NIST NVD API

**Key Methods:**
- `fetch_cpes()`: Fetch CPEs with various filters
- `fetch_recent_cpes()`: Fetch recently modified CPEs
- `fetch_cpe_by_match_string()`: Fetch by CPE match string
- `fetch_cpes_by_keyword()`: Search CPEs by keyword

**Features:**
- Pagination support
- Keyword search
- CPE match string filtering
- Modification date filtering

### 3. OSINT Ingesters (`ingesters/`)

Five source-specific ingesters that pull threat intelligence from public feeds and normalize documents into a unified corpus schema.

| Ingester | Source | Format | Auth |
|---|---|---|---|
| `PhishTankIngester` | PhishTank phishing feed | JSON API | None |
| `RansomwatchIngester` | ransomwatch leak feed | GitHub-hosted JSON | None |
| `MITREAttackIngester` | MITRE ATT&CK intrusion sets | STIX 2.1 bundle | None |
| `OTXIngester` | AlienVault OTX threat pulses | REST API | API key |
| `ExploitDBIngester` | ExploitDB exploit database | GitLab CSV | None |

Each ingester returns a list of normalized document dicts with fields: `id`, `source`, `title`, `content`, `url`, `published`, `tags`, and source-specific metadata.

### 4. Data Enrichment (`enrichment/`)

Enrichers that augment CVE data with additional context from external sources.

#### CWEEnricher

**Purpose:** Enrich CVEs with MITRE CWE weakness details

**Process:**
1. Extract CWE IDs from NIST CVE records
2. Fetch full CWE details from MITRE CWE API
3. Fetch parent/child relationships
4. Cache results to avoid duplicate API calls

**Enrichment Data Added:**
- Weakness name and descriptions
- Common consequences
- Potential mitigations
- Demonstrative examples
- Detection methods
- Related weaknesses
- Parent/child relationships

#### VulnCheckEnricher

**Purpose:** Add exploit intelligence to CVEs

**Process:**
1. Query VulnCheck API for each CVE
2. Handle 404s gracefully (not all CVEs exist in VulnCheck)
3. Cache results (including 404s) to avoid duplicate calls

**Enrichment Data Added:**
- Exploit availability
- Proof-of-concept information
- Threat context
- Vulnerability prioritization data

#### NVD Reference Scraping (`nvd_reference_scraper.py`, `content_cleaner.py`, `reference_classifier.py`)

**Purpose:** Fetch, classify, and clean reference URLs from CVE records to extract advisory and exploit content

**Process:**
1. Load CVE records from S3 and extract reference URLs
2. Classify each URL by type (advisory, patch, exploit, vendor, GitHub advisory/commit/issue, media, etc.)
3. Fetch content with rotating user agents, rate limiting, and redirect handling
4. Clean HTML/PDF content: strip boilerplate, extract main text via `ContentCleaner`
5. Score quality and store raw HTML, cleaned text, and metadata separately

**Storage:** `enriched/cve/ref_links/{date}/{raw,clean,meta}/`

**Features:**
- URL deduplication and tracking-parameter stripping
- `ContentCleaner`: HTML extraction via BeautifulSoup, PDF extraction via PyPDF2, language detection, chunking for large documents
- `reference_classifier`: Rule-based URL type classification with content-hint refinement
- Media URLs (YouTube, Vimeo) are skipped by default (metadata only)
- GitHub-specific extraction for advisories, commits, and issues

### 5. NLP Enrichment Layer (`nlp/`)

A multi-stage NLP pipeline that classifies corpus documents, extracts entities and relations, and assigns risk scores.

#### Labeling Functions (`labeling_functions.py`)

17 weak supervision labeling functions covering 6 threat categories:

| Label | Category | Example Signals |
|---|---|---|
| 0 | Vulnerability | CVE IDs, CVSS scores, severity keywords |
| 1 | Exploit | PoC code, exploit-db URLs, 0-day mentions |
| 2 | Phishing | Credential harvesting, spoofed domains, social engineering |
| 3 | Ransomware | Encryption malware, leak sites, extortion |
| 4 | Threat Actor | APT/UNC/FIN group names, campaign attribution |
| 5 | IOC | IP addresses, file hashes (MD5/SHA1/SHA256), C2 infrastructure |

Aggregation uses majority vote. A Snorkel `LabelModel` upgrade path is available for conflict resolution.

#### Entity Extraction

- **`entity_extractor.py`** -- Rule-based extraction for CVE IDs, IPv4 addresses, MD5/SHA1/SHA256 hashes, domains, and URLs using compiled regex patterns
- **`securebert_ner.py`** -- SecureBERT 2.0 NER integration for soft entity extraction via HuggingFace `transformers`; falls back gracefully if model is unavailable

Entities from both sources are merged with deduplication.

#### Relation Extraction (`relation_extractor.py`)

Rule-based relation extraction producing triples such as:
- `(CVE-XXXX, exploits, product)`
- `(threat_actor, uses, malware)`
- `(CVE-XXXX, targets, platform)`

#### Entity Normalization (`normalizer.py`)

Canonicalizes extracted entities (e.g., uppercase CVE IDs, consistent hash formats).

#### Risk Scoring (`risk_scorer.py`)

Assigns a risk tier (Critical, High, Medium, Low) based on document labels, entity counts, and keyword signals.

#### NLP Enricher (`nlp_enricher.py`)

Main pipeline orchestrator that composes all NLP components. For each document:
1. Apply labeling functions (majority vote)
2. Run rule-based entity extraction
3. Optionally run SecureBERT NER and merge entities
4. Extract relations
5. Score risk tier
6. Output enriched JSON

#### Evaluation and Gold Set

- **`evaluation.py`** -- Computes precision, recall, and F1 against a gold evaluation set
- **`prelabeler.py`** -- Heuristic pre-labeling to bootstrap the gold set
- **`classifier.py`** -- SecureBERT 2.0 multi-label classifier scaffold (for future fine-tuning)

Gold set: `data/gold/gold_100.jsonl` (100 stratified, manually verified documents).

### 6. Orchestration (`orchestrators/`)

High-level coordinators that manage workflows.

#### NISTIngestionOrchestrator

**Purpose:** Coordinate CVE and CPE ingestion from NIST NVD

**Key Methods:**
- `ingest_cves()`: Ingest CVE data with date filtering
- `ingest_cpes()`: Ingest CPE data with date filtering
- `ingest_all()`: Ingest both CVE and CPE data

**Features:**
- Coordinated ingestion of both CVE and CPE data
- Incremental updates by date
- Error handling and recovery
- Progress tracking
- Idempotent operations

#### NISTEnrichmentOrchestrator

**Purpose:** Coordinate CVE enrichment (CWE + VulnCheck)

**Key Methods:**
- `enrich_cves()`: Enrich CVE records with CWE and/or VulnCheck data

**Features:**
- Flexible configuration (enable/disable individual enrichment sources)
- Error isolation (one enrichment failure doesn't stop others)
- Batch processing
- Detailed result reporting

#### OSINTIngestionOrchestrator

**Purpose:** Compose all OSINT source ingesters and build a unified corpus

**Available Sources:** `phishtank`, `ransomwatch`, `mitre_attack`, `otx`, `exploitdb`, `nvd_refs`

**Key Methods:**
- `run_all()`: Run all (or selected) ingesters, normalize output, save to S3 and/or local

**Features:**
- Per-source max document limits
- NVD reference content normalization into corpus schema
- Uploads to `osint/corpus/` in S3 with date partitioning
- Optional local mirroring to `data/corpus/`

### 7. Data Storage (`storage/`)

#### DataStorage (`data_storage.py`)

Unified storage interface for NIST and enrichment data.

**Features:**
- Automatic S3 initialization (if credentials provided)
- Local fallback (works without S3)
- Date-based organization for easy querying
- Metadata tracking
- Helper methods for loading data from S3

#### CorpusStorage (`corpus_storage.py`)

S3 storage for unified OSINT corpus documents.

**Features:**
- Stores JSONL files under `osint/corpus/{YYYY}/{MM}/{DD}/`
- Gold set upload/download support (`gold/gold_100.jsonl`)
- Local mirroring to `data/corpus/`

#### ReferenceStorage (`reference_storage.py`)

S3 storage for NVD reference scraping outputs.

**Features:**
- Stores raw HTML, cleaned text, and metadata under `enriched/cve/ref_links/{date}/`
- Three subdirectories per date: `raw/`, `clean/`, `meta/`

### 8. Utilities (`utils/`)

#### APIClient

**Purpose:** Unified API client with rate limiting and retry logic

**Features:**
- Rate limiting using token bucket algorithm
- Automatic retry with exponential backoff
- Error handling and logging
- Request/response logging
- Configurable timeouts

#### RateLimiter

**Purpose:** Token bucket rate limiter with sliding window

**Features:**
- Sliding window algorithm
- Automatic wait when rate limit reached
- Thread-safe (for future multi-threading)

## Data Flow

### NIST Ingestion Pipeline

```
1. NISTIngestionOrchestrator calls NISTCVEIngester.fetch_cves()
   ↓
2. APIClient handles rate limiting and makes API request
   ↓
3. Response parsed and pagination handled automatically
   ↓
4. DataStorage.save_cve_data() saves to S3 (nist/cve/) and/or local
   ↓
5. Returns ingestion result with record counts and S3 keys
```

### NIST Enrichment Pipeline

```
1. Load CVEs from S3 (nist/cve/)
   ↓
2. NISTEnrichmentOrchestrator.enrich_cves() called
   ↓
3. CWEEnricher extracts CWE IDs and fetches details from MITRE
   ↓
4. VulnCheckEnricher fetches exploit data from VulnCheck
   ↓
5. Enriched data saved to S3 (enriched/cve/cwe/ and enriched/cve/vulncheck/)
   ↓
6. Returns enrichment results with success status and record counts
```

### NVD Reference Scraping Pipeline

```
1. Load CVE records from S3 and extract reference URLs
   ↓
2. Classify each URL by type (advisory, patch, exploit, vendor, etc.)
   ↓
3. Fetch content with rate limiting and rotating user agents
   ↓
4. Clean HTML/PDF content via ContentCleaner
   ↓
5. Store raw, cleaned, and metadata to S3 (enriched/cve/ref_links/{date}/)
```

### OSINT Corpus Ingestion Pipeline

```
1. OSINTIngestionOrchestrator.run_all() invoked
   ↓
2. Each ingester fetches from its source:
   PhishTank → JSON API
   ransomwatch → GitHub JSON
   MITRE ATT&CK → STIX bundle
   OTX → REST API
   ExploitDB → GitLab CSV
   ↓
3. Documents normalized to unified schema
   ↓
4. NVD reference content (from ref_links/clean/) optionally normalized into corpus
   ↓
5. CorpusStorage saves JSONL to S3 (osint/corpus/) and/or local (data/corpus/)
```

### NLP Enrichment Pipeline

```
1. Load corpus documents from data/corpus/combined_corpus.jsonl
   ↓
2. For each document, NLPEnricher.enrich_document() runs:
   a. Weak supervision labeling (17 LFs → majority vote)
   b. Rule-based entity extraction (CVEs, IPs, hashes, domains, URLs)
   c. SecureBERT NER extraction (if available) → merge entities
   d. Relation extraction (exploits, uses, targets)
   e. Risk tier assignment (Critical/High/Medium/Low)
   ↓
3. Enriched documents saved to S3 (nlp/enriched/{date}/) and/or local
```

## Storage Structure

```
S3 Bucket/
├── nist/
│   ├── cve/
│   │   └── YYYY/MM/DD/
│   │       └── nist_cve_YYYYMMDD_HHMMSS.json
│   └── cpe/
│       └── YYYY/MM/DD/
│           └── nist_cpe_YYYYMMDD_HHMMSS.json
├── enriched/
│   └── cve/
│       ├── cwe/
│       │   └── YYYY/MM/DD/
│       │       └── enriched_cve_cwe_YYYYMMDD_HHMMSS.json
│       ├── vulncheck/
│       │   └── YYYY/MM/DD/
│       │       └── enriched_cve_vulncheck_YYYYMMDD_HHMMSS.json
│       └── ref_links/
│           └── {date}/
│               ├── raw/        (original HTML/PDF content)
│               ├── clean/      (extracted and cleaned text)
│               └── meta/       (URL classification, quality scores)
├── osint/
│   └── corpus/
│       └── YYYY/MM/DD/
│           └── osint_corpus_YYYYMMDD_HHMMSS.jsonl
└── nlp/
    └── enriched/
        └── {date}/
            └── nlp_enriched_YYYYMMDD_HHMMSS.jsonl
```

## Run Scripts

| Script | Purpose |
|---|---|
| `scripts/run_osint_corpus_build.py` | Build unified OSINT corpus from all sources |
| `scripts/pull_all_osint_and_label.py` | Pull OSINT data and apply NLP labeling |
| `scripts/pull_and_label_nvd_refs.py` | Pull and label NVD reference content |
| `scripts/run_nvd_ref_scrape_from_s3.py` | Scrape NVD reference URLs from S3 CVE data |

## Error Handling Strategy

### API Errors

- **429 Rate Limit**: Automatic retry with wait
- **5xx Server Errors**: Retry with exponential backoff
- **4xx Client Errors**: Log and skip (except 429)
- **Network Errors**: Retry with exponential backoff
- **404 Not Found**: Handled gracefully (normal for VulnCheck and some OSINT sources)

### Data Errors

- **Invalid JSON/CSV**: Logged and skipped
- **Missing Fields**: Default values used where possible
- **Storage Failures**: Logged, local fallback attempted

## Rate Limiting

### NIST API
- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds
- **Implementation**: Automatic rate limiting via APIClient

### MITRE CWE API
- **No API Key Required**: Public API
- **Rate Limit**: 10 requests per 60 seconds (conservative)
- **Implementation**: RateLimiter with sliding window

### VulnCheck API
- **Requires API Key**: Bearer token authentication
- **Rate Limit**: 10 requests per 60 seconds
- **Implementation**: RateLimiter with sliding window

### OSINT Sources
- PhishTank, ransomwatch, MITRE ATT&CK, ExploitDB: Public, no key required
- AlienVault OTX: Requires API key, rate-limited by OTX service

## Caching Strategy

### In-Memory Caching

**CWEEnricher:**
- Caches CWE details by CWE ID
- Prevents duplicate API calls for same CWE
- Cache persists for duration of enrichment session

**VulnCheckEnricher:**
- Caches VulnCheck data by CVE ID
- Caches 404 responses (to avoid retrying non-existent CVEs)
- Cache persists for duration of enrichment session

## Scalability Considerations

### Current Design
- **Single-threaded**: Sequential processing
- **In-memory caching**: Efficient for batch processing
- **Pagination**: Handles large datasets automatically
- **S3 Storage**: Scalable cloud storage
- **Modular ingesters**: Each source independent, easily parallelizable

## Security

### API Keys
- Stored in environment variables (`.env.local`)
- Never committed to repository
- Loaded via `python-dotenv`

### AWS Credentials
- Access key and secret key from environment
- S3 bucket access only (no other AWS services)
- Region-specific access

### Data Privacy
- Only public CVE/CPE/OSINT data (no PII)
- All data from public APIs and feeds
- No sensitive information stored

## Testing

### Test Scripts
- `test_nist_ingestion.py`: Tests NIST ingestion pipeline
- `test_phase2_enrichment.py`: Tests enrichment pipeline
- `test_enrichment_simple.py`: Simple enrichment test
- `test_enrichment_apis.py`: API connectivity tests

### Evaluation
- `nlp/evaluation.py`: Gold set evaluation (precision, recall, F1 per category)
- Gold set: 100 stratified, manually verified documents in `data/gold/gold_100.jsonl`

## Monitoring and Logging

### Logging Levels
- **INFO**: Normal operations, progress updates
- **WARNING**: Non-critical issues, missing data, fallback paths taken
- **ERROR**: Failures, exceptions
- **DEBUG**: Detailed debugging information

### Key Metrics to Monitor
- API request rates per source
- Success/failure rates
- Records ingested per run (per source)
- Records enriched per run
- Storage operations (S3 uploads)
- Rate limit hits
- NLP enrichment throughput

## Dependencies

### Core
- `requests`: HTTP client for API calls
- `boto3`: AWS S3 integration
- `python-dotenv`: Environment variable management

### Content Processing
- `beautifulsoup4`: HTML parsing and content extraction
- `lxml`: XML/HTML parsing backend
- `PyPDF2`: PDF text extraction
- `charset-normalizer`: Encoding detection
- `langdetect`: Language detection for scraped content
- `feedparser`: RSS/Atom feed parsing (OSINT sources)

### NLP / ML
- `transformers`: HuggingFace model loading (SecureBERT 2.0)
- `torch`: PyTorch backend for transformer models
- `tokenizers`: Fast tokenization
- `spacy`: Tokenization and NLP utilities
- `snorkel`: Weak supervision framework (labeling functions)
- `regex`: Extended regex for entity extraction

### Data
- `pandas`: Data manipulation (CSV/JSONL processing)
- `urllib3`: Low-level HTTP utilities

## Remaining Work

- **Run NLP enrichment on full corpus**: Execute the NLP pipeline across all ~600 corpus documents and persist enriched output to S3
- **Evaluate weak labels**: Measure labeling function coverage, accuracy, and conflict rates against the gold set; tune LF thresholds
- **Snorkel LabelModel upgrade**: Replace majority vote aggregation with a trained Snorkel `LabelModel` for better conflict resolution and noise-aware label estimation
- **Active learning**: Use gold set evaluation results to identify low-confidence documents and iteratively expand the gold set
- **SecureBERT fine-tuning**: Fine-tune the multi-label classifier (`classifier.py` scaffold) on weak-labeled data for end-to-end document classification
- **Real-time ingestion**: Webhook/streaming-based ingestion for continuous updates
- **Dashboard**: Monitoring and visualization interface for pipeline status and enriched data
- **Persistent caching**: Redis or DynamoDB for cross-session caching of API responses
