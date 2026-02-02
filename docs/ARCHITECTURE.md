# System Architecture

## Overview

The ML Threat Intelligence System is a modular, production-ready pipeline for ingesting and enriching CVE (Common Vulnerabilities and Exposures) data. The system is designed with clear separation of concerns, robust error handling, and scalability in mind.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Threat Intelligence System                  │
└─────────────────────────────────────────────────────────────┘

                    ┌──────────────┐
                    │  NIST NVD    │
                    │     API      │
                    └──────┬───────┘
                           │
                           ▼
            ┌──────────────────────────┐
            │   NIST Ingesters         │
            │  - NISTCVEIngester       │
            │  - NISTCPEIngester       │
            └──────┬───────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │   DataStorage        │
        │  - S3 Storage        │
        │  - Local Storage     │
        └──────┬───────────────┘
               │
               ▼
    ┌──────────────────────────┐
    │  NISTEnrichment          │
    │  Orchestrator            │
    └──────┬───────────────────┘
           │
           ├──────────────────┐
           │                  │
           ▼                  ▼
    ┌─────────────┐    ┌──────────────┐
    │ CWEEnricher │    │VulnCheck     │
    │             │    │Enricher      │
    └──────┬──────┘    └──────┬───────┘
           │                  │
           ▼                  ▼
    ┌─────────────┐    ┌──────────────┐
    │ MITRE CWE  │    │ VulnCheck    │
    │    API     │    │    API       │
    └────────────┘    └──────────────┘
           │                  │
           └────────┬─────────┘
                    │
                    ▼
        ┌──────────────────────┐
        │   DataStorage        │
        │  (Enriched Data)     │
        └──────────────────────┘
```

## Component Details

### 1. Core Configuration (`core/config.py`)

Centralized configuration management using environment variables.

**Responsibilities:**
- Load configuration from `.env` and `.env.local` files
- Provide default values for all settings
- Validate required configuration

**Key Settings:**
- API endpoints and keys (NIST, MITRE, VulnCheck)
- Rate limiting parameters
- Retry logic configuration
- AWS S3 credentials
- Storage paths

### 2. Data Ingestion (`ingesters/`)

API clients for fetching data from NIST NVD API.

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

### 3. Data Enrichment (`enrichment/`)

Enrichers that augment CVE data with additional context.

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

### 4. Orchestration (`orchestrators/`)

High-level coordinators that manage workflows.

#### NISTIngestionOrchestrator

**Purpose:** Coordinate CVE and CPE ingestion

**Features:**
- Coordinated ingestion of both CVE and CPE data
- Incremental updates by date
- Error handling and recovery
- Progress tracking
- Idempotent operations

**Key Methods:**
- `ingest_cves()`: Ingest CVE data with date filtering
- `ingest_cpes()`: Ingest CPE data with date filtering
- `ingest_all()`: Ingest both CVE and CPE data

#### NISTEnrichmentOrchestrator

**Purpose:** Coordinate CVE enrichment workflow

**Features:**
- Flexible configuration (enable/disable individual enrichment sources)
- Error isolation (one enrichment failure doesn't stop others)
- Batch processing
- Detailed result reporting

**Key Methods:**
- `enrich_cves()`: Enrich CVE records with CWE and/or VulnCheck data

### 5. Data Storage (`storage/data_storage.py`)

Unified storage interface for S3 and local filesystem.

**Features:**
- Automatic S3 initialization (if credentials provided)
- Local fallback (works without S3)
- Date-based organization for easy querying
- Metadata tracking
- Helper methods for loading data from S3

**Storage Structure:**
```
S3 Bucket/
├── nist/
│   ├── cve/
│   │   └── YYYY/MM/DD/
│   │       └── nist_cve_YYYYMMDD_HHMMSS.json
│   └── cpe/
│       └── YYYY/MM/DD/
│           └── nist_cpe_YYYYMMDD_HHMMSS.json
└── enriched/
    └── cve/
        ├── cwe/
        │   └── YYYY/MM/DD/
        │       └── enriched_cve_cwe_YYYYMMDD_HHMMSS.json
        └── vulncheck/
            └── YYYY/MM/DD/
                └── enriched_cve_vulncheck_YYYYMMDD_HHMMSS.json
```

### 6. Utilities (`utils/`)

Shared utilities for API communication and rate limiting.

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

### Ingestion Pipeline

```
1. User/Orchestrator calls NISTCVEIngester.fetch_cves()
   ↓
2. APIClient handles rate limiting and makes API request
   ↓
3. Response parsed and pagination handled automatically
   ↓
4. DataStorage.save_cve_data() saves to S3 and/or local
   ↓
5. Returns ingestion result with record counts and S3 keys
```

### Enrichment Pipeline

```
1. Load CVEs from S3 (or provide directly)
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

## Error Handling Strategy

### API Errors

- **429 Rate Limit**: Automatic retry with wait
- **5xx Server Errors**: Retry with exponential backoff
- **4xx Client Errors**: Log and skip (except 429)
- **Network Errors**: Retry with exponential backoff
- **404 Not Found**: Handled gracefully (normal for VulnCheck)

### Data Errors

- **Invalid JSON**: Logged and skipped
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

### Future Enhancements
- Multi-threading for parallel enrichment
- Persistent caching (Redis/DynamoDB)
- Queue-based processing (SQS)
- Distributed processing (Lambda/ECS)

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
- Only public CVE/CPE data (no PII)
- All data from public APIs
- No sensitive information stored

## Testing

### Test Scripts
- `test_nist_ingestion.py`: Tests ingestion pipeline
- `test_phase2_enrichment.py`: Tests enrichment pipeline
- `test_enrichment_simple.py`: Simple enrichment test
- `test_enrichment_apis.py`: API connectivity tests

### Test Coverage
- Unit tests for individual components
- Integration tests for full pipelines
- Error handling tests
- Rate limiting tests

## Monitoring and Logging

### Logging Levels
- **INFO**: Normal operations, progress updates
- **WARNING**: Non-critical issues, missing data
- **ERROR**: Failures, exceptions
- **DEBUG**: Detailed debugging information

### Key Metrics to Monitor
- API request rates
- Success/failure rates
- Records ingested per run
- Records enriched per run
- Storage operations (S3 uploads)
- Rate limit hits

## Dependencies

### Core Dependencies
- `requests`: HTTP client for API calls
- `boto3`: AWS S3 integration
- `python-dotenv`: Environment variable management
- `beautifulsoup4`: HTML parsing (legacy, minimal use)

### Optional Dependencies
- `pandas`: Data analysis (if needed)
- `lxml`: XML/HTML parsing (if needed)

## Future Enhancements

### Planned Features
- **OSINT Enrichment** 🚧 (In Development)
  - Articles and blog posts enrichment
  - Social media feeds (Twitter/X, Reddit, LinkedIn)
  - GitHub repository analysis
  - Security advisories integration
  - Threat intelligence feed aggregation
- Real-time ingestion (webhooks/streaming)
- ML-based vulnerability prioritization
- Dashboard for monitoring and visualization
- API endpoints for querying enriched data

### Potential Integrations
- Notifications for critical CVEs
- SIEM integration for threat detection
- Automated remediation workflows

### OSINT Enrichment Pipeline (Planned)

```
┌─────────────────┐
│  OSINT        │
│  Sources      │
│  - Articles   │
│  - Social     │
│  - GitHub     │
└──────┬────────┘
       │
       ▼
┌─────────────────┐      ┌──────────────────┐
│  OSINT          │─────▶│  S3: enriched/    │
│  Enricher       │      │     osint/        │
│  (In Dev)       │      │                   │
└─────────────────┘      └──────────────────┘
       │
       └─▶ Links to CVE records
```

**Status**: Currently in development. Will extract CVEs/CWEs from OSINT sources and link them to CVE records for comprehensive threat intelligence.
