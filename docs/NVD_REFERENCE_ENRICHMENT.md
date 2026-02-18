# NVD Reference URL Scraping Enrichment

## Overview

This document describes the NVD Reference URL Scraping enrichment stage, which fetches and stores content from reference URLs listed in NIST CVE records. The stage runs immediately after CVE ingestion and **before** CWE and VulnCheck enrichments.

## Pipeline Placement

```
NIST NVD API → NISTCVEIngester → DataStorage.save_cve_data()
  → S3: nist/cve/YYYY/MM/DD/
  → NISTEnrichmentOrchestrator.enrich_cves()
    → NVDReferenceScraperEnricher (NEW) → S3: enriched/cve/ref_links/(date ingested)/
    → CWEEnricher → S3: enriched/cve/cwe/YYYY/MM/DD/
    → VulnCheckEnricher → S3: enriched/cve/vulncheck/YYYY/MM/DD/
```

The reference scraping enrichment is the **first** step in `enrich_cves()` and can be toggled via the `run_reference_scrape` parameter (default: `True`).

## S3 Layout

### Root Prefix

Reference content is stored under the **enriched** folder, aligned with other CVE enrichments:

```
enriched/cve/ref_links/<date_ingested>/
```

`<date_ingested>` is the fetch date in `YYYY-MM-DD` format.

### Subfolders

| Folder | Purpose |
|--------|---------|
| `raw/` | Raw fetched content (HTML, PDF, JSON, text, binary) |
| `clean/` | Cleaned plain text output |
| `meta/` | Metadata JSON files |

### Key Naming Pattern

```
enriched/cve/ref_links/<date_ingested>/<folder>/<cve_id>/<ref_index>_<url_hash>.<ext>
```

| Component | Description |
|-----------|-------------|
| `<date_ingested>` | Date ingested (fetch date), YYYY-MM-DD |
| `<folder>` | One of `raw`, `clean`, `meta` |
| `<cve_id>` | Literal CVE ID (e.g., CVE-2024-12345) |
| `<ref_index>` | Zero-padded index of reference in NVD list (000, 001, 002, …) |
| `<url_hash>` | Short deterministic hash of normalized URL (8 chars) |
| `<ext>` | Content type extension (.html, .pdf, .json, .txt, .bin) |

### Example

```
enriched/cve/ref_links/2025-02-06/raw/CVE-2024-12345/000_a1b2c3d4.html
enriched/cve/ref_links/2025-02-06/clean/CVE-2024-12345/000_a1b2c3d4.txt
enriched/cve/ref_links/2025-02-06/meta/CVE-2024-12345/000_a1b2c3d4.json
```

## Running Locally

### Prerequisites

- Python 3.8+
- Required packages: `beautifulsoup4`, `langdetect`, `PyPDF2`, `requests`

### Configuration

Set these environment variables (or use `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_REF_SCRAPE_ENABLED` | `True` | Enable/disable reference scraping |
| `NVD_REF_RATE_LIMIT_REQUESTS` | `10` | Max requests per window |
| `NVD_REF_RATE_LIMIT_WINDOW` | `60` | Window in seconds |
| `NVD_REF_TIMEOUT` | `30` | HTTP timeout (seconds) |
| `NVD_REF_MAX_RETRIES` | `3` | Retry attempts with backoff |
| `NVD_REF_MAX_SIZE_MB` | `10` | Max content size (bytes) |
| `NVD_REF_DEDUPE_TTL_DAYS` | `30` | Skip re-fetch if content exists and is newer than this |
| `NVD_REF_MAX_CHUNK_SIZE` | `1048576` | Max chunk size for large text (1MB) |
| `NVD_REF_USER_AGENT` | `ML-Threat-Intelligence-System/1.0` | User-Agent header |
| `NVD_REF_SKIP_MEDIA` | `True` | Skip fetching media URLs (YouTube, Vimeo, etc.); store metadata only |
| `NVD_REF_MIN_USEFUL_TEXT_LENGTH` | `50` | Min cleaned text length for quality label; below this marks `quality: "empty"` |

### AWS S3

Reference storage requires S3. Configure:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `S3_BUCKET_NAME`
- `AWS_REGION` (default: `us-east-1`)

If S3 is not configured, the enricher will process URLs but storage operations will be skipped (and will return `False`).

### Run Enrichment

```python
from src.threat_intelligence.core.config import Config
from src.threat_intelligence.orchestrators.nist_enrichment import NISTEnrichmentOrchestrator

config = Config()
orchestrator = NISTEnrichmentOrchestrator(config)

# With CVE records from ingestion
results = orchestrator.enrich_cves(
    cve_records,
    run_reference_scrape=True,
    run_cwe=True,
    run_vulncheck=True,
)
```

### Run Reference Scraping Only

```python
from src.threat_intelligence.enrichment.nvd_reference_scraper import NVDReferenceScraperEnricher

enricher = NVDReferenceScraperEnricher()
summary = enricher.enrich_cves(cve_records)
print(summary)  # urls_processed, urls_succeeded, urls_failed
```

## CI Integration

### Run Tests

```bash
# Install dependencies
pip install -r requirements.txt

# Run NVD reference scraper tests
pytest tests/test_nvd_reference_scraper.py -v
```

### Test Coverage

- URL normalization consistency
- URL hash stability (same URL → same hash)
- S3 key generation correctness
- Text cleaning routines
- Content type detection
- Integration tests with mocked HTTP responses

## Metadata Schema

Each metadata JSON file contains:

```json
{
  "cve_id": "CVE-2024-12345",
  "ref_index": 0,
  "original_url": "https://example.com/advisory",
  "normalized_url": "https://example.com/advisory",
  "final_url": "https://example.com/advisory",
  "ref_type": "vendor_advisory",
  "fetch_timestamp": "2025-02-06T10:30:00Z",
  "status_code": 200,
  "content_type": "text/html",
  "detected_encoding": "utf-8",
  "content_length": 15234,
  "content_truncated": false,
  "content_hash_sha256": "a1b2c3d4...",
  "extraction_success": true,
  "language": "en",
  "cleaned_text_length": 12345,
  "redirect_count": 0,
  "redirects": [],
  "quality": {
    "label": "good",
    "text_length": 12345,
    "sentence_count": 15,
    "has_cve_mention": true,
    "has_version_mention": true,
    "code_ratio": 0.05
  },
  "extracted_title": "Security Advisory",
  "extracted_meta_description": "A vulnerability in...",
  "error": null,
  "http_error_detail": null,
  "s3_keys": {
    "raw": "enriched/cve/ref_links/<date_ingested>/raw/...",
    "clean": "enriched/cve/ref_links/<date_ingested>/clean/...",
    "meta": "enriched/cve/ref_links/<date_ingested>/meta/..."
  }
}
```

## Troubleshooting

### No URLs processed

- Ensure CVE records have `cve.references.reference_data` populated.
- Check `NVD_REF_SCRAPE_ENABLED` is `True`.

### S3 upload failures

- Verify AWS credentials and bucket name.
- Ensure the bucket exists and the IAM user has `s3:PutObject` permission.

### Rate limiting / timeouts

- Reduce `NVD_REF_RATE_LIMIT_REQUESTS` or increase `NVD_REF_RATE_LIMIT_WINDOW`.
- Increase `NVD_REF_TIMEOUT` for slow hosts.

### PDF extraction failures

- Ensure `PyPDF2` (or `pdfplumber`) is installed.
- Some PDFs are image-based; extraction will fail and metadata will have `extraction_success: false`.

### Language detection unknown

- Short texts may return `"unknown"`. Install `langdetect` for detection.

## Module Structure

| Module | Purpose |
|--------|---------|
| `nvd_reference_scraper.py` | Main enricher: fetch, extract, store |
| `content_cleaner.py` | Text extraction (HTML/PDF), cleaning, chunking |
| `reference_storage.py` | S3 storage for raw, clean, meta |
