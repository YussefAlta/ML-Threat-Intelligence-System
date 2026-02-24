# ML Threat Intelligence System

Automated threat intelligence pipeline that ingests OSINT from 7 sources, classifies documents across 6 threat categories, extracts entities via regex + SecureBERT 2.0 NER, maps entity relationships, scores risk, and stores everything in AWS S3.

**10,000 documents | Macro F1: 0.94 | 7 sources | 6 categories | 20K+ entities**

## Quick Start

```bash
git clone https://github.com/YussefAlta/ML-Threat-Intelligence-System.git
cd ML-Threat-Intelligence-System

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the full automated pipeline (ingest → NLP → evaluate)
python scripts/run_automated_pipeline.py --target 10000 --local-only
```

## What It Does

```
ExploitDB (6,500) ──┐
ransomwatch (2,000) ┤
CISA KEV (1,527) ───┤
MITRE ATT&CK (181) ─┼──▶ Dedup ──▶ NLP Pipeline ──▶ S3 Storage
PhishTank (100) ────┤                    │
ThreatFox (52) ─────┤              ┌─────┴──────┐
NVD Refs (200) ─────┘              │            │
                              Classification   Entity Extraction
                              (6 categories)   (regex + NER)
                                   │            │
                              Relation       Risk Scoring
                              Extraction     (4 tiers)
```

Each document is enriched with:
- **Labels**: vulnerability, exploit, phishing, ransomware, threat_actor, ioc (with confidence scores)
- **Entities**: CVE IDs, IPs, domains, hashes, malware names, organizations, systems
- **Relations**: exploits, uses, targets, drops, affects (between entity pairs)
- **Risk tier**: Critical / High / Medium / Low (with contributing signals)

## Run Commands

```bash
# Full automated pipeline (ingestion + NLP + evaluation)
python scripts/run_automated_pipeline.py --target 10000

# NLP only on existing corpus
python scripts/run_nlp_pipeline.py --corpus data/corpus/combined_corpus.jsonl

# NLP with SecureBERT NER (requires torch)
python scripts/run_nlp_pipeline.py --corpus data/corpus/combined_corpus.jsonl

# NLP without SecureBERT (regex-only entities, faster)
python scripts/run_nlp_pipeline.py --corpus data/corpus/combined_corpus.jsonl --no-securebert

# Full multi-stage pipeline (ingest → enrich → OSINT → NLP)
python scripts/run_full_pipeline.py

# Individual stages via main.py
python -m threat_intelligence.main nlp --corpus data/corpus/combined_corpus.jsonl
python -m threat_intelligence.main ingest --days-back 7
python -m threat_intelligence.main osint
python -m threat_intelligence.main full

# Run tests
pytest tests/ -v
```

## Configuration

Create `.env.local` in the project root:

```bash
# AWS S3 (required for S3 storage; omit for local-only mode)
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket

# NIST API (optional, increases rate limits)
NIST_API_KEY=your_nist_key

# VulnCheck (required for VulnCheck enrichment)
VULNCHECK_API_KEY=your_vulncheck_key
```

All other sources (ExploitDB, ransomwatch, MITRE ATT&CK, CISA KEV, ThreatFox) require no API keys.

## Project Structure

```
src/threat_intelligence/
├── core/config.py                 # Environment-driven configuration
├── ingesters/                     # 7 data source ingesters
│   ├── nist_cve_ingester.py       #   NIST NVD CVEs
│   ├── nist_cpe_ingester.py       #   NIST NVD CPEs
│   ├── exploitdb_ingester.py      #   ExploitDB exploits
│   ├── ransomwatch_ingester.py    #   Ransomware leak activity
│   ├── mitre_attack_ingester.py   #   MITRE ATT&CK threat actors
│   ├── phishtank_ingester.py      #   PhishTank phishing URLs
│   ├── threatfox_ingester.py      #   Abuse.ch ThreatFox IOCs
│   └── cisa_kev_ingester.py       #   CISA Known Exploited Vulnerabilities
├── enrichment/                    # CVE enrichment
│   ├── cwe_enricher.py            #   MITRE CWE weakness details
│   ├── vulncheck_enricher.py      #   VulnCheck exploit intelligence
│   ├── nvd_reference_scraper.py   #   Reference URL scraping
│   ├── content_cleaner.py         #   HTML/PDF text extraction
│   └── reference_classifier.py    #   URL type classification
├── nlp/                           # NLP enrichment pipeline
│   ├── labeling_functions.py      #   17 weak supervision labeling functions
│   ├── entity_extractor.py        #   Regex entity extraction
│   ├── securebert_ner.py          #   SecureBERT 2.0 NER model
│   ├── normalizer.py              #   Entity canonicalization
│   ├── relation_extractor.py      #   Rule-based relation extraction
│   ├── risk_scorer.py             #   Risk tier scoring
│   ├── nlp_enricher.py            #   Pipeline orchestration
│   ├── evaluation.py              #   F1 evaluation framework
│   ├── classifier.py              #   SecureBERT fine-tuning (optional)
│   └── prelabeler.py              #   Gold set pre-labeling
├── orchestrators/                 # Pipeline coordination
│   ├── nist_ingestion.py          #   NIST CVE/CPE orchestrator
│   ├── nist_enrichment.py         #   Enrichment orchestrator
│   ├── osint_ingestion.py         #   OSINT collection orchestrator
│   ├── nlp_enrichment.py          #   NLP pipeline orchestrator
│   └── master_pipeline.py         #   End-to-end orchestrator
├── storage/                       # AWS S3 + local storage
│   ├── data_storage.py            #   NIST data storage
│   ├── corpus_storage.py          #   Corpus + gold set storage
│   └── reference_storage.py       #   Reference content storage
├── utils/api_client.py            # HTTP client with rate limiting
└── main.py                        # CLI entry point

scripts/
├── run_automated_pipeline.py      # Full automated pipeline (target: 10K docs)
├── run_nlp_pipeline.py            # NLP-only pipeline
├── run_full_pipeline.py           # Multi-stage pipeline
├── run_osint_corpus_build.py      # OSINT corpus builder
└── run_nvd_ref_scrape_from_s3.py  # NVD reference scraping

data/
├── corpus/combined_corpus.jsonl   # 10,000-doc unified corpus
├── gold/gold_100.jsonl            # 300-doc classification gold set
└── gold/gold_entities.jsonl       # 1,964-entity NER gold set
```

## S3 Storage Layout

```
S3 Bucket/
├── nist/cve/{YYYY}/{MM}/{DD}/          # Raw CVE records
├── nist/cpe/{YYYY}/{MM}/{DD}/          # Raw CPE records
├── enriched/cve/
│   ├── cwe/{YYYY}/{MM}/{DD}/           # CWE enrichment
│   ├── vulncheck/{YYYY}/{MM}/{DD}/     # VulnCheck enrichment
│   └── ref_links/{date}/{raw,clean,meta}/  # Reference content
├── osint/corpus/{YYYY}/{MM}/{DD}/      # OSINT corpus JSONL
└── nlp/enriched/{YYYY}/{MM}/{DD}/      # NLP-enriched output
```

## Evaluation Results

**Classification** (300-doc gold set, macro F1 = **0.94**):

| Category | Precision | Recall | F1 |
|----------|-----------|--------|-----|
| vulnerability | 1.00 | 1.00 | 1.00 |
| phishing | 0.98 | 0.98 | 0.98 |
| ransomware | 0.98 | 0.98 | 0.98 |
| threat_actor | 1.00 | 0.90 | 0.95 |
| ioc | 1.00 | 0.88 | 0.94 |
| exploit | 0.79 | 0.76 | 0.78 |

**NER Entity Extraction** (1,964-entity gold set, macro F1 = **0.70**):

| Type | Precision | Recall | F1 |
|------|-----------|--------|-----|
| ipv4 | 1.00 | 1.00 | 1.00 |
| cve_id | 1.00 | 0.97 | 0.98 |
| indicator | 0.82 | 1.00 | 0.90 |
| cvss_score | 0.75 | 1.00 | 0.85 |
| domain | 0.80 | 0.79 | 0.79 |
| malware | 0.68 | 0.47 | 0.56 |

## Tech Stack

- **Python 3.8+** with boto3, requests, BeautifulSoup
- **SecureBERT 2.0** (cisco-ai/SecureBERT2.0-NER) for NER
- **Weak supervision** via majority vote labeling functions
- **AWS S3** for storage with date-based key organization

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** — full system architecture, module structure, output schemas, evaluation results
- **[NLP Architecture Plan](docs/archive/NLP_ARCHITECTURE_PLAN.md)** — original design document for the NLP pipeline

## License

George Mason University CYSE 492/493 Senior Design Capstone — AVINT Sponsor Project (Fall 2025 / Spring 2026).
