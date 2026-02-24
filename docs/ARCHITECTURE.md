# System Architecture

## Overview

The ML Threat Intelligence System is an automated pipeline that ingests open-source threat intelligence from 7 data sources, classifies documents across 6 threat categories using weak supervision, extracts structured entities via regex and SecureBERT 2.0 NER, maps relationships between entities, scores risk, and stores all outputs in AWS S3.

The system processes 10,000+ documents with a classification macro F1 of 0.94 and NER entity macro F1 of 0.70.

## End-to-End Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DATA INGESTION                                   │
│                                                                         │
│  ExploitDB ────┐                                                        │
│  ransomwatch ──┤                                                        │
│  CISA KEV ─────┤                                                        │
│  MITRE ATT&CK ─┼──▶ OSINT Ingesters ──▶ Unified Corpus (JSONL)        │
│  PhishTank ────┤         │                     │                        │
│  ThreatFox ────┘         │                     ▼                        │
│                          │              Deduplication                    │
│  NIST NVD API ──▶ CVE Ingestion ──▶ S3: nist/cve/                     │
│                          │                                              │
│                          ▼                                              │
│                  CVE Enrichment                                         │
│                  ├─ CWE (MITRE API)     ──▶ S3: enriched/cve/cwe/      │
│                  ├─ VulnCheck API       ──▶ S3: enriched/cve/vulncheck/│
│                  └─ Reference Scraping  ──▶ S3: enriched/cve/ref_links/│
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        NLP ENRICHMENT                                   │
│                                                                         │
│  Unified Corpus (10,000 docs)                                          │
│       │                                                                 │
│       ├──▶ Classification (17 labeling functions, majority vote)        │
│       │    Output: 6 threat categories with confidence scores           │
│       │                                                                 │
│       ├──▶ Entity Extraction                                           │
│       │    ├─ Regex: CVE IDs, IPs, domains, URLs, hashes, CVSS        │
│       │    └─ SecureBERT 2.0 NER: malware, organizations, systems     │
│       │                                                                 │
│       ├──▶ Entity Normalization (canonical lookup tables)              │
│       │                                                                 │
│       ├──▶ Relation Extraction (rule-based pattern matching)           │
│       │    Types: exploits, uses, targets, drops, affects              │
│       │                                                                 │
│       └──▶ Risk Scoring (signal-based, 4-tier)                        │
│            Tiers: Critical, High, Medium, Low                          │
│                                                                         │
│       Output ──▶ S3: nlp/enriched/{date}/nlp_enriched_{ts}.jsonl      │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        EVALUATION                                       │
│                                                                         │
│  Gold Set (300 document labels + 1,964 entity annotations)             │
│       │                                                                 │
│       ├──▶ Classification F1 per category (macro F1 = 0.94)           │
│       └──▶ NER Entity F1 per type (macro F1 = 0.70)                  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Data Sources

| Source | Type | Auth Required | Documents | Category |
|--------|------|---------------|-----------|----------|
| ExploitDB | Public exploit archive | No | ~6,000 | exploit |
| ransomwatch | Ransomware leak tracker | No | ~2,000 | ransomware |
| CISA KEV | Known exploited vulns | No | ~1,527 | vulnerability |
| MITRE ATT&CK | Threat actor STIX data | No | ~181 | threat_actor |
| PhishTank | Phishing URL database | No | ~100 | phishing |
| ThreatFox (Abuse.ch) | IOC feed | No | ~50 groups | ioc |
| NIST NVD | CVE/CPE records | Optional key | ~200 refs | vulnerability |

## S3 Storage Layout

```
S3 Bucket/
├── nist/
│   ├── cve/{YYYY}/{MM}/{DD}/           # Raw CVE records
│   └── cpe/{YYYY}/{MM}/{DD}/           # Raw CPE records
├── enriched/cve/
│   ├── cwe/{YYYY}/{MM}/{DD}/           # CWE weakness details
│   ├── vulncheck/{YYYY}/{MM}/{DD}/     # VulnCheck exploit intel
│   └── ref_links/{date}/               # Scraped reference content
│       ├── raw/{cve_id}/               #   Raw HTML/PDF
│       ├── clean/{cve_id}/             #   Cleaned text
│       └── meta/{cve_id}/              #   Classification metadata
├── osint/corpus/{YYYY}/{MM}/{DD}/      # OSINT corpus (JSONL per source)
└── nlp/enriched/{YYYY}/{MM}/{DD}/      # NLP-enriched output (JSONL)
```

## Module Structure

```
src/threat_intelligence/
├── core/
│   └── config.py                  # Environment-driven configuration (all API keys, URLs, limits)
│
├── ingesters/                     # 7 data source ingesters
│   ├── nist_cve_ingester.py       # NIST NVD CVE API
│   ├── nist_cpe_ingester.py       # NIST NVD CPE API
│   ├── exploitdb_ingester.py      # ExploitDB CSV feed
│   ├── ransomwatch_ingester.py    # Ransomwatch GitHub JSON
│   ├── mitre_attack_ingester.py   # MITRE ATT&CK STIX bundle
│   ├── phishtank_ingester.py      # PhishTank phishing feed
│   ├── threatfox_ingester.py      # Abuse.ch ThreatFox IOC export
│   └── cisa_kev_ingester.py       # CISA Known Exploited Vulnerabilities
│
├── enrichment/                    # CVE enrichment pipeline
│   ├── cwe_enricher.py            # MITRE CWE API enrichment
│   ├── vulncheck_enricher.py      # VulnCheck API enrichment
│   ├── nvd_reference_scraper.py   # Reference URL scraping + classification
│   ├── content_cleaner.py         # HTML/PDF extraction, boilerplate removal, quality scoring
│   └── reference_classifier.py    # URL type classification (vendor advisory, GitHub, patch, etc.)
│
├── nlp/                           # NLP enrichment pipeline
│   ├── labeling_functions.py      # 17 weak supervision LFs across 6 categories
│   ├── entity_extractor.py        # Regex-based entity extraction (CVE, IP, hash, domain, CVSS)
│   ├── securebert_ner.py          # SecureBERT 2.0 NER (malware, org, system, indicator)
│   ├── normalizer.py              # Entity canonicalization (87 vendor/actor/malware mappings)
│   ├── relation_extractor.py      # Rule-based relation extraction (5 relation types)
│   ├── risk_scorer.py             # Risk tier assignment (10 signals, 4 tiers)
│   ├── nlp_enricher.py            # NLP pipeline orchestration + S3 storage
│   ├── evaluation.py              # P/R/F1 evaluation against gold set
│   ├── classifier.py              # SecureBERT fine-tuning (if weak labels F1 < 0.70)
│   └── prelabeler.py              # Heuristic pre-labeling for gold set creation
│
├── orchestrators/                 # Pipeline coordination
│   ├── nist_ingestion.py          # NIST CVE/CPE ingestion orchestrator
│   ├── nist_enrichment.py         # CWE + VulnCheck + reference scraping orchestrator
│   ├── osint_ingestion.py         # All OSINT sources orchestrator
│   ├── nlp_enrichment.py          # NLP pipeline orchestrator (load → enrich → evaluate → store)
│   └── master_pipeline.py         # End-to-end orchestrator (all stages)
│
├── storage/                       # AWS S3 storage
│   ├── data_storage.py            # NIST data + enriched CVE storage
│   ├── corpus_storage.py          # OSINT corpus + gold set storage
│   └── reference_storage.py       # NVD reference content storage
│
├── utils/
│   └── api_client.py              # HTTP client with rate limiting, retries, backoff
│
└── main.py                        # CLI entry point (ingest/osint/nlp/full stages)
```

## NLP Enriched Output Schema

Each document produces a JSON record with:

```json
{
  "id": "exploitdb_47526_9b1078ac",
  "source": "exploitdb",
  "title": "Exploit: Winrar 5.80 - XML External Entity Injection",
  "domain_labels": {
    "exploit": 0.5,
    "vulnerability": 0.33
  },
  "predicted_labels": {
    "exploit": 0.5,
    "vulnerability": 0.33
  },
  "entities": [
    {
      "type": "cve_id",
      "value": "CVE-2019-17124",
      "start": 45,
      "end": 60,
      "method": "regex",
      "canonical_value": "CVE-2019-17124"
    },
    {
      "type": "system",
      "value": "Winrar 5.80",
      "start": 10,
      "end": 21,
      "score": 0.95,
      "method": "securebert_ner",
      "canonical_value": "Winrar 5.80"
    }
  ],
  "relations": [
    {
      "type": "exploits",
      "source": "Winrar 5.80",
      "source_type": "system",
      "target": "CVE-2019-17124",
      "target_type": "cve_id",
      "evidence": "Winrar 5.80 exploit for CVE-2019-17124",
      "confidence": 0.9,
      "method": "rule_based"
    }
  ],
  "entity_summary": {
    "total": 5,
    "unique_cves": ["CVE-2019-17124"],
    "unique_ips": [],
    "unique_hashes": {"md5": [], "sha1": [], "sha256": []},
    "unique_domains": [],
    "unique_urls": ["https://exploit-db.com/exploits/47526"],
    "unique_emails": [],
    "cvss_scores": []
  },
  "risk_assessment": {
    "risk_tier": "high",
    "risk_score": 0.15,
    "signals": {
      "exploit_available": true,
      "actively_exploited": false,
      "severity_critical": false,
      "ransomware_mentioned": false
    },
    "contributing_factors": ["Exploit code or PoC available"]
  },
  "enriched_at": "2026-02-24T16:25:00+00:00",
  "enrichment_version": "1.0.0",
  "methods": {
    "classification": "weak_supervision_majority_vote",
    "entity_extraction": ["regex", "securebert_ner"],
    "entity_normalization": "canonical_lookup",
    "relation_extraction": "rule_based_v1",
    "risk_scoring": "rule_based_v1"
  }
}
```

## Classification Categories

| Category | Labeling Functions | Signals |
|----------|-------------------|---------|
| vulnerability | CVE pattern, advisory keywords, CVSS score | 3 LFs |
| exploit | PoC keywords, exploit URL patterns | 2 LFs |
| phishing | Phishing keywords, PhishTank source | 2 LFs |
| ransomware | Ransomware keywords, family names, ransomwatch source | 3 LFs |
| threat_actor | APT patterns, actor keywords, known actor names | 3 LFs |
| ioc | IP density, hash density, IOC keywords, ThreatFox source | 4 LFs |

## Entity Types

| Type | Method | Examples |
|------|--------|---------|
| cve_id | Regex | CVE-2024-1234 |
| ipv4 / ipv6 | Regex | 192.168.1.1 |
| domain | Regex | evil-domain.com |
| url | Regex | https://exploit-db.com/... |
| md5 / sha1 / sha256 | Regex | d41d8cd98f00b204e9800998ecf8427e |
| email | Regex | actor@evil.com |
| cvss_score | Regex | 9.8 |
| malware | SecureBERT NER | Cobalt Strike, LockBit, TrickBot |
| organization | SecureBERT NER | Microsoft, CrowdStrike, FBI |
| system | SecureBERT NER | Windows Server, Apache, Exchange |
| indicator | SecureBERT NER | C2 domain, malicious URL |
| vulnerability | SecureBERT NER | buffer overflow, privilege escalation |

## Evaluation Results

### Classification (300-doc gold set)

| Category | Precision | Recall | F1 |
|----------|-----------|--------|-----|
| vulnerability | 1.00 | 1.00 | 1.00 |
| phishing | 0.98 | 0.98 | 0.98 |
| ransomware | 0.98 | 0.98 | 0.98 |
| threat_actor | 1.00 | 0.90 | 0.95 |
| ioc | 1.00 | 0.88 | 0.94 |
| exploit | 0.79 | 0.76 | 0.78 |
| **Macro F1** | | | **0.94** |

### NER Entity Extraction (1,964-entity gold set)

| Type | Precision | Recall | F1 |
|------|-----------|--------|-----|
| ipv4 | 1.00 | 1.00 | 1.00 |
| cve_id | 1.00 | 0.97 | 0.98 |
| indicator | 0.82 | 1.00 | 0.90 |
| cvss_score | 0.75 | 1.00 | 0.85 |
| domain | 0.80 | 0.79 | 0.79 |
| malware | 0.68 | 0.47 | 0.56 |
| organization | 0.39 | 0.20 | 0.26 |
| system | 0.40 | 0.19 | 0.26 |
| **Macro F1** | | | **0.70** |
