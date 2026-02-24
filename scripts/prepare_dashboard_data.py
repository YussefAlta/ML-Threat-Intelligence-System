#!/usr/bin/env python3
"""
Prepare enriched data for the dashboard frontend.

Reads the latest NLP-enriched JSONL and computes aggregate statistics.
Outputs two JSON files for the Next.js public/data/ directory:
  - enriched.json: array of all enriched documents (slimmed)
  - stats.json: pre-computed aggregate statistics
"""

import json
import os
import sys
import glob
from collections import Counter, defaultdict

def find_latest_enriched():
    pattern = os.path.join("data", "processed", "nlp_enriched_*.jsonl")
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None

def load_jsonl(path):
    docs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                docs.append(json.loads(line))
    return docs

def slim_doc(doc):
    """Remove bulky nested fields to reduce JSON size for frontend."""
    slimmed = dict(doc)
    # Remove entity_summary.entities (redundant with top-level entities)
    if "entity_summary" in slimmed:
        es = dict(slimmed["entity_summary"])
        es.pop("entities", None)
        slimmed["entity_summary"] = es
    return slimmed

def compute_stats(docs):
    source_counts = Counter()
    label_counts = Counter()
    risk_counts = Counter()
    entity_type_counts = Counter()
    relation_type_counts = Counter()
    total_entities = 0
    total_relations = 0
    docs_labeled = 0
    docs_unlabeled = 0
    multi_label = 0

    # For top entities
    top_cves = Counter()
    top_ips = Counter()
    top_domains = Counter()
    top_malware = Counter()
    top_orgs = Counter()

    # Label confidence aggregates
    label_confidences = defaultdict(list)

    # Risk score distribution
    risk_scores = []

    for doc in docs:
        source_counts[doc.get("source", "unknown")] += 1

        labels = doc.get("predicted_labels", {})
        if labels:
            docs_labeled += 1
            if len(labels) > 1:
                multi_label += 1
            for lbl, conf in labels.items():
                label_counts[lbl] += 1
                label_confidences[lbl].append(conf)
        else:
            docs_unlabeled += 1

        ra = doc.get("risk_assessment", {})
        risk_counts[ra.get("risk_tier", "unknown")] += 1
        risk_scores.append(ra.get("risk_score", 0))

        for ent in doc.get("entities", []):
            total_entities += 1
            etype = ent.get("type", "unknown")
            entity_type_counts[etype] += 1
            val = ent.get("value", "")
            if etype == "cve_id":
                top_cves[val] += 1
            elif etype in ("ipv4", "ipv6"):
                top_ips[val] += 1
            elif etype == "domain":
                top_domains[val] += 1
            elif etype == "malware":
                top_malware[val] += 1
            elif etype == "organization":
                top_orgs[val] += 1

        for rel in doc.get("relations", []):
            total_relations += 1
            relation_type_counts[rel.get("type", "unknown")] += 1

    return {
        "total_documents": len(docs),
        "docs_labeled": docs_labeled,
        "docs_unlabeled": docs_unlabeled,
        "multi_label_docs": multi_label,
        "total_entities": total_entities,
        "total_relations": total_relations,
        "avg_entities_per_doc": round(total_entities / len(docs), 1) if docs else 0,
        "sources": [{"name": k, "count": v} for k, v in source_counts.most_common()],
        "labels": [{"name": k, "count": v, "avg_confidence": round(sum(label_confidences[k]) / len(label_confidences[k]), 3) if label_confidences[k] else 0} for k, v in label_counts.most_common()],
        "risk_tiers": [{"name": k, "count": v} for k, v in [("critical", risk_counts.get("critical", 0)), ("high", risk_counts.get("high", 0)), ("medium", risk_counts.get("medium", 0)), ("low", risk_counts.get("low", 0))]],
        "entity_types": [{"name": k, "count": v} for k, v in entity_type_counts.most_common()],
        "relation_types": [{"name": k, "count": v} for k, v in relation_type_counts.most_common()],
        "top_cves": [{"value": k, "count": v} for k, v in top_cves.most_common(20)],
        "top_ips": [{"value": k, "count": v} for k, v in top_ips.most_common(20)],
        "top_domains": [{"value": k, "count": v} for k, v in top_domains.most_common(20)],
        "top_malware": [{"value": k, "count": v} for k, v in top_malware.most_common(20)],
        "top_organizations": [{"value": k, "count": v} for k, v in top_orgs.most_common(20)],
        "evaluation": {
            "classification_macro_f1": 0.94,
            "ner_macro_f1": 0.70,
            "classification_per_category": [
                {"name": "vulnerability", "precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 59},
                {"name": "exploit", "precision": 0.79, "recall": 0.76, "f1": 0.78, "support": 66},
                {"name": "phishing", "precision": 0.98, "recall": 0.98, "f1": 0.98, "support": 50},
                {"name": "ransomware", "precision": 0.98, "recall": 0.98, "f1": 0.98, "support": 52},
                {"name": "threat_actor", "precision": 1.00, "recall": 0.90, "f1": 0.95, "support": 51},
                {"name": "ioc", "precision": 1.00, "recall": 0.88, "f1": 0.94, "support": 50},
            ],
            "ner_per_type": [
                {"name": "ipv4", "precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 229},
                {"name": "cve_id", "precision": 1.00, "recall": 0.97, "f1": 0.98, "support": 62},
                {"name": "indicator", "precision": 0.82, "recall": 1.00, "f1": 0.90, "support": 49},
                {"name": "cvss_score", "precision": 0.75, "recall": 1.00, "f1": 0.85, "support": 103},
                {"name": "domain", "precision": 0.80, "recall": 0.79, "f1": 0.79, "support": 140},
                {"name": "malware", "precision": 0.68, "recall": 0.47, "f1": 0.56, "support": 381},
                {"name": "organization", "precision": 0.39, "recall": 0.20, "f1": 0.26, "support": 544},
                {"name": "system", "precision": 0.40, "recall": 0.19, "f1": 0.26, "support": 456},
            ],
        },
    }


def main():
    enriched_path = find_latest_enriched()
    if not enriched_path:
        print("No enriched JSONL found in data/processed/")
        return 1

    print(f"Reading: {enriched_path}")
    docs = load_jsonl(enriched_path)
    print(f"Loaded {len(docs)} documents")

    # Compute stats
    stats = compute_stats(docs)

    # Slim documents
    slimmed = [slim_doc(d) for d in docs]

    # Output
    out_dir = os.path.join("dashboard", "public", "data")
    os.makedirs(out_dir, exist_ok=True)

    enriched_out = os.path.join(out_dir, "enriched.json")
    with open(enriched_out, "w") as f:
        json.dump(slimmed, f, ensure_ascii=False)
    print(f"Wrote {enriched_out} ({os.path.getsize(enriched_out) / 1024 / 1024:.1f} MB)")

    stats_out = os.path.join(out_dir, "stats.json")
    with open(stats_out, "w") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"Wrote {stats_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
