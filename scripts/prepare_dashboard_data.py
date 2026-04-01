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
from datetime import date, datetime, timedelta

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


def _parse_day(ts):
    """Parse ISO timestamp to YYYY-MM-DD, or None."""
    if not ts or not isinstance(ts, str):
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return s
        dt = datetime.fromisoformat(s)
        return dt.date().isoformat()
    except ValueError:
        return None


def doc_day(doc):
    """Prefer collection/publication time for trends; fallback enriched_at."""
    return (
        _parse_day(doc.get("collected_at"))
        or _parse_day(doc.get("published_at"))
        or _parse_day(doc.get("enriched_at"))
    )


def compute_trends(docs, max_days=90):
    """Time-bucketed counts for dashboard charts."""
    day_counts = Counter()
    day_source = defaultdict(Counter)
    day_risk = defaultdict(Counter)

    for doc in docs:
        d = doc_day(doc)
        if not d:
            continue
        day_counts[d] += 1
        day_source[d][doc.get("source", "unknown")] += 1
        ra = doc.get("risk_assessment") or {}
        day_risk[d][ra.get("risk_tier", "unknown")] += 1

    if not day_counts:
        return {
            "documents_by_day": [],
            "by_source_by_day": [],
            "by_risk_by_day": [],
            "window_days": max_days,
        }

    last_day = max(day_counts.keys())
    cutoff = (date.fromisoformat(last_day) - timedelta(days=max_days)).isoformat()
    window_days = sorted(d for d in day_counts if d >= cutoff)

    documents_by_day = [{"day": d, "count": day_counts[d]} for d in window_days]

    top_sources = [n for n, _ in Counter(doc.get("source", "unknown") for doc in docs).most_common(7)]
    by_source_by_day = []
    for d in window_days:
        row = {"day": d}
        for s in top_sources:
            row[s] = day_source[d].get(s, 0)
        by_source_by_day.append(row)

    risk_order = ["critical", "high", "medium", "low"]
    by_risk_by_day = []
    for d in window_days:
        row = {"day": d}
        for r in risk_order:
            row[r] = day_risk[d].get(r, 0)
        by_risk_by_day.append(row)

    return {
        "documents_by_day": documents_by_day,
        "by_source_by_day": by_source_by_day,
        "by_risk_by_day": by_risk_by_day,
        "window_days": max_days,
    }


CO_OCC_TYPES = frozenset({"cve_id", "domain", "malware", "organization", "ipv4", "ipv6"})
GRAPH_DOC_CAP = 150
GRAPH_MAX_NODES = 200
GRAPH_MAX_EDGES = 400


def build_graph_sample(docs):
    """Capped entity/relation graph from high-risk docs (relations + co-occurrence fallback)."""
    scored = []
    for d in docs:
        ra = d.get("risk_assessment") or {}
        scored.append((float(ra.get("risk_score") or 0), d))
    scored.sort(key=lambda x: -x[0])
    sample_docs = [d for _, d in scored[:GRAPH_DOC_CAP]]

    nodes = {}
    edges = []
    edge_seen = set()

    def node_id(raw, etype, doc_id):
        return f"{etype}:{raw}"[:240]

    def add_node(nid, label, ntype):
        if nid in nodes or len(nodes) >= GRAPH_MAX_NODES:
            return
        nodes[nid] = {"id": nid, "label": (label or "")[:200], "type": ntype}

    def add_edge(a, b, rel_type, doc_id):
        if a == b or not a or not b:
            return
        key = (a, b, rel_type) if a < b else (b, a, rel_type)
        if key in edge_seen or len(edges) >= GRAPH_MAX_EDGES:
            return
        edge_seen.add(key)
        edges.append(
            {"source": a, "target": b, "relation_type": rel_type, "doc_id": doc_id}
        )

    for doc in sample_docs:
        doc_id = doc.get("id", "")
        for rel in doc.get("relations") or []:
            s, t = rel.get("source"), rel.get("target")
            if not s or not t:
                continue
            sid = node_id(str(s), "mention", doc_id)
            tid = node_id(str(t), "mention", doc_id)
            add_node(sid, str(s), "relation_endpoint")
            add_node(tid, str(t), "relation_endpoint")
            add_edge(sid, tid, rel.get("type", "related"), doc_id)
            if len(edges) >= GRAPH_MAX_EDGES:
                break

        if len(edges) >= GRAPH_MAX_EDGES:
            break

        # Co-occurrence fallback: link key entity types within the same document
        ents = doc.get("entities") or []
        key_ents = []
        for e in ents:
            et = e.get("type", "")
            if et not in CO_OCC_TYPES:
                continue
            raw = (e.get("canonical_value") or e.get("value") or "").strip()
            if raw:
                key_ents.append((et, raw))
        per_doc_cap = 15
        key_ents = key_ents[:per_doc_cap]
        for i, (t1, v1) in enumerate(key_ents):
            for t2, v2 in key_ents[i + 1 :]:
                if v1 == v2 and t1 == t2:
                    continue
                nid1 = node_id(v1, t1, "")
                nid2 = node_id(v2, t2, "")
                add_node(nid1, v1, t1)
                add_node(nid2, v2, t2)
                add_edge(nid1, nid2, "co_occurs", doc_id)
                if len(edges) >= GRAPH_MAX_EDGES:
                    break
            if len(edges) >= GRAPH_MAX_EDGES:
                break

    truncated = len(edges) >= GRAPH_MAX_EDGES or len(nodes) >= GRAPH_MAX_NODES
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "truncated": truncated,
        "doc_sample_size": len(sample_docs),
    }

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
    stats["trends"] = compute_trends(docs, max_days=90)

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

    graph_sample = build_graph_sample(docs)
    graph_out = os.path.join(out_dir, "graph_sample.json")
    with open(graph_out, "w") as f:
        json.dump(graph_sample, f, ensure_ascii=False, indent=2)
    print(f"Wrote {graph_out} ({len(graph_sample['nodes'])} nodes, {len(graph_sample['edges'])} edges)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
