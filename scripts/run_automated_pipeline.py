#!/usr/bin/env python3
"""
Automated end-to-end threat intelligence pipeline.

Ingests from all OSINT sources, deduplicates, runs NLP enrichment,
evaluates against gold set, and stores results locally and to S3.

Scales ingestion until target corpus size is reached.

Usage:
    python scripts/run_automated_pipeline.py
    python scripts/run_automated_pipeline.py --target 10000 --local-only
    python scripts/run_automated_pipeline.py --no-securebert
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_intelligence.core.config import Config
from threat_intelligence.ingesters.exploitdb_ingester import ExploitDBIngester
from threat_intelligence.ingesters.phishtank_ingester import PhishTankIngester
from threat_intelligence.ingesters.ransomwatch_ingester import RansomwatchIngester
from threat_intelligence.ingesters.mitre_attack_ingester import MITREAttackIngester
from threat_intelligence.ingesters.threatfox_ingester import ThreatFoxIngester
from threat_intelligence.ingesters.cisa_kev_ingester import CISAKEVIngester
from threat_intelligence.nlp.nlp_enricher import NLPEnricher, deduplicate_corpus
from threat_intelligence.nlp.evaluation import evaluate_labels, generate_report, load_gold_set
from threat_intelligence.storage.corpus_storage import CorpusStorage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Per-source ingestion targets scaled to reach ~10K total
SOURCE_TARGETS = {
    "exploitdb": 6500,
    "phishtank": 3000,
    "ransomwatch": 2000,
    "cisa_kev": 1527,
    "threatfox": 500,
    "mitre_attack": 200,
}


def ingest_all_sources(config, targets):
    """Ingest from all OSINT sources with given per-source limits."""
    all_docs = []
    results = {}

    source_ingesters = {
        "exploitdb": ExploitDBIngester(config),
        "phishtank": PhishTankIngester(config),
        "ransomwatch": RansomwatchIngester(config),
        "mitre_attack": MITREAttackIngester(config),
        "threatfox": ThreatFoxIngester(config),
        "cisa_kev": CISAKEVIngester(config),
    }

    for source, ingester in source_ingesters.items():
        max_records = targets.get(source, 200)
        logger.info("=" * 60)
        logger.info("Ingesting from %s (max=%d)...", source.upper(), max_records)
        try:
            docs = ingester.ingest(max_records=max_records)
            all_docs.extend(docs)
            results[source] = {"count": len(docs), "status": "OK"}
            logger.info("  %s: %d documents", source, len(docs))
        except Exception as e:
            logger.error("  %s FAILED: %s", source, e)
            results[source] = {"count": 0, "status": f"FAILED: {e}"}

    return all_docs, results


def load_existing_corpus(corpus_path):
    """Load existing corpus if available."""
    if not os.path.isfile(corpus_path):
        return []
    docs = []
    with open(corpus_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    docs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return docs


def save_corpus(docs, path):
    """Save corpus to JSONL."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for doc in docs:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Automated threat intelligence pipeline")
    parser.add_argument("--target", type=int, default=10000,
                        help="Target corpus size (default: 10000)")
    parser.add_argument("--corpus", type=str, default="data/corpus/combined_corpus.jsonl")
    parser.add_argument("--gold", type=str, default="data/gold/gold_100.jsonl")
    parser.add_argument("--no-securebert", action="store_true")
    parser.add_argument("--local-only", action="store_true")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))
    start_time = time.time()

    config = Config()
    corpus_storage = CorpusStorage(config)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ----------------------------------------------------------------
    # STAGE 1: INGESTION
    # ----------------------------------------------------------------
    print("\n" + "=" * 70)
    print("STAGE 1: DATA INGESTION")
    print("=" * 70)

    existing = load_existing_corpus(args.corpus)
    logger.info("Existing corpus: %d documents", len(existing))

    new_docs, ingest_results = ingest_all_sources(config, SOURCE_TARGETS)
    logger.info("New documents ingested: %d", len(new_docs))

    # ----------------------------------------------------------------
    # STAGE 2: DEDUPLICATION & MERGE
    # ----------------------------------------------------------------
    print("\n" + "=" * 70)
    print("STAGE 2: DEDUPLICATION & MERGE")
    print("=" * 70)

    combined = existing + new_docs
    unique = deduplicate_corpus(combined)
    removed = len(combined) - len(unique)
    logger.info("Combined: %d -> Deduped: %d (removed %d duplicates)", len(combined), len(unique), removed)

    # Trim to target if over
    if len(unique) > args.target:
        unique = unique[:args.target]
        logger.info("Trimmed to target: %d documents", len(unique))

    # Save updated corpus
    save_corpus(unique, args.corpus)
    logger.info("Saved corpus: %s (%d docs)", args.corpus, len(unique))

    # ----------------------------------------------------------------
    # STAGE 3: NLP ENRICHMENT
    # ----------------------------------------------------------------
    print("\n" + "=" * 70)
    print("STAGE 3: NLP ENRICHMENT")
    print("=" * 70)

    enricher = NLPEnricher(config=config, use_securebert=not args.no_securebert)
    enriched = enricher.enrich_corpus(unique, progress_interval=100)
    logger.info("Enriched: %d documents", len(enriched))

    # Save enriched output locally
    output_path = os.path.join("data", "processed", f"nlp_enriched_{ts}.jsonl")
    enricher.save_enriched(enriched, output_path)
    logger.info("Saved enriched: %s", output_path)

    # Save to S3
    s3_key = None
    if not args.local_only:
        s3_key = enricher.save_enriched_to_s3(enriched, corpus_storage)

    # Also save corpus to S3
    if not args.local_only:
        try:
            corpus_s3_key = corpus_storage.save_corpus_batch(
                documents=unique, source="combined", save_local=False, upload_to_s3=True,
            )
            logger.info("Corpus saved to S3: %s", corpus_s3_key)
        except Exception as e:
            logger.warning("Failed to save corpus to S3: %s", e)

    # ----------------------------------------------------------------
    # STAGE 4: EVALUATION
    # ----------------------------------------------------------------
    print("\n" + "=" * 70)
    print("STAGE 4: EVALUATION")
    print("=" * 70)

    report_path = os.path.join("data", "processed", f"eval_report_{ts}.txt")
    eval_results = None

    if os.path.isfile(args.gold):
        gold = load_gold_set(args.gold)
        eval_results = evaluate_labels(enriched, gold)
        report = generate_report(eval_results, output_path=report_path)
        logger.info("Evaluation report:\n%s", report)
    else:
        logger.warning("Gold set not found: %s", args.gold)

    # ----------------------------------------------------------------
    # SUMMARY
    # ----------------------------------------------------------------
    elapsed = time.time() - start_time
    from collections import Counter
    source_counts = Counter(d.get("source") for d in unique)
    label_counts = Counter()
    for d in enriched:
        for l in d.get("predicted_labels", {}):
            label_counts[l] += 1
    risk_tiers = Counter(d.get("risk_assessment", {}).get("risk_tier") for d in enriched)
    total_entities = sum(len(d.get("entities", [])) for d in enriched)
    total_relations = sum(len(d.get("relations", [])) for d in enriched)

    print("\n" + "=" * 70)
    print("PIPELINE COMPLETE")
    print("=" * 70)

    print(f"\n  Corpus size:       {len(unique)}")
    print(f"  Target:            {args.target}")
    print(f"  Duplicates removed: {removed}")
    print(f"  Enriched:          {len(enriched)}")
    print(f"  Elapsed:           {elapsed:.0f}s")

    print(f"\n  Source distribution:")
    for src, cnt in source_counts.most_common():
        status = ingest_results.get(src, {}).get("status", "existing")
        print(f"    {src:<15} {cnt:>6}  ({status})")

    print(f"\n  Label distribution:")
    for lbl, cnt in label_counts.most_common():
        print(f"    {lbl:<20} {cnt:>6} ({100*cnt/len(enriched):.1f}%)")

    print(f"\n  Risk tiers:")
    for tier in ["critical", "high", "medium", "low"]:
        cnt = risk_tiers.get(tier, 0)
        print(f"    {tier:<10} {cnt:>6} ({100*cnt/len(enriched):.1f}%)")

    print(f"\n  Entities: {total_entities} ({total_entities/len(enriched):.1f} avg)")
    print(f"  Relations: {total_relations}")

    if eval_results:
        macro_f1 = eval_results.get("macro_avg", {}).get("f1", 0)
        micro_f1 = eval_results.get("micro_avg", {}).get("f1", 0)
        matched = eval_results.get("matched_documents", 0)
        total_gold = eval_results.get("total_documents", 0)
        print(f"\n  Evaluation:")
        print(f"    Gold matched:    {matched} / {total_gold}")
        print(f"    Micro F1:        {micro_f1:.2f}")
        print(f"    Macro F1:        {macro_f1:.2f}")
        verdict = "PASS" if macro_f1 >= 0.70 else "FAIL"
        print(f"    Verdict:         {verdict}")

    print(f"\n  Output files:")
    print(f"    Corpus:   {args.corpus}")
    print(f"    Enriched: {output_path}")
    if report_path and os.path.isfile(report_path):
        print(f"    Report:   {report_path}")
    if s3_key:
        print(f"    S3 key:   {s3_key}")

    print("=" * 70 + "\n")

    if eval_results:
        macro_f1 = eval_results.get("macro_avg", {}).get("f1", 0)
        return 0 if macro_f1 >= 0.70 else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
