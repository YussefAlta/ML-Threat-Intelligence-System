#!/usr/bin/env python3
"""
Run the NLP enrichment pipeline.

Loads the threat intelligence corpus, runs weak supervision labeling,
entity extraction, normalization, relation extraction, and risk scoring,
then evaluates against the gold set and stores results.

Usage:
    python scripts/run_nlp_pipeline.py
    python scripts/run_nlp_pipeline.py --corpus data/corpus/combined_corpus.jsonl
    python scripts/run_nlp_pipeline.py --no-securebert --local-only
"""

import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_intelligence.core.config import Config
from threat_intelligence.orchestrators.nlp_enrichment import NLPEnrichmentOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Run the NLP enrichment pipeline.")
    parser.add_argument(
        "--corpus", type=str, default=None,
        help="Path to local corpus JSONL (default: load from S3)",
    )
    parser.add_argument(
        "--gold", type=str, default=None,
        help="Path to gold set JSONL (default: data/gold/gold_100.jsonl)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output path for enriched JSONL",
    )
    parser.add_argument(
        "--report", type=str, default=None,
        help="Output path for evaluation report",
    )
    parser.add_argument(
        "--no-securebert", action="store_true",
        help="Disable SecureBERT NER (use regex-only entities)",
    )
    parser.add_argument(
        "--local-only", action="store_true",
        help="Skip S3 upload",
    )
    parser.add_argument(
        "--log-level", type=str, default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    config = Config()
    orchestrator = NLPEnrichmentOrchestrator(
        config=config, use_securebert=not args.no_securebert,
    )
    results = orchestrator.run(
        corpus_path=args.corpus,
        gold_path=args.gold,
        output_path=args.output,
        report_path=args.report,
        upload_to_s3=not args.local_only,
        save_local=True,
    )

    # Print summary
    print("\n" + "=" * 70)
    print("NLP Enrichment Pipeline Summary")
    print("=" * 70)
    print(f"  Corpus documents:  {results.get('corpus_size', 0)}")
    print(f"  Dedup removed:     {results.get('dedup_removed', 0)}")
    print(f"  Enriched:          {results.get('enriched_count', 0)}")
    print(f"  S3 key:            {results.get('s3_key') or '-'}")
    print(f"  Output path:       {results.get('output_path') or '-'}")

    ev = results.get("evaluation")
    if ev:
        macro = ev.get("macro_avg", {})
        micro = ev.get("micro_avg", {})
        print(f"\n  Evaluation:")
        print(f"    Matched docs:    {ev.get('matched_documents', 0)} / {ev.get('total_documents', 0)}")
        print(f"    Micro F1:        {micro.get('f1', 0):.2f}")
        print(f"    Macro F1:        {macro.get('f1', 0):.2f}")
        verdict = "PASS" if macro.get("f1", 0) >= 0.70 else "FAIL"
        print(f"    Verdict:         {verdict}")
        print(f"    Report:          {results.get('report_path') or '-'}")

        # Print per-category breakdown
        per_cat = ev.get("per_category", {})
        if per_cat:
            print(f"\n    Per-Category:")
            print(f"    {'Category':<16} {'Prec':>6} {'Recall':>7} {'F1':>6} {'Support':>8}")
            for cat in ["vulnerability", "exploit", "phishing", "ransomware", "threat_actor", "ioc"]:
                if cat in per_cat:
                    m = per_cat[cat]
                    print(f"    {cat:<16} {m['precision']:>6.2f} {m['recall']:>7.2f} {m['f1']:>6.2f} {m['support']:>8}")

    print("=" * 70 + "\n")

    return 0 if results.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
