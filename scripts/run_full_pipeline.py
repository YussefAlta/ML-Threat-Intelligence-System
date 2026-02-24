#!/usr/bin/env python3
"""
Run the full threat intelligence pipeline end-to-end.

Stages: NIST ingestion -> enrichment -> OSINT corpus -> NLP enrichment.
Each stage is optional and can be skipped.

Usage:
    python scripts/run_full_pipeline.py
    python scripts/run_full_pipeline.py --nlp-only --corpus data/corpus/combined_corpus.jsonl
    python scripts/run_full_pipeline.py --days-back 14 --local-only
"""

import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_intelligence.core.config import Config
from threat_intelligence.orchestrators.master_pipeline import MasterPipelineOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Run the full threat intelligence pipeline.",
    )
    parser.add_argument("--days-back", type=int, default=7)
    parser.add_argument("--max-per-source", type=int, default=200)
    parser.add_argument("--corpus", type=str, default=None,
                        help="Local corpus path for NLP stage")
    parser.add_argument("--gold", type=str, default=None,
                        help="Gold set path for NLP evaluation")
    parser.add_argument("--no-securebert", action="store_true")
    parser.add_argument("--local-only", action="store_true",
                        help="Skip all S3 uploads")
    parser.add_argument("--nlp-only", action="store_true",
                        help="Skip ingestion/enrichment/OSINT, run NLP only")
    parser.add_argument("--skip-nlp", action="store_true",
                        help="Skip NLP enrichment stage")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    config = Config()
    orchestrator = MasterPipelineOrchestrator(config)

    results = orchestrator.run(
        run_nist_ingestion=not args.nlp_only,
        run_nist_enrichment=not args.nlp_only,
        run_osint_corpus=not args.nlp_only,
        run_nlp_enrichment=not args.skip_nlp,
        days_back=args.days_back,
        max_per_source=args.max_per_source,
        corpus_path=args.corpus,
        gold_path=args.gold,
        use_securebert=not args.no_securebert,
        save_local=True,
        upload_to_s3=not args.local_only,
    )

    # Print summary
    print("\n" + "=" * 70)
    print("Full Pipeline Summary")
    print("=" * 70)
    for stage_name, stage_result in results.get("stages", {}).items():
        success = stage_result.get("success", False)
        print(f"  {stage_name:25} {'OK' if success else 'FAIL'}")
    print(f"\n  Overall success: {results.get('overall_success', False)}")
    print("=" * 70 + "\n")

    return 0 if results.get("overall_success") else 1


if __name__ == "__main__":
    sys.exit(main())
