#!/usr/bin/env python3
"""
Build the OSINT threat intelligence corpus.

Runs all OSINT source ingesters and stores unified corpus documents to S3.

Usage:
    python scripts/run_osint_corpus_build.py
    python scripts/run_osint_corpus_build.py --max-per-source 100
    python scripts/run_osint_corpus_build.py --sources phishtank,ransomwatch
    python scripts/run_osint_corpus_build.py --local-only
"""

import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_intelligence.core.config import Config
from threat_intelligence.orchestrators.osint_ingestion import (
    OSINTIngestionOrchestrator,
    AVAILABLE_SOURCES,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Build the OSINT threat intelligence corpus."
    )
    parser.add_argument(
        "--max-per-source",
        type=int,
        default=200,
        help="Maximum records per source (default: 200)",
    )
    parser.add_argument(
        "--sources",
        type=str,
        default=None,
        help="Comma-separated list of sources (default: all)",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Skip S3 upload, save locally only",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    sources = None
    if args.sources:
        sources = [s.strip() for s in args.sources.split(",") if s.strip()]
        invalid = [s for s in sources if s not in AVAILABLE_SOURCES]
        if invalid:
            logger.error("Invalid sources: %s. Available: %s", invalid, AVAILABLE_SOURCES)
            return 1

    config = Config()
    orchestrator = OSINTIngestionOrchestrator(config)
    results = orchestrator.run_all(
        max_per_source=args.max_per_source,
        save_local=True,
        sources=sources,
        upload_to_s3=not args.local_only,
    )

    print("\n" + "=" * 70)
    print("OSINT Corpus Build Summary")
    print("=" * 70)
    for key in AVAILABLE_SOURCES:
        if key in results and isinstance(results[key], dict):
            r = results[key]
            status = "OK" if r.get("success") else "FAIL"
            count = r.get("count", 0)
            s3_key = r.get("s3_key") or "-"
            err = f" | {r.get('error', '')}" if not r.get("success") else ""
            print(f"  {key:20} [{status:4}] count={count:4}  s3_key={s3_key}{err}")
    print("-" * 70)
    print(f"  Total documents:    {results.get('total_documents', 0)}")
    print(f"  Sources succeeded: {results.get('sources_succeeded', 0)}")
    print(f"  Sources failed:     {results.get('sources_failed', 0)}")
    print("=" * 70 + "\n")

    return 0 if results.get("sources_failed", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
