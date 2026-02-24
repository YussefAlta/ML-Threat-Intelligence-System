"""
Main entry point for the ML Threat Intelligence System.

Dispatches to the appropriate orchestrator based on command-line arguments.

Usage:
    python -m threat_intelligence.main nlp --corpus data/corpus/combined_corpus.jsonl
    python -m threat_intelligence.main full --days-back 7
    python -m threat_intelligence.main ingest
    python -m threat_intelligence.main osint
"""

import argparse
import logging
import sys

from .core.config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="ML Threat Intelligence System")
    parser.add_argument(
        "stage",
        nargs="?",
        default="nlp",
        choices=["ingest", "enrich", "osint", "nlp", "full"],
        help="Pipeline stage to run (default: nlp)",
    )
    parser.add_argument("--days-back", type=int, default=7)
    parser.add_argument("--max-per-source", type=int, default=200)
    parser.add_argument("--corpus", type=str, default=None)
    parser.add_argument("--gold", type=str, default=None)
    parser.add_argument("--no-securebert", action="store_true")
    parser.add_argument("--local-only", action="store_true")
    parser.add_argument(
        "--log-level", type=str, default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))
    config = Config()

    if args.stage == "nlp":
        from .orchestrators.nlp_enrichment import NLPEnrichmentOrchestrator
        orch = NLPEnrichmentOrchestrator(
            config=config, use_securebert=not args.no_securebert,
        )
        result = orch.run(
            corpus_path=args.corpus,
            gold_path=args.gold,
            upload_to_s3=not args.local_only,
        )
        logger.info("NLP enrichment success: %s", result.get("success"))

    elif args.stage == "full":
        from .orchestrators.master_pipeline import MasterPipelineOrchestrator
        orch = MasterPipelineOrchestrator(config)
        result = orch.run(
            days_back=args.days_back,
            max_per_source=args.max_per_source,
            corpus_path=args.corpus,
            gold_path=args.gold,
            use_securebert=not args.no_securebert,
            upload_to_s3=not args.local_only,
        )
        logger.info("Full pipeline success: %s", result.get("overall_success"))

    elif args.stage == "ingest":
        from .orchestrators.nist_ingestion import NISTIngestionOrchestrator
        orch = NISTIngestionOrchestrator(config)
        result = orch.ingest_all(days_back=args.days_back)
        logger.info("Ingestion success: %s", result.get("overall_success"))

    elif args.stage == "osint":
        from .orchestrators.osint_ingestion import OSINTIngestionOrchestrator
        orch = OSINTIngestionOrchestrator(config)
        result = orch.run_all(
            max_per_source=args.max_per_source,
            upload_to_s3=not args.local_only,
        )
        logger.info("OSINT corpus build: %d sources succeeded", result.get("sources_succeeded", 0))

    elif args.stage == "enrich":
        logger.info(
            "Use 'full' stage for enrichment (requires ingested CVE data), "
            "or run scripts/test_phase2_enrichment.py directly."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
