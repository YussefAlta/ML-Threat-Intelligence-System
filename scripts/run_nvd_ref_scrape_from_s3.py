#!/usr/bin/env python3
"""
Load NIST CVE data from S3 (or a local file), show how detailed our ref links are,
then scrape those CVEs' reference URLs, clean the content, and store under
enriched/cve/ref_links/(date ingested)/.

Usage:
  # From S3 (latest NIST CVE object)
  python scripts/run_nvd_ref_scrape_from_s3.py

  # Limit number of CVEs to process (e.g. first 5)
  python scripts/run_nvd_ref_scrape_from_s3.py --max-cves 5

  # Use a local NIST CVE JSON file instead of S3
  python scripts/run_nvd_ref_scrape_from_s3.py --local data/raw/nist_cve_20251203_120000.json

  # List what's in S3 and exit (no scraping)
  python scripts/run_nvd_ref_scrape_from_s3.py --list-only
"""

import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_intelligence.core.config import Config
from threat_intelligence.storage.data_storage import DataStorage
from threat_intelligence.enrichment.nvd_reference_scraper import NVDReferenceScraperEnricher
from threat_intelligence.enrichment.reference_classifier import classify_url, MEDIA

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _extract_references(cve_record: dict) -> list:
    """Extract reference_data from a CVE record (NIST 2.0 or legacy format)."""
    cve = cve_record.get("cve") or {}
    refs = cve.get("references")
    if isinstance(refs, list):
        return [r for r in refs if isinstance(r, dict) and r.get("url")]
    if isinstance(refs, dict):
        return refs.get("reference_data") or []
    return []


def _count_by_type(refs: list):
    """Return (total, count_media) for refs that have URLs."""
    total = 0
    media = 0
    for r in refs:
        url = r.get("url")
        if not url:
            continue
        total += 1
        if classify_url(url) == MEDIA:
            media += 1
    return total, media


def main():
    parser = argparse.ArgumentParser(
        description="Load NIST CVEs from S3 (or local), scrape reference links, clean and store."
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=None,
        help="Max number of CVEs to process (default: all)",
    )
    parser.add_argument(
        "--local",
        type=str,
        default=None,
        help="Path to local NIST CVE JSON file (overrides S3)",
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Only list S3 NIST CVE objects and exit (no scraping)",
    )
    args = parser.parse_args()

    config = Config()
    storage = DataStorage(config)

    # -------------------------------------------------------------------------
    # List-only: show what's in S3 under nist/cve/
    # -------------------------------------------------------------------------
    if args.list_only:
        if not storage.s3_client:
            logger.warning("S3 client not configured; cannot list objects.")
            return 1
        objects = storage.list_s3_objects("nist/cve/")
        if not objects:
            logger.info("No objects found under nist/cve/ in S3.")
            return 0
        logger.info("NIST CVE objects in S3 (nist/cve/):")
        for obj in sorted(objects, key=lambda o: o.get("LastModified", ""), reverse=True):
            key = obj.get("Key", "")
            mod = obj.get("LastModified", "")
            size = obj.get("Size", 0)
            logger.info("  %s  (modified: %s, size: %s bytes)", key, mod, size)
        return 0

    # -------------------------------------------------------------------------
    # Load CVE records: from local file or from S3
    # -------------------------------------------------------------------------
    cve_records = []
    source_label = ""

    if args.local:
        path = os.path.abspath(args.local)
        if not os.path.isfile(path):
            logger.error("Local file not found: %s", path)
            return 1
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cve_records = data.get("vulnerabilities", [])
        source_label = f"local:{path}"
    else:
        if not storage.s3_client:
            logger.error(
                "S3 client not configured. Use --local <path> to load from a local NIST CVE JSON file."
            )
            return 1
        latest_key = storage.get_latest_nist_cve_s3_key()
        if not latest_key:
            logger.error(
                "No NIST CVE objects found in S3 under nist/cve/. "
                "Run NIST ingestion first or use --local <path>."
            )
            return 1
        data = storage.load_json_from_s3(latest_key)
        if not data:
            logger.error("Failed to load JSON from S3 key: %s", latest_key)
            return 1
        cve_records = data.get("vulnerabilities", [])
        source_label = f"s3://{config.S3_BUCKET_NAME}/{latest_key}"

    if not cve_records:
        logger.warning("No CVE records in source. Exiting.")
        return 0

    # Optional limit
    if args.max_cves is not None:
        cve_records = cve_records[: args.max_cves]
        logger.info("Limited to first %s CVEs.", len(cve_records))

    # -------------------------------------------------------------------------
    # Detail summary: how many refs per CVE, sample URLs with ref_type
    # -------------------------------------------------------------------------
    enricher = NVDReferenceScraperEnricher(config)
    total_refs = 0
    total_media = 0
    cves_with_refs = 0
    sample_refs = []

    for rec in cve_records:
        refs = _extract_references(rec)
        if not refs:
            continue
        cves_with_refs += 1
        n_refs, n_media = _count_by_type(refs)
        total_refs += n_refs
        total_media += n_media
        cve_id = (rec.get("cve") or {}).get("id") or "?"
        for r in refs[:3]:
            url = r.get("url", "")
            if url and len(sample_refs) < 10:
                ref_type = classify_url(url)
                sample_refs.append((cve_id, url, ref_type))

    logger.info("=" * 70)
    logger.info("NIST CVE source: %s", source_label)
    logger.info("Total CVE records loaded: %s", len(cve_records))
    logger.info("CVEs with at least one reference: %s", cves_with_refs)
    logger.info("Total reference URLs: %s (media, skipped if NVD_REF_SKIP_MEDIA=True: %s)", total_refs, total_media)
    if sample_refs:
        logger.info("Sample reference URLs (first 10):")
        for cve_id, url, ref_type in sample_refs:
            skip = " (skipped: media)" if ref_type == MEDIA else f" [ref_type={ref_type}]"
            logger.info("  [%s] %s%s", cve_id, url[:80] + ("..." if len(url) > 80 else ""), skip)
    logger.info("=" * 70)

    # -------------------------------------------------------------------------
    # Run NVD reference scraper: fetch -> clean -> store to S3
    # -------------------------------------------------------------------------
    logger.info("Starting NVD reference scraping (fetch, clean, store)...")
    result = enricher.enrich_cves(cve_records)

    logger.info("=" * 70)
    logger.info("Reference scrape result:")
    logger.info("  URLs processed:             %s", result.get("urls_processed", 0))
    logger.info("  URLs succeeded (saved):    %s", result.get("urls_succeeded", 0))
    logger.info("  URLs failed:                %s", result.get("urls_failed", 0))
    logger.info("  URLs skipped (media):       %s", result.get("urls_skipped_media", 0))
    logger.info(
        "  Stored under: enriched/cve/ref_links/<date_ingested>/ (raw, clean, meta)"
    )
    logger.info("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
