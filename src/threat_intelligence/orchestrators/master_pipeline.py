"""
Master Pipeline Orchestrator.

Connects all pipeline stages end-to-end:
1. NIST CVE/CPE ingestion
2. NIST enrichment (CWE, VulnCheck, reference scraping)
3. OSINT corpus build (5 sources + NVD refs)
4. NLP enrichment (labeling, entities, relations, risk scoring)

Each stage is optional and independently configurable.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..core.config import Config

logger = logging.getLogger(__name__)


class MasterPipelineOrchestrator:
    """
    End-to-end pipeline orchestrator. Composes all existing orchestrators
    in sequence, passing data between stages where applicable.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.config.validate()
        logger.info("Master Pipeline Orchestrator initialized")

    def run(
        self,
        run_nist_ingestion: bool = True,
        run_nist_enrichment: bool = True,
        run_osint_corpus: bool = True,
        run_nlp_enrichment: bool = True,
        days_back: int = 7,
        max_per_source: int = 200,
        corpus_path: Optional[str] = None,
        gold_path: Optional[str] = None,
        use_securebert: bool = True,
        save_local: bool = True,
        upload_to_s3: bool = True,
    ) -> Dict[str, Any]:
        """
        Run the full pipeline or selected stages.

        Args:
            run_nist_ingestion: Whether to run NIST CVE/CPE ingestion.
            run_nist_enrichment: Whether to run NIST enrichment.
            run_osint_corpus: Whether to run OSINT corpus build.
            run_nlp_enrichment: Whether to run NLP enrichment.
            days_back: Days of NIST data to ingest.
            max_per_source: Max records per OSINT source.
            corpus_path: Local corpus path for NLP (overrides S3 load).
            gold_path: Local gold set path for NLP evaluation.
            use_securebert: Whether to use SecureBERT NER.
            save_local: Whether to save outputs locally.
            upload_to_s3: Whether to upload outputs to S3.

        Returns:
            Dict with per-stage results and overall status.
        """
        results: Dict[str, Any] = {
            "started_at": datetime.now().isoformat(),
            "stages": {},
            "overall_success": False,
        }

        cve_records: List[Dict] = []

        # Stage 1: NIST ingestion
        if run_nist_ingestion:
            logger.info("=" * 60)
            logger.info("Stage 1: NIST CVE/CPE Ingestion")
            logger.info("=" * 60)
            try:
                from .nist_ingestion import NISTIngestionOrchestrator
                nist_orch = NISTIngestionOrchestrator(self.config)
                stage_result = nist_orch.ingest_cves(
                    days_back=days_back, save_local=save_local,
                )
                results["stages"]["nist_ingestion"] = stage_result

                if stage_result.get("success") and stage_result.get("s3_key"):
                    from ..storage.data_storage import DataStorage
                    storage = DataStorage(self.config)
                    data = storage.load_json_from_s3(stage_result["s3_key"])
                    if isinstance(data, dict):
                        cve_records = data.get("vulnerabilities", [])
                        logger.info("Loaded %d CVE records for enrichment", len(cve_records))
            except Exception as e:
                logger.error("NIST ingestion failed: %s", e)
                results["stages"]["nist_ingestion"] = {"success": False, "error": str(e)}

        # Stage 2: NIST enrichment
        if run_nist_enrichment and cve_records:
            logger.info("=" * 60)
            logger.info("Stage 2: NIST Enrichment (CWE, VulnCheck, Reference Scraping)")
            logger.info("=" * 60)
            try:
                from .nist_enrichment import NISTEnrichmentOrchestrator
                enrich_orch = NISTEnrichmentOrchestrator(self.config)
                stage_result = enrich_orch.enrich_cves(
                    cve_records, save_local=save_local,
                )
                results["stages"]["nist_enrichment"] = stage_result
            except Exception as e:
                logger.error("NIST enrichment failed: %s", e)
                results["stages"]["nist_enrichment"] = {"success": False, "error": str(e)}
        elif run_nist_enrichment and not cve_records:
            logger.info("Skipping NIST enrichment: no CVE records available")
            results["stages"]["nist_enrichment"] = {"success": True, "skipped": "no_cve_records"}

        # Stage 3: OSINT corpus build
        if run_osint_corpus:
            logger.info("=" * 60)
            logger.info("Stage 3: OSINT Corpus Build")
            logger.info("=" * 60)
            try:
                from .osint_ingestion import OSINTIngestionOrchestrator
                osint_orch = OSINTIngestionOrchestrator(self.config)
                stage_result = osint_orch.run_all(
                    max_per_source=max_per_source,
                    save_local=save_local,
                    upload_to_s3=upload_to_s3,
                )
                results["stages"]["osint_corpus"] = stage_result
            except Exception as e:
                logger.error("OSINT corpus build failed: %s", e)
                results["stages"]["osint_corpus"] = {"success": False, "error": str(e)}

        # Stage 4: NLP enrichment
        if run_nlp_enrichment:
            logger.info("=" * 60)
            logger.info("Stage 4: NLP Enrichment")
            logger.info("=" * 60)
            try:
                from .nlp_enrichment import NLPEnrichmentOrchestrator
                nlp_orch = NLPEnrichmentOrchestrator(
                    config=self.config, use_securebert=use_securebert,
                )
                stage_result = nlp_orch.run(
                    corpus_path=corpus_path,
                    gold_path=gold_path,
                    upload_to_s3=upload_to_s3,
                    save_local=save_local,
                )
                results["stages"]["nlp_enrichment"] = stage_result
            except Exception as e:
                logger.error("NLP enrichment failed: %s", e)
                results["stages"]["nlp_enrichment"] = {"success": False, "error": str(e)}

        # Determine overall success
        stages_run = results["stages"]
        if stages_run:
            results["overall_success"] = all(
                s.get("success", False) for s in stages_run.values()
            )
        results["completed_at"] = datetime.now().isoformat()

        logger.info("=" * 60)
        logger.info("Pipeline complete. Overall success: %s", results["overall_success"])
        for name, result in stages_run.items():
            status = "OK" if result.get("success", False) else "FAIL"
            logger.info("  %s: %s", name, status)
        logger.info("=" * 60)

        return results
