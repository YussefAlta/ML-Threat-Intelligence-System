"""
CWE enrichment for CVE records using the MITRE CWE REST API.

This module:
- Extracts CWE IDs from NIST CVE records
- Queries the CWE API for weakness details
- Caches responses to avoid duplicate API calls
- Produces an enrichment structure suitable for storage
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Any, Set

from ..core.config import Config
from ..utils.api_client import APIClient, RateLimiter

logger = logging.getLogger(__name__)


class CWEEnricher:
    """
    Enrich CVE records with CWE weakness details.

    Usage pattern:
        enricher = CWEEnricher(config)
        enriched = enricher.enrich_cves(cve_records)

    The result is a list of dicts, each containing:
        {
          "cve_id": "CVE-2024-1234",
          "cwe_ids": ["79", "89"],
          "cwe_details": {
              "79": {
                  ...full CWE weakness details including:
                  - Name, Description, ExtendedDescription
                  - CommonConsequences, PotentialMitigations
                  - DemonstrativeExamples, ObservedExamples
                  - DetectionMethods, RelatedWeaknesses
                  - Relationships (parents/children)
                  - And all other MITRE CWE fields
                  ...,
                  "relationships": {
                      "parents": [...],
                      "children": [...]
                  }
              },
              "89": {...}
          }
        }
    """

    CWE_ID_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

        # Rate limiter for CWE API
        rate_limiter = RateLimiter(
            max_requests=self.config.CWE_RATE_LIMIT_REQUESTS,
            window_seconds=self.config.CWE_RATE_LIMIT_WINDOW,
        )

        # CWE API client (no API key needed)
        self.api_client = APIClient(
            base_url=self.config.CWE_API_BASE_URL,
            api_key=None,
            rate_limiter=rate_limiter,
            max_retries=self.config.CWE_MAX_RETRIES,
            backoff_multiplier=self.config.NIST_RETRY_BACKOFF,
            timeout=30,
        )

        # Simple in-memory cache to avoid duplicate lookups
        self._cwe_cache: Dict[str, Dict[str, Any]] = {}

        # Maximum number of CWE IDs per multi-ID request
        self.max_ids_per_request: int = 50

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_cves(self, cve_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a list of CVE records with CWE weakness details.

        Args:
            cve_records: List of NIST CVE records (as returned by NISTCVEScraper)

        Returns:
            List of enrichment records (one per CVE that has CWE IDs)
        """
        if not cve_records:
            logger.info("No CVE records provided for CWE enrichment")
            return []

        # 1) Extract CWE IDs per CVE
        cve_to_cwe_ids: Dict[str, Set[str]] = {}
        all_cwe_ids: Set[str] = set()

        for cve in cve_records:
            cve_data = cve.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
                continue

            cwe_ids = self._extract_cwe_ids_from_cve(cve_data)
            if not cwe_ids:
                continue

            cve_to_cwe_ids[cve_id] = cwe_ids
            all_cwe_ids.update(cwe_ids)

        if not all_cwe_ids:
            logger.info("No CWE IDs found in provided CVE records")
            return []

        logger.info(
            f"Found {len(all_cwe_ids)} unique CWE IDs across "
            f"{len(cve_to_cwe_ids)} CVEs"
        )

        # 2) Fetch CWE details (using cache + multi-ID requests)
        self._populate_cwe_cache(all_cwe_ids)

        # 3) Build enrichment records
        enriched: List[Dict[str, Any]] = []
        for cve in cve_records:
            cve_data = cve.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id or cve_id not in cve_to_cwe_ids:
                continue

            cwe_ids = sorted(cve_to_cwe_ids[cve_id])
            cwe_details = {
                cwe_id: self._cwe_cache.get(cwe_id)
                for cwe_id in cwe_ids
                if cwe_id in self._cwe_cache
            }

            enriched.append(
                {
                    "cve_id": cve_id,
                    "cwe_ids": cwe_ids,
                    "cwe_details": cwe_details,
                }
            )

        logger.info(
            f"CWE enrichment completed for {len(enriched)} CVEs "
            f"(from {len(cve_records)} input records)"
        )
        return enriched

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_cwe_ids_from_cve(self, cve_data: Dict[str, Any]) -> Set[str]:
        """
        Extract CWE IDs (as strings without the 'CWE-' prefix) from a CVE record.

        NIST CVE JSON 5.0 typically encodes weaknesses like:
            cve.weaknesses[].description[].value = 'CWE-79'
        """
        cwe_ids: Set[str] = set()

        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            descriptions = weakness.get("description", [])
            for desc in descriptions:
                text = desc.get("value") or ""
                for match in self.CWE_ID_PATTERN.findall(text):
                    if match:
                        cwe_ids.add(match)

        return cwe_ids

    def _populate_cwe_cache(self, cwe_ids: Set[str]) -> None:
        """
        Fetch comprehensive CWE weakness details for all given IDs using all MITRE endpoints.
        - Uses /cwe/weakness/{id} for full weakness details
        - Fetches relationships (parents/children) for context
        - Caches all data to avoid duplicate API calls
        """
        # Determine which IDs we still need
        missing_ids = [cwe_id for cwe_id in cwe_ids if cwe_id not in self._cwe_cache]
        if not missing_ids:
            return

        logger.info(
            f"Fetching comprehensive CWE details for {len(missing_ids)} IDs "
            f"(cache already has {len(self._cwe_cache)} entries)"
        )

        # Fetch full details for each CWE ID individually
        # The /cwe/weakness/{id} endpoint provides comprehensive data
        for cwe_id in missing_ids:
            try:
                # Fetch full weakness details from /cwe/weakness/{id}
                weakness_data = self._fetch_full_weakness_details(cwe_id)
                
                if weakness_data:
                    # Fetch relationships (parents and children)
                    relationships = self._fetch_weakness_relationships(cwe_id)
                    
                    # Combine all data
                    complete_data = {
                        **weakness_data,
                        "relationships": relationships
                    }
                    
                    self._cwe_cache[cwe_id] = complete_data
                    logger.debug(f"Fetched comprehensive data for CWE-{cwe_id}")
                else:
                    logger.warning(f"No data found for CWE-{cwe_id}")

            except Exception as e:
                logger.error(f"Failed to fetch CWE-{cwe_id}: {str(e)}")
                # Continue with other IDs

        logger.info(
            f"Completed fetching CWE details. Cache now has {len(self._cwe_cache)} entries"
        )

    def _fetch_full_weakness_details(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch full weakness details using /cwe/weakness/{id} endpoint.
        
        This endpoint returns comprehensive data including:
        - Name, Description, ExtendedDescription
        - CommonConsequences, PotentialMitigations
        - DemonstrativeExamples, ObservedExamples
        - DetectionMethods, RelatedWeaknesses
        - And many more fields
        """
        endpoint = f"cwe/weakness/{cwe_id}"
        
        try:
            response = self.api_client.get(endpoint)
            data = response.json()
            
            # The endpoint returns {"Weaknesses": [...]}
            if isinstance(data, dict) and "Weaknesses" in data:
                weaknesses = data.get("Weaknesses", [])
                if weaknesses:
                    return weaknesses[0]  # Return the first (and typically only) weakness
            
            return None
            
        except Exception as e:
            logger.debug(f"Error fetching full details for CWE-{cwe_id}: {str(e)}")
            return None

    def _fetch_weakness_relationships(self, cwe_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetch relationship data (parents and children) for a CWE.
        
        Returns:
            Dict with 'parents' and 'children' keys, each containing a list of related CWEs
        """
        relationships = {
            "parents": [],
            "children": []
        }
        
        # Fetch parents
        try:
            endpoint = f"cwe/{cwe_id}/parents"
            response = self.api_client.get(endpoint)
            data = response.json()
            if isinstance(data, list):
                relationships["parents"] = data
        except Exception as e:
            logger.debug(f"Could not fetch parents for CWE-{cwe_id}: {str(e)}")
        
        # Fetch children
        try:
            endpoint = f"cwe/{cwe_id}/children"
            response = self.api_client.get(endpoint)
            data = response.json()
            if isinstance(data, list):
                relationships["children"] = data
        except Exception as e:
            logger.debug(f"Could not fetch children for CWE-{cwe_id}: {str(e)}")
        
        return relationships


