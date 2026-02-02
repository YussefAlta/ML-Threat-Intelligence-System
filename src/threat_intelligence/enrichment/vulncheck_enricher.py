"""
VulnCheck enrichment for CVE records using the VulnCheck API.

This module:
- Queries VulnCheck for additional context about CVEs
- Adds exploit/threat intelligence to CVE records
- Caches responses to avoid duplicate API calls
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any
import requests

from ..core.config import Config
from ..utils.api_client import APIClient, RateLimiter

logger = logging.getLogger(__name__)


class VulnCheckEnricher:
    """
    Enrich CVE records with VulnCheck vulnerability intelligence.

    NOTE: The exact VulnCheck API endpoints and response schema may evolve.
    This implementation follows the general pattern described in the VulnCheck
    API docs (`/v3/index`, `/v3/vulns/{cve_id}`) and can be adjusted as needed.

    Usage:
        enricher = VulnCheckEnricher(config)
        enriched = enricher.enrich_cves(cve_records)

    The result is a list of dicts, each containing:
        {
          "cve_id": "CVE-2024-1234",
          "vulncheck_data": {...}  # Raw VulnCheck response for this CVE (or None)
        }
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

        if not self.config.VULNCHECK_API_KEY:
            logger.warning(
                "VulnCheck API key not configured. VulnCheck enrichment will be disabled."
            )

        # Rate limiter for VulnCheck API
        rate_limiter = RateLimiter(
            max_requests=self.config.VULNCHECK_RATE_LIMIT_REQUESTS,
            window_seconds=self.config.VULNCHECK_RATE_LIMIT_WINDOW,
        )

        # VulnCheck API client (uses Bearer token in headers, not query params)
        self.api_client = APIClient(
            base_url=self.config.VULNCHECK_API_BASE_URL,
            api_key=None,  # We handle auth via headers
            rate_limiter=rate_limiter,
            max_retries=self.config.VULNCHECK_MAX_RETRIES,
            backoff_multiplier=self.config.NIST_RETRY_BACKOFF,
            timeout=30,
        )

        # Override session headers to include Authorization
        if self.config.VULNCHECK_API_KEY:
            self.api_client.session.headers.update(
                {
                    "Authorization": f"Bearer {self.config.VULNCHECK_API_KEY}",
                    "Accept": "application/json",
                }
            )

        # Simple in-memory cache to avoid duplicate lookups
        self._cve_cache: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_cves(self, cve_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a list of CVE records with VulnCheck intelligence.

        Args:
            cve_records: List of NIST CVE records (as returned by NISTCVEIngester)

        Returns:
            List of enrichment records (one per CVE)
        """
        if not self.config.VULNCHECK_API_KEY:
            logger.warning(
                "VulnCheck API key not configured. Skipping VulnCheck enrichment."
            )
            return []

        if not cve_records:
            logger.info("No CVE records provided for VulnCheck enrichment")
            return []

        enriched: List[Dict[str, Any]] = []

        for cve in cve_records:
            cve_data = cve.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
                continue

            vuln_data = self._get_vuln_for_cve(cve_id)
            enriched.append(
                {
                    "cve_id": cve_id,
                    "vulncheck_data": vuln_data,
                }
            )

        logger.info(
            f"VulnCheck enrichment completed for {len(enriched)} CVEs "
            f"(from {len(cve_records)} input records)"
        )
        return enriched

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_vuln_for_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch VulnCheck data for a given CVE ID, with caching.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')

        Returns:
            Parsed JSON response from VulnCheck, or None if not found / error
        """
        if cve_id in self._cve_cache:
            return self._cve_cache[cve_id]

        # Try common VulnCheck CVE endpoints.
        # Adjust as needed based on VulnCheck API documentation.
        candidate_endpoints = [
            f"vulns/{cve_id}",
            f"cve/{cve_id}",
            f"vulnerability/{cve_id}",
        ]

        for endpoint in candidate_endpoints:
            try:
                # Make the request and check status before it raises
                # We need to access the response directly to handle 404s gracefully
                url = f"{self.api_client.base_url}/{endpoint.lstrip('/')}"
                
                # Apply rate limiting
                if self.api_client.rate_limiter:
                    self.api_client.rate_limiter.wait_if_needed()
                
                # Make request directly to check status code before raising
                response = self.api_client.session.get(
                    url,
                    timeout=self.api_client.timeout
                )
                
                # Handle 404 gracefully (CVE not in VulnCheck database - this is normal)
                if response.status_code == 404:
                    logger.debug(
                        f"VulnCheck: {cve_id} not found at endpoint '{endpoint}' (404 - this is normal)"
                    )
                    continue
                
                # Raise for other HTTP errors
                if response.status_code >= 400:
                    response.raise_for_status()
                
                # Success - parse and return
                data = response.json()
                self._cve_cache[cve_id] = data
                logger.info(f"Fetched VulnCheck data for {cve_id} from '{endpoint}'")
                return data
                
            except requests.HTTPError as e:
                # For other HTTP errors, log and continue to next endpoint
                response = getattr(e, 'response', None)
                logger.debug(
                    f"VulnCheck: HTTP error {response.status_code if response else 'unknown'} "
                    f"fetching {cve_id} from '{endpoint}': {str(e)}"
                )
                continue
            except Exception as e:
                # For other exceptions, log and continue
                logger.debug(
                    f"VulnCheck: error fetching {cve_id} from '{endpoint}': {str(e)}"
                )
                continue

        # No data found for this CVE (404 on all endpoints is normal - not all CVEs exist in VulnCheck)
        self._cve_cache[cve_id] = None
        logger.debug(f"No VulnCheck data found for {cve_id} (this is normal for new/recent CVEs)")
        return None


