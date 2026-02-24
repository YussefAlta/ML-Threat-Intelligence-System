"""
Unit tests for the refactored NVD Reference Scraper Enricher.

Tests URL normalization, hash stability, S3 key generation, reference extraction,
classification integration, encoding detection, media skip, and full pipeline.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock

from threat_intelligence.enrichment.nvd_reference_scraper import (
    NVDReferenceScraperEnricher,
)
from threat_intelligence.enrichment.content_cleaner import ContentCleaner
from threat_intelligence.storage.reference_storage import ReferenceStorage
from threat_intelligence.core.config import Config


class TestURLNormalization:

    def test_normalize_url_removes_fragment(self):
        enricher = NVDReferenceScraperEnricher()
        assert enricher._normalize_url("https://example.com/page#section") == "https://example.com/page"

    def test_normalize_url_lowercases_scheme_and_host(self):
        enricher = NVDReferenceScraperEnricher()
        normalized = enricher._normalize_url("HTTPS://EXAMPLE.COM/Path")
        assert "https://" in normalized
        assert "example.com" in normalized

    def test_normalize_url_removes_tracking_params(self):
        enricher = NVDReferenceScraperEnricher()
        normalized = enricher._normalize_url("https://example.com/page?utm_source=test&id=1")
        assert "utm_source" not in normalized
        assert "id=1" in normalized

    def test_normalize_url_removes_trailing_slash(self):
        enricher = NVDReferenceScraperEnricher()
        assert enricher._normalize_url("https://example.com/path/") == "https://example.com/path"

    def test_normalize_url_preserves_root_slash(self):
        enricher = NVDReferenceScraperEnricher()
        assert enricher._normalize_url("https://example.com/").endswith("/")


class TestURLHashStability:

    def test_same_url_same_hash(self):
        enricher = NVDReferenceScraperEnricher()
        url = "https://example.com/advisory/CVE-2024-1234"
        assert enricher._generate_url_hash(url) == enricher._generate_url_hash(url)

    def test_normalized_urls_same_hash(self):
        enricher = NVDReferenceScraperEnricher()
        h1 = enricher._generate_url_hash("https://example.com/page#x")
        h2 = enricher._generate_url_hash("https://example.com/page")
        assert h1 == h2

    def test_different_urls_different_hash(self):
        enricher = NVDReferenceScraperEnricher()
        assert enricher._generate_url_hash("https://example.com/a") != enricher._generate_url_hash("https://example.com/b")

    def test_hash_length(self):
        enricher = NVDReferenceScraperEnricher()
        h = enricher._generate_url_hash("https://example.com")
        assert len(h) == 8
        assert all(c in "0123456789abcdef" for c in h)


class TestS3KeyGeneration:

    def test_raw_key_format(self):
        storage = ReferenceStorage()
        fetch_date = datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)
        key = storage.generate_s3_key("CVE-2024-12345", 0, "a1b2c3d4", "text/html", fetch_date, "raw")
        assert "enriched/cve/ref_links/" in key
        assert "2025-02-06" in key
        assert "/raw/" in key
        assert "CVE-2024-12345" in key
        assert key.endswith(".html")

    def test_clean_key_format(self):
        storage = ReferenceStorage()
        fetch_date = datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)
        key = storage.generate_s3_key("CVE-2024-12345", 5, "xyz789", "text/html", fetch_date, "clean")
        assert "enriched/cve/ref_links/" in key
        assert "2025-02-06" in key
        assert "/clean/" in key
        assert key.endswith(".txt")

    def test_meta_key_format(self):
        storage = ReferenceStorage()
        fetch_date = datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)
        key = storage.generate_s3_key("CVE-2024-12345", 12, "abc123", "application/json", fetch_date, "meta")
        assert "enriched/cve/ref_links/" in key
        assert "2025-02-06" in key
        assert "/meta/" in key
        assert key.endswith(".json")

    def test_content_type_extension_mapping(self):
        storage = ReferenceStorage()
        fetch_date = datetime(2025, 2, 6)
        for ct, ext in [
            ("text/html", ".html"),
            ("application/pdf", ".pdf"),
            ("application/json", ".json"),
            ("text/plain", ".txt"),
        ]:
            key = storage.generate_s3_key("CVE-1", 0, "x", ct, fetch_date, "raw")
            assert key.endswith(ext)


class TestReferenceExtraction:

    def test_extract_references_standard_format(self):
        enricher = NVDReferenceScraperEnricher()
        cve_record = {
            "cve": {
                "id": "CVE-2024-12345",
                "references": {
                    "reference_data": [
                        {"url": "https://example.com/advisory", "name": "Advisory"},
                        {"url": "https://vendor.com/patch", "name": "Patch"},
                    ]
                },
            }
        }
        refs = enricher._extract_references(cve_record)
        assert len(refs) == 2

    def test_extract_references_nvd_2_0_format(self):
        enricher = NVDReferenceScraperEnricher()
        cve_record = {
            "cve": {
                "id": "CVE-2024-12345",
                "references": [
                    {"url": "https://example.com/advisory", "source": "nvd"},
                ],
            }
        }
        refs = enricher._extract_references(cve_record)
        assert len(refs) == 1

    def test_extract_references_empty(self):
        enricher = NVDReferenceScraperEnricher()
        assert enricher._extract_references({"cve": {"id": "CVE-1", "references": {"reference_data": []}}}) == []

    def test_extract_references_missing(self):
        enricher = NVDReferenceScraperEnricher()
        assert enricher._extract_references({"cve": {"id": "CVE-1"}}) == []


class TestEncodingDetection:

    def test_charset_from_header(self):
        enc = NVDReferenceScraperEnricher._detect_encoding(b"", "text/html; charset=iso-8859-1")
        assert enc == "iso-8859-1"

    def test_charset_from_header_utf8(self):
        enc = NVDReferenceScraperEnricher._detect_encoding(b"", "text/html; charset=utf-8")
        assert enc == "utf-8"

    def test_auto_detect_fallback(self):
        content = "Hello world".encode("utf-8")
        enc = NVDReferenceScraperEnricher._detect_encoding(content, "text/html")
        assert enc  # Should return some encoding


class TestMediaSkip:

    def test_youtube_url_skipped(self):
        config = Config()
        config.NVD_REF_SCRAPE_ENABLED = True
        config.NVD_REF_SKIP_MEDIA = True
        config.S3_BUCKET_NAME = None
        config.AWS_ACCESS_KEY_ID = None
        enricher = NVDReferenceScraperEnricher(config)
        enricher.storage.s3_client = None
        enricher.storage.save_reference_metadata = lambda m, k: True

        cve_records = [{
            "cve": {
                "id": "CVE-2024-12345",
                "references": {"reference_data": [
                    {"url": "https://youtu.be/abc123", "name": "Video"},
                ]},
            }
        }]
        result = enricher.enrich_cves(cve_records)
        assert result["urls_skipped_media"] == 1
        assert result["urls_processed"] == 0


class TestGitHubURLsNowProcessed:
    """Verify GitHub URLs are no longer skipped."""

    @patch("threat_intelligence.enrichment.nvd_reference_scraper.requests.Session")
    def test_github_advisory_is_processed(self, mock_session_class):
        html = b'<html><body><h1>GHSA Advisory</h1><div class="advisory-body">Critical vuln description.</div></body></html>'
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "https://github.com/org/repo/security/advisories/GHSA-xxxx-xxxx-xxxx"
        mock_response.content = html
        mock_response._content = html
        mock_response.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_response.history = []
        mock_response.iter_content = lambda chunk_size=65536: [html]

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        config = Config()
        config.NVD_REF_SCRAPE_ENABLED = True
        config.S3_BUCKET_NAME = None
        config.AWS_ACCESS_KEY_ID = None

        enricher = NVDReferenceScraperEnricher(config)
        enricher.storage.save_reference_raw = lambda *a, **kw: True
        enricher.storage.save_reference_clean = lambda *a, **kw: True
        enricher.storage.save_reference_metadata = lambda *a, **kw: True
        enricher.storage.check_exists = lambda k: False

        cve_records = [{
            "cve": {
                "id": "CVE-2024-12345",
                "references": {"reference_data": [
                    {"url": "https://github.com/org/repo/security/advisories/GHSA-xxxx-xxxx-xxxx"},
                ]},
            }
        }]
        result = enricher.enrich_cves(cve_records)
        assert result["urls_processed"] == 1
        assert result["urls_succeeded"] == 1


class TestEnrichCvesIntegration:

    @patch("threat_intelligence.enrichment.nvd_reference_scraper.requests.Session")
    def test_full_pipeline_with_new_metadata(self, mock_session_class):
        """Full pipeline: fetch -> classify -> clean -> quality-score -> store."""
        html_body = (
            b"<html><head><title>Vendor Advisory</title>"
            b'<meta name="description" content="CVE-2024-99999 advisory">'
            b"</head><body>"
            b"<main><p>CVE-2024-99999 is a critical vulnerability in version 2.4.51. "
            b"Upgrade to version 2.4.52 to fix it. This is a detailed advisory.</p></main>"
            b"</body></html>"
        )
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "https://vendor.com/advisory/CVE-2024-99999"
        mock_response.content = html_body
        mock_response._content = html_body
        mock_response.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_response.history = []
        mock_response.iter_content = lambda chunk_size=65536: [html_body]

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        saved_meta = []

        config = Config()
        config.NVD_REF_SCRAPE_ENABLED = True
        config.S3_BUCKET_NAME = None
        config.AWS_ACCESS_KEY_ID = None

        enricher = NVDReferenceScraperEnricher(config)
        enricher.storage.save_reference_raw = lambda *a, **kw: True
        enricher.storage.save_reference_clean = lambda *a, **kw: True
        enricher.storage.save_reference_metadata = lambda m, k: saved_meta.append(m) or True
        enricher.storage.check_exists = lambda k: False

        cve_records = [{
            "cve": {
                "id": "CVE-2024-99999",
                "references": {"reference_data": [
                    {"url": "https://vendor.com/advisory/CVE-2024-99999", "name": "Advisory"},
                ]},
            }
        }]

        result = enricher.enrich_cves(cve_records)
        assert result["urls_processed"] == 1
        assert result["urls_succeeded"] == 1

        meta = saved_meta[0]

        # New metadata fields
        assert meta["ref_type"] == "vendor_advisory"
        assert "detected_encoding" in meta
        assert isinstance(meta["content_truncated"], bool)
        assert isinstance(meta["redirect_count"], int)

        # Quality block
        assert "quality" in meta
        assert meta["quality"]["label"] == "good"
        assert meta["quality"]["has_cve_mention"] is True
        assert meta["quality"]["has_version_mention"] is True

        # Extracted HTML metadata
        assert meta["extracted_title"] == "Vendor Advisory"
        assert "CVE-2024-99999" in meta["extracted_meta_description"]

        # Standard fields still present
        assert meta["cve_id"] == "CVE-2024-99999"
        assert meta["content_type"] == "text/html"
        assert meta["extraction_success"] is True

    def test_enrich_cves_disabled(self):
        config = Config()
        config.NVD_REF_SCRAPE_ENABLED = False
        enricher = NVDReferenceScraperEnricher(config)
        result = enricher.enrich_cves([{"cve": {"id": "CVE-1", "references": {"reference_data": [{"url": "https://x.com"}]}}}])
        assert result["urls_processed"] == 0

    def test_enrich_cves_skips_non_http_urls(self):
        config = Config()
        config.NVD_REF_SCRAPE_ENABLED = True
        config.S3_BUCKET_NAME = None
        config.AWS_ACCESS_KEY_ID = None
        enricher = NVDReferenceScraperEnricher(config)
        enricher.storage.s3_client = None

        cve_records = [{
            "cve": {
                "id": "CVE-2024-12345",
                "references": {"reference_data": [
                    {"url": "ftp://example.com/file", "name": "FTP"},
                ]},
            }
        }]
        result = enricher.enrich_cves(cve_records)
        assert result["urls_processed"] == 1
        assert result["urls_succeeded"] == 0
        assert result["urls_failed"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
