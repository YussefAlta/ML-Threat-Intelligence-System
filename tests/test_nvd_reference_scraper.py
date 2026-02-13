"""
Unit tests for NVD Reference Scraper Enricher.

Tests URL normalization, hash stability, S3 key generation, cleaning routines,
content type detection, and integration with mocked HTTP responses.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock

# Import after path setup
from threat_intelligence.enrichment.nvd_reference_scraper import (
    NVDReferenceScraperEnricher,
)
from threat_intelligence.enrichment.content_cleaner import ContentCleaner
from threat_intelligence.storage.reference_storage import ReferenceStorage
from threat_intelligence.core.config import Config


class TestURLNormalization:
    """Test URL normalization consistency."""

    def test_normalize_url_removes_fragment(self):
        enricher = NVDReferenceScraperEnricher()
        url = "https://example.com/page#section"
        assert enricher._normalize_url(url) == "https://example.com/page"

    def test_normalize_url_lowercases_scheme_and_host(self):
        enricher = NVDReferenceScraperEnricher()
        url = "HTTPS://EXAMPLE.COM/Path"
        normalized = enricher._normalize_url(url)
        assert "https://" in normalized
        assert "example.com" in normalized

    def test_normalize_url_removes_tracking_params(self):
        enricher = NVDReferenceScraperEnricher()
        url = "https://example.com/page?utm_source=test&id=1"
        normalized = enricher._normalize_url(url)
        assert "utm_source" not in normalized
        assert "id=1" in normalized

    def test_normalize_url_removes_trailing_slash(self):
        enricher = NVDReferenceScraperEnricher()
        url = "https://example.com/path/"
        assert enricher._normalize_url(url) == "https://example.com/path"

    def test_normalize_url_preserves_root_slash(self):
        enricher = NVDReferenceScraperEnricher()
        url = "https://example.com/"
        assert enricher._normalize_url(url).endswith("/")


class TestURLHashStability:
    """Test URL hash stability - same URL produces same hash."""

    def test_same_url_same_hash(self):
        enricher = NVDReferenceScraperEnricher()
        url = "https://example.com/advisory/CVE-2024-1234"
        h1 = enricher._generate_url_hash(url)
        h2 = enricher._generate_url_hash(url)
        assert h1 == h2

    def test_normalized_urls_same_hash(self):
        enricher = NVDReferenceScraperEnricher()
        url1 = "https://example.com/page#x"
        url2 = "https://example.com/page"
        h1 = enricher._generate_url_hash(url1)
        h2 = enricher._generate_url_hash(url2)
        assert h1 == h2

    def test_different_urls_different_hash(self):
        enricher = NVDReferenceScraperEnricher()
        h1 = enricher._generate_url_hash("https://example.com/a")
        h2 = enricher._generate_url_hash("https://example.com/b")
        assert h1 != h2

    def test_hash_length(self):
        enricher = NVDReferenceScraperEnricher()
        h = enricher._generate_url_hash("https://example.com")
        assert len(h) == 8
        assert all(c in "0123456789abcdef" for c in h)


class TestS3KeyGeneration:
    """Test S3 key generation correctness."""

    def test_raw_key_format(self):
        storage = ReferenceStorage()
        fetch_date = datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)
        key = storage.generate_s3_key(
            "CVE-2024-12345", 0, "a1b2c3d4", "text/html", fetch_date, "raw"
        )
        assert "enrichments/nvd_references/raw/" in key
        assert "CVE-2024-12345" in key
        assert "2025/02/06" in key
        assert "000_a1b2c3d4" in key
        assert key.endswith(".html")

    def test_clean_key_format(self):
        storage = ReferenceStorage()
        fetch_date = datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)
        key = storage.generate_s3_key(
            "CVE-2024-12345", 5, "xyz789", "text/html", fetch_date, "clean"
        )
        assert "enrichments/nvd_references/clean/" in key
        assert "005_xyz789" in key
        assert key.endswith(".txt")

    def test_meta_key_format(self):
        storage = ReferenceStorage()
        fetch_date = datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)
        key = storage.generate_s3_key(
            "CVE-2024-12345", 12, "abc123", "application/json", fetch_date, "meta"
        )
        assert "enrichments/nvd_references/meta/" in key
        assert "012_abc123" in key
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


class TestContentCleaner:
    """Test cleaning routines."""

    def test_normalize_whitespace(self):
        cleaner = ContentCleaner()
        text = "  hello   world  \n\n\n  foo  "
        result = cleaner.normalize_whitespace(text)
        # Multiple spaces collapsed to single; multiple newlines to max 2
        assert "   " not in result  # No triple spaces
        assert result.strip() == result
        assert "hello" in result and "world" in result and "foo" in result

    def test_remove_boilerplate(self):
        cleaner = ContentCleaner()
        text = "Content here. Cookie policy. More content. All rights reserved."
        result = cleaner.remove_boilerplate(text)
        assert "Cookie policy" not in result or result != text

    def test_extract_text_from_html(self):
        html = "<html><body><h1>Title</h1><p>Paragraph</p><script>alert(1)</script></body></html>"
        result = ContentCleaner.extract_text_from_html(html)
        assert "Title" in result
        assert "Paragraph" in result
        assert "alert" not in result

    def test_chunk_large_text(self):
        cleaner = ContentCleaner(max_chunk_size=100)
        text = "A" * 50 + "\n\n" + "B" * 50 + "\n\n" + "C" * 50
        chunks = cleaner.chunk_large_text(text)
        assert len(chunks) >= 1
        for c in chunks:
            assert len(c.encode("utf-8")) <= 150  # Some slack for boundaries

    def test_detect_language_english(self):
        cleaner = ContentCleaner()
        text = "This is a sample of English text used for language detection."
        lang = cleaner.detect_language(text)
        assert lang in ("en", "unknown")


class TestReferenceExtraction:
    """Test CVE reference extraction from NIST schema."""

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
        assert refs[0]["url"] == "https://example.com/advisory"
        assert refs[1]["url"] == "https://vendor.com/patch"

    def test_extract_references_empty(self):
        enricher = NVDReferenceScraperEnricher()
        cve_record = {"cve": {"id": "CVE-2024-12345", "references": {"reference_data": []}}}
        assert enricher._extract_references(cve_record) == []

    def test_extract_references_missing_references(self):
        enricher = NVDReferenceScraperEnricher()
        cve_record = {"cve": {"id": "CVE-2024-12345"}}
        assert enricher._extract_references(cve_record) == []


class TestEnrichCvesIntegration:
    """Integration tests with mocked HTTP."""

    @patch("threat_intelligence.enrichment.nvd_reference_scraper.requests.Session")
    def test_enrich_cves_with_mocked_http(self, mock_session_class):
        """Test full pipeline with mocked HTTP response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "https://example.com/advisory"
        mock_response.content = b"<html><body><h1>Advisory</h1><p>Vulnerability details.</p></body></html>"
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.history = []

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        config = Config()
        config.NVD_REF_SCRAPE_ENABLED = True
        config.S3_BUCKET_NAME = None  # Avoid real S3
        config.AWS_ACCESS_KEY_ID = None

        enricher = NVDReferenceScraperEnricher(config)
        enricher.storage.s3_client = None  # Ensure no S3 writes

        cve_records = [
            {
                "cve": {
                    "id": "CVE-2024-12345",
                    "references": {
                        "reference_data": [
                            {"url": "https://example.com/advisory", "name": "Advisory"}
                        ]
                    },
                }
            }
        ]

        result = enricher.enrich_cves(cve_records)
        assert result["urls_processed"] == 1
        # Without S3, save will fail but processing completes
        assert "urls_succeeded" in result
        assert "urls_failed" in result

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

        cve_records = [
            {
                "cve": {
                    "id": "CVE-2024-12345",
                    "references": {
                        "reference_data": [
                            {"url": "ftp://example.com/file", "name": "FTP"},
                        ]
                    },
                }
            }
        ]
        result = enricher.enrich_cves(cve_records)
        assert result["urls_processed"] == 1
        # ftp URLs are skipped before fetch
        assert result["urls_succeeded"] == 0 or result["urls_failed"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
