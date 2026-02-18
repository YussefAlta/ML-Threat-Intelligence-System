"""
Tests for the URL-pattern-based reference classifier.
"""

import pytest
from threat_intelligence.enrichment.reference_classifier import (
    classify_url,
    classify_with_content_hint,
    VENDOR_ADVISORY, GITHUB_ADVISORY, GITHUB_COMMIT, GITHUB_ISSUE,
    GITHUB_REPO, PATCH, MAILING_LIST, CODE, MEDIA, GOVERNMENT,
    ARTICLE, UNKNOWN,
)


class TestGitHubClassification:

    def test_github_advisory_ghsa_direct(self):
        assert classify_url("https://github.com/advisories/GHSA-4g74-7cff-xcv8") == GITHUB_ADVISORY

    def test_github_advisory_repo_security(self):
        url = "https://github.com/youki-dev/youki/security/advisories/GHSA-vf95-55w6-qmrf"
        assert classify_url(url) == GITHUB_ADVISORY

    def test_github_commit(self):
        url = "https://github.com/youki-dev/youki/commit/5886c91073b9be748bd8d5aed49c4a820548030a"
        assert classify_url(url) == GITHUB_COMMIT

    def test_github_issue(self):
        assert classify_url("https://github.com/user/repo/issues/123") == GITHUB_ISSUE

    def test_github_pull_request(self):
        assert classify_url("https://github.com/user/repo/pull/456") == GITHUB_ISSUE

    def test_github_generic_repo(self):
        assert classify_url("https://github.com/user/repo") == GITHUB_REPO

    def test_raw_githubusercontent(self):
        url = "https://raw.githubusercontent.com/org/repo/main/file.py"
        assert classify_url(url) == CODE

    def test_gist_github(self):
        assert classify_url("https://gist.github.com/user/abc123") == CODE


class TestMediaClassification:

    def test_youtube(self):
        assert classify_url("https://www.youtube.com/watch?v=abc123") == MEDIA

    def test_youtu_be(self):
        assert classify_url("https://youtu.be/abc123") == MEDIA

    def test_vimeo(self):
        assert classify_url("https://vimeo.com/123456") == MEDIA


class TestCodeClassification:

    def test_pastebin(self):
        assert classify_url("https://pastebin.com/abc123") == CODE


class TestMailingListClassification:

    def test_seclists(self):
        assert classify_url("https://seclists.org/fulldisclosure/2024/Jan/1") == MAILING_LIST

    def test_openwall(self):
        assert classify_url("https://www.openwall.com/lists/oss-security/2024/01/01/1") == MAILING_LIST

    def test_lists_prefix(self):
        assert classify_url("https://lists.apache.org/thread/abc123") == MAILING_LIST


class TestGovernmentClassification:

    def test_nist_nvd(self):
        assert classify_url("https://nvd.nist.gov/vuln/detail/CVE-2024-1234") == GOVERNMENT

    def test_cisa(self):
        assert classify_url("https://www.cisa.gov/known-exploited-vulnerabilities") == GOVERNMENT

    def test_gov_tld(self):
        assert classify_url("https://cyber.gov.au/advisory/2024-001") == GOVERNMENT


class TestVendorAdvisoryClassification:

    def test_known_advisory_domain(self):
        assert classify_url("https://security.gentoo.org/glsa/202401-01") == VENDOR_ADVISORY

    def test_exploit_db(self):
        assert classify_url("https://www.exploit-db.com/exploits/12345") == VENDOR_ADVISORY

    def test_path_advisory_keyword(self):
        assert classify_url("https://vendor.com/security/advisory/CVE-2024-1234") == VENDOR_ADVISORY

    def test_msrc(self):
        assert classify_url("https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-1234") == VENDOR_ADVISORY


class TestPatchClassification:

    def test_patch_path(self):
        assert classify_url("https://example.com/patch/12345") == PATCH

    def test_diff_path(self):
        assert classify_url("https://example.com/diff/abc") == PATCH


class TestArticleFallback:

    def test_generic_blog(self):
        assert classify_url("https://blog.example.com/vuln-writeup") == ARTICLE

    def test_news_site(self):
        assert classify_url("https://therecord.media/some-news-article") == ARTICLE

    def test_news_with_cve_in_path_classified_advisory(self):
        # A URL containing "CVE-2024" in path is reasonably classified as advisory
        assert classify_url("https://therecord.media/cve-2024-exploit") == VENDOR_ADVISORY


class TestContentHintReclassification:

    def test_article_promoted_to_advisory(self):
        result = classify_with_content_hint(
            "https://blog.example.com/post",
            title="Security Advisory for CVE-2024-1234",
        )
        assert result == VENDOR_ADVISORY

    def test_github_not_reclassified(self):
        result = classify_with_content_hint(
            "https://github.com/user/repo/commit/abc123",
            title="Security fix",
        )
        assert result == GITHUB_COMMIT

    def test_no_hint_stays_article(self):
        result = classify_with_content_hint(
            "https://blog.example.com/post",
            title="Random tech article",
        )
        assert result == ARTICLE


class TestEdgeCases:

    def test_empty_url(self):
        assert classify_url("") == UNKNOWN

    def test_malformed_url(self):
        assert classify_url("not-a-url") in (ARTICLE, UNKNOWN)

    def test_ftp_scheme(self):
        result = classify_url("ftp://example.com/file")
        assert result in (ARTICLE, UNKNOWN)
