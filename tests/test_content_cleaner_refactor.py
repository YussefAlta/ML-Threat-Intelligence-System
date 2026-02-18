"""
Tests for the refactored ContentCleaner: HTML improvements, GitHub extractors,
boilerplate removal, quality scoring.
"""

import pytest
from threat_intelligence.enrichment.content_cleaner import ContentCleaner


class TestHTMLExtraction:

    def test_removes_script_and_style(self):
        html = "<html><head><script>alert(1)</script><style>body{}</style></head><body><p>Good</p></body></html>"
        text = ContentCleaner.extract_text_from_html(html)
        assert "Good" in text
        assert "alert" not in text
        assert "body{}" not in text

    def test_removes_nav_header_footer_aside_form(self):
        html = (
            "<html><body>"
            "<nav>Nav links</nav>"
            "<header>Site header</header>"
            "<main><p>Main content</p></main>"
            "<footer>Footer</footer>"
            "<aside>Sidebar</aside>"
            "<form>Search form</form>"
            "</body></html>"
        )
        text = ContentCleaner.extract_text_from_html(html)
        assert "Main content" in text
        assert "Nav links" not in text
        assert "Site header" not in text
        assert "Footer" not in text
        assert "Sidebar" not in text
        assert "Search form" not in text

    def test_preserves_table_as_pipe_delimited(self):
        html = (
            "<html><body>"
            "<table><tr><th>Col1</th><th>Col2</th></tr>"
            "<tr><td>A</td><td>B</td></tr></table>"
            "</body></html>"
        )
        text = ContentCleaner.extract_text_from_html(html)
        assert "Col1" in text
        assert "Col2" in text
        assert "|" in text

    def test_preserves_unordered_list(self):
        html = "<html><body><ul><li>First</li><li>Second</li></ul></body></html>"
        text = ContentCleaner.extract_text_from_html(html)
        assert "- First" in text
        assert "- Second" in text

    def test_preserves_ordered_list(self):
        html = "<html><body><ol><li>One</li><li>Two</li></ol></body></html>"
        text = ContentCleaner.extract_text_from_html(html)
        assert "1. One" in text
        assert "2. Two" in text

    def test_prefers_main_tag(self):
        html = "<html><body><div>Noise</div><main><p>Important</p></main></body></html>"
        text = ContentCleaner.extract_text_from_html(html)
        assert "Important" in text

    def test_empty_html(self):
        assert ContentCleaner.extract_text_from_html("") == ""
        assert ContentCleaner.extract_text_from_html(None) == ""


class TestHTMLMetadataExtraction:

    def test_extracts_title(self):
        html = "<html><head><title>My Page Title</title></head><body></body></html>"
        meta = ContentCleaner.extract_html_metadata(html)
        assert meta["title"] == "My Page Title"

    def test_extracts_meta_description(self):
        html = '<html><head><meta name="description" content="Page about CVE"></head><body></body></html>'
        meta = ContentCleaner.extract_html_metadata(html)
        assert meta["meta_description"] == "Page about CVE"

    def test_returns_none_when_missing(self):
        html = "<html><head></head><body></body></html>"
        meta = ContentCleaner.extract_html_metadata(html)
        assert meta["title"] is None
        assert meta["meta_description"] is None


class TestGitHubAdvisoryExtractor:

    def test_extracts_title(self):
        html = '<html><body><h1>GHSA-xxxx Advisory Title</h1><div class="advisory-body">Vuln description.</div></body></html>'
        fields = ContentCleaner.extract_github_advisory(html)
        assert fields["title"] == "GHSA-xxxx Advisory Title"

    def test_extracts_description(self):
        html = '<html><body><div class="advisory-body">This is a critical vulnerability.</div></body></html>'
        fields = ContentCleaner.extract_github_advisory(html)
        assert "critical vulnerability" in fields["description"]

    def test_handles_empty(self):
        fields = ContentCleaner.extract_github_advisory("")
        assert fields["title"] is None
        assert fields["description"] is None


class TestGitHubCommitExtractor:

    def test_extracts_commit_message(self):
        html = '<html><body><div class="commit-title">Fix CVE-2024-1234 buffer overflow</div></body></html>'
        fields = ContentCleaner.extract_github_commit(html)
        assert "Fix CVE-2024-1234" in fields["commit_message"]

    def test_fallback_to_title_tag(self):
        html = "<html><head><title>Commit abc123</title></head><body></body></html>"
        fields = ContentCleaner.extract_github_commit(html)
        assert fields["commit_message"] == "Commit abc123"


class TestGitHubIssueExtractor:

    def test_extracts_body(self):
        html = '<html><body><div class="comment-body">Issue body text here.</div></body></html>'
        fields = ContentCleaner.extract_github_issue(html)
        assert "Issue body text" in fields["body"]

    def test_extracts_title_from_h1(self):
        html = "<html><body><h1>Bug Report: crash on startup</h1></body></html>"
        fields = ContentCleaner.extract_github_issue(html)
        assert "crash on startup" in fields["title"]


class TestBoilerplateRemoval:

    def test_removes_cookie_policy(self):
        cleaner = ContentCleaner()
        text = "Content here. Cookie policy notice. More content."
        result = cleaner.remove_boilerplate(text)
        assert "Cookie" not in result

    def test_removes_social_patterns(self):
        cleaner = ContentCleaner()
        text = "Main text. Share this article. Follow us on Twitter. Subscribe to newsletter."
        result = cleaner.remove_boilerplate(text)
        assert "Share this" not in result
        assert "Follow us" not in result
        assert "Subscribe" not in result

    def test_removes_all_rights_reserved(self):
        cleaner = ContentCleaner()
        text = "Content. All rights reserved."
        result = cleaner.remove_boilerplate(text)
        assert "All rights reserved" not in result

    def test_removes_javascript_notice(self):
        cleaner = ContentCleaner()
        text = "Please enable javascript to view this page."
        result = cleaner.remove_boilerplate(text)
        assert "enable javascript" not in result


class TestQualityScoring:

    def test_empty_text(self):
        q = ContentCleaner.assess_quality("")
        assert q["label"] == "empty"
        assert q["text_length"] == 0

    def test_short_text_marked_empty(self):
        q = ContentCleaner.assess_quality("Hi.", min_useful_length=50)
        assert q["label"] == "empty"

    def test_good_quality(self):
        text = (
            "CVE-2024-1234 is a critical vulnerability in Apache HTTP Server version 2.4.51. "
            "An attacker can exploit this to gain remote code execution. "
            "Users should upgrade to version 2.4.52 immediately."
        )
        q = ContentCleaner.assess_quality(text)
        assert q["label"] == "good"
        assert q["has_cve_mention"] is True
        assert q["has_version_mention"] is True
        assert q["sentence_count"] >= 2

    def test_code_only(self):
        text = "\n".join([
            "def exploit():",
            "    import os",
            "    return os.system('id')",
            "class Payload:",
            "    def run(self):",
            "        return True",
            "if __name__ == '__main__':",
            "    Payload().run()",
        ] * 5)
        q = ContentCleaner.assess_quality(text)
        assert q["label"] == "code_only"
        assert q["code_ratio"] > 0.5

    def test_no_cve_mention(self):
        q = ContentCleaner.assess_quality("This is a generic article about security. It has multiple sentences.")
        assert q["has_cve_mention"] is False

    def test_version_mention(self):
        q = ContentCleaner.assess_quality("Affected versions: 1.2.3 through 1.2.9. Upgrade to version 1.3.0.")
        assert q["has_version_mention"] is True


class TestNormalizeWhitespace:

    def test_collapses_spaces(self):
        cleaner = ContentCleaner()
        assert "hello world" == cleaner.normalize_whitespace("hello    world")

    def test_collapses_newlines(self):
        cleaner = ContentCleaner()
        result = cleaner.normalize_whitespace("a\n\n\n\n\nb")
        assert result.count("\n") <= 2


class TestChunking:

    def test_small_text_returns_single_chunk(self):
        cleaner = ContentCleaner(max_chunk_size=1000)
        assert cleaner.chunk_large_text("Short text") == ["Short text"]

    def test_large_text_splits(self):
        cleaner = ContentCleaner(max_chunk_size=100)
        text = "A" * 50 + "\n\n" + "B" * 50 + "\n\n" + "C" * 50
        chunks = cleaner.chunk_large_text(text)
        assert len(chunks) >= 2
