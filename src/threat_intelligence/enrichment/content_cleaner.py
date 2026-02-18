"""
Content cleaning utilities for NVD reference scraping.

Provides text extraction from HTML (including GitHub-specific pages),
boilerplate removal, normalization, language detection, quality scoring,
and chunking for large documents.
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


BOILERPLATE_PATTERNS = [
    r"cookie\s*(?:policy|notice|banner|consent)",
    r"gdpr\s*(?:notice|consent|compliant)",
    r"privacy\s*policy",
    r"terms\s*of\s*(?:service|use)",
    r"©\s*\d{4}.*?(?=\n|$)",
    r"all\s*rights\s*reserved",
    r"skip\s*(?:to\s*)?(?:main\s*)?content",
    r"page\s*\d+\s*of\s*\d+",
    r"^\s*[-=*]{3,}\s*$",
    # Social / engagement
    r"share\s*this\s*(?:article|page|post)?",
    r"follow\s*us\s*(?:on)?",
    r"subscribe\s*(?:to\s*)?(?:our\s*)?(?:newsletter)?",
    r"related\s*(?:articles?|posts?|links?)",
    r"read\s*more\s*(?:articles?)?",
    r"leave\s*a\s*(?:comment|reply)",
    r"comments?\s*(?:section|area)",
    r"(?:like|tweet|pin|share)\s*(?:on\s*)?\w+",
    # Navigation remnants
    r"\[?\s*menu\s*\]?",
    r"\[?\s*home\s*\]?",
    r"\[?\s*search\s*\]?",
    r"\[?\s*login\s*\]?",
    r"\[?\s*sign\s*(?:in|up)\s*\]?",
    r"\[?\s*register\s*\]?",
    r"\[?\s*close\s*\]?",
    r"breadcrumb",
    # Ads / tracking
    r"advertisement",
    r"sponsored\s*(?:content|post)?",
    r"powered\s*by\s*\w+",
    # Loading / dynamic
    r"loading\s*\.\.\.",
    r"please\s*wait",
    r"javascript\s*(?:is\s*)?(?:required|disabled|not\s*enabled)",
    r"enable\s*javascript",
]

# Regex to detect lines that look like code
_CODE_LINE_RE = re.compile(
    r"^\s*(?:[{}\[\]();]|//|/\*|\*/|#\s*(?:include|define|if|else|endif)|"
    r"(?:def|class|import|from|return|if|else|for|while|try|except|raise|with|var|let|const|function)\s)",
)

CVE_MENTION_RE = re.compile(r"CVE-\d{4}-\d{4,}")
VERSION_RE = re.compile(
    r"(?:version|v)?\s*\d+\.\d+(?:\.\d+)*(?:[-._]?\w+)?",
    re.IGNORECASE,
)


class ContentCleaner:
    """Cleaning utilities for reference content."""

    def __init__(self, max_chunk_size: int = 1_048_576):
        self.max_chunk_size = max_chunk_size

    # ------------------------------------------------------------------
    # Main cleaning entry point
    # ------------------------------------------------------------------

    def clean_text(self, text: str, content_type: str = "text/plain") -> str:
        """Clean text: normalize whitespace then strip boilerplate."""
        if not text or not isinstance(text, str):
            return ""
        text = self.normalize_whitespace(text)
        text = self.remove_boilerplate(text)
        return text.strip()

    # ------------------------------------------------------------------
    # Boilerplate removal
    # ------------------------------------------------------------------

    def remove_boilerplate(self, text: str) -> str:
        """Remove common boilerplate patterns (cookie notices, nav, social, etc.)."""
        if not text:
            return ""
        result = text
        for pattern in BOILERPLATE_PATTERNS:
            result = re.sub(pattern, "", result, flags=re.IGNORECASE | re.DOTALL)
        return result

    # ------------------------------------------------------------------
    # Whitespace normalization
    # ------------------------------------------------------------------

    def normalize_whitespace(self, text: str) -> str:
        """Collapse multiple spaces/newlines and remove control chars."""
        if not text:
            return ""
        text = "".join(
            c for c in text if c in "\n\t\r" or (ord(c) >= 32 and ord(c) != 127)
        )
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------

    def detect_language(self, text: str) -> str:
        """Detect language using langdetect (needs 50+ chars)."""
        if not text or len(text.strip()) < 50:
            return "unknown"
        sample = text[:1000]
        try:
            import langdetect
            return langdetect.detect(sample)
        except Exception as e:
            logger.debug(f"Language detection failed: {e}")
            return "unknown"

    # ------------------------------------------------------------------
    # Chunking
    # ------------------------------------------------------------------

    def chunk_large_text(self, text: str, max_chunk_size: Optional[int] = None) -> List[str]:
        """Split text into chunks respecting paragraph/sentence boundaries."""
        size = max_chunk_size or self.max_chunk_size
        if not text or len(text.encode("utf-8")) <= size:
            return [text] if text else []

        chunks: List[str] = []
        remaining = text
        while remaining:
            if len(remaining.encode("utf-8")) <= size:
                chunks.append(remaining)
                break
            target = remaining[:size]
            last_newline = target.rfind("\n")
            last_period = target.rfind(". ")
            break_point = last_newline if last_newline > size // 2 else last_period
            if break_point <= 0:
                break_point = size
            chunk = remaining[: break_point + 1].strip()
            if chunk:
                chunks.append(chunk)
            remaining = remaining[break_point + 1 :].strip()
        return chunks

    # ------------------------------------------------------------------
    # Quality scoring
    # ------------------------------------------------------------------

    @staticmethod
    def assess_quality(
        cleaned_text: str,
        min_useful_length: int = 50,
    ) -> Dict:
        """
        Assess quality of cleaned text.

        Returns dict with: quality_label, text_length, sentence_count,
        has_cve_mention, has_version_mention, code_ratio.
        """
        if not cleaned_text:
            return {
                "label": "empty",
                "text_length": 0,
                "sentence_count": 0,
                "has_cve_mention": False,
                "has_version_mention": False,
                "code_ratio": 0.0,
            }

        text_length = len(cleaned_text)
        lines = cleaned_text.splitlines()
        non_empty_lines = [l for l in lines if l.strip()]
        total_lines = len(non_empty_lines) or 1

        code_lines = sum(1 for l in non_empty_lines if _CODE_LINE_RE.match(l))
        code_ratio = round(code_lines / total_lines, 3)

        sentence_count = len(re.findall(r"[.!?]+\s", cleaned_text)) + (
            1 if cleaned_text.rstrip()[-1:] in ".!?" else 0
        )

        has_cve = bool(CVE_MENTION_RE.search(cleaned_text))
        has_version = bool(VERSION_RE.search(cleaned_text))

        if text_length < min_useful_length:
            label = "empty"
        elif code_ratio > 0.7:
            label = "code_only"
        elif sentence_count < 2 and text_length < 200:
            label = "low"
        else:
            label = "good"

        return {
            "label": label,
            "text_length": text_length,
            "sentence_count": sentence_count,
            "has_cve_mention": has_cve,
            "has_version_mention": has_version,
            "code_ratio": code_ratio,
        }

    # ------------------------------------------------------------------
    # HTML extraction (general)
    # ------------------------------------------------------------------

    @staticmethod
    def extract_text_from_html(html: str) -> str:
        """
        Extract body text from HTML using BeautifulSoup.

        Removes script, style, nav, header, footer, aside, form.
        Preserves table and list structure in plain-text form.
        """
        if not html:
            return ""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
        except ImportError:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, "html.parser")
            except ImportError:
                logger.warning("BeautifulSoup not available, using regex fallback")
                return _extract_text_from_html_regex(html)

        for tag in soup.find_all(["script", "style", "nav", "header", "footer", "aside", "form", "iframe"]):
            tag.decompose()

        # Convert tables to pipe-delimited text before get_text
        for table in soup.find_all("table"):
            _convert_table(table)

        # Convert lists to indented plain text
        for ul in soup.find_all(["ul", "ol"]):
            _convert_list(ul)

        # Content area: prefer <main>/<article> then paragraph-density scoring
        main = soup.find("main") or soup.find("article")
        if not main:
            main = _best_content_block(soup)
        body = main or soup.find("body") or soup

        text = body.get_text(separator="\n", strip=True)
        return text

    @staticmethod
    def extract_html_metadata(html: str) -> Dict[str, Optional[str]]:
        """
        Extract <title> and <meta name='description'> from HTML.

        Returns dict with keys 'title' and 'meta_description'.
        """
        result: Dict[str, Optional[str]] = {"title": None, "meta_description": None}
        if not html:
            return result
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
        except ImportError:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, "html.parser")
            except ImportError:
                return result

        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            result["title"] = title_tag.string.strip()

        meta_desc = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        if meta_desc and meta_desc.get("content"):
            result["meta_description"] = meta_desc["content"].strip()

        return result

    # ------------------------------------------------------------------
    # GitHub-specific extractors
    # ------------------------------------------------------------------

    @staticmethod
    def extract_github_advisory(html: str) -> Dict[str, Optional[str]]:
        """
        Extract structured fields from a GitHub Security Advisory (GHSA) page.

        Returns dict with: title, severity, description, affected_packages,
        cvss_score, references.
        """
        fields: Dict[str, Optional[str]] = {
            "title": None,
            "severity": None,
            "description": None,
            "affected_packages": None,
            "cvss_score": None,
            "references": None,
        }
        if not html:
            return fields
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
        except ImportError:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, "html.parser")
            except ImportError:
                return fields

        # Title
        h1 = soup.find("h1")
        if h1:
            fields["title"] = h1.get_text(strip=True)

        # Severity badge
        severity_el = (
            soup.find(class_=re.compile(r"severity", re.I))
            or soup.find("span", string=re.compile(r"(critical|high|medium|low)", re.I))
        )
        if severity_el:
            fields["severity"] = severity_el.get_text(strip=True)

        # Description -- typically in advisory-body / markdown-body
        desc_el = (
            soup.find(class_=re.compile(r"advisory-body|markdown-body|comment-body", re.I))
        )
        if desc_el:
            fields["description"] = desc_el.get_text(separator="\n", strip=True)

        # Affected packages
        pkg_el = soup.find(class_=re.compile(r"affected-package|vulnerability-package", re.I))
        if pkg_el:
            fields["affected_packages"] = pkg_el.get_text(separator=", ", strip=True)

        # CVSS
        cvss_el = soup.find(string=re.compile(r"CVSS\s*:?\s*\d"))
        if cvss_el:
            m = re.search(r"(\d+\.?\d*)", cvss_el)
            if m:
                fields["cvss_score"] = m.group(1)

        # References section
        refs_section = soup.find(id=re.compile(r"references", re.I))
        if refs_section:
            links = refs_section.find_all("a", href=True)
            if links:
                fields["references"] = " | ".join(a["href"] for a in links[:10])

        return fields

    @staticmethod
    def extract_github_commit(html: str) -> Dict[str, Optional[str]]:
        """
        Extract structured fields from a GitHub commit page.

        Returns dict with: commit_message, files_changed, diff_stats.
        """
        fields: Dict[str, Optional[str]] = {
            "commit_message": None,
            "files_changed": None,
            "diff_stats": None,
        }
        if not html:
            return fields
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
        except ImportError:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, "html.parser")
            except ImportError:
                return fields

        # Commit message
        msg_el = soup.find(class_=re.compile(r"commit-title|commit-desc", re.I))
        if msg_el:
            fields["commit_message"] = msg_el.get_text(separator=" ", strip=True)
        else:
            title_el = soup.find("title")
            if title_el and title_el.string:
                fields["commit_message"] = title_el.string.strip()

        # Files changed list
        file_els = soup.find_all(class_=re.compile(r"file-header|file-info", re.I))
        if file_els:
            names = []
            for el in file_els[:50]:
                name = el.get_text(strip=True)
                if name:
                    names.append(name.split()[-1] if " " in name else name)
            fields["files_changed"] = ", ".join(names) if names else None

        # Diff stats
        stats_el = soup.find(class_=re.compile(r"diffstat|toc-diff-stats", re.I))
        if stats_el:
            fields["diff_stats"] = stats_el.get_text(separator=" ", strip=True)

        return fields

    @staticmethod
    def extract_github_issue(html: str) -> Dict[str, Optional[str]]:
        """
        Extract structured fields from a GitHub issue or pull request page.

        Returns dict with: title, body, labels, state.
        """
        fields: Dict[str, Optional[str]] = {
            "title": None,
            "body": None,
            "labels": None,
            "state": None,
        }
        if not html:
            return fields
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
        except ImportError:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, "html.parser")
            except ImportError:
                return fields

        # Title
        title_el = soup.find(class_=re.compile(r"js-issue-title|gh-header-title", re.I))
        if title_el:
            fields["title"] = title_el.get_text(strip=True)
        else:
            h1 = soup.find("h1")
            if h1:
                fields["title"] = h1.get_text(strip=True)

        # Body (first comment)
        body_el = soup.find(class_=re.compile(r"comment-body|markdown-body", re.I))
        if body_el:
            fields["body"] = body_el.get_text(separator="\n", strip=True)

        # Labels
        label_els = soup.find_all(class_=re.compile(r"IssueLabel|label", re.I))
        if label_els:
            labels = [l.get_text(strip=True) for l in label_els if l.get_text(strip=True)]
            fields["labels"] = ", ".join(labels[:10]) if labels else None

        # State (open/closed/merged)
        state_el = soup.find(class_=re.compile(r"State--", re.I))
        if state_el:
            fields["state"] = state_el.get_text(strip=True)

        return fields

    # ------------------------------------------------------------------
    # PDF extraction
    # ------------------------------------------------------------------

    @staticmethod
    def extract_text_from_pdf(pdf_bytes: bytes) -> Optional[str]:
        """Extract text from PDF using PyPDF2 or pdfplumber."""
        if not pdf_bytes:
            return None
        try:
            from PyPDF2 import PdfReader
            from io import BytesIO
            reader = PdfReader(BytesIO(pdf_bytes))
            parts = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    parts.append(text)
            if parts:
                return "\n\n".join(parts)
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"PyPDF2 extraction failed: {e}")

        try:
            import pdfplumber
            from io import BytesIO
            with pdfplumber.open(BytesIO(pdf_bytes)) as pdf:
                parts = []
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        parts.append(text)
                if parts:
                    return "\n\n".join(parts)
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"pdfplumber extraction failed: {e}")

        return None


# ------------------------------------------------------------------
# HTML helper: convert <table> to pipe-delimited text in-place
# ------------------------------------------------------------------

def _convert_table(table_tag) -> None:
    """Replace a <table> tag's content with pipe-delimited plain text rows."""
    from bs4 import NavigableString
    rows = table_tag.find_all("tr")
    if not rows:
        return
    lines = []
    for row in rows:
        cells = row.find_all(["td", "th"])
        cell_texts = [c.get_text(separator=" ", strip=True) for c in cells]
        lines.append("| " + " | ".join(cell_texts) + " |")
    table_tag.clear()
    table_tag.append(NavigableString("\n".join(lines)))


# ------------------------------------------------------------------
# HTML helper: convert <ul>/<ol> to indented text
# ------------------------------------------------------------------

def _convert_list(list_tag) -> None:
    """Replace a <ul>/<ol> tag's content with plain-text list items."""
    from bs4 import NavigableString
    items = list_tag.find_all("li", recursive=False)
    if not items:
        return
    is_ordered = list_tag.name == "ol"
    lines = []
    for i, item in enumerate(items, 1):
        prefix = f"{i}. " if is_ordered else "- "
        lines.append(prefix + item.get_text(separator=" ", strip=True))
    list_tag.clear()
    list_tag.append(NavigableString("\n".join(lines)))


# ------------------------------------------------------------------
# HTML helper: paragraph-density content block selection
# ------------------------------------------------------------------

def _best_content_block(soup):
    """
    Find the element with the highest density of <p> text.
    Falls back to <body> if nothing scores well.
    """
    best = None
    best_score = 0
    for div in soup.find_all(["div", "section", "main", "article"]):
        paragraphs = div.find_all("p")
        if not paragraphs:
            continue
        total_len = sum(len(p.get_text(strip=True)) for p in paragraphs)
        if total_len > best_score:
            best_score = total_len
            best = div
    return best


# ------------------------------------------------------------------
# Regex fallback
# ------------------------------------------------------------------

def _extract_text_from_html_regex(html: str) -> str:
    """Fallback HTML text extraction using regex when BeautifulSoup is unavailable."""
    if not html:
        return ""
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    text = text.replace("&nbsp;", " ")
    text = text.replace("&amp;", "&")
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    text = text.replace("&quot;", '"')
    return re.sub(r"\s+", " ", text).strip()
