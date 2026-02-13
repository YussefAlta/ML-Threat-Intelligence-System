"""
Content cleaning utilities for NVD reference scraping.

Provides text extraction from HTML, boilerplate removal, normalization,
language detection, and chunking for large documents.
"""

from __future__ import annotations

import re
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


# Common boilerplate patterns to remove
BOILERPLATE_PATTERNS = [
    r"cookie\s*(?:policy|notice|banner|consent)",
    r"gdpr\s*(?:notice|consent|compliant)",
    r"privacy\s*policy",
    r"terms\s*of\s*(?:service|use)",
    r"©\s*\d{4}.*?(?=\n|$)",
    r"all\s*rights\s*reserved",
    r"skip\s*(?:to\s*)?(?:main\s*)?content",
    r"\[?\s*menu\s*\]?",
    r"\[?\s*home\s*\]?",
    r"\[?\s*search\s*\]?",
    r"\[?\s*login\s*\]?",
    r"\[?\s*sign\s*in\s*\]?",
    r"page\s*\d+\s*of\s*\d+",
    r"^\s*[-=*]{3,}\s*$",
]


class ContentCleaner:
    """Cleaning utilities for reference content."""

    def __init__(self, max_chunk_size: int = 1_048_576):
        """
        Initialize content cleaner.

        Args:
            max_chunk_size: Maximum size in bytes for a single chunk (default 1MB)
        """
        self.max_chunk_size = max_chunk_size

    def clean_text(self, text: str, content_type: str = "text/plain") -> str:
        """
        Clean text based on content type.

        Args:
            text: Raw text to clean
            content_type: MIME type of original content

        Returns:
            Cleaned text
        """
        if not text or not isinstance(text, str):
            return ""

        text = self.normalize_whitespace(text)
        text = self.remove_boilerplate(text)
        return text.strip()

    def remove_boilerplate(self, text: str) -> str:
        """
        Remove common boilerplate patterns (cookie notices, nav menus, etc.).

        Args:
            text: Input text

        Returns:
            Text with boilerplate removed
        """
        if not text:
            return ""

        result = text
        for pattern in BOILERPLATE_PATTERNS:
            result = re.sub(pattern, "", result, flags=re.IGNORECASE | re.DOTALL)

        return result

    def normalize_whitespace(self, text: str) -> str:
        """
        Normalize whitespace: collapse multiple spaces/newlines, remove control chars.

        Args:
            text: Input text

        Returns:
            Normalized text
        """
        if not text:
            return ""

        # Remove control characters (except newline, tab)
        text = "".join(
            c for c in text if c in "\n\t\r" or (ord(c) >= 32 and ord(c) != 127)
        )
        # Collapse multiple spaces to single space
        text = re.sub(r"[ \t]+", " ", text)
        # Collapse multiple newlines to max 2
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def detect_language(self, text: str) -> str:
        """
        Detect language of text. Uses langdetect if available.

        Args:
            text: Input text (sample, first ~1000 chars used)

        Returns:
            Language code (e.g., 'en', 'de') or 'unknown'
        """
        if not text or len(text.strip()) < 50:
            return "unknown"

        sample = text[:1000] if len(text) > 1000 else text
        try:
            import langdetect

            return langdetect.detect(sample)
        except Exception as e:
            logger.debug(f"Language detection failed: {e}")
            return "unknown"

    def chunk_large_text(self, text: str, max_chunk_size: Optional[int] = None) -> List[str]:
        """
        Split large text into chunks while maintaining paragraph boundaries.

        Args:
            text: Input text
            max_chunk_size: Max bytes per chunk (default: self.max_chunk_size)

        Returns:
            List of text chunks
        """
        size = max_chunk_size or self.max_chunk_size
        if not text or len(text.encode("utf-8")) <= size:
            return [text] if text else []

        chunks: List[str] = []
        remaining = text
        encoding = "utf-8"

        while remaining:
            if len(remaining.encode(encoding)) <= size:
                chunks.append(remaining)
                break

            # Find a good break point within the limit
            target = remaining[:size]
            last_newline = target.rfind("\n")
            last_period = target.rfind(". ")

            # Prefer breaking at paragraph, then sentence
            break_point = last_newline if last_newline > size // 2 else last_period
            if break_point <= 0:
                break_point = size

            chunk = remaining[: break_point + 1].strip()
            if chunk:
                chunks.append(chunk)
            remaining = remaining[break_point + 1 :].strip()

        return chunks

    @staticmethod
    def extract_text_from_html(html: str) -> str:
        """
        Extract text from HTML using BeautifulSoup.

        Removes script, style, nav, header, footer. Tries to get main content.

        Args:
            html: Raw HTML string

        Returns:
            Extracted plain text
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

        # Remove unwanted elements
        for tag in soup.find_all(["script", "style", "nav", "header", "footer", "aside"]):
            tag.decompose()

        # Prefer main content areas
        main = soup.find("main") or soup.find("article") or soup.find(class_=re.compile(r"content|main|post"))
        if main:
            body = main
        else:
            body = soup.find("body") or soup

        if not body:
            return ""

        text = body.get_text(separator="\n", strip=True)
        # Decode common HTML entities (BeautifulSoup usually does this)
        return text

    @staticmethod
    def extract_text_from_pdf(pdf_bytes: bytes) -> Optional[str]:
        """
        Extract text from PDF using PyPDF2 or pdfplumber.

        Args:
            pdf_bytes: Raw PDF bytes

        Returns:
            Extracted text or None if extraction fails
        """
        if not pdf_bytes:
            return None

        # Try PyPDF2 first
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

        # Try pdfplumber as fallback
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


def _extract_text_from_html_regex(html: str) -> str:
    """Fallback HTML text extraction using regex when BeautifulSoup is unavailable."""
    if not html:
        return ""
    # Remove script and style
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    # Strip tags
    text = re.sub(r"<[^>]+>", " ", html)
    # Decode common entities
    text = text.replace("&nbsp;", " ")
    text = text.replace("&amp;", "&")
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    text = text.replace("&quot;", '"')
    return re.sub(r"\s+", " ", text).strip()
