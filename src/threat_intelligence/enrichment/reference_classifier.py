"""
URL-pattern-based reference classifier for NVD CVE reference links.

Classifies each reference URL into a category (e.g. vendor_advisory,
github_advisory, github_commit, media, code, etc.) using domain matching,
path patterns, and lightweight content hints. No ML -- pure rules.
"""

from __future__ import annotations

import re
import logging
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger(__name__)

# Categories returned by the classifier
VENDOR_ADVISORY = "vendor_advisory"
GITHUB_ADVISORY = "github_advisory"
GITHUB_COMMIT = "github_commit"
GITHUB_ISSUE = "github_issue"
GITHUB_REPO = "github_repo"
PATCH = "patch"
MAILING_LIST = "mailing_list"
CODE = "code"
MEDIA = "media"
GOVERNMENT = "government"
ARTICLE = "article"
UNKNOWN = "unknown"

# Domains that host security advisories
_ADVISORY_DOMAINS = frozenset({
    "security.gentoo.org",
    "www.debian.org",
    "ubuntu.com",
    "access.redhat.com",
    "security.netapp.com",
    "cert.org",
    "www.kb.cert.org",
    "kb.cert.org",
    "jvn.jp",
    "jvndb.jvn.jp",
    "www.oracle.com",
    "www.zerodayinitiative.com",
    "zerodayinitiative.com",
    "www.exploit-db.com",
    "exploit-db.com",
    "packetstormsecurity.com",
    "www.cisa.gov",
    "msrc.microsoft.com",
    "portal.msrc.microsoft.com",
    "chromereleases.googleblog.com",
    "support.apple.com",
    "www.mozilla.org",
    "bugzilla.mozilla.org",
    "bugzilla.redhat.com",
    "bugs.chromium.org",
})

# Domains that host mailing lists / disclosure archives
_MAILING_LIST_DOMAINS = frozenset({
    "seclists.org",
    "www.openwall.com",
    "openwall.com",
    "marc.info",
    "www.mail-archive.com",
    "mail-archive.com",
})

# Domains for media (video/audio) -- skip fetching
_MEDIA_DOMAINS = frozenset({
    "youtube.com",
    "www.youtube.com",
    "youtu.be",
    "vimeo.com",
    "www.vimeo.com",
    "dailymotion.com",
    "www.dailymotion.com",
})

# Domains for raw code / paste sites
_CODE_DOMAINS = frozenset({
    "pastebin.com",
    "www.pastebin.com",
    "paste.debian.net",
    "dpaste.org",
    "hastebin.com",
})

# Government TLDs / domains
_GOV_DOMAINS = frozenset({
    "nvd.nist.gov",
    "www.cisa.gov",
    "cisa.gov",
    "cyber.gov.au",
    "www.ncsc.gov.uk",
    "ncsc.gov.uk",
    "cert.europa.eu",
})

# Path patterns that indicate advisory content
_ADVISORY_PATH_RE = re.compile(
    r"/(advisory|advisories|security-advisory|security-notice|security-bulletin"
    r"|vuln/|vulnerability/|CVE-\d{4})",
    re.IGNORECASE,
)

# Path patterns for patches
_PATCH_PATH_RE = re.compile(
    r"/(patch|diff|changeset)(/|$)",
    re.IGNORECASE,
)


def _normalize_host(netloc: str) -> str:
    """Lowercase, strip port and www. prefix."""
    host = (netloc or "").lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_github_host(host: str) -> bool:
    return host in (
        "github.com",
        "raw.githubusercontent.com",
        "gist.github.com",
    )


def classify_url(url: str) -> str:
    """
    Classify a reference URL into a category based on domain and path patterns.

    Returns one of the module-level category constants.
    """
    if not url or not url.strip():
        return UNKNOWN

    try:
        parsed = urlparse(url)
    except Exception:
        return UNKNOWN

    if not parsed.netloc:
        return UNKNOWN

    host = _normalize_host(parsed.netloc)
    host_with_www = f"www.{host}"
    path = parsed.path or ""
    path_lower = path.lower()

    # --- GitHub ---
    if _is_github_host(host):
        if host == "raw.githubusercontent.com":
            return CODE
        if host == "gist.github.com":
            return CODE
        # GHSA advisory pages
        if "/advisories/GHSA-" in path or "/security/advisories/GHSA-" in path:
            return GITHUB_ADVISORY
        if "/commit/" in path_lower:
            return GITHUB_COMMIT
        if "/issues/" in path_lower or "/pull/" in path_lower:
            return GITHUB_ISSUE
        return GITHUB_REPO

    # --- Media ---
    if host in _MEDIA_DOMAINS or host_with_www in _MEDIA_DOMAINS:
        return MEDIA

    # --- Raw code / paste sites ---
    if host in _CODE_DOMAINS or host_with_www in _CODE_DOMAINS:
        return CODE

    # --- Mailing lists ---
    if host in _MAILING_LIST_DOMAINS or host_with_www in _MAILING_LIST_DOMAINS:
        return MAILING_LIST
    if host.startswith("lists."):
        return MAILING_LIST

    # --- Government ---
    if host.endswith(".gov") or host.endswith(".gov.uk") or host.endswith(".gov.au"):
        return GOVERNMENT
    if host in _GOV_DOMAINS or host_with_www in _GOV_DOMAINS:
        return GOVERNMENT

    # --- Known advisory vendors ---
    if host in _ADVISORY_DOMAINS or host_with_www in _ADVISORY_DOMAINS:
        return VENDOR_ADVISORY

    # --- Path-based heuristics ---
    if _PATCH_PATH_RE.search(path_lower):
        return PATCH
    if _ADVISORY_PATH_RE.search(path):
        return VENDOR_ADVISORY

    return ARTICLE


def classify_with_content_hint(
    url: str,
    title: Optional[str] = None,
    first_paragraph: Optional[str] = None,
) -> str:
    """
    Classify URL with optional content hints from fetched page.

    Falls back to pure URL classification when no hints improve the result.
    """
    base = classify_url(url)

    if base != ARTICLE or not (title or first_paragraph):
        return base

    combined = f"{title or ''} {first_paragraph or ''}".lower()

    advisory_signals = (
        "security advisory", "vulnerability", "cve-", "patch",
        "security bulletin", "security update", "security notice",
    )
    if any(s in combined for s in advisory_signals):
        return VENDOR_ADVISORY

    return base
