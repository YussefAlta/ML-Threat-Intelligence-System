"""
Weak supervision labeling functions for threat intelligence document classification.

Each labeling function examines a document and returns a label or ABSTAIN.
Functions can conflict (multiple LFs may label the same doc differently).
The aggregation layer (majority vote or Snorkel LabelModel) resolves conflicts.

Categories:
    - vulnerability: CVE advisories, patches, security updates
    - exploit: PoC code, exploit writeups, 0-day disclosures
    - phishing: Credential harvesting, spoofed pages, social engineering
    - ransomware: Encryption malware, data leak sites, extortion
    - threat_actor: APT groups, campaigns, attribution
    - ioc: Indicators of compromise, C2 infrastructure, malware hashes
"""

import re
from typing import Callable, Dict, List

ABSTAIN = -1
VULNERABILITY = 0
EXPLOIT = 1
PHISHING = 2
RANSOMWARE = 3
THREAT_ACTOR = 4
IOC = 5

LABEL_NAMES = {
    VULNERABILITY: "vulnerability",
    EXPLOIT: "exploit",
    PHISHING: "phishing",
    RANSOMWARE: "ransomware",
    THREAT_ACTOR: "threat_actor",
    IOC: "ioc",
}

_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_RE_CVSS = re.compile(r"CVSS[^0-9]*[0-9]\.[0-9]", re.IGNORECASE)
_RE_SEVERITY = re.compile(r"severity\s*:\s*(critical|high)", re.IGNORECASE)
_RE_EXPLOIT_URL = re.compile(
    r"(exploit-db\.com|github\.com[^\s]*/(?:exploit|poc))", re.IGNORECASE
)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_APT = re.compile(r"\b(APT\d+|UNC\d+|FIN\d+|TA\d+)\b", re.IGNORECASE)

_VULNERABILITY_KEYWORDS = [
    r"\badvisory\b",
    r"\bsecurity update\b",
    r"\bpatch available\b",
    r"\baffected versions\b",
    r"\bremediation\b",
]
_RE_VULN = [re.compile(kw, re.IGNORECASE) for kw in _VULNERABILITY_KEYWORDS]

_EXPLOIT_KEYWORDS = [
    r"\bproof of concept\b",
    r"\bPoC\b",
    r"\bexploit code\b",
    r"\bexploitation\b",
    r"\bshellcode\b",
    r"\bMetasploit\b",
    r"\b0day\b",
    r"\bzero-day\b",
    r"\bweaponized\b",
]
_RE_EXPLOIT = [re.compile(kw, re.IGNORECASE) for kw in _EXPLOIT_KEYWORDS]

_PHISHING_KEYWORDS = [
    r"\bphishing\b",
    r"\bcredential harvesting\b",
    r"\bspoofed\b",
    r"\blure\b",
    r"\bphishing kit\b",
    r"\bfake login\b",
    r"\bsocial engineering\b",
    r"\bspear-phishing\b",
    r"\bbrand impersonation\b",
]
_RE_PHISH = [re.compile(kw, re.IGNORECASE) for kw in _PHISHING_KEYWORDS]

_RANSOMWARE_KEYWORDS = [
    r"\bransomware\b",
    r"\bransom\b",
    r"\bencrypt\b",
    r"\bdecryptor\b",
    r"\bdouble extortion\b",
    r"\bdata leak site\b",
    r"\bransom note\b",
    r"\bfile encryption\b",
]
_RE_RANSOM = [re.compile(kw, re.IGNORECASE) for kw in _RANSOMWARE_KEYWORDS]

_RANSOMWARE_FAMILIES = [
    "LockBit",
    "BlackCat",
    "ALPHV",
    "Conti",
    "REvil",
    "Clop",
    "Hive",
    "Royal",
    "Akira",
    "Play",
    "8Base",
    "Medusa",
    "BlackBasta",
    "Rhysida",
    "Vice Society",
    "Cuba",
    "Ragnar Locker",
]
_RE_RANSOM_FAMILY = re.compile(
    r"\b(" + "|".join(re.escape(f) for f in _RANSOMWARE_FAMILIES) + r")\b",
    re.IGNORECASE,
)

_THREAT_ACTOR_KEYWORDS = [
    r"\bthreat actor\b",
    r"\bthreat group\b",
    r"\battributed to\b",
    r"\bnation-state\b",
    r"\bespionage\b",
    r"\bcampaign\b",
    r"\bintrusion set\b",
    r"\bsuspected state-sponsored\b",
]
_RE_ACTOR_KW = [re.compile(kw, re.IGNORECASE) for kw in _THREAT_ACTOR_KEYWORDS]

_KNOWN_ACTORS = [
    "Lazarus",
    "Cozy Bear",
    "Fancy Bear",
    "Sandworm",
    "Turla",
    "Kimsuky",
    "Mustang Panda",
    "Charming Kitten",
    "Equation Group",
    "OceanLotus",
    "Winnti",
    "Hafnium",
    "Nobelium",
]
_RE_KNOWN_ACTOR = re.compile(
    r"\b(" + "|".join(re.escape(a) for a in _KNOWN_ACTORS) + r")\b",
    re.IGNORECASE,
)

_IOC_KEYWORDS = [
    r"\bindicator of compromise\b",
    r"\bIOC\b",
    r"\bC2\b",
    r"\bcommand and control\b",
    r"\bbeacon\b",
    r"\bcallback\b",
    r"\binfrastructure\b",
]
_RE_IOC = [re.compile(kw, re.IGNORECASE) for kw in _IOC_KEYWORDS]


def lf_cve_pattern(text: str, title: str, metadata: dict) -> int:
    """Returns VULNERABILITY if CVE pattern found, else ABSTAIN."""
    combined = f"{title} {text}"
    return VULNERABILITY if _RE_CVE.search(combined) else ABSTAIN


def lf_advisory_keywords(text: str, title: str, metadata: dict) -> int:
    """Returns VULNERABILITY if >=2 advisory-related keywords found, else ABSTAIN."""
    combined = f"{title} {text}"
    count = sum(1 for r in _RE_VULN if r.search(combined))
    return VULNERABILITY if count >= 2 else ABSTAIN


def lf_cvss_score(text: str, title: str, metadata: dict) -> int:
    """Returns VULNERABILITY if CVSS or severity pattern found, else ABSTAIN."""
    combined = f"{title} {text}"
    if _RE_CVSS.search(combined) or _RE_SEVERITY.search(combined):
        return VULNERABILITY
    return ABSTAIN


def lf_poc_keywords(text: str, title: str, metadata: dict) -> int:
    """Returns EXPLOIT if any PoC/exploit keyword found, else ABSTAIN."""
    combined = f"{title} {text}"
    return EXPLOIT if any(r.search(combined) for r in _RE_EXPLOIT) else ABSTAIN


def lf_exploit_url(text: str, title: str, metadata: dict) -> int:
    """Returns EXPLOIT if exploit-db or github exploit/PoC URL found, else ABSTAIN."""
    combined = f"{title} {text}"
    return EXPLOIT if _RE_EXPLOIT_URL.search(combined) else ABSTAIN


def lf_phishing_keywords(text: str, title: str, metadata: dict) -> int:
    """Returns PHISHING if >=2 phishing-related keywords found, else ABSTAIN."""
    combined = f"{title} {text}"
    count = sum(1 for r in _RE_PHISH if r.search(combined))
    return PHISHING if count >= 2 else ABSTAIN


def lf_phishing_source(text: str, title: str, metadata: dict) -> int:
    """Returns PHISHING if source is phishtank (distant supervision), else ABSTAIN."""
    return PHISHING if metadata.get("source") == "phishtank" else ABSTAIN


def lf_ransomware_keywords(text: str, title: str, metadata: dict) -> int:
    """Returns RANSOMWARE if >=2 ransomware-related keywords found, else ABSTAIN."""
    combined = f"{title} {text}"
    count = sum(1 for r in _RE_RANSOM if r.search(combined))
    return RANSOMWARE if count >= 2 else ABSTAIN


def lf_ransomware_families(text: str, title: str, metadata: dict) -> int:
    """Returns RANSOMWARE if known family name found, else ABSTAIN."""
    combined = f"{title} {text}"
    return RANSOMWARE if _RE_RANSOM_FAMILY.search(combined) else ABSTAIN


def lf_ransomware_source(text: str, title: str, metadata: dict) -> int:
    """Returns RANSOMWARE if source is ransomwatch, else ABSTAIN."""
    return RANSOMWARE if metadata.get("source") == "ransomwatch" else ABSTAIN


def lf_apt_pattern(text: str, title: str, metadata: dict) -> int:
    """Returns THREAT_ACTOR if APT/UNC/FIN/TA pattern found, else ABSTAIN."""
    combined = f"{title} {text}"
    return THREAT_ACTOR if _RE_APT.search(combined) else ABSTAIN


def lf_threat_actor_keywords(text: str, title: str, metadata: dict) -> int:
    """Returns THREAT_ACTOR if >=2 threat actor-related keywords found, else ABSTAIN."""
    combined = f"{title} {text}"
    count = sum(1 for r in _RE_ACTOR_KW if r.search(combined))
    return THREAT_ACTOR if count >= 2 else ABSTAIN


def lf_known_actors(text: str, title: str, metadata: dict) -> int:
    """Returns THREAT_ACTOR if known group name found, else ABSTAIN."""
    combined = f"{title} {text}"
    return THREAT_ACTOR if _RE_KNOWN_ACTOR.search(combined) else ABSTAIN


def lf_ioc_ip_density(text: str, title: str, metadata: dict) -> int:
    """Returns IOC if >3 IPv4 addresses found, else ABSTAIN."""
    ips = _RE_IPV4.findall(text)
    return IOC if len(ips) > 3 else ABSTAIN


def lf_ioc_hash_density(text: str, title: str, metadata: dict) -> int:
    """Returns IOC if >2 hash patterns (MD5/SHA1/SHA256) found, else ABSTAIN."""
    md5 = len(_RE_MD5.findall(text))
    sha1 = len(_RE_SHA1.findall(text))
    sha256 = len(_RE_SHA256.findall(text))
    total = md5 + sha1 + sha256
    return IOC if total > 2 else ABSTAIN


def lf_ioc_keywords(text: str, title: str, metadata: dict) -> int:
    """Returns IOC if >=2 IOC-related keywords found, else ABSTAIN."""
    combined = f"{title} {text}"
    count = sum(1 for r in _RE_IOC if r.search(combined))
    return IOC if count >= 2 else ABSTAIN


def lf_ioc_source(text: str, title: str, metadata: dict) -> int:
    """Returns IOC if source is otx, else ABSTAIN."""
    return IOC if metadata.get("source") == "otx" else ABSTAIN


def get_all_labeling_functions() -> List[Callable]:
    """Returns list of all labeling functions."""
    return [
        lf_cve_pattern,
        lf_advisory_keywords,
        lf_cvss_score,
        lf_poc_keywords,
        lf_exploit_url,
        lf_phishing_keywords,
        lf_phishing_source,
        lf_ransomware_keywords,
        lf_ransomware_families,
        lf_ransomware_source,
        lf_apt_pattern,
        lf_threat_actor_keywords,
        lf_known_actors,
        lf_ioc_ip_density,
        lf_ioc_hash_density,
        lf_ioc_keywords,
        lf_ioc_source,
    ]


def apply_labeling_functions(doc: dict) -> Dict[str, List[int]]:
    """
    Run all LFs on document and return votes per category.
    ABSTAIN votes are filtered out.
    """
    content = doc.get("content", "")
    title = doc.get("title", "")
    metadata = doc.get("metadata", {})

    votes: Dict[str, List[int]] = {
        LABEL_NAMES[VULNERABILITY]: [],
        LABEL_NAMES[EXPLOIT]: [],
        LABEL_NAMES[PHISHING]: [],
        LABEL_NAMES[RANSOMWARE]: [],
        LABEL_NAMES[THREAT_ACTOR]: [],
        LABEL_NAMES[IOC]: [],
    }

    for lf in get_all_labeling_functions():
        label = lf(content, title, metadata)
        if label != ABSTAIN:
            votes[LABEL_NAMES[label]].append(label)

    return votes


def majority_vote(doc: dict, threshold: float = 0.3) -> Dict[str, float]:
    """
    Run LFs and return predicted labels with confidence.
    Label included if votes / (non-abstaining LFs for that category) >= threshold.
    Returns {"unknown": 0.0} if no labels predicted.
    """
    votes = apply_labeling_functions(doc)
    lfs_per_category = {
        LABEL_NAMES[VULNERABILITY]: 3,
        LABEL_NAMES[EXPLOIT]: 2,
        LABEL_NAMES[PHISHING]: 2,
        LABEL_NAMES[RANSOMWARE]: 3,
        LABEL_NAMES[THREAT_ACTOR]: 3,
        LABEL_NAMES[IOC]: 4,
    }

    result: Dict[str, float] = {}
    for cat_name, cat_votes in votes.items():
        total_lfs = lfs_per_category[cat_name]
        n_votes = len(cat_votes)
        if n_votes > 0:
            ratio = n_votes / total_lfs
            if ratio >= threshold:
                result[cat_name] = round(ratio, 4)

    if not result:
        return {"unknown": 0.0}
    return result


def label_corpus(documents: List[dict]) -> List[dict]:
    """
    Apply majority vote to each document.
    Returns list of docs with predicted_labels and label_votes added.
    """
    labeled = []
    for doc in documents:
        votes = apply_labeling_functions(doc)
        predicted = majority_vote(doc)
        label_votes = {k: len(v) for k, v in votes.items()}
        labeled.append(
            {
                **doc,
                "predicted_labels": predicted,
                "label_votes": label_votes,
            }
        )
    return labeled
