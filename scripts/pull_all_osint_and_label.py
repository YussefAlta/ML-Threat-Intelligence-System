#!/usr/bin/env python3
"""
Pull documents from all OSINT sources, label them, and merge with
existing NVD corpus into a single combined corpus + labeled set.

Sources: ransomwatch, MITRE ATT&CK, ExploitDB, AlienVault OTX, PhishTank
"""

import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from dotenv import load_dotenv
    load_dotenv()
    load_dotenv(".env.local")
except ImportError:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env.local")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    os.environ.setdefault(key.strip(), val.strip())

import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Simple config object so ingesters work without full Config class
# ---------------------------------------------------------------------------
class SimpleConfig:
    PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
    PHISHTANK_FEED_URL = os.getenv(
        "PHISHTANK_FEED_URL", "http://data.phishtank.com/data/online-valid.json"
    )
    RANSOMWATCH_FEED_URL = os.getenv(
        "RANSOMWATCH_FEED_URL",
        "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
    )
    RANSOMWATCH_GROUPS_URL = os.getenv(
        "RANSOMWATCH_GROUPS_URL",
        "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json",
    )
    MITRE_ATTACK_URL = os.getenv(
        "MITRE_ATTACK_URL",
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    )
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    OTX_API_BASE_URL = os.getenv("OTX_API_BASE_URL", "https://otx.alienvault.com/api/v1/")
    EXPLOITDB_CSV_URL = os.getenv(
        "EXPLOITDB_CSV_URL",
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    )
    EXPLOITDB_BASE_URL = os.getenv("EXPLOITDB_BASE_URL", "https://www.exploit-db.com/")


# ---------------------------------------------------------------------------
# Labeling logic (same rules as labeling_functions.py)
# ---------------------------------------------------------------------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
APT_RE = re.compile(r"\b(APT\d+|UNC\d+|FIN\d+|TA\d+)\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

VULN_KW = ["vulnerability", "advisory", "patch", "security update", "cwe-", "affected versions",
            "cvss", "remediation", "buffer overflow", "injection", "cross-site", "denial of service",
            "privilege escalation", "authentication bypass", "information disclosure"]
EXPLOIT_KW = ["proof of concept", "poc", "exploit code", "metasploit", "rce exploit", "shellcode",
              "0day", "zero-day", "weaponized", "exploitation", "exploit", "remote code execution",
              "arbitrary code", "code execution"]
PHISHING_KW = ["phishing", "credential harvesting", "spoofed", "lure", "phishing kit",
               "fake login", "social engineering", "spear-phishing", "brand impersonation"]
RANSOM_KW = ["ransomware", "ransom", "encrypt", "decryptor", "double extortion",
             "data leak", "ransom note", "file encryption", "leak site"]
RANSOM_FAMILIES = ["lockbit", "blackcat", "alphv", "conti", "revil", "clop", "hive",
                   "royal", "akira", "play", "8base", "medusa", "blackbasta", "rhysida",
                   "vice society", "cuba", "ragnar"]
ACTOR_KW = ["threat actor", "threat group", "attributed to", "nation-state", "espionage",
            "campaign", "intrusion set", "state-sponsored", "apt"]
ACTOR_NAMES = ["lazarus", "cozy bear", "fancy bear", "sandworm", "turla", "kimsuky",
               "mustang panda", "charming kitten", "hafnium", "nobelium", "wizard spider",
               "darkside", "fin7", "fin11", "carbanak", "ocean lotus", "winnti"]
IOC_KW = ["indicator of compromise", "ioc", "c2", "command and control", "beacon",
          "callback", "indicator", "infrastructure"]


def kw_count(text_lower, keywords):
    return sum(1 for kw in keywords if kw in text_lower)


def label_document(doc):
    text = (doc.get("content") or "").lower()
    title = (doc.get("title") or "").lower()
    combined = title + " " + text
    source = doc.get("source", "")
    hint = doc.get("source_category_hint", "")
    labels = {}

    # Vulnerability
    v = 0.0
    vs = []
    if CVE_RE.search(combined):
        v += 0.35; vs.append("cve_pattern")
    kc = kw_count(combined, VULN_KW)
    if kc >= 1:
        v += min(kc * 0.08, 0.5); vs.append(f"vuln_kw({kc})")
    if v >= 0.3:
        labels["vulnerability"] = {"confidence": min(v, 1.0), "signals": vs}

    # Exploit
    e = 0.0
    es = []
    kc = kw_count(combined, EXPLOIT_KW)
    if kc >= 1:
        e += min(kc * 0.12, 0.8); es.append(f"exploit_kw({kc})")
    if "exploit-db" in combined:
        e += 0.25; es.append("exploitdb_url")
    if source == "exploitdb":
        e += 0.3; es.append("source_exploitdb")
    if hint == "exploit":
        e += 0.15; es.append("hint_exploit")
    if e >= 0.3:
        labels["exploit"] = {"confidence": min(e, 1.0), "signals": es}

    # Phishing
    p = 0.0
    ps = []
    kc = kw_count(combined, PHISHING_KW)
    if kc >= 1:
        p += min(kc * 0.2, 0.8); ps.append(f"phish_kw({kc})")
    if source == "phishtank":
        p += 0.4; ps.append("source_phishtank")
    if hint == "phishing":
        p += 0.2; ps.append("hint_phishing")
    if p >= 0.3:
        labels["phishing"] = {"confidence": min(p, 1.0), "signals": ps}

    # Ransomware
    r = 0.0
    rs = []
    kc = kw_count(combined, RANSOM_KW)
    if kc >= 1:
        r += min(kc * 0.12, 0.7); rs.append(f"ransom_kw({kc})")
    fam = [f for f in RANSOM_FAMILIES if f in combined]
    if fam:
        r += min(len(fam) * 0.2, 0.6); rs.append(f"families({','.join(fam[:3])})")
    if source == "ransomwatch":
        r += 0.35; rs.append("source_ransomwatch")
    if hint == "ransomware":
        r += 0.15; rs.append("hint_ransomware")
    if r >= 0.3:
        labels["ransomware"] = {"confidence": min(r, 1.0), "signals": rs}

    # Threat Actor
    t = 0.0
    ts = []
    if APT_RE.search(combined):
        t += 0.4; ts.append("apt_pattern")
    kc = kw_count(combined, ACTOR_KW)
    if kc >= 1:
        t += min(kc * 0.1, 0.5); ts.append(f"actor_kw({kc})")
    nm = [n for n in ACTOR_NAMES if n in combined]
    if nm:
        t += min(len(nm) * 0.2, 0.6); ts.append(f"actors({','.join(nm[:3])})")
    if source == "mitre_attack":
        t += 0.3; ts.append("source_mitre")
    if hint == "threat_actor":
        t += 0.15; ts.append("hint_threat_actor")
    if t >= 0.3:
        labels["threat_actor"] = {"confidence": min(t, 1.0), "signals": ts}

    # IOC
    i = 0.0
    iis = []
    ip_count = len(IPV4_RE.findall(text))
    if ip_count > 3:
        i += 0.4; iis.append(f"ip_density({ip_count})")
    hash_count = len(HASH_MD5.findall(text)) + len(HASH_SHA1.findall(text)) + len(HASH_SHA256.findall(text))
    if hash_count > 2:
        i += 0.3; iis.append(f"hash_density({hash_count})")
    kc = kw_count(combined, IOC_KW)
    if kc >= 1:
        i += min(kc * 0.1, 0.5); iis.append(f"ioc_kw({kc})")
    if source == "otx":
        i += 0.3; iis.append("source_otx")
    if hint == "ioc":
        i += 0.15; iis.append("hint_ioc")
    if i >= 0.3:
        labels["ioc"] = {"confidence": min(i, 1.0), "signals": iis}

    if not labels:
        labels[hint or "unknown"] = {"confidence": 0.2, "signals": ["default_hint"]}

    return labels


def build_labeled_entry(doc, label_map):
    label_names = sorted(label_map.keys(), key=lambda k: label_map[k]["confidence"], reverse=True)
    primary = label_names[0] if label_names else "unknown"
    primary_conf = label_map[primary]["confidence"] if primary != "unknown" else 0.0
    return {
        "id": doc["id"],
        "title": doc["title"],
        "url": doc.get("url", ""),
        "source": doc.get("source", ""),
        "source_category_hint": doc.get("source_category_hint", ""),
        "content_length": len(doc.get("content", "")),
        "labels": label_names,
        "primary_label": primary,
        "primary_confidence": round(primary_conf, 2),
        "label_details": {
            k: {"confidence": round(v["confidence"], 2), "signals": v["signals"]}
            for k, v in label_map.items()
        },
        "content_preview": (doc.get("content") or "")[:300].replace("\n", " "),
    }


def main():
    from src.threat_intelligence.ingesters.ransomwatch_ingester import RansomwatchIngester
    from src.threat_intelligence.ingesters.mitre_attack_ingester import MITREAttackIngester
    from src.threat_intelligence.ingesters.exploitdb_ingester import ExploitDBIngester
    from src.threat_intelligence.ingesters.otx_ingester import OTXIngester
    from src.threat_intelligence.ingesters.phishtank_ingester import PhishTankIngester

    config = SimpleConfig()
    all_docs = []
    results = {}

    # --- Ransomwatch (ransomware) ---
    logger.info("=" * 60)
    logger.info("Pulling from RANSOMWATCH...")
    try:
        rw = RansomwatchIngester(config)
        rw_docs = rw.ingest(max_records=100)
        all_docs.extend(rw_docs)
        results["ransomwatch"] = {"count": len(rw_docs), "status": "OK"}
        logger.info(f"  Ransomwatch: {len(rw_docs)} docs")
    except Exception as ex:
        logger.error(f"  Ransomwatch failed: {ex}")
        results["ransomwatch"] = {"count": 0, "status": f"FAILED: {ex}"}

    # --- MITRE ATT&CK (threat actors) ---
    logger.info("Pulling from MITRE ATT&CK...")
    try:
        ma = MITREAttackIngester(config)
        ma_docs = ma.ingest(max_records=100)
        all_docs.extend(ma_docs)
        results["mitre_attack"] = {"count": len(ma_docs), "status": "OK"}
        logger.info(f"  MITRE ATT&CK: {len(ma_docs)} docs")
    except Exception as ex:
        logger.error(f"  MITRE ATT&CK failed: {ex}")
        results["mitre_attack"] = {"count": 0, "status": f"FAILED: {ex}"}

    # --- ExploitDB (exploits) ---
    logger.info("Pulling from EXPLOITDB...")
    try:
        edb = ExploitDBIngester(config)
        edb_docs = edb.ingest(max_records=100)
        all_docs.extend(edb_docs)
        results["exploitdb"] = {"count": len(edb_docs), "status": "OK"}
        logger.info(f"  ExploitDB: {len(edb_docs)} docs")
    except Exception as ex:
        logger.error(f"  ExploitDB failed: {ex}")
        results["exploitdb"] = {"count": 0, "status": f"FAILED: {ex}"}

    # --- AlienVault OTX (IOCs) ---
    logger.info("Pulling from ALIENVAULT OTX...")
    try:
        otx = OTXIngester(config)
        otx_docs = otx.ingest(max_records=50)
        all_docs.extend(otx_docs)
        results["otx"] = {"count": len(otx_docs), "status": "OK"}
        logger.info(f"  OTX: {len(otx_docs)} docs")
    except Exception as ex:
        logger.error(f"  OTX failed: {ex}")
        results["otx"] = {"count": 0, "status": f"FAILED: {ex}"}

    # --- PhishTank (phishing) ---
    logger.info("Pulling from PHISHTANK...")
    try:
        pt = PhishTankIngester(config)
        pt_docs = pt.ingest(max_records=100)
        all_docs.extend(pt_docs)
        results["phishtank"] = {"count": len(pt_docs), "status": "OK"}
        logger.info(f"  PhishTank: {len(pt_docs)} docs")
    except Exception as ex:
        logger.error(f"  PhishTank failed: {ex}")
        results["phishtank"] = {"count": 0, "status": f"FAILED: {ex}"}

    logger.info(f"\nTotal OSINT docs collected: {len(all_docs)}")

    # --- Label all OSINT docs ---
    logger.info("Labeling OSINT documents...")
    osint_labeled = []
    for doc in all_docs:
        lm = label_document(doc)
        doc["_labels"] = lm
        osint_labeled.append(build_labeled_entry(doc, lm))

    # --- Load existing NVD corpus ---
    nvd_corpus_path = "data/corpus/nvd_cves_200.jsonl"
    nvd_labeled_path = "data/gold/nvd_cves_labeled_200.jsonl"
    nvd_docs = []
    nvd_labeled = []
    if os.path.exists(nvd_corpus_path):
        with open(nvd_corpus_path) as f:
            for line in f:
                nvd_docs.append(json.loads(line))
        logger.info(f"Loaded {len(nvd_docs)} existing NVD docs from {nvd_corpus_path}")
    if os.path.exists(nvd_labeled_path):
        with open(nvd_labeled_path) as f:
            for line in f:
                nvd_labeled.append(json.loads(line))

    # --- Merge ---
    combined_corpus = nvd_docs + [{k: v for k, v in d.items() if k != "_labels"} for d in all_docs]
    combined_labeled = nvd_labeled + osint_labeled

    # --- Save ---
    os.makedirs("data/corpus", exist_ok=True)
    os.makedirs("data/gold", exist_ok=True)

    corpus_path = "data/corpus/combined_corpus.jsonl"
    with open(corpus_path, "w") as f:
        for doc in combined_corpus:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")

    labeled_path = "data/gold/combined_labeled.jsonl"
    with open(labeled_path, "w") as f:
        for item in combined_labeled:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    logger.info(f"Saved combined corpus ({len(combined_corpus)} docs) to {corpus_path}")
    logger.info(f"Saved combined labels ({len(combined_labeled)} docs) to {labeled_path}")

    # --- Summary ---
    from collections import Counter
    label_counts = Counter()
    source_counts = Counter()
    for item in combined_labeled:
        for lbl in item["labels"]:
            label_counts[lbl] += 1
        source_counts[item.get("source", "unknown")] += 1

    print(f"\n{'='*70}")
    print(f"Combined Corpus Summary -- {len(combined_labeled)} total documents")
    print(f"{'='*70}")

    print(f"\nSource breakdown:")
    print(f"  {'Source':<20s} {'Count':>5s}  {'Status'}")
    print(f"  {'-'*20} {'-'*5}  {'-'*20}")
    for src in ["nvd_ref", "ransomwatch", "mitre_attack", "exploitdb", "otx", "phishtank"]:
        cnt = source_counts.get(src, 0)
        status = results.get(src, {}).get("status", "existing")
        print(f"  {src:<20s} {cnt:>5d}  {status}")

    print(f"\nLabel distribution (multi-label):")
    print(f"  {'Category':<20s} {'Count':>5s}  {'%':>6s}")
    print(f"  {'-'*20} {'-'*5}  {'-'*6}")
    for lbl, cnt in label_counts.most_common():
        pct = cnt / len(combined_labeled) * 100
        print(f"  {lbl:<20s} {cnt:>5d}  {pct:5.1f}%")

    multi = sum(1 for item in combined_labeled if len(item["labels"]) > 1)
    print(f"\n  Multi-label docs:    {multi} ({multi/len(combined_labeled)*100:.1f}%)")

    print(f"\nSample docs per source:")
    shown_sources = set()
    for item in combined_labeled:
        src = item.get("source", "unknown")
        if src in shown_sources:
            continue
        shown_sources.add(src)
        labels_str = ", ".join(f"{l}({item['label_details'][l]['confidence']})" for l in item["labels"])
        print(f"\n  [{src}] {item['title'][:80]}")
        print(f"    Labels: {labels_str}")

    print(f"\n{'='*70}")
    print(f"Output files:")
    print(f"  Corpus:  {corpus_path}  ({len(combined_corpus)} docs)")
    print(f"  Labels:  {labeled_path}  ({len(combined_labeled)} docs)")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
