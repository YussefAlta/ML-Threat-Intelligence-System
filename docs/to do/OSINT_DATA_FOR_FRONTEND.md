# OSINT Data for Frontend Visualization

This document outlines the unique data fields provided by OSINT sources that are not available from NVD, CWE, or VulnCheck, and how they can be visualized in the frontend.

---

## Unique Data by Source

### PhishTank (Phishing)

| Field | Frontend Value |
|-------|----------------|
| **Target brand** | Which companies/banks are being impersonated (e.g., "PayPal", "Chase Bank") |
| **Malicious URLs** | Actual phishing URLs for blocklists |
| **Verification status** | Whether the phish has been community-verified |
| **Submission time** | How fresh the phishing campaign is |

**Not in NVD/VulnCheck**: NVD tracks software vulnerabilities. PhishTank tracks active social engineering campaigns -- a completely different threat vector.

---

### ransomwatch (Ransomware)

| Field | Frontend Value |
|-------|----------------|
| **Ransomware group name** | LockBit, BlackCat, Clop, etc. |
| **Victim organization** | Companies currently being extorted |
| **Discovery date** | When the leak was posted |
| **Group profile/meta** | Description of the group's operations |
| **Leak site URLs** | Where the data is being dumped |

**Not in NVD/VulnCheck**: NVD has CVEs that might be used by ransomware. ransomwatch shows active extortion in progress with named victims. This is operational threat intel, not vulnerability metadata.

---

### MITRE ATT&CK (Threat Actors)

| Field | Frontend Value |
|-------|----------------|
| **APT group names** | APT29, Lazarus, Sandworm, etc. |
| **Aliases** | Cozy Bear, NOBELIUM, etc. (same actor, different names) |
| **Techniques (TTPs)** | Specific attack methods used (spearphishing, credential dumping, etc.) |
| **Associated malware** | Which malware families the group deploys |
| **Associated tools** | Legitimate tools abused (Cobalt Strike, Mimikatz) |
| **Attribution context** | Nation-state, financially motivated, etc. |

**Not in NVD/VulnCheck**: NVD tells you "this CVE exists." ATT&CK tells you *who* exploits it, *how* they operate, and *what* else they use. This links CVEs to human adversaries.

---

### ExploitDB (Exploits)

| Field | Frontend Value |
|-------|----------------|
| **Platform** | Windows, Linux, macOS, iOS, etc. |
| **Exploit type** | Local, Remote, DoS, WebApps, Shellcode |
| **Target port** | Which service/port is targeted |
| **Author** | Who wrote the exploit |
| **Exploit description** | More detailed than VulnCheck summaries |

**Overlaps with VulnCheck but adds**: Platform specificity, exploit type classification, and port targeting -- useful for filtering ("show me all remote Linux exploits").

---

### AlienVault OTX (IOCs)

| Field | Frontend Value |
|-------|----------------|
| **Indicator type breakdown** | Count of IPs, domains, hashes, URLs per pulse |
| **Tags** | Malware names, campaign names, threat types |
| **Pulse descriptions** | Analyst write-ups with context |
| **Author** | Who contributed the intel |
| **References** | Links to reports, blogs, analysis |

**Not in NVD/VulnCheck**: Raw IOCs (IPs, domains, hashes) that can be exported to firewalls, SIEMs, and EDR tools. NVD has no IOC data at all.

---

## Frontend Visualization Opportunities

| Visualization | Data Source | What It Shows |
|---------------|-------------|---------------|
| **Brand Impersonation Heatmap** | PhishTank | Which brands are most targeted by phishing |
| **Ransomware Group Activity Timeline** | ransomwatch | Victim count per group over time |
| **APT TTP Matrix** | MITRE ATT&CK | Technique coverage by threat actor (like the ATT&CK Navigator) |
| **IOC Blocklist Export** | OTX | Downloadable IPs/domains/hashes for security tools |
| **Exploit Platform Distribution** | ExploitDB | Pie chart of exploits by target platform |
| **Threat Actor to CVE Mapping** | ATT&CK + NVD | Which APT groups are known to exploit which CVEs |
| **Active Threats Dashboard** | All OSINT | Unified view of current phishing, ransomware, and IOC activity |

---

## Summary

**NVD/CWE/VulnCheck answer**: "What vulnerabilities exist and how severe are they?"

**OSINT sources answer**: "What's being actively exploited right now, by whom, against which targets?"

The OSINT layer transforms the system from a vulnerability database into an operational threat intelligence platform.

---

## Implementation Notes

### Data Fields Available in Unified Schema

Each OSINT document in the corpus includes:

```json
{
  "id": "source_uniqueid_hash",
  "title": "Document title",
  "content": "Full text content",
  "url": "Source URL",
  "source": "phishtank|ransomwatch|mitre_attack|exploitdb|otx",
  "source_category_hint": "phishing|ransomware|threat_actor|exploit|ioc",
  "published_at": "ISO timestamp",
  "collected_at": "ISO timestamp",
  "metadata": {
    // Source-specific fields (see below)
  }
}
```

### Source-Specific Metadata Fields

**PhishTank:**
- `phish_id` - PhishTank record ID
- `target` - Target brand being impersonated
- `verified` - Verification status
- `original_url` - The phishing URL

**ransomwatch:**
- `group_name` - Ransomware group name
- `discovered` - Discovery timestamp
- `group_profile` - Group metadata and leak site URLs

**MITRE ATT&CK:**
- `mitre_id` - ATT&CK ID (e.g., G0016)
- `aliases` - Alternative names for the group
- `created` / `modified` - Record timestamps

**ExploitDB:**
- `edb_id` - ExploitDB ID
- `author` - Exploit author
- `platform` - Target platform
- `type` - Exploit type (local, remote, DoS, etc.)
- `port` - Target port

**AlienVault OTX:**
- `pulse_id` - OTX pulse ID
- `author` - Pulse author
- `tags` - Associated tags
- `indicator_count` - Total indicators in pulse
- `indicator_types` - Breakdown by indicator type
