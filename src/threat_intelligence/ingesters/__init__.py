"""
Data ingesters for threat intelligence sources.

Includes NIST NVD ingesters (CVE/CPE) and OSINT source ingesters
for building a multi-category threat intelligence corpus.
"""

from .nist_cve_ingester import NISTCVEIngester
from .nist_cpe_ingester import NISTCPEIngester

__all__ = [
    'NISTCVEIngester',
    'NISTCPEIngester',
]

try:
    from .phishtank_ingester import PhishTankIngester
    from .ransomwatch_ingester import RansomwatchIngester
    from .mitre_attack_ingester import MITREAttackIngester
    from .exploitdb_ingester import ExploitDBIngester
    from .threatfox_ingester import ThreatFoxIngester
    from .cisa_kev_ingester import CISAKEVIngester

    __all__ += [
        'PhishTankIngester',
        'RansomwatchIngester',
        'MITREAttackIngester',
        'ExploitDBIngester',
        'ThreatFoxIngester',
        'CISAKEVIngester',
    ]
except ImportError:
    pass
