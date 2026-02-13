import sys
sys.path.insert(0, "src")

from threat_intelligence.storage.reference_storage import ReferenceStorage
from threat_intelligence.enrichment.content_cleaner import ContentCleaner
from threat_intelligence.enrichment.github_security_enricher import GitHubSecurityEnricher

def main():
    storage = ReferenceStorage()
    cleaner = ContentCleaner()
    enr = GitHubSecurityEnricher(storage, cleaner)

    cves = [{"cve_id": "CVE-2021-44228"}]
    print(enr.enrich_cves(cves))

if __name__ == "__main__":
    main()

