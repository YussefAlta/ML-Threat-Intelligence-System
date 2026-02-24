"""
MITRE ATT&CK threat actor (intrusion-set) ingester.

Fetches the enterprise-attack STIX bundle and produces unified documents
for threat actor groups, enriched with technique, malware, and tool information.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class MITREAttackIngester:
    """
    Ingests threat actor (intrusion-set) data from MITRE ATT&CK STIX bundle.
    Produces unified documents for use in the threat intelligence corpus.
    """

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ML-Threat-Intelligence-System/1.0',
            'Accept': 'application/json',
        })

    def ingest(self, max_records: int = 200) -> List[Dict]:
        url = getattr(self.config, 'MITRE_ATTACK_URL', None) or (
            'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
        )
        try:
            resp = self.session.get(url, timeout=120)
            resp.raise_for_status()
            bundle = resp.json()
        except requests.RequestException as e:
            logger.error("Failed to fetch MITRE ATT&CK bundle: %s", e)
            return []
        except ValueError as e:
            logger.error("Invalid JSON from MITRE ATT&CK: %s", e)
            return []

        objects = bundle.get('objects', [])
        if not objects:
            logger.warning("MITRE ATT&CK bundle has no objects")
            return []

        by_id = {obj['id']: obj for obj in objects if obj.get('id')}
        intrusion_sets = [
            obj for obj in objects
            if obj.get('type') == 'intrusion-set'
        ]
        malware_by_id = {obj['id']: obj for obj in objects if obj.get('type') == 'malware'}
        tools_by_id = {obj['id']: obj for obj in objects if obj.get('type') == 'tool'}
        attack_patterns = {obj['id']: obj for obj in objects if obj.get('type') == 'attack-pattern'}
        relationships = [obj for obj in objects if obj.get('type') == 'relationship']

        docs = []
        for i, obj in enumerate(intrusion_sets):
            if len(docs) >= max_records:
                break
            if obj.get('revoked'):
                continue
            try:
                doc = self._to_unified_doc(
                    obj,
                    by_id,
                    attack_patterns,
                    malware_by_id,
                    tools_by_id,
                    relationships,
                )
                if doc:
                    docs.append(doc)
                    if (len(docs) % 50) == 0:
                        logger.info("MITRE ATT&CK ingester: collected %d documents...", len(docs))
            except Exception as e:
                logger.warning("Skipping intrusion-set %s: %s", obj.get('id'), e)
                continue

        logger.info(
            "MITRE ATT&CK ingester: collected %d documents (max=%d)",
            len(docs),
            max_records,
        )
        return docs

    def _to_unified_doc(
        self,
        obj: Dict,
        by_id: Dict,
        attack_patterns: Dict,
        malware_by_id: Dict,
        tools_by_id: Dict,
        relationships: List[Dict],
    ) -> Optional[Dict]:
        mitre_ref = None
        for r in obj.get('external_references') or []:
            if r.get('source_name') == 'mitre-attack':
                mitre_ref = r
                break
        external_id = (mitre_ref or {}).get('external_id') or (obj.get('id', '')[-8:] if obj.get('id') else 'unknown')
        url = (mitre_ref or {}).get('url') or ''

        techniques = []
        for rel in relationships:
            if rel.get('source_ref') != obj.get('id') or rel.get('relationship_type') != 'uses':
                continue
            target = attack_patterns.get(rel.get('target_ref'))
            if target and target.get('name'):
                techniques.append(target['name'])

        malware = []
        for rel in relationships:
            if rel.get('source_ref') != obj.get('id') or rel.get('relationship_type') != 'uses':
                continue
            target = malware_by_id.get(rel.get('target_ref'))
            if target and target.get('name'):
                malware.append(target['name'])

        tools = []
        for rel in relationships:
            if rel.get('source_ref') != obj.get('id') or rel.get('relationship_type') != 'uses':
                continue
            target = tools_by_id.get(rel.get('target_ref'))
            if target and target.get('name'):
                tools.append(target['name'])

        name = obj.get('name') or 'Unknown'
        description = (obj.get('description') or '').strip()
        aliases = obj.get('aliases') or []
        alias_str = ', '.join(aliases) if aliases else ''
        technique_str = ', '.join(techniques[:20]) if techniques else 'None documented'
        malware_str = ', '.join(malware[:10]) if malware else ''
        tool_str = ', '.join(tools[:10]) if tools else ''

        parts = [f"Threat actor: {name}."]
        if alias_str:
            parts.append(f"Aliases: {alias_str}.")
        if description:
            parts.append(description)
        if techniques:
            parts.append(f"Known techniques: {technique_str}.")
        if malware:
            parts.append(f"Associated malware: {malware_str}.")
        if tools:
            parts.append(f"Associated tools: {tool_str}.")
        content = ' '.join(parts)

        raw_id = f"{external_id}{name}{url}"
        hash8 = hashlib.sha256(raw_id.encode()).hexdigest()[:8]
        doc_id = f"mitre_attack_{external_id}_{hash8}"

        created = obj.get('created') or obj.get('modified')
        return {
            "id": doc_id,
            "title": f"Threat Actor: {name}",
            "content": content,
            "url": url or None,
            "source": "mitre_attack",
            "source_category_hint": "threat_actor",
            "published_at": created,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "mitre_id": external_id,
                "aliases": aliases,
                "created": obj.get('created'),
                "modified": obj.get('modified'),
                "revoked": bool(obj.get('revoked')),
            },
        }
