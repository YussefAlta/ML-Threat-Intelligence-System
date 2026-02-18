"""
Entity normalization for threat intelligence.

Canonicalizes entity mentions to reduce fragmentation: maps vendor/product
name variants to canonical forms, normalizes threat actor aliases, and
standardizes malware family names.
"""

from typing import Dict, List, Any


class EntityNormalizer:
    """
    Canonicalizes entity values using lookup tables for vendors, threat actors,
    and malware families.
    """

    VENDOR_ORGANIZATION: Dict[str, str] = {
        "microsoft": "Microsoft",
        "msft": "Microsoft",
        "ms": "Microsoft",
        "google": "Google",
        "alphabet": "Google",
        "apple": "Apple",
        "apple inc": "Apple",
        "amazon": "Amazon",
        "aws": "Amazon Web Services",
        "cisco": "Cisco",
        "cisco systems": "Cisco",
        "oracle": "Oracle",
        "oracle corp": "Oracle",
        "adobe": "Adobe",
        "adobe systems": "Adobe",
        "vmware": "VMware",
        "broadcom": "Broadcom",
        "fortinet": "Fortinet",
        "fortigate": "Fortinet",
        "palo alto": "Palo Alto Networks",
        "pan": "Palo Alto Networks",
        "crowdstrike": "CrowdStrike",
        "mandiant": "Mandiant",
        "sophos": "Sophos",
        "sentinelone": "SentinelOne",
    }

    THREAT_ACTOR_ALIASES: Dict[str, str] = {
        "apt29": "APT29",
        "cozy bear": "APT29",
        "the dukes": "APT29",
        "nobelium": "APT29",
        "midnight blizzard": "APT29",
        "apt28": "APT28",
        "fancy bear": "APT28",
        "sofacy": "APT28",
        "forest blizzard": "APT28",
        "lazarus": "Lazarus Group",
        "lazarus group": "Lazarus Group",
        "hidden cobra": "Lazarus Group",
        "diamond sleet": "Lazarus Group",
        "sandworm": "Sandworm",
        "voodoo bear": "Sandworm",
        "seashell blizzard": "Sandworm",
        "turla": "Turla",
        "venomous bear": "Turla",
        "secret blizzard": "Turla",
        "kimsuky": "Kimsuky",
        "velvet chollima": "Kimsuky",
        "emerald sleet": "Kimsuky",
        "hafnium": "HAFNIUM",
        "silk typhoon": "HAFNIUM",
        "mustang panda": "Mustang Panda",
        "bronze president": "Mustang Panda",
        "charming kitten": "Charming Kitten",
        "apt35": "Charming Kitten",
        "mint sandstorm": "Charming Kitten",
    }

    MALWARE_FAMILIES: Dict[str, str] = {
        "lockbit": "LockBit",
        "lockbit 3.0": "LockBit",
        "lockbit black": "LockBit",
        "blackcat": "BlackCat",
        "alphv": "BlackCat",
        "noberus": "BlackCat",
        "conti": "Conti",
        "revil": "REvil",
        "sodinokibi": "REvil",
        "clop": "Clop",
        "cl0p": "Clop",
        "cobalt strike": "Cobalt Strike",
        "cobaltstrike": "Cobalt Strike",
        "mimikatz": "Mimikatz",
        "emotet": "Emotet",
        "trickbot": "TrickBot",
        "qakbot": "Qakbot",
        "qbot": "Qakbot",
    }

    def __init__(self) -> None:
        pass

    def normalize_entity(self, entity: Dict) -> Dict:
        """
        Add canonical_value to an entity based on its type and value.

        Args:
            entity: Entity dict with type and value.

        Returns:
            New entity dict with canonical_value added. If no mapping exists,
            canonical_value equals value.
        """
        result = dict(entity)
        value = entity.get("value", "")
        if not value:
            result["canonical_value"] = value
            return result

        etype = entity.get("type", "").lower()
        key = str(value).strip().lower()
        canonical = value

        if etype in ("organization", "system"):
            canonical = self.VENDOR_ORGANIZATION.get(key, value)
        elif etype == "threat_actor":
            canonical = self.THREAT_ACTOR_ALIASES.get(key, value)
        elif etype == "malware":
            canonical = self.MALWARE_FAMILIES.get(key, value)

        result["canonical_value"] = canonical
        return result

    def normalize_entities(self, entities: List[Dict]) -> List[Dict]:
        """
        Normalize all entities in the list.

        Args:
            entities: List of entity dicts with type and value.

        Returns:
            New list of entity dicts with canonical_value added to each.
        """
        return [self.normalize_entity(e) for e in entities]

    def deduplicate_by_canonical(self, entities: List[Dict]) -> List[Dict]:
        """
        Deduplicate entities by (type, canonical_value), keeping the one with
        the highest score or first occurrence if no score.

        Args:
            entities: List of entity dicts. Must have canonical_value (run
                normalize_entities first) or value used as fallback.

        Returns:
            Deduplicated list of entity dicts.
        """
        groups: Dict[tuple, Dict] = {}
        for e in entities:
            canonical = e.get("canonical_value", e.get("value", ""))
            key = (e.get("type", ""), canonical)
            score = e.get("score", 0.0)
            if key not in groups:
                groups[key] = e
            else:
                existing_score = groups[key].get("score", 0.0)
                if score > existing_score:
                    groups[key] = e
        return list(groups.values())
