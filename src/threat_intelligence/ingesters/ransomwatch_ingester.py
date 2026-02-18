"""
Ransomwatch ransomware leak feed ingester.
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List

import requests

logger = logging.getLogger(__name__)

RANSOMWATCH_GITHUB_URL = "https://github.com/joshhighet/ransomwatch"


class RansomwatchIngester:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ML-Threat-Intelligence-System/1.0 (https://github.com)'
        })

    def _fetch_groups(self) -> Dict[str, Dict]:
        url = getattr(self.config, 'RANSOMWATCH_GROUPS_URL', None) or \
              'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json'
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            groups = resp.json()
        except (requests.RequestException, ValueError) as e:
            logger.warning("Failed to fetch Ransomwatch groups: %s", e)
            return {}

        lookup = {}
        for g in groups if isinstance(groups, list) else []:
            name = g.get('name') if isinstance(g, dict) else None
            if name:
                profile = g.get('profile', [])
                meta = g.get('meta')
                locations = g.get('locations', [])
                slugs = []
                for loc in locations if isinstance(locations, list) else []:
                    if isinstance(loc, dict) and loc.get('slug'):
                        slugs.append(loc['slug'])
                lookup[name] = {
                    "meta": meta,
                    "profile": profile,
                    "urls": slugs[:3] if slugs else (profile[:2] if profile else []),
                }
        return lookup

    def ingest(self, max_records: int = 200) -> List[Dict]:
        group_lookup = self._fetch_groups()

        url = getattr(self.config, 'RANSOMWATCH_FEED_URL', None) or \
              'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json'
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            posts = resp.json()
        except requests.RequestException as e:
            logger.error("Failed to fetch Ransomwatch posts: %s", e)
            return []
        except ValueError as e:
            logger.error("Invalid JSON from Ransomwatch posts: %s", e)
            return []

        if not isinstance(posts, list):
            logger.error("Ransomwatch posts feed is not a JSON array")
            return []

        docs = []
        for i, post in enumerate(posts[:max_records]):
            try:
                doc = self._to_unified_doc(post, group_lookup)
                if doc:
                    docs.append(doc)
            except Exception as e:
                logger.warning("Skipping Ransomwatch post %s: %s", post.get('post_title'), e)
                continue

        logger.info("Ransomwatch ingester: collected %d documents (max=%d)", len(docs), max_records)
        return docs

    def _to_unified_doc(self, post: Dict, group_lookup: Dict[str, Dict]) -> Dict:
        group_name = post.get('group_name', 'unknown')
        post_title = post.get('post_title', 'Untitled')
        discovered = post.get('discovered', '')
        description = post.get('description', '')

        hash8 = hashlib.sha256(f"{group_name}{post_title}{discovered}".encode()).hexdigest()[:8]
        doc_id = f"ransomwatch_{hash8}"

        group_profile = group_lookup.get(group_name, {})
        meta = group_profile.get("meta") or ""
        urls = group_profile.get("urls") or []

        parts = [f"Ransomware group: {group_name}. Post: {post_title}."]
        if discovered:
            parts.append(f"Discovered: {discovered}.")
        if meta:
            parts.append(f"Group profile: {meta}.")
        if urls:
            parts.append(f"Related URLs: {', '.join(urls[:3])}.")
        if description:
            parts.append(description)
        content = " ".join(parts)

        doc_url = post.get('link') or RANSOMWATCH_GITHUB_URL

        return {
            "id": doc_id,
            "title": f"Ransomware: {group_name} - {post_title}",
            "content": content,
            "url": doc_url,
            "source": "ransomwatch",
            "source_category_hint": "ransomware",
            "published_at": discovered if discovered else None,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "group_name": group_name,
                "discovered": discovered,
                "group_profile": group_profile,
            },
        }
