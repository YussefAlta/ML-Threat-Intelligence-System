"""
Preprocessing utilities for converting raw HTML to readable content.
Preserves all original data while adding processed versions.
Intelligently removes boilerplate and extracts only article content.
"""
import re
import json
import logging
import hashlib
import unicodedata
from typing import Dict, List, Optional, Any, Tuple
from bs4 import BeautifulSoup
from datetime import datetime

logger = logging.getLogger(__name__)


class HTMLPreprocessor:
    """
    Preprocessor for converting raw HTML to readable content.
    Preserves all original data while adding enhanced processed versions.
    """
    
    def __init__(self):
        """Initialize the HTML preprocessor."""
        pass
    
    def preprocess_post(self, post: Dict) -> Dict:
        """
        Preprocess a single post by extracting only article content.
        Removes boilerplate, detects paywalls, and structures output.
        
        Args:
            post: Raw post data dictionary
            
        Returns:
            Enhanced post dictionary with clean, structured content
        """
        try:
            # Create a copy to avoid modifying the original
            processed_post = post.copy()
            
            # Get HTML content from raw_content
            html_content = processed_post.get('raw_content', {}).get('html', '')
            
            # Extract clean article content with boilerplate removal
            extraction_result = self._extract_article_content(html_content, processed_post)
            
            # Add processed content fields to raw_content (preserve original)
            if 'raw_content' not in processed_post:
                processed_post['raw_content'] = {}
            
            # Store clean content
            processed_post['clean_text'] = extraction_result['clean_text']
            processed_post['clean_html'] = extraction_result['clean_html']
            processed_post['sections'] = extraction_result['sections']
            processed_post['images'] = extraction_result['images']
            processed_post['paywalled'] = extraction_result['paywalled']
            processed_post['content_truncated'] = extraction_result['content_truncated']
            processed_post['extraction_quality'] = extraction_result['extraction_quality']
            
            # Update metadata with extracted info (prioritize canonical metadata)
            if extraction_result.get('dek'):
                processed_post['dek'] = extraction_result['dek']
            if extraction_result.get('publication'):
                processed_post['publication'] = extraction_result['publication']
            if extraction_result.get('reading_time_minutes'):
                processed_post['reading_time_minutes'] = extraction_result['reading_time_minutes']
            
            # Use canonical metadata if available
            if extraction_result.get('canonical_url'):
                processed_post['canonical_url'] = extraction_result['canonical_url']
            if extraction_result.get('resolved_url'):
                processed_post['resolved_url'] = extraction_result['resolved_url']
            if extraction_result.get('source_canonical_domain'):
                processed_post['source_canonical_domain'] = extraction_result['source_canonical_domain']
            
            # Extract canonical author and date from metadata
            canonical_author = self._extract_canonical_author(html_content, processed_post)
            canonical_date = self._extract_canonical_date(html_content, processed_post)
            
            # Normalize date format (YYYY-MM-DD or ISO format)
            if canonical_date:
                processed_post['published_date'] = canonical_date
            elif processed_post.get('published_date'):
                normalized_date = self._normalize_date(processed_post['published_date'])
                if normalized_date:
                    processed_post['published_date'] = normalized_date
            
            # Use canonical author if available
            if canonical_author:
                processed_post['author'] = self._normalize_author(canonical_author)
            elif processed_post.get('author'):
                processed_post['author'] = self._normalize_author(processed_post['author'])
            
            # Update main content field with clean text
            processed_post['content'] = extraction_result['clean_text']
            
            # Store preview and content_extract_level for paywalled content
            if extraction_result.get('preview'):
                processed_post['preview'] = extraction_result['preview']
            if extraction_result.get('content_extract_level'):
                processed_post['content_extract_level'] = extraction_result['content_extract_level']
            
            # Store paywall artifact
            if extraction_result.get('paywall_artifact'):
                processed_post['paywall_artifact'] = extraction_result['paywall_artifact']
            
            # Store security enrichments
            if extraction_result.get('security'):
                processed_post['security'] = extraction_result['security']
            
            # Generate clean keywords from clean text only (with proper NLP)
            if extraction_result['clean_text']:
                clean_keywords = self._extract_clean_keywords(extraction_result['clean_text'])
                processed_post['keywords'] = clean_keywords
            
            # Add content hash for deduplication
            content_hash = hashlib.sha256(extraction_result['clean_text'].encode('utf-8')).hexdigest()
            processed_post['content_hash'] = content_hash
            
            # Add preprocessing metadata
            if 'preprocessing_notes' not in processed_post:
                processed_post['preprocessing_notes'] = {}
            processed_post['preprocessing_notes']['html_processed'] = True
            processed_post['preprocessing_notes']['html_processed_at'] = datetime.now().isoformat()
            processed_post['preprocessing_notes']['processing_method'] = 'intelligent_article_extraction'
            processed_post['preprocessing_notes']['extraction_status'] = extraction_result.get('extraction_status', 'complete')
            
            logger.info(f"Preprocessed post {processed_post.get('id', 'unknown')} - paywalled: {extraction_result['paywalled']}")
            return processed_post
            
        except Exception as e:
            logger.error(f"Error preprocessing post: {str(e)}")
            # Return original post if preprocessing fails
            return post
    
    def _extract_article_content(self, html: str, post: Dict) -> Dict:
        """
        Intelligently extract article content, removing boilerplate and detecting paywalls.
        
        Args:
            html: Raw HTML content
            post: Post dictionary for metadata extraction
            
        Returns:
            Dictionary with clean extracted content and metadata
        """
        if not html:
            return self._empty_extraction_result()
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Detect if this is a Medium domain
            domain = post.get('domain', '') if post else ''
            is_medium = 'medium.com' in domain or any(word in domain for word in ['blog', 'medium']) if domain else False
            
            # Find article container FIRST (before pruning)
            article_container = self._find_article_container(soup, is_medium)
            
            if not article_container:
                logger.warning("No article container found")
                return self._empty_extraction_result()
            
            # Detect paywall
            paywall_info = self._detect_paywall(soup, html)
            
            # Extract structured content from article container (before filtering)
            sections = self._extract_sections(article_container)
            images = self._extract_content_images(article_container)
            
            # Extract canonical metadata from OpenGraph and JSON-LD FIRST
            canonical_metadata = self._extract_canonical_metadata(soup, post)
            
            # Extract additional metadata from DOM (fallback)
            dek = self._extract_dek(article_container, post) or canonical_metadata.get('description')
            publication = self._extract_publication(article_container, post) or canonical_metadata.get('publication')
            reading_time = self._extract_reading_time(article_container, post) or canonical_metadata.get('reading_time')
            
            # Filter out sections that come after paywall markers
            if paywall_info['detected'] and sections:
                sections = self._filter_sections_before_paywall(sections)
            
            # Remove boilerplate sections (like "Member-only story")
            sections = [s for s in sections if not self._is_boilerplate_text(s.get('text', ''))]
            
            # Deduplicate consecutive identical sections
            sections = self._deduplicate_sections(sections)
            
            # Normalize Unicode and smart quotes in sections
            sections = self._normalize_sections(sections)
            
            # Generate clean text and HTML (normalized)
            clean_text = self._sections_to_text(sections)
            clean_html = self._sections_to_html(sections, images)
            
            # Extract preview for paywalled content
            preview = None
            content_extract_level = "full"
            if paywall_info['detected']:
                content_extract_level = "preview"
                preview = self._extract_preview(sections)
            
            # Quality checks
            extraction_status = self._check_extraction_quality(sections, clean_text, paywall_info['detected'])
            
            # Extract security enrichments
            security_data = self._extract_security_enrichments(clean_text)
            
            # Build result
            result = {
                'clean_text': clean_text,
                'clean_html': clean_html,
                'sections': sections,
                'images': images,
                'paywalled': paywall_info['detected'],
                'content_truncated': paywall_info['detected'],
                'content_extract_level': content_extract_level,
                'preview': preview,
                'dek': dek or canonical_metadata.get('description'),
                'publication': publication or canonical_metadata.get('publication'),
                'reading_time_minutes': reading_time,
                'canonical_url': canonical_metadata.get('canonical_url'),
                'resolved_url': post.get('url') if post else None,
                'source_canonical_domain': canonical_metadata.get('canonical_domain'),
                'extraction_quality': {
                    'link_density_removed': True,
                    'boilerplate_removed': True,
                    'signals': paywall_info['signals'],
                    'extraction_status': extraction_status
                },
                'extraction_status': extraction_status,
                'paywall_artifact': {
                    'member_only': paywall_info['detected'],
                    'regwall_detected': paywall_info['detected'],
                    'signals': paywall_info['signals']
                },
                'security': security_data
            }
            
            return result
            
        except Exception as e:
            import traceback
            logger.error(f"Error extracting article content: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return self._empty_extraction_result()
    
    def _prune_boilerplate(self, soup: BeautifulSoup, is_medium: bool = False):
        """Remove boilerplate elements from HTML."""
        # Remove script, style, noscript
        for tag in soup(["script", "style", "noscript", "meta", "link", "head"]):
            tag.decompose()
        
        # Find article container first to protect it
        article_container = soup.find('article') or soup.find('main')
        
        # Remove elements by class/id patterns (but preserve article content)
        boilerplate_pattern = re.compile(
            r'(header|nav|footer|aside|modal|signup|signin|share|clap|paywall|regwall|'
            r'recaptcha|comments|cookie|gdpr|newsletter|subscribe|sticky|sidebar)',
            re.I
        )
        
        for tag in soup.find_all(True):
            # Skip NavigableString objects (they don't have .get method)
            if not hasattr(tag, 'get') or not hasattr(tag, 'attrs') or tag.attrs is None:
                continue
            
            # Protect article and main containers
            if tag.name in ['article', 'main'] or tag == article_container:
                continue
            
            # Check if tag is inside article container - protect it
            if article_container and (tag in article_container or tag.find_parent('article') or tag.find_parent('main')):
                # Only remove if it's clearly paywall/regwall
                tag_class = tag.get('class', [])
                classes = ' '.join(tag_class) if isinstance(tag_class, list) else ''
                tag_id = tag.get('id', '') or ''
                
                if re.search(r'(regwall|paywall)', classes, re.I) or re.search(r'(regwall|paywall)', tag_id, re.I):
                    tag.decompose()
                continue
            
            # Check class/id for boilerplate patterns
            tag_class = tag.get('class', [])
            classes = ' '.join(tag_class) if isinstance(tag_class, list) else ''
            tag_id = tag.get('id', '') or ''
            
            if boilerplate_pattern.search(classes) or boilerplate_pattern.search(tag_id):
                tag.decompose()
                continue
            
            # Remove high link-density blocks (but not if inside article)
            if self._has_high_link_density(tag):
                tag.decompose()
                continue
            
            # Remove very short repeated UI strings
            text = tag.get_text(strip=True)
            ui_strings = ['Sign up', 'Sign in', 'Open in app', 'Follow', 'Share', 'Listen']
            if text in ui_strings and len(text) < 50:
                tag.decompose()
                continue
            
            # Remove very short nodes (unless they're headings/blockquotes)
            if len(text) < 30 and tag.name not in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'figcaption']:
                tag.decompose()
                continue
    
    def _has_high_link_density(self, tag) -> bool:
        """Check if a tag has high link density (mostly links)."""
        links = tag.find_all('a')
        if not links:
            return False
        
        link_text_len = sum(len(link.get_text(strip=True)) for link in links)
        total_text_len = len(tag.get_text(strip=True))
        
        if total_text_len == 0:
            return False
        
        return (link_text_len / total_text_len) > 0.6
    
    def _detect_paywall(self, soup: BeautifulSoup, html: str) -> Dict:
        """Detect paywall/truncation signals."""
        signals = []
        
        # Check for paywall text patterns
        paywall_text_patterns = [
            r'Create an account to read',
            r'member-only',
            r'Continue in app',
            r'Sign up with email',
            r'read the full story'
        ]
        
        text = soup.get_text().lower()
        for pattern in paywall_text_patterns:
            if re.search(pattern, text, re.I):
                signals.append(pattern)
        
        # Check for paywall DOM classes/ids
        paywall_pattern = re.compile(r'(meteredContent|post_regwall|regwall|paywall|member-only)', re.I)
        
        for tag in soup.find_all(True):
            # Skip NavigableString objects
            if not hasattr(tag, 'get') or not hasattr(tag, 'attrs') or tag.attrs is None:
                continue
            
            tag_class = tag.get('class', [])
            classes = ' '.join(tag_class) if isinstance(tag_class, list) else ''
            tag_id = tag.get('id', '') or ''
            data_testid = tag.get('data-testid', '') or ''
            
            if (paywall_pattern.search(classes) or 
                paywall_pattern.search(tag_id) or
                'regwall' in data_testid.lower()):
                signals.append(f"DOM: {classes or tag_id or data_testid}")
                break
        
        detected = len(signals) > 0
        
        return {
            'detected': detected,
            'signals': signals
        }
    
    def _find_article_container(self, soup: BeautifulSoup, is_medium: bool = False):
        """Find the main article container."""
        # Try article tag first
        article = soup.find('article')
        if article:
            text_len = len(article.get_text(strip=True))
            if text_len > 100:  # Has some content
                return article
        
        # Try main tag
        main = soup.find('main')
        if main:
            text_len = len(main.get_text(strip=True))
            if text_len > 100:
                return main
        
        # Medium-specific: look for meteredContent or article-like divs
        if is_medium:
            # Look for meteredContent class
            metered = soup.find(class_=re.compile(r'meteredContent', re.I))
            if metered:
                return metered
            
            # Look for article-like divs with substantial content
            for tag in soup.find_all(['div', 'section'], class_=re.compile(r'article|content|post', re.I)):
                if hasattr(tag, 'get_text'):
                    text_len = len(tag.get_text(strip=True))
                    if text_len > 500:  # Substantial content
                        return tag
        
        # Fallback: find any div/section with substantial content
        for tag in soup.find_all(['div', 'section']):
            if hasattr(tag, 'get_text'):
                text_len = len(tag.get_text(strip=True))
                if text_len > 1000:  # Substantial content
                    return tag
        
        # Last resort: return body if it has content
        body = soup.find('body')
        if body:
            text_len = len(body.get_text(strip=True))
            if text_len > 100:
                return body
        
        return None
    
    def _filter_sections_before_paywall(self, sections: List[Dict]) -> List[Dict]:
        """Filter out sections that appear after paywall markers."""
        paywall_indicators = [
            'create an account to read',
            'member-only story',
            'continue in app',
            'sign up with email',
            'already have an account'
        ]
        
        filtered_sections = []
        for section in sections:
            text_lower = section.get('text', '').lower()
            
            # Check if this section is a paywall indicator
            is_paywall = any(indicator in text_lower for indicator in paywall_indicators)
            
            if is_paywall:
                # Stop here, don't include this or any following sections
                break
            
            filtered_sections.append(section)
        
        return filtered_sections
    
    def _extract_sections(self, container) -> List[Dict]:
        """Extract structured sections from article."""
        sections = []
        
        if not container:
            return sections
        
        # Only keep content-ish tags
        content_tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'blockquote', 'figure', 'figcaption']
        
        for tag in container.find_all(content_tags):
            if not hasattr(tag, 'name'):
                continue
                
            tag_name = tag.name
            text = tag.get_text(strip=True)
            
            # Skip if too short (unless it's a heading or blockquote)
            if len(text) < 10 and tag_name not in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote']:
                continue
            
            # Skip boilerplate text
            if self._is_boilerplate_text(text):
                continue
            
            sections.append({
                'type': tag_name,
                'text': text
            })
        
        return sections
    
    def _is_boilerplate_text(self, text: str) -> bool:
        """Check if text is boilerplate."""
        boilerplate_patterns = [
            r'^Sign (up|in)$',
            r'^Open in app$',
            r'^Follow$',
            r'^Share$',
            r'^Listen$',
            r'^Create an account',
            r'^Continue in app',
            r'^Member-only story$',
            r'^Member only story$',
            r'reCAPTCHA',
            r'Privacy.*Terms',
            r'^Help$',
            r'^Status$',
            r'^About$',
            r'^\d+$',  # Just numbers
            r'^[·•]\s*$',  # Just bullet points
        ]
        
        text_lower = text.lower().strip()
        for pattern in boilerplate_patterns:
            if re.match(pattern, text_lower, re.I):
                return True
        
        # Check if it's very short and common UI text
        if len(text) < 5 and text_lower in ['1', '·', '•', 'follow', 'share']:
            return True
        
        return False
    
    def _extract_content_images(self, container) -> List[Dict]:
        """Extract images from article content."""
        images = []
        
        for img in container.find_all('img'):
            src = img.get('src', '')
            alt = img.get('alt', '')
            caption = None
            
            # Try to find caption
            figcaption = img.find_parent('figure')
            if figcaption:
                cap_elem = figcaption.find('figcaption')
                if cap_elem:
                    caption = cap_elem.get_text(strip=True)
            
            if src:
                images.append({
                    'src': src,
                    'alt': alt or None,
                    'caption': caption
                })
        
        return images
    
    def _extract_dek(self, container, post: Optional[Dict]) -> Optional[str]:
        """Extract dek/summary (first sentence under title)."""
        if not container:
            return None
        
        # Try to find subtitle or first paragraph after title
        h1 = container.find('h1')
        if h1:
            # Get first paragraph after h1 (not boilerplate)
            next_p = h1.find_next('p')
            while next_p:
                text = next_p.get_text(strip=True)
                # Skip boilerplate
                if not self._is_boilerplate_text(text) and len(text) > 20:
                    # Take first sentence
                    sentences = re.split(r'[.!?]+', text)
                    if sentences and sentences[0].strip():
                        dek = sentences[0].strip()
                        # Remove trailing punctuation
                        dek = re.sub(r'[.!?]+$', '', dek)
                        return dek
                next_p = next_p.find_next('p')
        
        return None
    
    def _extract_publication(self, container, post: Optional[Dict]) -> Optional[str]:
        """Extract publication name."""
        # Look for publication indicators
        pub_patterns = [
            r'Published in\s+([^\n]+)',
            r'([A-Z][a-z]+ [A-Z][a-z]+)\s+followers'
        ]
        
        text = container.get_text()
        for pattern in pub_patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1).strip()
        
        return None
    
    def _extract_reading_time(self, container, post: Optional[Dict]) -> Optional[int]:
        """Extract reading time in minutes."""
        # Look for "X min read" pattern
        text = container.get_text()
        match = re.search(r'(\d+)\s*min\s*read', text, re.I)
        if match:
            return int(match.group(1))
        
        return None
    
    def _sections_to_text(self, sections: List[Dict]) -> str:
        """Convert sections to clean text."""
        text_parts = []
        for section in sections:
            text_parts.append(section['text'])
        return '\n\n'.join(text_parts)
    
    def _sections_to_html(self, sections: List[Dict], images: List[Dict]) -> str:
        """Convert sections to clean HTML."""
        html_parts = []
        for section in sections:
            tag = section['type']
            text = section['text']
            html_parts.append(f"<{tag}>{text}</{tag}>")
        
        # Add images
        for img in images:
            img_html = f'<img src="{img["src"]}"'
            if img.get('alt'):
                img_html += f' alt="{img["alt"]}"'
            img_html += '>'
            html_parts.append(img_html)
        
        return '\n'.join(html_parts)
    
    def _check_extraction_quality(self, sections: List[Dict], clean_text: str, paywalled: bool) -> str:
        """Check extraction quality and return status."""
        # Check for heading
        has_h1 = any(s['type'] in ['h1', 'h2'] for s in sections)
        has_p = any(s['type'] == 'p' for s in sections)
        
        if not (has_h1 and has_p):
            return 'partial'
        
        # Check content density
        if clean_text:
            letters = len(re.sub(r'[^a-zA-Z]', '', clean_text))
            total_len = len(clean_text)
            if total_len > 0:
                density = letters / total_len
                if density < 0.6:
                    return 'low_quality'
        
        # Check length vs paywall
        if paywalled and len(clean_text) < 1000:
            return 'truncated'
        
        return 'complete'
    
    def _extract_canonical_metadata(self, soup: BeautifulSoup, post: Optional[Dict]) -> Dict:
        """Extract canonical metadata from OpenGraph and JSON-LD."""
        metadata = {}
        
        try:
            # Extract from OpenGraph meta tags
            og_title = soup.find('meta', property='og:title')
            if og_title:
                metadata['title'] = og_title.get('content', '')
            
            og_description = soup.find('meta', property='og:description')
            if og_description:
                metadata['description'] = og_description.get('content', '')
            
            og_url = soup.find('meta', property='og:url')
            if og_url:
                metadata['canonical_url'] = og_url.get('content', '')
            
            # Extract from JSON-LD
            json_scripts = soup.find_all('script', type='application/ld+json')
            for script in json_scripts:
                try:
                    data = json.loads(script.string)
                    if isinstance(data, dict):
                        if data.get('@type') == 'Article' or data.get('@type') == 'NewsArticle':
                            if 'headline' in data and not metadata.get('title'):
                                metadata['title'] = data['headline']
                            if 'description' in data and not metadata.get('description'):
                                metadata['description'] = data['description']
                            if 'datePublished' in data:
                                metadata['published_date'] = data['datePublished']
                            if 'author' in data:
                                if isinstance(data['author'], dict):
                                    metadata['author'] = data['author'].get('name', '')
                                elif isinstance(data['author'], list) and len(data['author']) > 0:
                                    metadata['author'] = data['author'][0].get('name', '') if isinstance(data['author'][0], dict) else ''
                            if 'publisher' in data:
                                pub = data['publisher']
                                if isinstance(pub, dict):
                                    metadata['publication'] = pub.get('name', '')
                except:
                    continue
            
            # Extract canonical URL from link tag
            canonical_link = soup.find('link', rel='canonical')
            if canonical_link:
                metadata['canonical_url'] = canonical_link.get('href', '')
            
            # Extract canonical domain
            if metadata.get('canonical_url'):
                from urllib.parse import urlparse
                parsed = urlparse(metadata['canonical_url'])
                metadata['canonical_domain'] = parsed.netloc
            
        except Exception as e:
            logger.error(f"Error extracting canonical metadata: {str(e)}")
        
        return metadata
    
    def _extract_canonical_author(self, html: str, post: Optional[Dict]) -> Optional[str]:
        """Extract author from JSON-LD and OpenGraph."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Try JSON-LD first
            json_scripts = soup.find_all('script', type='application/ld+json')
            for script in json_scripts:
                try:
                    data = json.loads(script.string)
                    if isinstance(data, dict) and data.get('@type') in ['Article', 'NewsArticle']:
                        if 'author' in data:
                            if isinstance(data['author'], dict):
                                return data['author'].get('name', '')
                            elif isinstance(data['author'], list) and len(data['author']) > 0:
                                author = data['author'][0]
                                return author.get('name', '') if isinstance(author, dict) else ''
                except:
                    continue
            
            # Try OpenGraph
            og_author = soup.find('meta', property='article:author')
            if og_author:
                return og_author.get('content', '')
            
            # Try meta author tag
            meta_author = soup.find('meta', attrs={'name': 'author'})
            if meta_author:
                return meta_author.get('content', '')
            
            return None
        except:
            return None
    
    def _extract_canonical_date(self, html: str, post: Optional[Dict]) -> Optional[str]:
        """Extract published date from JSON-LD and OpenGraph."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Try JSON-LD first
            json_scripts = soup.find_all('script', type='application/ld+json')
            for script in json_scripts:
                try:
                    data = json.loads(script.string)
                    if isinstance(data, dict) and data.get('@type') in ['Article', 'NewsArticle']:
                        if 'datePublished' in data:
                            date_str = data['datePublished']
                            # Normalize to ISO format
                            return self._normalize_date(date_str)
                except:
                    continue
            
            # Try OpenGraph
            og_date = soup.find('meta', property='article:published_time')
            if og_date:
                return self._normalize_date(og_date.get('content', ''))
            
            # Try time tag with datetime
            time_tag = soup.find('time', datetime=True)
            if time_tag:
                return self._normalize_date(time_tag.get('datetime', ''))
            
            return None
        except:
            return None
    
    def _deduplicate_sections(self, sections: List[Dict]) -> List[Dict]:
        """Remove duplicate consecutive sections."""
        if not sections:
            return sections
        
        deduplicated = [sections[0]]
        for i in range(1, len(sections)):
            current_text = sections[i].get('text', '').strip()
            prev_text = sections[i-1].get('text', '').strip()
            
            # Skip if identical to previous (allowing for small differences)
            if current_text != prev_text or len(current_text) < 10:
                deduplicated.append(sections[i])
        
        return deduplicated
    
    def _normalize_sections(self, sections: List[Dict]) -> List[Dict]:
        """Normalize Unicode and smart quotes in sections."""
        normalized = []
        for section in sections:
            text = section.get('text', '')
            
            # Unicode normalization (NFKC)
            text = unicodedata.normalize('NFKC', text)
            
            # Map smart quotes to ASCII
            text = text.replace('\u201C', '"').replace('\u201D', '"')  # Left/Right double quote
            text = text.replace('\u2018', "'").replace('\u2019', "'")  # Left/Right single quote
            text = text.replace('\u2013', '-').replace('\u2014', '--')  # En/em dash
            text = text.replace('\u2026', '...')  # Ellipsis
            
            # Normalize whitespace
            text = re.sub(r'\s+', ' ', text).strip()
            
            normalized.append({
                'type': section['type'],
                'text': text
            })
        
        return normalized
    
    def _extract_preview(self, sections: List[Dict]) -> Dict:
        """Extract preview content for paywalled articles."""
        preview = {
            'lede_blockquote': None,
            'paragraphs': []
        }
        
        for section in sections:
            if section['type'] == 'blockquote' and not preview['lede_blockquote']:
                preview['lede_blockquote'] = section['text']
            elif section['type'] == 'p' and len(section['text']) > 30:
                preview['paragraphs'].append(section['text'])
                # Limit to first 3-5 paragraphs
                if len(preview['paragraphs']) >= 5:
                    break
        
        return preview
    
    def _extract_security_enrichments(self, clean_text: str) -> Dict:
        """Extract security-specific enrichments (IoCs, CVEs, etc.)."""
        enrichments = {
            'iocs': {
                'ips': [],
                'urls': [],
                'wallets': [],
                'hashes': []
            },
            'has_wallet_address': False,
            'cves': [],
            'cwes': [],
            'products': [],
            'attack_theme': None
        }
        
        if not clean_text:
            return enrichments
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, clean_text)
        enrichments['iocs']['ips'] = list(set(ips))
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"\'\)]+'
        urls = re.findall(url_pattern, clean_text)
        enrichments['iocs']['urls'] = list(set(urls))
        
        # Extract crypto wallet addresses (basic patterns)
        wallet_patterns = [
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # Bitcoin
            r'\b0x[a-fA-F0-9]{40}\b',  # Ethereum
        ]
        wallets = []
        for pattern in wallet_patterns:
            wallets.extend(re.findall(pattern, clean_text))
        enrichments['iocs']['wallets'] = list(set(wallets))
        enrichments['has_wallet_address'] = len(wallets) > 0
        
        # Extract CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = re.findall(cve_pattern, clean_text, re.I)
        enrichments['cves'] = list(set(cves))
        
        # Extract CWE IDs
        cwe_pattern = r'CWE-\d+'
        cwes = re.findall(cwe_pattern, clean_text, re.I)
        enrichments['cwes'] = list(set(cwes))
        
        # Extract hash patterns (MD5, SHA256, etc.)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b',  # SHA256
        ]
        hashes = []
        for pattern in hash_patterns:
            found = re.findall(pattern, clean_text)
            # Filter out false positives (not all hex strings are hashes)
            hashes.extend([h for h in found if len(h) >= 32])
        enrichments['iocs']['hashes'] = list(set(hashes))
        
        # Detect attack themes (simple keyword matching)
        attack_themes = {
            'printer exploit': ['printer', 'firmware', 'exploit'],
            'firmware vulnerability': ['firmware', 'vulnerability', 'outdated'],
            'ransomware': ['ransom', 'wallet', 'cryptocurrency'],
            'network attack': ['networked', 'peripheral', 'device']
        }
        
        text_lower = clean_text.lower()
        for theme, keywords in attack_themes.items():
            if all(kw in text_lower for kw in keywords[:2]):  # Match at least 2 keywords
                enrichments['attack_theme'] = theme
                break
        
        return enrichments
    
    def _extract_clean_keywords(self, clean_text: str) -> List[str]:
        """Extract keywords from clean text with proper NLP (stopwords, lemmatization, bigrams)."""
        if not clean_text:
            return []
        
        # Extended stopwords list
        stopwords = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with',
            'by', 'from', 'up', 'about', 'into', 'through', 'during', 'including', 'against',
            'among', 'throughout', 'despite', 'towards', 'upon', 'concerning', 'to', 'of', 'in',
            'for', 'on', 'with', 'at', 'by', 'from', 'up', 'about', 'into', 'through', 'during',
            'that', 'this', 'these', 'those', 'have', 'has', 'had', 'been', 'being', 'be',
            'was', 'were', 'is', 'are', 'will', 'would', 'could', 'should', 'may', 'might',
            'must', 'can', 'what', 'when', 'where', 'why', 'how', 'which', 'who', 'whom',
            'their', 'there', 'they', 'them', 'this', 'that', 'these', 'those', 'it', 'its',
            'we', 'our', 'us', 'you', 'your', 'he', 'she', 'his', 'her', 'him', 'hers',
            'started', 'coming', 'thought', 'wasn', 'turned', 'began', 'became'
        }
        
        # Normalize text
        text = unicodedata.normalize('NFKC', clean_text.lower())
        
        # Extract words (minimum 4 chars, exclude stopwords)
        words = re.findall(r'\b[a-zA-Z]{4,}\b', text)
        words = [w for w in words if w not in stopwords]
        
        # Count frequency
        word_freq = {}
        for word in words:
            word_freq[word] = word_freq.get(word, 0) + 1
        
        # Generate bigrams for common word pairs
        bigrams = []
        words_list = re.findall(r'\b[a-zA-Z]{4,}\b', text)
        for i in range(len(words_list) - 1):
            if words_list[i] not in stopwords and words_list[i+1] not in stopwords:
                bigram = f"{words_list[i]} {words_list[i+1]}"
                bigrams.append(bigram)
        
        bigram_freq = {}
        for bigram in bigrams:
            bigram_freq[bigram] = bigram_freq.get(bigram, 0) + 1
        
        # Combine and rank
        all_keywords = []
        for word, count in sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:30]:
            all_keywords.append(word)
        
        for bigram, count in sorted(bigram_freq.items(), key=lambda x: x[1], reverse=True)[:10]:
            if bigram not in all_keywords:
                all_keywords.append(bigram)
        
        return all_keywords[:50]
    
    def _normalize_date(self, date_str: str) -> Optional[str]:
        """Normalize date to ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)."""
        if not date_str:
            return None
        
        try:
            # Try parsing common date formats
            date_formats = [
                '%Y-%m-%d',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%B %d, %Y',
                '%b %d, %Y',
                '%d %B %Y',
                '%d %b %Y',
                '%Y/%m/%d',
                '%m/%d/%Y',
                '%d-%m-%Y'
            ]
            
            for fmt in date_formats:
                try:
                    dt = datetime.strptime(date_str.strip(), fmt)
                    # Return ISO format with timezone if time info available
                    if '%H' in fmt or '%M' in fmt or '%S' in fmt:
                        return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                    else:
                        return dt.strftime('%Y-%m-%d')
                except ValueError:
                    continue
            
            # Try ISO format parsing (handles various ISO formats)
            try:
                # Handle Z timezone
                clean_str = date_str.strip().replace('Z', '+00:00')
                dt = datetime.fromisoformat(clean_str)
                # Return in ISO format with Z
                if dt.tzinfo:
                    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                else:
                    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            except:
                pass
            
            # Fallback: try to extract just the date part
            date_match = re.search(r'(\d{4}-\d{2}-\d{2})', date_str)
            if date_match:
                return date_match.group(1)
            
            return None
        except Exception as e:
            logger.error(f"Error normalizing date {date_str}: {str(e)}")
            return None
    
    def _normalize_author(self, author: str) -> str:
        """Normalize author name (strip emojis, handles, etc.)."""
        if not author:
            return ""
        
        # Remove emojis and special characters
        author = re.sub(r'[^\w\s-]', '', author)
        author = author.strip()
        
        return author
    
    def _empty_extraction_result(self) -> Dict:
        """Return empty extraction result."""
        return {
            'clean_text': '',
            'clean_html': '',
            'sections': [],
            'images': [],
            'paywalled': False,
            'content_truncated': False,
            'dek': None,
            'publication': None,
            'reading_time_minutes': None,
            'extraction_quality': {
                'link_density_removed': False,
                'boilerplate_removed': False,
                'signals': [],
                'extraction_status': 'failed'
            },
            'extraction_status': 'failed'
        }
    
    def _html_to_readable(self, html: str) -> str:
        """
        Convert HTML to plain readable text, removing ALL HTML formatting.
        
        Args:
            html: Raw HTML content
            
        Returns:
            Plain text content with no HTML tags or formatting
        """
        if not html:
            return ""
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remove all script, style, and other non-content elements
            for element in soup(["script", "style", "noscript", "meta", "link", "head"]):
                element.decompose()
            
            # Get all text content - this removes all HTML tags
            text = soup.get_text(separator=' ', strip=True)
            
            # Clean up whitespace - normalize multiple spaces/newlines to single spaces
            text = re.sub(r'\s+', ' ', text)
            
            # Remove any remaining HTML entities
            text = text.replace('&nbsp;', ' ')
            text = text.replace('&amp;', '&')
            text = text.replace('&lt;', '<')
            text = text.replace('&gt;', '>')
            text = text.replace('&quot;', '"')
            text = text.replace('&#39;', "'")
            
            # Final cleanup - remove any stray HTML-like patterns
            text = re.sub(r'<[^>]+>', '', text)  # Remove any remaining tags
            text = re.sub(r'&[a-zA-Z]+;', '', text)  # Remove any remaining entities
            
            # Normalize whitespace one more time
            text = re.sub(r'\s+', ' ', text)
            text = text.strip()
            
            return text
            
        except Exception as e:
            logger.error(f"Error converting HTML to readable text: {str(e)}")
            # Fallback: use regex to strip HTML tags
            try:
                # Remove HTML tags
                text = re.sub(r'<[^>]+>', '', html)
                # Remove HTML entities
                text = re.sub(r'&[a-zA-Z]+;', '', text)
                # Normalize whitespace
                text = re.sub(r'\s+', ' ', text)
                return text.strip()
            except:
                return html
    
    def _markdown_to_readable(self, markdown: str) -> str:
        """
        Convert markdown to plain readable text, removing all formatting.
        
        Args:
            markdown: Markdown content
            
        Returns:
            Plain text with no markdown formatting
        """
        if not markdown:
            return ""
        
        try:
            # Remove markdown formatting
            # Headers (# ## ### etc.)
            text = re.sub(r'^#{1,6}\s+', '', markdown, flags=re.MULTILINE)
            
            # Bold (**text** or __text__)
            text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)
            text = re.sub(r'__([^_]+)__', r'\1', text)
            
            # Italic (*text* or _text_)
            text = re.sub(r'\*([^*]+)\*', r'\1', text)
            text = re.sub(r'_([^_]+)_', r'\1', text)
            
            # Links [text](url)
            text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
            
            # Images ![alt](url)
            text = re.sub(r'!\[([^\]]*)\]\([^\)]+\)', r'\1', text)
            
            # Code blocks ```code```
            text = re.sub(r'```[^`]*```', '', text, flags=re.DOTALL)
            
            # Inline code `code`
            text = re.sub(r'`([^`]+)`', r'\1', text)
            
            # Lists (- or * or 1.)
            text = re.sub(r'^[\s]*[-*+]\s+', '', text, flags=re.MULTILINE)
            text = re.sub(r'^[\s]*\d+\.\s+', '', text, flags=re.MULTILINE)
            
            # Blockquotes (>)
            text = re.sub(r'^>\s+', '', text, flags=re.MULTILINE)
            
            # Horizontal rules (--- or ***)
            text = re.sub(r'^[-*]{3,}$', '', text, flags=re.MULTILINE)
            
            # Strikethrough (~~text~~)
            text = re.sub(r'~~([^~]+)~~', r'\1', text)
            
            # Normalize whitespace
            text = re.sub(r'\n{3,}', '\n\n', text)
            text = re.sub(r'[ \t]+', ' ', text)
            
            return text.strip()
            
        except Exception as e:
            logger.error(f"Error processing markdown: {str(e)}")
            return markdown
    
    def _extract_structured_elements(self, html: str) -> Dict:
        """
        Extract structured elements from HTML (tables, lists, links, images).
        Preserves important structural information.
        
        Args:
            html: Raw HTML content
            
        Returns:
            Dictionary with structured elements
        """
        if not html:
            return {}
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            structured = {
                'tables': [],
                'links': [],
                'images': [],
                'code_blocks': []
            }
            
            # Extract tables
            for table in soup.find_all('table'):
                rows = []
                for tr in table.find_all('tr'):
                    cells = [td.get_text(strip=True) for td in tr.find_all(['td', 'th'])]
                    if cells:
                        rows.append(cells)
                if rows:
                    structured['tables'].append(rows)
            
            # Extract links (with context)
            for link in soup.find_all('a', href=True):
                text = link.get_text(strip=True)
                href = link.get('href', '')
                if text and href:
                    structured['links'].append({
                        'text': text,
                        'url': href,
                        'title': link.get('title', '')
                    })
            
            # Extract images (with alt text)
            for img in soup.find_all('img'):
                src = img.get('src', '')
                alt = img.get('alt', '')
                if src:
                    structured['images'].append({
                        'src': src,
                        'alt': alt,
                        'title': img.get('title', '')
                    })
            
            # Extract code blocks
            for code in soup.find_all(['pre', 'code']):
                text = code.get_text(strip=True)
                if text and len(text) > 10:
                    structured['code_blocks'].append({
                        'text': text[:500],  # Limit length
                        'language': code.get('class', [None])[0] if code.get('class') else None
                    })
            
            # Only return if we found something
            if any(structured.values()):
                return structured
            return {}
            
        except Exception as e:
            logger.error(f"Error extracting structured elements: {str(e)}")
            return {}
    
    def preprocess_batch(self, posts: List[Dict]) -> List[Dict]:
        """
        Preprocess a batch of posts.
        
        Args:
            posts: List of raw post dictionaries
            
        Returns:
            List of preprocessed posts
        """
        processed_posts = []
        for post in posts:
            processed_post = self.preprocess_post(post)
            processed_posts.append(processed_post)
        
        logger.info(f"Preprocessed {len(processed_posts)} posts")
        return processed_posts

