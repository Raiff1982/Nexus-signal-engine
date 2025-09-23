"""Hoax detection filter implementation."""

import re
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple, List

_NUMBER_UNIT = re.compile(
    r'(?P<num>[\d,]+(?:\.\d+)?)\s*(?P<unit>mile|miles|km|kilometer|kilometers)',
    re.I
)

LANG_RED_FLAGS = [
    r'\brecently\s+declassified\b',
    r'\bshocking\b',
    r'\bastonishing\b',
    r'\bexplosive\b',
    r'\bexperts\s+say\b',
    r'\breportedly\b',
    r'\bmothership\b',
    r'\bancient\s+alien\b',
    r'\bdormant\s+(?:observational\s+)?craft\b',
    r'\bangular\s+edges\b',
    r'\bviral\b',
    r'\bnever\s+before\s+seen\b',
]

DENY_DOMAINS = {
    'm.facebook.com', 'facebook.com', 'x.com', 'twitter.com', 't.co',
    'tiktok.com', 'youtube.com', 'youtu.be', 'instagram.com', 'reddit.com',
}

MEDIUM_DOMAINS = {
    'dailyMail.co.uk', 'dailymail.co.uk', 'newyorkpost.com', 'the-sun.com',
    'mirror.co.uk', 'sputniknews.com', 'rt.com',
}

@dataclass
class HoaxFilterResult:
    red_flag_hits: int
    source_score: float
    scale_score: float
    combined: float
    notes: Dict[str, Any]

class HoaxFilter:
    """
    Scores are in [0,1]; higher means more likely hoax/misinformation.
    """

    def __init__(self,
                 red_flag_weight: float = 0.35,
                 source_weight: float = 0.25,
                 scale_weight: float = 0.40,
                 extraordinary_km: float = 50.0):
        """
        extraordinary_km: any single claimed length >= this is 'extraordinary'.
        Adjust to tighten/loosen sensitivity (100–500 for stricter).
        """
        self.red_flag_weight = red_flag_weight
        self.source_weight = source_weight
        self.scale_weight = scale_weight
        self.extraordinary_km = extraordinary_km
        self._flag_res = [re.compile(p, re.I) for p in LANG_RED_FLAGS]

    @staticmethod
    def _km_from_match(num: str, unit: str) -> float:
        """Convert a number and unit to kilometers."""
        n = float(num.replace(',', ''))
        if unit.lower().startswith('mile'):
            return n * 1.609344
        return n

    def language_red_flags(self, text: str) -> Tuple[int, List[str]]:
        """Count red flag phrases in text. Returns (count, list of matches)."""
        hits = []
        for pattern in self._flag_res:
            if pattern.search(text):
                hits.append(pattern.pattern)
        return len(hits), hits

    def source_heuristic(self, url: Optional[str]) -> Tuple[float, str]:
        """
        Returns (risk, note). risk in [0,1]; higher is worse.
        """
        if not url:
            return 0.5, "No source URL provided"
        
        try:
            domain = urlparse(url).netloc.lower()
            if domain in DENY_DOMAINS:
                return 1.0, f"High-risk source: {domain}"
            if domain in MEDIUM_DOMAINS:
                return 0.6, f"Medium-risk source: {domain}"
            return 0.2, f"Source domain: {domain}"
        except Exception:
            return 0.5, "Invalid URL format"

    def scale_check(self, text: str, context_keywords: Optional[List[str]] = None) -> Tuple[float, Dict]:
        """
        Parse lengths and judge extraordinariness, boosting risk when context
        suggests planetary/astronomical claims.
        """
        context_keywords = context_keywords or []
        sizes_km = []
        for m in _NUMBER_UNIT.finditer(text):
            sizes_km.append(self._km_from_match(m.group('num'), m.group('unit')))

        if not sizes_km:
            return 0.0, {"sizes_km": []}

        max_km = max(sizes_km)
        extraordinary_context = any(k in text.lower() for k in context_keywords)
        ratio = max_km / max(self.extraordinary_km, 1.0)
        base = min(ratio, 1.0)  # saturate at 1.0
        if extraordinary_context:
            base = min(base * 1.5, 1.0)  # boost for astronomical context

        return base, {
            "sizes_km": sizes_km,
            "extraordinary_context": extraordinary_context,
            "max_km": max_km
        }

    def score(self, text: str, url: Optional[str] = None,
              context_keywords: Optional[List[str]] = None) -> HoaxFilterResult:
        """Score the text for hoax likelihood using all available heuristics."""
        rf_count, rf_hits = self.language_red_flags(text)
        rf_score = min(rf_count / 4.0, 1.0)

        src_risk, src_note = self.source_heuristic(url)
        scale_risk, scale_notes = self.scale_check(text, context_keywords=context_keywords)

        combined = (self.red_flag_weight * rf_score
                   + self.source_weight * src_risk
                   + self.scale_weight * scale_risk)

        return HoaxFilterResult(
            red_flag_hits=rf_count,
            source_score=src_risk,
            scale_score=scale_risk,
            combined=min(combined, 1.0),
            notes={
                "red_flag_patterns": rf_hits,
                "source": src_note,
                **scale_notes
            }
        )