"""Multimodal analysis module for enhanced threat detection."""

from typing import Dict, List, Any, Optional, Tuple, Union
import numpy as np
from dataclasses import dataclass
from enum import Enum
import re
import json
import logging
from datetime import datetime
import hashlib

# Required for advanced text processing
from transformers import pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import LatentDirichletAllocation
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk import ngrams

logger = logging.getLogger(__name__)

class ContentType(str, Enum):
    """Types of content that can be analyzed."""
    TEXT = "text"
    CODE = "code"
    URL = "url"
    EMOJI = "emoji"
    UNICODE = "unicode"
    COMMAND = "command"
    SCRIPT = "script"
    MARKDOWN = "markdown"

@dataclass
class ContentFeatures:
    """Features extracted from content analysis."""
    content_type: ContentType
    raw_content: str
    features: Dict[str, Any]
    risk_score: float
    confidence: float
    detection_time: datetime

class MultimodalAnalyzer:
    """Analyzes content across multiple modalities."""
    
    def __init__(self):
        # Initialize NLP components
        self.sentiment_analyzer = pipeline("sentiment-analysis")
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.topic_model = LatentDirichletAllocation(n_components=5)
        
        # Load NLTK resources
        nltk.download('punkt')
        nltk.download('stopwords')
        self.stop_words = set(stopwords.words('english'))
        
        # Initialize pattern detectors
        self._init_detectors()
    
    def _init_detectors(self):
        """Initialize various pattern detectors."""
        self.patterns = {
            'code_blocks': re.compile(r'```[\s\S]*?```|`[\s\S]*?`'),
            'urls': re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'),
            'emojis': re.compile(r'[\U0001F300-\U0001F9FF]'),
            'commands': re.compile(r'\$\s*[^\n;]+|>\s*[^\n;]+'),
            'unicode_special': re.compile(r'[^\x00-\x7F]+')
        }
    
    def analyze_content(
        self,
        content: str,
        context: Optional[Dict] = None
    ) -> ContentFeatures:
        """
        Perform comprehensive multimodal analysis of content.
        
        Args:
            content: The content to analyze
            context: Additional context for analysis
            
        Returns:
            ContentFeatures object with analysis results
        """
        # Determine content type
        content_type = self._detect_content_type(content)
        
        # Extract features based on content type
        features = self._extract_features(content, content_type)
        
        # Calculate risk score and confidence
        risk_score, confidence = self._assess_risk(features, content_type, context)
        
        return ContentFeatures(
            content_type=content_type,
            raw_content=content,
            features=features,
            risk_score=risk_score,
            confidence=confidence,
            detection_time=datetime.utcnow()
        )
    
    def _detect_content_type(self, content: str) -> ContentType:
        """Detect the primary type of content."""
        # Check for code blocks
        if self.patterns['code_blocks'].search(content):
            return ContentType.CODE
        
        # Check for URLs
        if self.patterns['urls'].search(content):
            return ContentType.URL
        
        # Check for emojis
        if self.patterns['emojis'].search(content):
            return ContentType.EMOJI
        
        # Check for commands
        if self.patterns['commands'].search(content):
            return ContentType.COMMAND
        
        # Check for unicode special characters
        if self.patterns['unicode_special'].search(content):
            return ContentType.UNICODE
        
        # Check for markdown
        if re.search(r'[*_#\[\]\(\)]+', content):
            return ContentType.MARKDOWN
        
        return ContentType.TEXT
    
    def _extract_features(
        self,
        content: str,
        content_type: ContentType
    ) -> Dict[str, Any]:
        """Extract features based on content type."""
        features = {}
        
        # Basic text features
        features['length'] = len(content)
        features['word_count'] = len(content.split())
        
        # Content-type specific features
        if content_type == ContentType.TEXT:
            features.update(self._extract_text_features(content))
        elif content_type == ContentType.CODE:
            features.update(self._extract_code_features(content))
        elif content_type == ContentType.URL:
            features.update(self._extract_url_features(content))
        elif content_type == ContentType.EMOJI:
            features.update(self._extract_emoji_features(content))
        elif content_type == ContentType.UNICODE:
            features.update(self._extract_unicode_features(content))
        
        return features
    
    def _extract_text_features(self, text: str) -> Dict[str, Any]:
        """Extract features from text content."""
        features = {}
        
        # Tokenization
        tokens = word_tokenize(text.lower())
        filtered_tokens = [t for t in tokens if t not in self.stop_words]
        
        # N-grams
        features['bigrams'] = list(ngrams(filtered_tokens, 2))
        features['trigrams'] = list(ngrams(filtered_tokens, 3))
        
        # Sentiment analysis
        try:
            sentiment = self.sentiment_analyzer(text[:512])[0]
            features['sentiment'] = {
                'label': sentiment['label'],
                'score': sentiment['score']
            }
        except Exception as e:
            logger.warning(f"Sentiment analysis failed: {e}")
            features['sentiment'] = {'label': 'UNKNOWN', 'score': 0.0}
        
        # Topic modeling
        try:
            vectorized = self.vectorizer.fit_transform([text])
            topics = self.topic_model.fit_transform(vectorized)
            features['topic_distribution'] = topics.tolist()[0]
        except Exception as e:
            logger.warning(f"Topic modeling failed: {e}")
            features['topic_distribution'] = []
        
        return features
    
    def _extract_code_features(self, content: str) -> Dict[str, Any]:
        """Extract features from code content."""
        features = {}
        
        # Remove code block markers
        code = re.sub(r'```\w*\n|```', '', content)
        
        # Basic code metrics
        features['line_count'] = len(code.splitlines())
        features['has_imports'] = bool(re.search(r'import\s+|from\s+.*\s+import', code))
        features['has_functions'] = bool(re.search(r'def\s+\w+\s*\(', code))
        features['has_classes'] = bool(re.search(r'class\s+\w+', code))
        
        # Security patterns
        features['security_patterns'] = {
            'exec_eval': bool(re.search(r'exec\(|eval\(', code)),
            'system_calls': bool(re.search(r'os\.|sys\.|subprocess\.', code)),
            'file_ops': bool(re.search(r'open\(|read\(|write\(', code)),
            'network_ops': bool(re.search(r'socket\.|urllib|requests\.', code))
        }
        
        return features
    
    def _extract_url_features(self, content: str) -> Dict[str, Any]:
        """Extract features from URL content."""
        features = {}
        urls = self.patterns['urls'].findall(content)
        
        features['url_count'] = len(urls)
        features['domains'] = [re.search(r'https?://([^/]+)', url).group(1)
                             for url in urls if re.search(r'https?://([^/]+)', url)]
        features['protocols'] = [url.split('://')[0] for url in urls]
        
        return features
    
    def _extract_emoji_features(self, content: str) -> Dict[str, Any]:
        """Extract features from emoji content."""
        features = {}
        emojis = self.patterns['emojis'].findall(content)
        
        features['emoji_count'] = len(emojis)
        features['unique_emojis'] = len(set(emojis))
        
        return features
    
    def _extract_unicode_features(self, content: str) -> Dict[str, Any]:
        """Extract features from unicode content."""
        features = {}
        special_chars = self.patterns['unicode_special'].findall(content)
        
        features['special_char_count'] = len(special_chars)
        features['unique_special_chars'] = len(set(special_chars))
        features['unicode_ranges'] = self._get_unicode_ranges(special_chars)
        
        return features
    
    def _get_unicode_ranges(self, chars: List[str]) -> Dict[str, int]:
        """Categorize unicode characters into ranges."""
        ranges = {
            'Basic Latin': 0,
            'Extended Latin': 0,
            'CJK': 0,
            'Emoji': 0,
            'Other': 0
        }
        
        for char in chars:
            code_point = ord(char)
            if code_point < 0x80:
                ranges['Basic Latin'] += 1
            elif code_point < 0x250:
                ranges['Extended Latin'] += 1
            elif 0x4E00 <= code_point <= 0x9FFF:
                ranges['CJK'] += 1
            elif 0x1F300 <= code_point <= 0x1F9FF:
                ranges['Emoji'] += 1
            else:
                ranges['Other'] += 1
        
        return ranges
    
    def _assess_risk(
        self,
        features: Dict[str, Any],
        content_type: ContentType,
        context: Optional[Dict]
    ) -> Tuple[float, float]:
        """
        Assess risk score and confidence based on features.
        
        Returns:
            Tuple of (risk_score, confidence) where both are floats 0-1
        """
        risk_factors = []
        confidence_factors = []
        
        # Content-type specific risk assessment
        if content_type == ContentType.CODE:
            # Assess code security patterns
            security_patterns = features.get('security_patterns', {})
            if security_patterns.get('exec_eval'):
                risk_factors.append(0.8)
                confidence_factors.append(0.9)
            if security_patterns.get('system_calls'):
                risk_factors.append(0.6)
                confidence_factors.append(0.8)
            if security_patterns.get('network_ops'):
                risk_factors.append(0.5)
                confidence_factors.append(0.7)
        
        elif content_type == ContentType.URL:
            # Assess URL patterns
            if features.get('url_count', 0) > 5:
                risk_factors.append(0.4)
                confidence_factors.append(0.6)
            
            # Check for suspicious domains
            domains = features.get('domains', [])
            if any(d.endswith(('.xyz', '.tk', '.pw')) for d in domains):
                risk_factors.append(0.7)
                confidence_factors.append(0.8)
        
        elif content_type == ContentType.UNICODE:
            # Assess unicode patterns
            unicode_ranges = features.get('unicode_ranges', {})
            if unicode_ranges.get('Other', 0) > 10:
                risk_factors.append(0.6)
                confidence_factors.append(0.7)
        
        # General text analysis
        if 'sentiment' in features:
            sentiment = features['sentiment']
            if sentiment['label'] == 'NEGATIVE' and sentiment['score'] > 0.8:
                risk_factors.append(0.3)
                confidence_factors.append(sentiment['score'])
        
        # Calculate final scores
        if risk_factors:
            risk_score = np.mean(risk_factors)
            confidence = np.mean(confidence_factors)
        else:
            risk_score = 0.1
            confidence = 0.5
        
        return risk_score, confidence