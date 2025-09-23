"""Pattern correlation engine for enhanced threat detection."""

from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict
import logging
from enum import Enum

from .multimodal import ContentFeatures, ContentType
from .behavior import BehaviorPattern, BehaviorType, ThreatLevel

logger = logging.getLogger(__name__)

class CorrelationType(str, Enum):
    """Types of pattern correlations."""
    TEMPORAL = "temporal"
    CONTEXTUAL = "contextual"
    BEHAVIORAL = "behavioral"
    COMPOUND = "compound"

@dataclass
class CorrelatedPattern:
    """Represents correlated patterns across different analyses."""
    correlation_type: CorrelationType
    content_features: List[ContentFeatures]
    behavior_patterns: List[BehaviorPattern]
    correlation_score: float
    confidence: float
    timestamp: datetime
    metadata: Dict[str, Any]

class PatternCorrelator:
    """Correlates patterns across different analysis types."""
    
    def __init__(
        self,
        temporal_window: timedelta = timedelta(hours=1),
        min_correlation: float = 0.5
    ):
        self.temporal_window = temporal_window
        self.min_correlation = min_correlation
        self.content_buffer: List[ContentFeatures] = []
        self.behavior_buffer: List[BehaviorPattern] = []
        self.correlations: List[CorrelatedPattern] = []
    
    def add_content_analysis(self, content: ContentFeatures):
        """Add content analysis results for correlation."""
        self.content_buffer.append(content)
        self._prune_old_data()
        self._update_correlations()
    
    def add_behavior_pattern(self, pattern: BehaviorPattern):
        """Add behavior pattern for correlation."""
        self.behavior_buffer.append(pattern)
        self._prune_old_data()
        self._update_correlations()
    
    def _prune_old_data(self):
        """Remove old data outside the temporal window."""
        cutoff = datetime.utcnow() - self.temporal_window
        
        self.content_buffer = [
            c for c in self.content_buffer
            if c.detection_time >= cutoff
        ]
        
        self.behavior_buffer = [
            b for b in self.behavior_buffer
            if b.last_seen >= cutoff
        ]
        
        self.correlations = [
            c for c in self.correlations
            if c.timestamp >= cutoff
        ]
    
    def _update_correlations(self):
        """Update pattern correlations."""
        new_correlations = []
        
        # Temporal correlations
        temporal = self._find_temporal_correlations()
        new_correlations.extend(temporal)
        
        # Contextual correlations
        contextual = self._find_contextual_correlations()
        new_correlations.extend(contextual)
        
        # Behavioral correlations
        behavioral = self._find_behavioral_correlations()
        new_correlations.extend(behavioral)
        
        # Compound correlations
        compound = self._find_compound_correlations(
            temporal + contextual + behavioral
        )
        new_correlations.extend(compound)
        
        # Update correlations list
        self.correlations = sorted(
            new_correlations,
            key=lambda x: (x.correlation_score, x.confidence),
            reverse=True
        )
    
    def _find_temporal_correlations(self) -> List[CorrelatedPattern]:
        """Find temporally correlated patterns."""
        correlations = []
        
        for content in self.content_buffer:
            # Find behavior patterns close in time
            related_patterns = []
            for pattern in self.behavior_buffer:
                time_diff = abs(
                    (content.detection_time - pattern.last_seen).total_seconds()
                )
                if time_diff <= 60:  # Within 1 minute
                    related_patterns.append(pattern)
            
            if related_patterns:
                # Calculate correlation score based on temporal proximity
                correlation_score = min(
                    1.0,
                    len(related_patterns) / 5  # Normalize by expected max patterns
                )
                
                if correlation_score >= self.min_correlation:
                    correlations.append(CorrelatedPattern(
                        correlation_type=CorrelationType.TEMPORAL,
                        content_features=[content],
                        behavior_patterns=related_patterns,
                        correlation_score=correlation_score,
                        confidence=np.mean([p.confidence for p in related_patterns]),
                        timestamp=datetime.utcnow(),
                        metadata={
                            'time_differences': [
                                abs((content.detection_time - p.last_seen).total_seconds())
                                for p in related_patterns
                            ]
                        }
                    ))
        
        return correlations
    
    def _find_contextual_correlations(self) -> List[CorrelatedPattern]:
        """Find contextually correlated patterns."""
        correlations = []
        
        for content in self.content_buffer:
            # Find behavior patterns with similar context
            related_patterns = []
            for pattern in self.behavior_buffer:
                context_similarity = self._calculate_context_similarity(
                    content, pattern
                )
                if context_similarity >= self.min_correlation:
                    related_patterns.append((pattern, context_similarity))
            
            if related_patterns:
                patterns, similarities = zip(*related_patterns)
                correlations.append(CorrelatedPattern(
                    correlation_type=CorrelationType.CONTEXTUAL,
                    content_features=[content],
                    behavior_patterns=list(patterns),
                    correlation_score=np.mean(similarities),
                    confidence=np.mean([p.confidence for p in patterns]),
                    timestamp=datetime.utcnow(),
                    metadata={
                        'context_similarities': similarities
                    }
                ))
        
        return correlations
    
    def _find_behavioral_correlations(self) -> List[CorrelatedPattern]:
        """Find behaviorally correlated patterns."""
        correlations = []
        
        # Group content by type
        content_by_type = defaultdict(list)
        for content in self.content_buffer:
            content_by_type[content.content_type].append(content)
        
        # Look for behavioral patterns in each content type
        for content_type, contents in content_by_type.items():
            if len(contents) >= 3:  # Minimum sample size
                # Calculate behavioral metrics
                risk_scores = [c.risk_score for c in contents]
                risk_trend = np.polyfit(
                    range(len(risk_scores)),
                    risk_scores,
                    1
                )[0]
                
                # Find related behavior patterns
                related_patterns = []
                for pattern in self.behavior_buffer:
                    if (
                        (risk_trend > 0 and pattern.pattern_type == BehaviorType.ESCALATING) or
                        (len(contents) > 5 and pattern.pattern_type == BehaviorType.REPETITIVE)
                    ):
                        related_patterns.append(pattern)
                
                if related_patterns:
                    correlations.append(CorrelatedPattern(
                        correlation_type=CorrelationType.BEHAVIORAL,
                        content_features=contents,
                        behavior_patterns=related_patterns,
                        correlation_score=min(1.0, abs(risk_trend) * 2),
                        confidence=np.mean([p.confidence for p in related_patterns]),
                        timestamp=datetime.utcnow(),
                        metadata={
                            'risk_trend': risk_trend,
                            'sample_size': len(contents)
                        }
                    ))
        
        return correlations
    
    def _find_compound_correlations(
        self,
        base_correlations: List[CorrelatedPattern]
    ) -> List[CorrelatedPattern]:
        """Find compound correlations across different types."""
        compound_correlations = []
        
        # Group correlations by content
        by_content = defaultdict(list)
        for corr in base_correlations:
            for content in corr.content_features:
                by_content[id(content)].append(corr)
        
        # Look for content with multiple correlation types
        for content_correlations in by_content.values():
            if len(content_correlations) >= 2:
                # Combine correlations
                compound_correlations.append(CorrelatedPattern(
                    correlation_type=CorrelationType.COMPOUND,
                    content_features=list({
                        c for corr in content_correlations
                        for c in corr.content_features
                    }),
                    behavior_patterns=list({
                        p for corr in content_correlations
                        for p in corr.behavior_patterns
                    }),
                    correlation_score=np.mean([
                        c.correlation_score for c in content_correlations
                    ]),
                    confidence=np.mean([
                        c.confidence for c in content_correlations
                    ]),
                    timestamp=datetime.utcnow(),
                    metadata={
                        'correlation_types': [
                            c.correlation_type for c in content_correlations
                        ],
                        'component_scores': [
                            c.correlation_score for c in content_correlations
                        ]
                    }
                ))
        
        return compound_correlations
    
    def _calculate_context_similarity(
        self,
        content: ContentFeatures,
        pattern: BehaviorPattern
    ) -> float:
        """Calculate contextual similarity between content and pattern."""
        # Extract relevant features for comparison
        content_features = {
            'type': content.content_type,
            'risk_score': content.risk_score,
            **content.features
        }
        
        pattern_features = {
            'type': pattern.pattern_type,
            'threat_level': pattern.threat_level,
            'frequency': pattern.frequency,
            **pattern.metadata
        }
        
        # Calculate feature overlap
        common_keys = set(content_features.keys()) & set(pattern_features.keys())
        if not common_keys:
            return 0.0
        
        similarities = []
        for key in common_keys:
            if isinstance(content_features[key], (int, float)):
                # Numeric comparison
                try:
                    similarity = 1.0 - min(
                        1.0,
                        abs(
                            float(content_features[key]) -
                            float(pattern_features[key])
                        ) / max(
                            float(content_features[key]),
                            float(pattern_features[key])
                        )
                    )
                    similarities.append(similarity)
                except (ValueError, ZeroDivisionError):
                    continue
            else:
                # String comparison
                from difflib import SequenceMatcher
                similarity = SequenceMatcher(
                    None,
                    str(content_features[key]),
                    str(pattern_features[key])
                ).ratio()
                similarities.append(similarity)
        
        return np.mean(similarities) if similarities else 0.0
    
    def get_correlations(
        self,
        correlation_type: Optional[CorrelationType] = None,
        min_score: float = 0.5,
        min_confidence: float = 0.5
    ) -> List[CorrelatedPattern]:
        """Get current pattern correlations."""
        correlations = [
            c for c in self.correlations
            if c.correlation_score >= min_score
            and c.confidence >= min_confidence
        ]
        
        if correlation_type:
            correlations = [
                c for c in correlations
                if c.correlation_type == correlation_type
            ]
        
        return sorted(
            correlations,
            key=lambda x: (x.correlation_score, x.confidence),
            reverse=True
        )
    
    def get_correlation_summary(self) -> Dict:
        """Get summary of current correlations."""
        correlations = self.get_correlations()
        
        return {
            'total_correlations': len(correlations),
            'by_type': {
                t.value: len([c for c in correlations if c.correlation_type == t])
                for t in CorrelationType
            },
            'average_score': np.mean([
                c.correlation_score for c in correlations
            ]) if correlations else 0.0,
            'average_confidence': np.mean([
                c.confidence for c in correlations
            ]) if correlations else 0.0,
            'latest_correlation': max(
                (c.timestamp for c in correlations),
                default=datetime.utcnow()
            ).isoformat()
        }