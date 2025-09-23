"""Comprehensive threat scoring system."""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, UTC
import numpy as np
from enum import Enum

from .multimodal import ContentFeatures
from .behavior import BehaviorPattern, ThreatLevel
from .correlator import CorrelatedPattern
from .threat_detector import ThreatAssessment, ThreatCategory

class ScoreCategory(str, Enum):
    """Categories for threat scores."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    THREATENING = "threatening"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"

@dataclass
class ThreatScore:
    """Comprehensive threat score with detailed analysis."""
    score: float  # 0.0 to 1.0
    category: ScoreCategory
    confidence: float
    components: Dict[str, float]
    evidence: Dict[str, Any]
    timestamp: datetime

class ThreatScorer:
    """Comprehensive threat scoring system."""
    
    def __init__(
        self,
        content_weight: float = 0.3,
        behavior_weight: float = 0.3,
        correlation_weight: float = 0.2,
        ml_weight: float = 0.2
    ):
        self.weights = {
            'content': content_weight,
            'behavior': behavior_weight,
            'correlation': correlation_weight,
            'ml': ml_weight
        }
        
        # Validate weights sum to 1.0
        total = sum(self.weights.values())
        if not np.isclose(total, 1.0):
            raise ValueError(
                f"Weights must sum to 1.0, got {total}"
            )
    
    def _score_content(
        self,
        content: ContentFeatures
    ) -> Tuple[float, Dict[str, Any]]:
        """Score content features."""
        subscores = {
            'risk_score': content.risk_score,
            'complexity': content.features.get('complexity', 0.0),
            'entropy': min(
                1.0,
                content.features.get('entropy', 0.0) / 8.0
            ),
            'sentiment': abs(
                content.features.get('sentiment', 0.0)
            )
        }
        
        # Weight the subscores
        weighted_score = np.mean(list(subscores.values()))
        
        evidence = {
            'subscores': subscores,
            'content_type': content.content_type,
            'detection_time': content.detection_time.isoformat()
        }
        
        return weighted_score, evidence
    
    def _score_behavior(
        self,
        behavior: BehaviorPattern
    ) -> Tuple[float, Dict[str, Any]]:
        """Score behavior patterns."""
        # Get threat level score
        base_score = behavior.threat_level.to_float()
        
        # Get threat level score
        base_score = behavior.threat_level.to_float()
        
        # Adjust for frequency and confidence
        frequency_factor = min(1.0, behavior.frequency / 10.0)
        
        adjusted_score = base_score * (
            0.7 +  # Base weight
            0.15 * frequency_factor +  # Frequency adjustment
            0.15 * behavior.confidence  # Confidence adjustment
        )
        
        evidence = {
            'base_score': base_score,
            'frequency_factor': frequency_factor,
            'confidence': behavior.confidence,
            'pattern_type': behavior.pattern_type,
            'last_seen': behavior.last_seen.isoformat()
        }
        
        return adjusted_score, evidence
    
    def _score_correlations(
        self,
        correlations: List[CorrelatedPattern]
    ) -> Tuple[float, Dict[str, Any]]:
        """Score pattern correlations."""
        if not correlations:
            return 0.0, {'correlation_count': 0}
        
        # Score by correlation type
        type_scores = {}
        for corr in correlations:
            current = type_scores.get(corr.correlation_type, [])
            current.append(corr.correlation_score * corr.confidence)
            type_scores[corr.correlation_type] = current
        
        # Calculate weighted average for each type
        weighted_scores = {}
        for ctype, scores in type_scores.items():
            # Weight higher scores more heavily
            weights = np.exp(scores) / np.sum(np.exp(scores))  # Softmax
            weighted_scores[ctype] = np.average(scores, weights=weights)
        
        # Calculate final score with emphasis on compound correlations
        type_weights = {
            'temporal': 0.2,
            'contextual': 0.25,
            'behavioral': 0.25,
            'compound': 0.3
        }
        
        final_score = sum(
            weighted_scores.get(ctype, 0.0) * weight
            for ctype, weight in type_weights.items()
        )
        
        evidence = {
            'correlation_count': len(correlations),
            'type_scores': weighted_scores,
            'type_weights': type_weights
        }
        
        return final_score, evidence
    
    def _score_ml_assessment(
        self,
        assessment: ThreatAssessment
    ) -> Tuple[float, Dict[str, Any]]:
        """Score ML-based threat assessment."""
        # Map categories to base scores
        category_scores = {
            ThreatCategory.UNKNOWN: 0.2,
            ThreatCategory.LOW_RISK: 0.4,
            ThreatCategory.MEDIUM_RISK: 0.6,
            ThreatCategory.HIGH_RISK: 0.8,
            ThreatCategory.CRITICAL: 1.0
        }
        
        base_score = category_scores[assessment.category]
        
        # Adjust based on confidence and risk score
        confidence_factor = assessment.confidence
        risk_factor = assessment.risk_score
        
        adjusted_score = base_score * (
            0.6 +  # Base weight
            0.2 * confidence_factor +  # Confidence adjustment
            0.2 * risk_factor  # Risk score adjustment
        )
        
        evidence = {
            'category': assessment.category,
            'base_score': base_score,
            'confidence': confidence_factor,
            'risk_score': risk_factor,
            'top_features': dict(sorted(
                assessment.features_importance.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5])
        }
        
        return adjusted_score, evidence
    
    def calculate_score(
        self,
        content: Optional[ContentFeatures] = None,
        behavior: Optional[BehaviorPattern] = None,
        correlations: Optional[List[CorrelatedPattern]] = None,
        ml_assessment: Optional[ThreatAssessment] = None
    ) -> ThreatScore:
        """Calculate comprehensive threat score."""
        components = {}
        evidence = {}
        
        # Calculate component scores
        if content:
            score, evidence['content'] = self._score_content(content)
            components['content'] = score * self.weights['content']
        
        if behavior:
            score, evidence['behavior'] = self._score_behavior(behavior)
            components['behavior'] = score * self.weights['behavior']
        
        if correlations:
            score, evidence['correlations'] = self._score_correlations(
                correlations
            )
            components['correlation'] = score * self.weights['correlation']
        
        if ml_assessment:
            score, evidence['ml_assessment'] = self._score_ml_assessment(
                ml_assessment
            )
            components['ml'] = score * self.weights['ml']
        
        # Calculate final score
        final_score = sum(components.values())
        
        # Determine score category
        category = ScoreCategory.BENIGN
        if final_score >= 0.8:
            category = ScoreCategory.CRITICAL
        elif final_score >= 0.6:
            category = ScoreCategory.DANGEROUS
        elif final_score >= 0.4:
            category = ScoreCategory.THREATENING
        elif final_score >= 0.2:
            category = ScoreCategory.SUSPICIOUS
        
        # Calculate confidence based on component confidences
        confidences = []
        if content:
            confidences.append(1.0)  # Content analysis is deterministic
        if behavior:
            confidences.append(behavior.confidence)
        if correlations:
            confidences.append(
                np.mean([c.confidence for c in correlations])
            )
        if ml_assessment:
            confidences.append(ml_assessment.confidence)
        
        confidence = np.mean(confidences) if confidences else 0.0
        
        return ThreatScore(
            score=final_score,
            category=category,
            confidence=confidence,
            components=components,
            evidence=evidence,
            timestamp=datetime.now(UTC)
        )