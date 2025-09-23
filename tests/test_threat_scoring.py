"""Tests for threat scoring system."""

import unittest
from datetime import datetime, timedelta, UTC
from nexus_signal_engine.detection.threat_scoring import (
    ThreatScorer,
    ScoreCategory
)
from nexus_signal_engine.detection.multimodal import (
    ContentFeatures,
    ContentType
)
from nexus_signal_engine.detection.behavior import (
    BehaviorPattern,
    BehaviorType,
    ThreatLevel
)
from nexus_signal_engine.detection.correlator import (
    CorrelatedPattern,
    CorrelationType
)
from nexus_signal_engine.detection.threat_detector import (
    ThreatAssessment,
    ThreatCategory
)

class TestThreatScoring(unittest.TestCase):
    """Test threat scoring functionality."""
    
    def setUp(self):
        self.scorer = ThreatScorer()
        
        # Sample content
        self.benign_content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Benign test content",
            risk_score=0.2,
            features={
                'complexity': 0.3,
                'entropy': 2.5,
                'sentiment': 0.1
            },
            confidence=0.85,
            detection_time=datetime.now(UTC)
        )
        
        self.threat_content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Threatening test content",
            risk_score=0.9,
            features={
                'complexity': 0.9,
                'entropy': 7.5,
                'sentiment': -0.7
            },
            confidence=0.9,
            detection_time=datetime.now(UTC)
        )
        
        # Sample behavior
        current_time = datetime.now(UTC)
        self.benign_behavior = BehaviorPattern(
            pattern_type=BehaviorType.REPETITIVE,
            threat_level=ThreatLevel.LOW,
            frequency=2,
            evidence=[{'type': 'test'}],
            first_seen=current_time - timedelta(seconds=1500),
            last_seen=current_time,
            confidence=0.8,
            metadata={}
        )
        
        current_time = datetime.now(UTC)
        self.threat_behavior = BehaviorPattern(
            pattern_type=BehaviorType.ESCALATING,
            threat_level=ThreatLevel.HIGH,
            frequency=10,
            evidence=[{'type': 'test'}],
            first_seen=current_time - timedelta(seconds=5000),
            last_seen=current_time,
            confidence=0.9,
            metadata={}
        )
        
        # Sample correlations
        self.correlations = [
            CorrelatedPattern(
                correlation_type=CorrelationType.TEMPORAL,
                content_features=[self.threat_content],
                behavior_patterns=[self.threat_behavior],
                correlation_score=0.85,
                confidence=0.9,
                timestamp=datetime.now(UTC),
                metadata={}
            )
        ]
        
        # Sample ML assessment
        self.ml_assessment = ThreatAssessment(
            category=ThreatCategory.HIGH_RISK,
            confidence=0.9,
            risk_score=0.85,
            features_importance={'risk_score': 0.8},
            contributing_patterns=self.correlations,
            timestamp=datetime.now(UTC),
            metadata={}
        )
    
    def test_benign_scoring(self):
        """Test scoring of benign activity."""
        score = self.scorer.calculate_score(
            content=self.benign_content,
            behavior=self.benign_behavior
        )
        
        self.assertLess(score.score, 0.5)
        self.assertIn(
            score.category,
            [ScoreCategory.BENIGN, ScoreCategory.SUSPICIOUS]
        )
    
    def test_threat_scoring(self):
        """Test scoring of threatening activity."""
        score = self.scorer.calculate_score(
            content=self.threat_content,
            behavior=self.threat_behavior,
            correlations=self.correlations,
            ml_assessment=self.ml_assessment
        )
        
        self.assertGreater(score.score, 0.6)
        self.assertIn(
            score.category,
            [ScoreCategory.DANGEROUS, ScoreCategory.CRITICAL]
        )
    
    def test_component_weights(self):
        """Test component weight validation."""
        with self.assertRaises(ValueError):
            ThreatScorer(
                content_weight=0.4,
                behavior_weight=0.4,
                correlation_weight=0.4,
                ml_weight=0.4
            )  # Sum > 1.0