"""Tests for threat scoring system."""

import unittest
from datetime import datetime
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
            risk_score=0.2,
            features={
                'complexity': 0.3,
                'entropy': 2.5,
                'sentiment': 0.1
            },
            detection_time=datetime.utcnow()
        )
        
        self.threat_content = ContentFeatures(
            content_type=ContentType.TEXT,
            risk_score=0.9,
            features={
                'complexity': 0.9,
                'entropy': 7.5,
                'sentiment': -0.7
            },
            detection_time=datetime.utcnow()
        )
        
        # Sample behavior
        self.benign_behavior = BehaviorPattern(
            pattern_type=BehaviorType.REPETITIVE,
            threat_level=ThreatLevel.LOW,
            frequency=2,
            duration=1500,
            confidence=0.8,
            last_seen=datetime.utcnow(),
            metadata={}
        )
        
        self.threat_behavior = BehaviorPattern(
            pattern_type=BehaviorType.ESCALATING,
            threat_level=ThreatLevel.HIGH,
            frequency=10,
            duration=5000,
            confidence=0.9,
            last_seen=datetime.utcnow(),
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
                timestamp=datetime.utcnow(),
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
            timestamp=datetime.utcnow(),
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
        
        self.assertGreater(score.score, 0.7)
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