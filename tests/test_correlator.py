"""Tests for pattern correlation engine."""

import unittest
from datetime import datetime, timedelta
from nexus_signal_engine.detection.correlator import (
    PatternCorrelator,
    CorrelationType,
    CorrelatedPattern
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

class TestPatternCorrelation(unittest.TestCase):
    """Test pattern correlation functionality."""
    
    def setUp(self):
        self.correlator = PatternCorrelator(
            temporal_window=timedelta(minutes=5),
            min_correlation=0.5
        )
        
        # Sample content
        self.content = ContentFeatures(
            content_type=ContentType.TEXT,
            risk_score=0.7,
            features={
                'complexity': 0.8,
                'entropy': 4.5,
                'sentiment': -0.3
            },
            detection_time=datetime.utcnow()
        )
        
        # Sample behavior
        self.behavior = BehaviorPattern(
            pattern_type=BehaviorType.REPETITIVE,
            threat_level=ThreatLevel.MEDIUM,
            frequency=5,
            duration=timedelta(minutes=30),
            confidence=0.85,
            last_seen=datetime.utcnow(),
            metadata={'source': 'test'}
        )
    
    def test_temporal_correlation(self):
        """Test temporal correlation detection."""
        self.correlator.add_content_analysis(self.content)
        self.correlator.add_behavior_pattern(self.behavior)
        
        correlations = self.correlator.get_correlations(
            correlation_type=CorrelationType.TEMPORAL
        )
        
        self.assertTrue(len(correlations) > 0)
        self.assertEqual(
            correlations[0].correlation_type,
            CorrelationType.TEMPORAL
        )
    
    def test_correlation_pruning(self):
        """Test old correlation pruning."""
        # Add old content
        old_content = ContentFeatures(
            content_type=ContentType.TEXT,
            risk_score=0.5,
            features={},
            detection_time=datetime.utcnow() - timedelta(hours=1)
        )
        self.correlator.add_content_analysis(old_content)
        
        # Add current content
        self.correlator.add_content_analysis(self.content)
        
        # Check that old content was pruned
        correlations = self.correlator.get_correlations()
        for corr in correlations:
            for content in corr.content_features:
                self.assertGreater(
                    content.detection_time,
                    datetime.utcnow() - timedelta(minutes=5)
                )