"""Tests for pattern correlation engine."""

import unittest
from datetime import datetime, timedelta, UTC
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
            temporal_window=timedelta(seconds=10),
            min_correlation=0.3
        )
        
        # Sample content
        self.content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Test content for correlation",
            risk_score=0.7,
            features={
                'complexity': 0.8,
                'entropy': 4.5,
                'sentiment': -0.3
            },
            confidence=0.85,
            detection_time=datetime.now(UTC)
        )
        
        # Sample behavior
        current_time = datetime.now(UTC)
        self.behavior = BehaviorPattern(
            pattern_type=BehaviorType.REPETITIVE,
            threat_level=ThreatLevel.MEDIUM,
            confidence=0.85,
            evidence=[{'source': 'test'}],
            first_seen=current_time - timedelta(minutes=30),
            last_seen=current_time,
            frequency=5,
            metadata={'source': 'test'}
        )
    
    def test_temporal_correlation(self):
        """Test temporal correlation detection."""
        # Add content first
        current_time = datetime.now(UTC)
        content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Test content for correlation",
            risk_score=0.7,
            features={
                'complexity': 0.8,
                'entropy': 4.5,
                'sentiment': -0.3
            },
            confidence=0.85,
            detection_time=current_time
        )
        self.correlator.add_content_analysis(content)
        
        # Add behavior 2 seconds later
        behavior_time = current_time + timedelta(seconds=2)
        behavior = BehaviorPattern(
            pattern_type=BehaviorType.REPETITIVE,
            threat_level=ThreatLevel.MEDIUM,
            confidence=0.85,
            evidence=[{'source': 'test'}],
            first_seen=current_time,
            last_seen=behavior_time,
            frequency=5,
            metadata={'source': 'test'}
        )
        self.correlator.add_behavior_pattern(behavior)
        
        # Get temporal correlations
        correlations = self.correlator.get_correlations(
            correlation_type=CorrelationType.TEMPORAL
        )
        
        # Should find at least one correlation
        self.assertTrue(len(correlations) > 0)
        
        if correlations:
            self.assertEqual(
                correlations[0].correlation_type,
                CorrelationType.TEMPORAL
            )
            self.assertGreater(correlations[0].correlation_score, 0.5)
        self.assertEqual(
            correlations[0].correlation_type,
            CorrelationType.TEMPORAL
        )
    
    def test_correlation_pruning(self):
        """Test old correlation pruning."""
        # Add old content
        old_content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Old test content",
            risk_score=0.5,
            features={},
            confidence=0.8,
            detection_time=datetime.now(UTC) - timedelta(hours=1)
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
                    datetime.now(UTC) - timedelta(minutes=5)
                )