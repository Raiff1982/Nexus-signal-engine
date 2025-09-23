"""Tests for behavioral pattern detection system."""

import unittest
from datetime import datetime, timedelta, UTC
from nexus_signal_engine.detection.behavior import (
    BehaviorPattern,
    BehaviorType,
    ThreatLevel
)

class TestBehaviorDetection(unittest.TestCase):
    """Test behavior pattern detection functionality."""
    
    def setUp(self):
        current_time = datetime.now(UTC)
        self.sample_pattern = BehaviorPattern(
            pattern_type=BehaviorType.REPETITIVE,
            threat_level=ThreatLevel.MEDIUM,
            confidence=0.85,
            evidence=[{'source': 'test'}],
            first_seen=current_time - timedelta(minutes=30),
            last_seen=current_time,
            frequency=5,
            metadata={'source': 'test'}
        )
    
    def test_behavior_pattern(self):
        """Test behavior pattern creation and validation."""
        self.assertEqual(
            self.sample_pattern.pattern_type,
            BehaviorType.REPETITIVE
        )
        self.assertEqual(
            self.sample_pattern.threat_level,
            ThreatLevel.MEDIUM
        )
        self.assertEqual(self.sample_pattern.frequency, 5)
        self.assertEqual(self.sample_pattern.confidence, 0.85)
        self.assertEqual(len(self.sample_pattern.evidence), 1)
        self.assertEqual(
            self.sample_pattern.metadata['source'],
            'test'
        )
    
    def test_confidence_bounds(self):
        """Test confidence score validation."""
        current_time = datetime.now(UTC)
        with self.assertRaises(ValueError):
            BehaviorPattern(
                pattern_type=BehaviorType.REPETITIVE,
                threat_level=ThreatLevel.MEDIUM,
                frequency=5,
                evidence=[{'type': 'test'}],
                first_seen=current_time - timedelta(minutes=30),
                last_seen=current_time,
                confidence=1.5,  # Should be <= 1.0
                metadata={}
            )
        
        with self.assertRaises(ValueError):
            BehaviorPattern(
                pattern_type=BehaviorType.REPETITIVE,
                threat_level=ThreatLevel.MEDIUM,
                frequency=5,
                evidence=[{'type': 'test'}],
                first_seen=current_time - timedelta(minutes=30),
                last_seen=current_time,
                confidence=-0.1,  # Should be >= 0.0
                metadata={}
            )