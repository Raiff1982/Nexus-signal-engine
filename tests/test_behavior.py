"""Tests for behavioral pattern detection system."""

import unittest
from datetime import datetime, timedelta
from nexus_signal_engine.detection.behavior import (
    BehaviorPattern,
    BehaviorType,
    ThreatLevel
)

class TestBehaviorDetection(unittest.TestCase):
    """Test behavior pattern detection functionality."""
    
    def setUp(self):
        self.sample_pattern = BehaviorPattern(
            pattern_type=BehaviorType.REPETITIVE,
            threat_level=ThreatLevel.MEDIUM,
            frequency=5,
            duration=timedelta(minutes=30),
            confidence=0.85,
            last_seen=datetime.utcnow(),
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
        self.assertEqual(
            self.sample_pattern.duration,
            timedelta(minutes=30)
        )
        self.assertEqual(self.sample_pattern.confidence, 0.85)
    
    def test_confidence_bounds(self):
        """Test confidence score validation."""
        with self.assertRaises(ValueError):
            BehaviorPattern(
                pattern_type=BehaviorType.REPETITIVE,
                threat_level=ThreatLevel.MEDIUM,
                frequency=5,
                duration=timedelta(minutes=30),
                confidence=1.5,  # Should be <= 1.0
                last_seen=datetime.utcnow(),
                metadata={}
            )
        
        with self.assertRaises(ValueError):
            BehaviorPattern(
                pattern_type=BehaviorType.REPETITIVE,
                threat_level=ThreatLevel.MEDIUM,
                frequency=5,
                duration=timedelta(minutes=30),
                confidence=-0.1,  # Should be >= 0.0
                last_seen=datetime.utcnow(),
                metadata={}
            )