"""Tests for multimodal analysis system."""

import unittest
from datetime import datetime, UTC
from nexus_signal_engine.detection.multimodal import ContentFeatures, ContentType

class TestMultimodalAnalysis(unittest.TestCase):
    """Test multimodal content analysis functionality."""
    
    def setUp(self):
        self.sample_content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Test content for analysis",
            risk_score=0.7,
            features={
                'complexity': 0.8,
                'entropy': 4.5,
                'sentiment': -0.3
            },
            confidence=0.85,
            detection_time=datetime.now(UTC)
        )
    
    def test_content_features(self):
        """Test content features creation and validation."""
        self.assertEqual(self.sample_content.content_type, ContentType.TEXT)
        self.assertEqual(self.sample_content.risk_score, 0.7)
        self.assertEqual(self.sample_content.features['complexity'], 0.8)
        self.assertEqual(self.sample_content.features['entropy'], 4.5)
        self.assertEqual(self.sample_content.features['sentiment'], -0.3)
    
    def test_risk_score_bounds(self):
        """Test risk score validation."""
        with self.assertRaises(ValueError):
            ContentFeatures(
                content_type=ContentType.TEXT,
                raw_content="Test content",
                risk_score=1.5,  # Should be <= 1.0
                features={},
                confidence=0.85,
                detection_time=datetime.now(UTC)
            )
        
        with self.assertRaises(ValueError):
            ContentFeatures(
                content_type=ContentType.TEXT,
                raw_content="Test content",
                risk_score=-0.5,  # Should be >= 0.0
                features={},
                confidence=0.85,
                detection_time=datetime.now(UTC)
            )