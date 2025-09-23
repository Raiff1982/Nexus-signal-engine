"""Tests for ML-based threat detection system."""

import unittest
import tempfile
import os
from datetime import datetime, timedelta, UTC
import numpy as np
from nexus_signal_engine.detection.threat_detector import (
    ThreatDetector,
    ThreatCategory
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
from nexus_signal_engine.detection.correlator import CorrelatedPattern

class TestThreatDetection(unittest.TestCase):
    """Test ML-based threat detection functionality."""
    
    def setUp(self):
        self.detector = ThreatDetector()
        
        # Sample training data
        self.training_data = []
        
        # Generate benign samples
        for _ in range(10):
            current_time = datetime.now(UTC)
            self.training_data.append({
                'inputs': {
                    'content': ContentFeatures(
                        content_type=ContentType.TEXT,
                        raw_content=f"Benign test content {_}",
                        risk_score=np.random.uniform(0, 0.3),
                        features={
                            'complexity': np.random.uniform(0, 0.4),
                            'entropy': np.random.uniform(0, 3),
                            'sentiment': np.random.uniform(-0.2, 0.2)
                        },
                        confidence=np.random.uniform(0.7, 0.9),
                        detection_time=current_time
                    ),
                    'behavior': BehaviorPattern(
                        pattern_type=BehaviorType.REPETITIVE,
                        threat_level=ThreatLevel.LOW,
                        frequency=np.random.randint(1, 3),
                        evidence=[{'type': 'test'}],
                        first_seen=current_time - timedelta(seconds=np.random.uniform(0, 1800)),
                        last_seen=current_time,
                        confidence=np.random.uniform(0.7, 0.9),
                        metadata={}
                    )
                },
                'threat_category': ThreatCategory.LOW_RISK
            })
        
        # Generate threatening samples
        for _ in range(10):
            current_time = datetime.now(UTC)
            self.training_data.append({
                'inputs': {
                    'content': ContentFeatures(
                        content_type=ContentType.TEXT,
                        raw_content=f"Threatening test content {_}",
                        risk_score=np.random.uniform(0.7, 1.0),
                        features={
                            'complexity': np.random.uniform(0.7, 1.0),
                            'entropy': np.random.uniform(6, 8),
                            'sentiment': np.random.uniform(-0.8, -0.5)
                        },
                        confidence=np.random.uniform(0.8, 1.0),
                        detection_time=current_time
                    ),
                    'behavior': BehaviorPattern(
                        pattern_type=BehaviorType.ESCALATING,
                        threat_level=ThreatLevel.HIGH,
                        frequency=np.random.randint(8, 12),
                        evidence=[{'type': 'test'}],
                        first_seen=current_time - timedelta(seconds=np.random.uniform(3600, 7200)),
                        last_seen=current_time,
                        confidence=np.random.uniform(0.8, 1.0),
                        metadata={}
                    )
                },
                'threat_category': ThreatCategory.HIGH_RISK
            })
    
    def test_model_training(self):
        """Test model training and prediction."""
        # Train model
        self.detector.train(self.training_data)
        
        # Test benign prediction
        current_time = datetime.now(UTC)
        benign_content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Test benign content",
            risk_score=0.2,
            features={
                'complexity': 0.3,
                'entropy': 2.5,
                'sentiment': 0.1
            },
            confidence=0.8,
            detection_time=current_time
        )
        
        benign_behavior = BehaviorPattern(
            pattern_type=BehaviorType.REPETITIVE,
            threat_level=ThreatLevel.LOW,
            frequency=2,
            evidence=[{'type': 'test'}],
            first_seen=current_time - timedelta(minutes=15),
            last_seen=current_time,
            confidence=0.8,
            metadata={}
        )
        
        benign_assessment = self.detector.detect(
            content=benign_content,
            behavior=benign_behavior
        )
        
        self.assertIn(
            benign_assessment.category,
            [ThreatCategory.LOW_RISK, ThreatCategory.UNKNOWN]
        )
        
        # Test threatening prediction
        current_time = datetime.now(UTC)
        threat_content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Test threatening content",
            risk_score=0.9,
            features={
                'complexity': 0.9,
                'entropy': 7.5,
                'sentiment': -0.7
            },
            confidence=0.9,
            detection_time=current_time
        )
        
        threat_behavior = BehaviorPattern(
            pattern_type=BehaviorType.ESCALATING,
            threat_level=ThreatLevel.HIGH,
            frequency=10,
            evidence=[{'type': 'test'}],
            first_seen=current_time - timedelta(minutes=45),
            last_seen=current_time,
            confidence=0.9,
            metadata={}
        )
        
        threat_assessment = self.detector.detect(
            content=threat_content,
            behavior=threat_behavior
        )
        
        self.assertIn(
            threat_assessment.category,
            [ThreatCategory.HIGH_RISK, ThreatCategory.CRITICAL]
        )
    
    def test_model_persistence(self):
        """Test model saving and loading."""
        # Train model
        self.detector.train(self.training_data)
        
        # Save model
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            model_path = tmp.name
            self.detector.save_model(model_path)
        
        # Load model in new detector
        new_detector = ThreatDetector()
        new_detector.load_model(model_path)
        
        # Clean up
        os.unlink(model_path)
        
        # Test prediction consistency
        current_time = datetime.now(UTC)
        content = ContentFeatures(
            content_type=ContentType.TEXT,
            raw_content="Test content for persistence check",
            risk_score=0.8,
            features={
                'complexity': 0.8,
                'entropy': 6.5,
                'sentiment': -0.6
            },
            confidence=0.9,
            detection_time=current_time
        )
        
        behavior = BehaviorPattern(
            pattern_type=BehaviorType.ESCALATING,
            threat_level=ThreatLevel.HIGH,
            frequency=9,
            evidence=[{'type': 'test'}],
            first_seen=current_time - timedelta(minutes=30),
            last_seen=current_time,
            confidence=0.85,
            metadata={}
        )
        
        assessment1 = self.detector.detect(
            content=content,
            behavior=behavior
        )
        assessment2 = new_detector.detect(
            content=content,
            behavior=behavior
        )
        
        self.assertEqual(assessment1.category, assessment2.category)