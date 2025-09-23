"""Advanced threat detection using ML models and integrated analysis."""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from enum import Enum

from .multimodal import ContentFeatures
from .behavior import BehaviorPattern, ThreatLevel
from .correlator import CorrelatedPattern, CorrelationType

logger = logging.getLogger(__name__)

class ThreatCategory(str, Enum):
    """Categories of detected threats."""
    UNKNOWN = "unknown"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"

@dataclass
class ThreatAssessment:
    """Comprehensive threat assessment result."""
    category: ThreatCategory
    confidence: float
    risk_score: float
    features_importance: Dict[str, float]
    contributing_patterns: List[CorrelatedPattern]
    timestamp: datetime
    metadata: Dict[str, Any]

class ThreatDetector:
    """Advanced threat detection using ML models."""
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        retrain_threshold: int = 1000
    ):
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.samples_since_training = 0
        self.retrain_threshold = retrain_threshold
        self.training_data: List[Dict] = []
        
        if model_path:
            self.load_model(model_path)
    
    def extract_features(
        self,
        content: Optional[ContentFeatures] = None,
        behavior: Optional[BehaviorPattern] = None,
        correlations: Optional[List[CorrelatedPattern]] = None
    ) -> Dict[str, float]:
        """Extract features from various analysis results."""
        features = {}
        
        # Content features
        if content:
            features.update({
                'content_risk_score': content.risk_score,
                'content_complexity': content.features.get('complexity', 0.0),
                'content_entropy': content.features.get('entropy', 0.0),
                'content_sentiment': content.features.get('sentiment', 0.0)
            })
        
        # Behavioral features
        if behavior:
            features.update({
                'behavior_threat_level': float(behavior.threat_level.value),
                'behavior_frequency': behavior.frequency,
                'behavior_duration': behavior.duration.total_seconds(),
                'behavior_confidence': behavior.confidence
            })
        
        # Correlation features
        if correlations:
            by_type = {
                t: [c for c in correlations if c.correlation_type == t]
                for t in CorrelationType
            }
            
            features.update({
                f'correlations_{t.lower()}_count': len(corrs)
                for t, corrs in by_type.items()
            })
            
            features.update({
                f'correlations_{t.lower()}_avg_score': np.mean([
                    c.correlation_score for c in corrs
                ]) if corrs else 0.0
                for t, corrs in by_type.items()
            })
            
            features.update({
                f'correlations_{t.lower()}_max_score': max(
                    (c.correlation_score for c in corrs),
                    default=0.0
                )
                for t, corrs in by_type.items()
            })
        
        return features
    
    def prepare_features(
        self,
        features: Dict[str, float]
    ) -> Tuple[np.ndarray, List[str]]:
        """Prepare feature vector for ML model."""
        # Ensure consistent feature ordering
        if not self.feature_names:
            self.feature_names = sorted(features.keys())
        
        # Create feature vector
        feature_vector = np.array([
            features.get(name, 0.0)
            for name in self.feature_names
        ]).reshape(1, -1)
        
        return feature_vector, self.feature_names
    
    def train(
        self,
        training_data: List[Dict],
        save_path: Optional[str] = None
    ):
        """Train the threat detection model."""
        if not training_data:
            raise ValueError("No training data provided")
        
        # Extract features and labels
        X = []
        y = []
        for sample in training_data:
            features = self.extract_features(**sample['inputs'])
            feature_vector, _ = self.prepare_features(features)
            X.append(feature_vector.flatten())
            y.append(sample['threat_category'].value)
        
        X = np.array(X)
        y = np.array(y)
        
        # Fit scaler and transform features
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Train classifier
        self.classifier.fit(X_scaled, y)
        
        # Reset counter
        self.samples_since_training = 0
        
        # Save model if requested
        if save_path:
            self.save_model(save_path)
    
    def detect(
        self,
        content: Optional[ContentFeatures] = None,
        behavior: Optional[BehaviorPattern] = None,
        correlations: Optional[List[CorrelatedPattern]] = None
    ) -> ThreatAssessment:
        """Detect threats using the trained model."""
        # Extract and prepare features
        features = self.extract_features(
            content=content,
            behavior=behavior,
            correlations=correlations
        )
        feature_vector, feature_names = self.prepare_features(features)
        
        # Scale features
        X_scaled = self.scaler.transform(feature_vector)
        
        # Get predictions and probabilities
        prediction = self.classifier.predict(X_scaled)[0]
        probabilities = self.classifier.predict_proba(X_scaled)[0]
        
        # Get confidence and category
        confidence = max(probabilities)
        category = ThreatCategory(prediction)
        
        # Calculate feature importance
        importance = dict(zip(
            feature_names,
            self.classifier.feature_importances_
        ))
        
        # Calculate risk score
        risk_weights = {
            ThreatCategory.UNKNOWN: 0.2,
            ThreatCategory.LOW_RISK: 0.4,
            ThreatCategory.MEDIUM_RISK: 0.6,
            ThreatCategory.HIGH_RISK: 0.8,
            ThreatCategory.CRITICAL: 1.0
        }
        
        base_risk = risk_weights[category]
        
        # Adjust risk based on confidence and correlations
        risk_modifiers = []
        
        if confidence < 0.5:
            risk_modifiers.append(0.8)  # Reduce risk on low confidence
        elif confidence > 0.8:
            risk_modifiers.append(1.2)  # Increase risk on high confidence
        
        if correlations:
            correlation_scores = [c.correlation_score for c in correlations]
            if any(score > 0.8 for score in correlation_scores):
                risk_modifiers.append(1.3)  # Strong correlations increase risk
        
        risk_score = base_risk * np.prod(risk_modifiers)
        risk_score = max(0.0, min(1.0, risk_score))  # Clamp to [0, 1]
        
        # Store sample for potential retraining
        self.training_data.append({
            'inputs': {
                'content': content,
                'behavior': behavior,
                'correlations': correlations
            },
            'threat_category': category
        })
        
        self.samples_since_training += 1
        
        # Check if retraining is needed
        if self.samples_since_training >= self.retrain_threshold:
            logger.info("Retraining threshold reached, model should be retrained")
        
        return ThreatAssessment(
            category=category,
            confidence=confidence,
            risk_score=risk_score,
            features_importance=importance,
            contributing_patterns=(correlations or []),
            timestamp=datetime.utcnow(),
            metadata={
                'prediction_probabilities': dict(zip(
                    [c.value for c in ThreatCategory],
                    probabilities
                )),
                'risk_modifiers': risk_modifiers,
                'samples_since_training': self.samples_since_training
            }
        )
    
    def save_model(self, path: str):
        """Save the trained model to disk."""
        model_data = {
            'classifier': self.classifier,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        joblib.dump(model_data, path)
    
    def load_model(self, path: str):
        """Load a trained model from disk."""
        model_data = joblib.load(path)
        self.classifier = model_data['classifier']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']