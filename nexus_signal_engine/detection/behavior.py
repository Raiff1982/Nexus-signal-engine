"""Behavioral pattern detection system for enhanced threat analysis."""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import numpy as np
from datetime import datetime, timedelta, UTC
from collections import defaultdict
import logging
import json
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)

class BehaviorType(str, Enum):
    """Types of behavioral patterns."""
    REPETITIVE = "repetitive"
    ANOMALOUS = "anomalous"
    ESCALATING = "escalating"
    EVASIVE = "evasive"
    COLLABORATIVE = "collaborative"

class ThreatLevel(str, Enum):
    """Threat levels for detected patterns."""
    NONE = "none"  # 0.0
    LOW = "low"  # 0.25
    MEDIUM = "medium"  # 0.5
    HIGH = "high"  # 0.75
    CRITICAL = "critical"  # 1.0

    def to_float(self) -> float:
        """Convert threat level to float value."""
        values = {
            self.NONE: 0.0,
            self.LOW: 0.25,
            self.MEDIUM: 0.5,
            self.HIGH: 0.75,
            self.CRITICAL: 1.0
        }
        return values[self]

@dataclass
class BehaviorPattern:
    """Represents a detected behavioral pattern."""
    pattern_type: BehaviorType
    threat_level: ThreatLevel
    confidence: float
    evidence: List[Dict]
    first_seen: datetime
    last_seen: datetime
    frequency: int = 0
    metadata: Dict = field(default_factory=dict)

    def __post_init__(self):
        """Validate the pattern after initialization."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"Confidence must be between 0.0 and 1.0, got {self.confidence}"
            )

@dataclass
class ActivityNode:
    """Node in the activity graph."""
    activity_type: str
    timestamp: datetime
    metadata: Dict
    edges: Set[str] = field(default_factory=set)

class BehaviorDetector:
    """Detects and analyzes behavioral patterns."""
    
    def __init__(self, window_size: timedelta = timedelta(hours=24)):
        self.window_size = window_size
        self.activity_graph: Dict[str, ActivityNode] = {}
        self.patterns: Dict[str, BehaviorPattern] = {}
        
        # Initialize pattern detectors
        self._init_detectors()
    
    def _init_detectors(self):
        """Initialize pattern detection algorithms."""
        self.detection_rules = {
            BehaviorType.REPETITIVE: {
                'min_frequency': 5,
                'time_window': timedelta(minutes=10),
                'threshold': 0.8
            },
            BehaviorType.ANOMALOUS: {
                'zscore_threshold': 3.0,
                'min_samples': 10,
                'confidence_threshold': 0.7
            },
            BehaviorType.ESCALATING: {
                'min_steps': 3,
                'risk_increase': 0.2,
                'time_window': timedelta(hours=1)
            },
            BehaviorType.EVASIVE: {
                'similarity_threshold': 0.7,
                'mutation_rate': 0.3,
                'min_variants': 3
            },
            BehaviorType.COLLABORATIVE: {
                'min_participants': 2,
                'interaction_threshold': 0.6,
                'time_window': timedelta(minutes=30)
            }
        }
    
    def add_activity(
        self,
        activity_type: str,
        metadata: Dict,
        timestamp: Optional[datetime] = None
    ) -> str:
        """
        Add a new activity to the behavior graph.
        
        Args:
            activity_type: Type of activity
            metadata: Additional activity information
            timestamp: Activity timestamp (default: current time)
            
        Returns:
            str: Activity ID
        """
        timestamp = timestamp or datetime.now(UTC)
        
        # Generate activity ID
        activity_id = self._generate_activity_id(activity_type, metadata, timestamp)
        
        # Create activity node
        node = ActivityNode(
            activity_type=activity_type,
            timestamp=timestamp,
            metadata=metadata
        )
        
        self.activity_graph[activity_id] = node
        
        # Prune old activities
        self._prune_old_activities()
        
        # Update pattern detection
        self._update_patterns(activity_id, node)
        
        return activity_id
    
    def _generate_activity_id(
        self,
        activity_type: str,
        metadata: Dict,
        timestamp: datetime
    ) -> str:
        """Generate unique ID for activity."""
        data = {
            'type': activity_type,
            'metadata': metadata,
            'timestamp': timestamp.isoformat()
        }
        return hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()
    
    def _prune_old_activities(self):
        """Remove activities outside the time window."""
        cutoff = datetime.now(UTC) - self.window_size
        old_activities = [
            aid for aid, node in self.activity_graph.items()
            if node.timestamp < cutoff
        ]
        
        for aid in old_activities:
            del self.activity_graph[aid]
    
    def _update_patterns(self, activity_id: str, node: ActivityNode):
        """Update pattern detection with new activity."""
        self._detect_repetitive_patterns(activity_id, node)
        self._detect_anomalous_patterns(activity_id, node)
        self._detect_escalating_patterns(activity_id, node)
        self._detect_evasive_patterns(activity_id, node)
        self._detect_collaborative_patterns(activity_id, node)
    
    def _detect_repetitive_patterns(self, activity_id: str, node: ActivityNode):
        """Detect repetitive behavior patterns."""
        rules = self.detection_rules[BehaviorType.REPETITIVE]
        recent = datetime.now(UTC) - rules['time_window']
        
        # Count similar activities
        similar_activities = [
            n for n in self.activity_graph.values()
            if n.activity_type == node.activity_type
            and n.timestamp > recent
        ]
        
        if len(similar_activities) >= rules['min_frequency']:
            pattern_id = f"repetitive_{node.activity_type}"
            
            if pattern_id not in self.patterns:
                self.patterns[pattern_id] = BehaviorPattern(
                    pattern_type=BehaviorType.REPETITIVE,
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.0,
                    evidence=[],
                    first_seen=node.timestamp,
                    last_seen=node.timestamp
                )
            
            pattern = self.patterns[pattern_id]
            pattern.frequency = len(similar_activities)
            pattern.last_seen = node.timestamp
            pattern.confidence = min(
                1.0,
                pattern.frequency / rules['min_frequency']
            )
            
            if pattern.confidence >= rules['threshold']:
                pattern.threat_level = ThreatLevel.HIGH
    
    def _detect_anomalous_patterns(self, activity_id: str, node: ActivityNode):
        """Detect anomalous behavior patterns."""
        rules = self.detection_rules[BehaviorType.ANOMALOUS]
        
        # Get historical activities of same type
        history = [
            n for n in self.activity_graph.values()
            if n.activity_type == node.activity_type
        ]
        
        if len(history) >= rules['min_samples']:
            # Calculate z-score for numeric metadata
            z_scores = {}
            for key, value in node.metadata.items():
                if isinstance(value, (int, float)):
                    values = [h.metadata.get(key, 0) for h in history]
                    mean = np.mean(values)
                    std = np.std(values)
                    if std > 0:
                        z_scores[key] = abs((value - mean) / std)
            
            # Check for anomalies
            if any(z > rules['zscore_threshold'] for z in z_scores.values()):
                pattern_id = f"anomalous_{activity_id}"
                
                self.patterns[pattern_id] = BehaviorPattern(
                    pattern_type=BehaviorType.ANOMALOUS,
                    threat_level=ThreatLevel.HIGH,
                    confidence=max(
                        rules['confidence_threshold'],
                        min(1.0, max(z_scores.values()) / rules['zscore_threshold'])
                    ),
                    evidence=[{
                        'activity_id': activity_id,
                        'z_scores': z_scores
                    }],
                    first_seen=node.timestamp,
                    last_seen=node.timestamp
                )
    
    def _detect_escalating_patterns(self, activity_id: str, node: ActivityNode):
        """Detect escalating behavior patterns."""
        rules = self.detection_rules[BehaviorType.ESCALATING]
        recent = datetime.now(UTC) - rules['time_window']
        
        # Get recent activities
        activities = sorted(
            [n for n in self.activity_graph.values() if n.timestamp > recent],
            key=lambda x: x.timestamp
        )
        
        if len(activities) >= rules['min_steps']:
            # Check for increasing risk scores
            risk_scores = [
                float(a.metadata.get('risk_score', 0))
                for a in activities
            ]
            
            increases = [
                (b - a) >= rules['risk_increase']
                for a, b in zip(risk_scores[:-1], risk_scores[1:])
            ]
            
            if all(increases):
                pattern_id = f"escalating_{activity_id}"
                
                self.patterns[pattern_id] = BehaviorPattern(
                    pattern_type=BehaviorType.ESCALATING,
                    threat_level=ThreatLevel.CRITICAL,
                    confidence=min(1.0, sum(increases) / rules['min_steps']),
                    evidence=[{
                        'activities': [a.activity_type for a in activities],
                        'risk_scores': risk_scores
                    }],
                    first_seen=activities[0].timestamp,
                    last_seen=node.timestamp
                )
    
    def _detect_evasive_patterns(self, activity_id: str, node: ActivityNode):
        """Detect evasive behavior patterns."""
        rules = self.detection_rules[BehaviorType.EVASIVE]
        
        # Get recent activities
        activities = list(self.activity_graph.values())
        
        if len(activities) >= rules['min_variants']:
            # Calculate similarity between activities
            from difflib import SequenceMatcher
            
            def similarity(a: Dict, b: Dict) -> float:
                """Calculate similarity between two activities."""
                return SequenceMatcher(
                    None,
                    json.dumps(a, sort_keys=True),
                    json.dumps(b, sort_keys=True)
                ).ratio()
            
            # Find similar but slightly different activities
            similar_activities = []
            for a in activities:
                sim = similarity(a.metadata, node.metadata)
                if (sim > rules['similarity_threshold'] and
                    sim < (1 - rules['mutation_rate'])):
                    similar_activities.append(a)
            
            if len(similar_activities) >= rules['min_variants']:
                pattern_id = f"evasive_{activity_id}"
                
                self.patterns[pattern_id] = BehaviorPattern(
                    pattern_type=BehaviorType.EVASIVE,
                    threat_level=ThreatLevel.HIGH,
                    confidence=min(
                        1.0,
                        len(similar_activities) / rules['min_variants']
                    ),
                    evidence=[{
                        'variants': len(similar_activities),
                        'mutation_rates': [
                            1 - similarity(a.metadata, node.metadata)
                            for a in similar_activities
                        ]
                    }],
                    first_seen=min(a.timestamp for a in similar_activities),
                    last_seen=node.timestamp
                )
    
    def _detect_collaborative_patterns(self, activity_id: str, node: ActivityNode):
        """Detect collaborative behavior patterns."""
        rules = self.detection_rules[BehaviorType.COLLABORATIVE]
        recent = datetime.now(UTC) - rules['time_window']
        
        # Get recent activities
        activities = [
            n for n in self.activity_graph.values()
            if n.timestamp > recent
        ]
        
        if len(activities) >= rules['min_participants']:
            # Group activities by user/source
            by_source = defaultdict(list)
            for a in activities:
                source = a.metadata.get('source', 'unknown')
                by_source[source].append(a)
            
            # Check for interactions between sources
            if len(by_source) >= rules['min_participants']:
                # Calculate interaction score
                total_interactions = sum(
                    1 for s1 in by_source.values()
                    for s2 in by_source.values()
                    if s1 != s2 and self._have_interaction(s1, s2)
                )
                max_interactions = len(by_source) * (len(by_source) - 1)
                interaction_score = total_interactions / max_interactions
                
                if interaction_score >= rules['interaction_threshold']:
                    pattern_id = f"collaborative_{activity_id}"
                    
                    self.patterns[pattern_id] = BehaviorPattern(
                        pattern_type=BehaviorType.COLLABORATIVE,
                        threat_level=ThreatLevel.HIGH,
                        confidence=interaction_score,
                        evidence=[{
                            'sources': len(by_source),
                            'interactions': total_interactions,
                            'interaction_score': interaction_score
                        }],
                        first_seen=min(a.timestamp for a in activities),
                        last_seen=node.timestamp
                    )
    
    def _have_interaction(
        self,
        activities1: List[ActivityNode],
        activities2: List[ActivityNode]
    ) -> bool:
        """Check if two sets of activities have meaningful interaction."""
        # Example: Check for temporal proximity and related content
        for a1 in activities1:
            for a2 in activities2:
                time_diff = abs((a1.timestamp - a2.timestamp).total_seconds())
                if time_diff <= 60:  # Within 1 minute
                    # Check for content similarity or references
                    if any(
                        ref in str(a2.metadata)
                        for ref in a1.metadata.get('references', [])
                    ):
                        return True
        return False
    
    def get_active_patterns(
        self,
        pattern_type: Optional[BehaviorType] = None,
        min_confidence: float = 0.5
    ) -> List[BehaviorPattern]:
        """Get currently active behavior patterns."""
        patterns = [
            p for p in self.patterns.values()
            if p.confidence >= min_confidence
        ]
        
        if pattern_type:
            patterns = [p for p in patterns if p.pattern_type == pattern_type]
        
        return sorted(
            patterns,
            key=lambda p: (p.threat_level, p.confidence),
            reverse=True
        )
    
    def get_threat_summary(self) -> Dict:
        """Get summary of current threat patterns."""
        active_patterns = self.get_active_patterns()
        
        return {
            'total_patterns': len(active_patterns),
            'by_type': {
                t.value: len([p for p in active_patterns if p.pattern_type == t])
                for t in BehaviorType
            },
            'by_threat_level': {
                l.value: len([p for p in active_patterns if p.threat_level == l])
                for l in ThreatLevel
            },
            'highest_confidence': max(
                (p.confidence for p in active_patterns),
                default=0.0
            ),
            'latest_detection': max(
                (p.last_seen for p in active_patterns),
                default=datetime.now(UTC)
            ).isoformat()
        }