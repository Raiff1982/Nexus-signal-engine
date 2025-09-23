"""
Core NexisSignalEngine implementation with multi-agent analysis and language awareness.
"""

import time
import logging
import numpy as np
from datetime import datetime, UTC
from collections import Counter
from typing import Dict, List, Tuple
from nltk.tokenize import word_tokenize 
from nltk.stem import WordNetLemmatizer
from rapidfuzz import fuzz

from .lang_analyzer import LanguageAnalyzer

logger = logging.getLogger(__name__)

class NexisSignalEngine:
    def __init__(self):
        self.lemmatizer = WordNetLemmatizer()
        self.entropy_threshold = 0.7
        self.fuzzy_threshold = 85
        self.language_analyzer = LanguageAnalyzer()
        
        # Initialize perspectives
        self.perspectives = ["Colleen", "Luke", "Kellyanne"]
        
        # Load configuration
        self.config = {
            "virtue_terms": ["good", "kind", "honest", "true", "peace"],
            "risk_terms": ["hack", "exploit", "attack", "malware", "virus"]
        }

    def process(self, input_signal: str) -> Dict:
        """
        Process an input signal, analyze it with multi-agent and language analysis,
        and return a structured verdict.
        """
        start_time = time.perf_counter()
        signal_lower = input_signal.lower()
        tokens = self._tokenize_and_lemmatize(signal_lower)
        
        # Perform language analysis
        lang_analysis = self.language_analyzer.analyze(input_signal)
        lang_risk_factors = self.language_analyzer.get_risk_factors(lang_analysis)
        lang_risk_score = self.language_analyzer.get_risk_score(lang_analysis)
        
        # Get agent perspectives
        perspectives_output = {
            "Colleen": self._perspective_colleen(input_signal),
            "Luke": self._perspective_luke(signal_lower, tokens),
            "Kellyanne": self._perspective_kellyanne(signal_lower)
        }
        
        # Predict intent and get reasoning
        intent_vector = self._predict_intent_vector(signal_lower, tokens)
        reasoning, risk_factors = self._universal_reasoning(
            signal_lower, 
            tokens, 
            perspectives_output,
            lang_analysis
        )
        
        # Combine risk factors from all sources
        all_risk_factors = risk_factors + lang_risk_factors
        
        # Calculate final risk score with positive content bonus
        agent_risk = reasoning.get("combined_score", 0)
        
        # Apply positive content and ethics bonuses
        if perspectives_output["Luke"]["ethics"] == "aligned":
            agent_risk = max(0, agent_risk - 0.3)  # Larger reduction for positive content
            
        if perspectives_output["Luke"]["state"] == "stabilized":
            agent_risk = max(0, agent_risk - 0.1)  # Bonus for stable state
            
        # More permissive weighting
        combined_risk = (agent_risk * 0.5) + (lang_risk_score * 0.1)
        
        # Strong bonus for benign text patterns
        if lang_analysis.get("benign_matches", 0) > 0:
            combined_risk = max(0, combined_risk - 0.3)
        
        # Consider content length and complexity
        if len(input_signal.split()) <= 5 and lang_risk_score < 0.2:
            combined_risk = max(0, combined_risk - 0.2)  # Bigger reduction for simple messages
            
        # Cap the minimum risk
        combined_risk = max(0, min(combined_risk, 1.0))
            
        # Determine verdict with final risk score
        verdict = self._determine_verdict(combined_risk, all_risk_factors)
        
        # Prepare final record
        final_record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "input": input_signal,
            "language_analysis": lang_analysis,
            "intent_signature": intent_vector,
            "perspectives": perspectives_output,
            "reasoning": reasoning,
            "risk_factors": all_risk_factors,
            "combined_score": combined_risk,
            "verdict": verdict
        }

        logger.info(f"Processed signal in {time.perf_counter() - start_time:.3f}s")
        return final_record

    def _determine_verdict(self, risk_score: float, risk_factors: List[str]) -> str:
        """
        Determine verdict based on risk score and factors, with very lenient thresholds
        for benign messages and strong preference for approval by default.
        """
        # Much more permissive thresholds
        if risk_score >= 0.9 and len(risk_factors) >= 3:  # Require very high risk and multiple strong factors
            return "blocked"
        elif risk_score >= 0.75 and len(risk_factors) >= 2:  # Need high risk and multiple factors
            return "review"
        else:
            return "approved"  # Default to approved - strong bias toward permitting content

    def _universal_reasoning(self, signal: str, tokens: List[str], 
                           perspectives: Dict, lang_analysis: Dict) -> Tuple[Dict, List[str]]:
        """
        Apply multiple reasoning frameworks with language awareness.
        """
        risk_factors = []
        score = 0.0
        
        # Check ethics alignment
        if perspectives["Luke"]["ethics"] == "misaligned":
            risk_factors.append("Ethics violation")
            score += 0.3
            
        # Check entropy and state
        if perspectives["Luke"]["entropy"] > self.entropy_threshold:
            risk_factors.append("High entropy")
            score += 0.2
            
        if perspectives["Luke"]["state"] == "diffused":
            risk_factors.append("Unstable state")
            score += 0.2
            
        # Check harmonic stability
        harmonics = perspectives["Kellyanne"]["harmonics"]
        if len(harmonics) > 1:
            primary_amplitude = harmonics[0]["amplitude"]
            total_amplitude = sum(h["amplitude"] for h in harmonics)
            if primary_amplitude / total_amplitude < 0.6:
                risk_factors.append("Harmonic instability")
                score += 0.2
                
        # Check script stability
        if lang_analysis["script_mixing"] > 0.5:
            risk_factors.append("Excessive script mixing")
            score += 0.2
            
        return {
            "risk_analysis": {
                "ethical_risk": perspectives["Luke"]["ethics"] == "misaligned",
                "entropy_risk": perspectives["Luke"]["entropy"] > self.entropy_threshold,
                "state_risk": perspectives["Luke"]["state"] == "diffused",
                "harmonic_risk": len(harmonics) > 1 and primary_amplitude / total_amplitude < 0.6,
                "script_risk": lang_analysis["script_mixing"] > 0.5
            },
            "combined_score": min(score, 1.0)
        }, risk_factors

    def _perspective_luke(self, signal_lower: str, tokens: List[str]) -> Dict:
        """Luke's perspective: Evaluate ethics, entropy, and stability state."""
        ethics = self._tag_ethics(signal_lower, tokens)
        entropy = self._entropy(signal_lower, tokens)
        state = "stabilized" if entropy < self.entropy_threshold else "diffused"
        
        return {
            "agent": "Luke",
            "ethics": ethics,
            "entropy": entropy,
            "state": state
        }

    def _perspective_kellyanne(self, signal_lower: str) -> Dict:
        """Kellyanne's perspective: Compute harmonic profile of the signal."""
        harmonics = self._compute_harmonics(signal_lower)
        return {
            "agent": "Kellyanne",
            "harmonics": harmonics
        }

    def _perspective_colleen(self, signal: str) -> Dict:
        """Colleen's perspective: Transform signal into a rotated complex vector."""
        vector = self._compute_vector(signal)
        return {
            "agent": "Colleen",
            "vector": vector
        }

    def _tag_ethics(self, signal_lower: str, tokens: List[str]) -> str:
        """Tag signal ethics based on content analysis."""
        virtue_matches = sum(
            1 for term in self.config["virtue_terms"]
            if any(fuzz.ratio(term, token) >= self.fuzzy_threshold for token in tokens)
        )
        risk_matches = sum(
            1 for term in self.config["risk_terms"]
            if any(fuzz.ratio(term, token) >= self.fuzzy_threshold for token in tokens)
        )
        
        if risk_matches > virtue_matches:
            return "misaligned"
        elif virtue_matches > risk_matches:
            return "aligned"
        else:
            return "neutral"

    def _entropy(self, signal_lower: str, tokens: List[str]) -> float:
        """Calculate signal entropy."""
        if not tokens:
            return 0.0
            
        # Use character frequency distribution
        freqs = Counter(signal_lower)
        total = sum(freqs.values())
        
        entropy = -sum(
            (count/total) * np.log2(count/total)
            for count in freqs.values()
        )
        
        return min(entropy / 4.0, 1.0)  # Normalize to 0-1

    def _compute_harmonics(self, signal: str) -> List[Dict]:
        """Compute harmonic frequency components of the signal."""
        # Convert signal to numerical sequence
        values = [ord(c) for c in signal]
        if not values:
            return [{"freq": 0, "amplitude": 0}]
            
        # Compute FFT
        fft = np.fft.fft(values)
        freqs = np.fft.fftfreq(len(values))
        
        # Get main frequency components
        idx = np.argsort(-np.abs(fft))[:3]  # Top 3 frequencies
        
        return [
            {
                "freq": int(abs(freqs[i]) * 1000),
                "amplitude": float(abs(fft[i]))
            }
            for i in idx
        ]

    def _compute_vector(self, signal: str) -> List[Dict]:
        """Transform signal into a complex vector representation."""
        values = [ord(c) for c in signal]
        if not values:
            return [{"real": 0.0, "imag": 0.0}]
            
        # Create complex representation
        angles = np.linspace(0, 2*np.pi, len(values))
        magnitudes = np.array(values)
        
        vectors = magnitudes * np.exp(1j * angles)
        
        return [
            {"real": float(v.real), "imag": float(v.imag)}
            for v in vectors
        ]

    def _predict_intent_vector(self, signal_lower: str, tokens: List[str]) -> Dict:
        """Predict intent based on signal characteristics."""
        return {
            "entropy_index": self._entropy(signal_lower, tokens),
            "ethics": self._tag_ethics(signal_lower, tokens),
            "harmonic_volatility": self._compute_harmonic_volatility(signal_lower),
            "suspicion_score": self._compute_suspicion_score(tokens)
        }

    def _compute_harmonic_volatility(self, signal: str) -> float:
        """Compute volatility of harmonic components."""
        harmonics = self._compute_harmonics(signal)
        if len(harmonics) <= 1:
            return 0.0
            
        amplitudes = [h["amplitude"] for h in harmonics]
        return float(np.std(amplitudes))

    def _compute_suspicion_score(self, tokens: List[str]) -> float:
        """Compute suspicion score based on risk terms."""
        matches = sum(
            1 for term in self.config["risk_terms"]
            if any(fuzz.ratio(term, token) >= self.fuzzy_threshold for token in tokens)
        )
        return matches / len(self.config["risk_terms"])

    def _tokenize_and_lemmatize(self, text: str) -> List[str]:
        """Tokenize and lemmatize text."""
        tokens = word_tokenize(text)
        return [self.lemmatizer.lemmatize(token) for token in tokens]