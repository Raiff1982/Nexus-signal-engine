"""
Language analysis module for NexisSignalEngine.
Provides language detection and script analysis capabilities.
"""

import re
import unicodedata
from collections import Counter
from typing import Dict, List, Tuple

class LanguageAnalyzer:
    def __init__(self):
        # Common script ranges for major writing systems
        self.script_ranges = {
            'Latin': (0x0020, 0x024F),
            'Cyrillic': (0x0400, 0x04FF),
            'Arabic': (0x0600, 0x06FF),
            'Devanagari': (0x0900, 0x097F),
            'Chinese': (0x4E00, 0x9FFF),
            'Japanese_Hiragana': (0x3040, 0x309F),
            'Japanese_Katakana': (0x30A0, 0x30FF),
            'Korean': (0xAC00, 0xD7AF),
            'Thai': (0x0E00, 0x0E7F)
        }
        
        # Common patterns that might indicate language mixing or script abuse
        self.suspicious_patterns = [
            r'[a-zA-Z]\d+[а-яА-Я]',  # Latin-number-Cyrillic mix
            r'[а-яА-Я]\d+[a-zA-Z]',  # Cyrillic-number-Latin mix
            r'[\u0600-\u06FF]\d+[a-zA-Z]',  # Arabic-number-Latin mix
        ]

    def analyze(self, text: str) -> Dict:
        """
        Analyze text for language and script characteristics.
        
        Returns:
            Dict containing:
            - script_distribution: percentage of characters in each script
            - primary_script: the dominant writing system
            - script_mixing: level of script mixing (0-1)
            - suspicious_patterns: count of suspicious script combinations
        """
        if not text:
            return {
                'script_distribution': {},
                'primary_script': None,
                'script_mixing': 0,
                'suspicious_patterns': 0
            }

        # Count characters by script
        script_counts = Counter()
        total_chars = 0
        
        for char in text:
            if char.isspace():
                continue
                
            script = unicodedata.name(char).split()[0]
            script_counts[script] += 1
            total_chars += 1

        # Calculate script distribution
        script_distribution = {
            script: count/total_chars 
            for script, count in script_counts.items()
        }
        
        # Identify primary script
        primary_script = max(script_counts.items(), key=lambda x: x[1])[0] if script_counts else None
        
        # Calculate script mixing level (0 = single script, 1 = completely mixed)
        num_scripts = len([s for s, p in script_distribution.items() if p > 0.1])
        script_mixing = (num_scripts - 1) / (len(self.script_ranges) - 1) if num_scripts > 1 else 0
        
        # Check for suspicious patterns
        suspicious_count = sum(
            1 for pattern in self.suspicious_patterns
            if re.search(pattern, text)
        )
        
        return {
            'script_distribution': script_distribution,
            'primary_script': primary_script,
            'script_mixing': script_mixing,
            'suspicious_patterns': suspicious_count
        }

    def get_risk_factors(self, analysis: Dict) -> List[str]:
        """
        Convert language analysis into risk factors.
        """
        risk_factors = []
        
        # Check for excessive script mixing
        if analysis['script_mixing'] > 0.5:
            risk_factors.append('High script mixing')
            
        # Check for suspicious patterns
        if analysis['suspicious_patterns'] > 0:
            risk_factors.append('Suspicious script combinations')
            
        # Check for unusual script distributions
        primary_script_pct = max(analysis['script_distribution'].values()) if analysis['script_distribution'] else 0
        if primary_script_pct < 0.6:  # No dominant script
            risk_factors.append('No dominant script')
            
        return risk_factors

    def get_risk_score(self, analysis: Dict) -> float:
        """
        Calculate a risk score based on language analysis.
        Returns a value between 0 (safe) and 1 (high risk).
        """
        score = 0.0
        
        # Weight factors
        score += analysis['script_mixing'] * 0.4
        score += min(analysis['suspicious_patterns'] * 0.2, 0.4)
        
        # Script distribution factor
        primary_script_pct = max(analysis['script_distribution'].values()) if analysis['script_distribution'] else 0
        if primary_script_pct < 0.6:
            score += (0.6 - primary_script_pct) * 0.2
            
        return min(score, 1.0)  # Cap at 1.0