"""Core Nexis Signal Engine implementation."""

import json
import os
import hashlib
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
import filelock
import pathlib
import shutil
import sqlite3
from rapidfuzz import fuzz
import secrets
import re
import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from tenacity import retry, stop_after_attempt, wait_exponential
import logging
import time

from ..hoax import HoaxFilter

# Configure logging
logger = logging.getLogger(__name__)

# Download required NLTK data
nltk.download('punkt')
nltk.download('wordnet')

class NexisSignalEngine:
    def __init__(self, memory_path="memory.db"):
        """Initialize the Nexis Signal Engine."""
        self.memory_path = memory_path
        self.memory = {}
        self.cache = defaultdict(list)
        self.lemmatizer = WordNetLemmatizer()
        self.perspectives = ["Colleen", "Luke", "Kellyanne"]
        self.entropy_threshold = 0.7
        self.init_sqlite()

    def init_sqlite(self):
        """Initialize SQLite database with memory and FTS tables."""
        try:
            with sqlite3.connect(self.memory_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS memory (
                        hash TEXT PRIMARY KEY,
                        record JSON,
                        timestamp TEXT,
                        integrity_hash TEXT,
                        salt TEXT
                    )
                """)
                conn.execute("""
                    CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts
                    USING FTS5(input, intent_signature, reasoning, verdict)
                """)
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error initializing SQLite database: {e}")
            raise

    def _save_memory(self):
        """Save memory to SQLite with integrity hashes and thread-safe locking."""
        lock = filelock.FileLock(f"{self.memory_path}.lock")
        with lock:
            try:
                with sqlite3.connect(self.memory_path) as conn:
                    cursor = conn.cursor()
                    for key, record in self.memory.items():
                        salt = secrets.token_hex(16)
                        integrity = hashlib.sha256(
                            f"{json.dumps(record, sort_keys=True)}{salt}".encode()
                        ).hexdigest()
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO memory
                            (hash, record, timestamp, integrity_hash, salt)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            key,
                            json.dumps(record),
                            record['timestamp'],
                            integrity,
                            salt
                        ))
                        
                        row_id = cursor.lastrowid
                        intent_signature = record.get('intent_signature', {})
                        intent_str = f"suspicion_score:{intent_signature.get('suspicion_score', 0)} entropy_index:{intent_signature.get('entropy_index', 0)}"
                        reasoning = record.get('reasoning', {})
                        reasoning_str = " ".join(f"{k}:{v}" for k, v in reasoning.items())
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO memory_fts (rowid, input, intent_signature, reasoning, verdict)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            row_id,
                            record['input'],
                            intent_str,
                            reasoning_str,
                            record.get('verdict', '')
                        ))
                    conn.commit()
            except Exception as e:
                logger.error(f"Error saving memory: {e}")
                raise

    def _prune_and_rotate_memory(self):
        """Prune expired entries and rotate memory database if needed."""
        db_path = pathlib.Path(self.memory_path)
        if db_path.exists() and db_path.stat().st_size > 100 * 1024 * 1024:  # 100MB
            self._rotate_memory_file()
            
        cutoff = datetime.utcnow() - timedelta(days=30)
        self.memory = {
            k: v for k, v in self.memory.items()
            if datetime.fromisoformat(v['timestamp']) > cutoff
        }

    def _rotate_memory_file(self):
        """Archive current memory database and start a new one."""
        lock = filelock.FileLock(f"{self.memory_path}.lock")
        with lock:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            archive_path = f"{self.memory_path}.{timestamp}"
            shutil.copy2(self.memory_path, archive_path)
            with sqlite3.connect(self.memory_path) as conn:
                conn.execute("DELETE FROM memory")
                conn.execute("DELETE FROM memory_fts")
                conn.commit()
                conn.execute("VACUUM")

    def _hash(self, signal):
        """Compute SHA-256 hash of the input signal."""
        return hashlib.sha256(signal.encode()).hexdigest()

    def _rotate_vector(self, signal):
        """Transform signal into a rotated complex vector."""
        vec = np.array([ord(c) for c in signal], dtype=np.complex128)
        angle = np.pi / 4
        rotation = np.exp(1j * angle)
        rotated = vec * rotation
        serialized = [{"real": v.real, "imag": v.imag} for v in rotated]
        return rotated, serialized

    def _entanglement_tensor(self, signal_vec):
        """Compute entanglement tensor from signal vector."""
        n = len(signal_vec)
        phases = np.angle(signal_vec)
        entangled = np.zeros(n, dtype=np.complex128)
        
        for i in range(n):
            neighbors = signal_vec[max(0, i-2):min(n, i+3)]
            phase_coherence = np.exp(1j * np.mean(phases[max(0, i-2):min(n, i+3)]))
            entangled[i] = np.mean(neighbors) * phase_coherence
            
        return entangled

    def _resonance_equation(self, signal):
        """Compute harmonic resonance profile."""
        freqs = np.fft.fft([ord(c) for c in signal])
        dominant = sorted(enumerate(np.abs(freqs)), key=lambda x: x[1], reverse=True)[:3]
        return [{"freq": int(f), "amplitude": float(a)} for f, a in dominant]

    def _tokenize_and_lemmatize(self, signal_lower):
        """Tokenize and lemmatize the signal, including n-gram scanning for obfuscation."""
        tokens = word_tokenize(signal_lower)
        lemmas = [self.lemmatizer.lemmatize(t) for t in tokens]
        
        # Additional n-gram pass for obfuscation detection
        n_grams = []
        for n in range(2, 4):  # bi-grams and tri-grams
            for i in range(len(tokens) - n + 1):
                n_gram = "".join(tokens[i:i+n])
                n_grams.append(n_gram)
                
        return list(set(lemmas + n_grams))

    def _entropy(self, signal_lower, tokens):
        """Calculate entropy based on fuzzy-matched entropic term frequency."""
        entropic_terms = [
            "chaos", "random", "uncertain", "unknown", "error",
            "noise", "corrupt", "damaged", "lost", "missing"
        ]
        
        entropy_score = 0
        for term in entropic_terms:
            for token in tokens:
                if fuzz.ratio(term, token) > 80:  # Fuzzy match threshold
                    entropy_score += 1
                    
        return min(entropy_score / len(entropic_terms), 1.0)

    def _tag_ethics(self, signal_lower, tokens):
        """Tag signal as aligned if it contains fuzzy-matched ethical terms."""
        ethical_terms = [
            "truth", "honest", "ethical", "moral", "right",
            "good", "help", "protect", "safe", "respect"
        ]
        
        for term in ethical_terms:
            for token in tokens:
                if fuzz.ratio(term, token) > 85:  # Stricter threshold for ethics
                    return "aligned"
        return "neutral"

    def _predict_intent_vector(self, signal_lower, tokens):
        """Predict intent based on risk, entropy, ethics, and harmonic volatility."""
        entropy_index = self._entropy(signal_lower, tokens)
        ethics = self._tag_ethics(signal_lower, tokens)
        harmonics = self._resonance_equation(signal_lower)
        
        volatility = np.std([h["amplitude"] for h in harmonics])
        suspicion_score = (entropy_index * 0.4 +
                          (1 if ethics != "aligned" else 0) * 0.3 +
                          min(volatility / 100, 1.0) * 0.3)
        
        return {
            "entropy_index": float(entropy_index),
            "ethics": ethics,
            "harmonic_volatility": float(volatility),
            "suspicion_score": float(suspicion_score)
        }

    def _universal_reasoning(self, signal, tokens):
        """Apply multiple reasoning frameworks to evaluate signal integrity."""
        perspectives = {
            "Colleen": self._perspective_colleen(signal),
            "Luke": self._perspective_luke(signal.lower(), tokens),
            "Kellyanne": self._perspective_kellyanne(signal.lower())
        }
        
        # Combine perspectives with weights
        weights = {"Colleen": 0.35, "Luke": 0.35, "Kellyanne": 0.30}
        total_score = sum(
            weights[p] * (1 if perspectives[p].get("ethics") == "aligned" else 0)
            for p in self.perspectives
        )
        
        risk_factors = []
        if any("diffused" in str(p.get("state")) for p in perspectives.values()):
            risk_factors.append("diffused_state")
        if any(p.get("entropy", 0) > self.entropy_threshold for p in perspectives.values()):
            risk_factors.append("high_entropy")
            
        verdict = "approved" if total_score > 0.6 and not risk_factors else "blocked"
        
        return {
            "perspectives": perspectives,
            "risk_factors": risk_factors,
            "combined_score": total_score
        }, verdict

    def _perspective_colleen(self, signal):
        """Colleen's perspective: Transform signal into a rotated complex vector."""
        vec, vec_serialized = self._rotate_vector(signal)
        return {"agent": "Colleen", "vector": vec_serialized}

    def _perspective_luke(self, signal_lower, tokens):
        """Luke's perspective: Evaluate ethics, entropy, and stability state."""
        ethics = self._tag_ethics(signal_lower, tokens)
        entropy_level = self._entropy(signal_lower, tokens)
        state = "stabilized" if entropy_level < self.entropy_threshold else "diffused"
        return {"agent": "Luke", "ethics": ethics, "entropy": entropy_level, "state": state}

    def _perspective_kellyanne(self, signal_lower):
        """Kellyanne's perspective: Compute harmonic profile of the signal."""
        harmonics = self._resonance_equation(signal_lower)
        return {"agent": "Kellyanne", "harmonics": harmonics}

    def process(self, input_signal):
        """
        Process an input signal, analyze it, and return a structured verdict.
        """
        start_time = time.perf_counter()
        signal_lower = input_signal.lower()
        tokens = self._tokenize_and_lemmatize(signal_lower)
        key = self._hash(input_signal)
        
        # Fast path for known high-risk signals
        if key in self.cache and len(self.cache[key]) >= 3:
            prior_verdicts = [r["verdict"] for r in self.cache[key][-3:]]
            if all(v == "blocked" for v in prior_verdicts):
                intent_vector = self._predict_intent_vector(signal_lower, tokens)
                final_record = {
                    "hash": key,
                    "timestamp": datetime.utcnow().isoformat(),
                    "input": input_signal,
                    "intent_signature": intent_vector,
                    "verdict": "blocked",
                    "fast_path": True
                }
                self.memory[key] = final_record
                self._save_memory()
                logger.info(f"Processed {input_signal} (high risk) in {time.perf_counter() - start_time}s")
                return final_record

        perspectives_output = {
            "Colleen": self._perspective_colleen(input_signal),
            "Luke": self._perspective_luke(signal_lower, tokens),
            "Kellyanne": self._perspective_kellyanne(signal_lower)
        }
        
        spider_signal = "::".join([str(perspectives_output[p]) for p in self.perspectives])
        vec, _ = self._rotate_vector(spider_signal)
        entangled = self._entanglement_tensor(vec)
        entangled_serialized = [{"real": v.real, "imag": v.imag} for v in entangled]
        reasoning, verdict = self._universal_reasoning(spider_signal, tokens)
        
        final_record = {
            "hash": key,
            "timestamp": datetime.utcnow().isoformat(),
            "input": input_signal,
            "intent_signature": self._predict_intent_vector(signal_lower, tokens),
            "perspectives": perspectives_output,
            "entangled": entangled_serialized,
            "reasoning": reasoning,
            "verdict": verdict
        }
        
        self.cache[key].append(final_record)
        self.memory[key] = final_record
        self._save_memory()
        self._prune_and_rotate_memory()
        logger.info(f"Processed {input_signal} in {time.perf_counter() - start_time:.3f}s")
        return final_record

    def process_batch(self, signals):
        """Process multiple signals concurrently."""
        return [self.process(s) for s in signals]

    def query_memory(self, query_string):
        """Query memory using FTS with a sanitized query string."""
        safe_query = re.sub(r'[^\w\s]', '', query_string)
        with sqlite3.connect(self.memory_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT m.* FROM memory m
                JOIN memory_fts f ON m.rowid = f.rowid
                WHERE memory_fts MATCH ?
            """, (safe_query,))
            return [json.loads(row[1]) for row in cursor.fetchall()]

    def process_news(self, input_signal: str, source_url: str | None = None) -> dict:
        """
        Augmented pipeline for news/claims. Applies HoaxFilter and escalates verdict.
        """
        # Standard signal processing
        result = self.process(input_signal)
        
        # Additional hoax detection layer
        hoax_filter = HoaxFilter()
        hoax_score = hoax_filter.score(
            input_signal,
            url=source_url,
            context_keywords=["planet", "space", "ufo", "alien", "spacecraft"]
        )
        
        # Combine verdicts
        combined_risk = (
            result["intent_signature"]["suspicion_score"] * 0.6 +
            hoax_score.combined * 0.4
        )
        
        if combined_risk >= 0.70:
            final_verdict = "blocked"
        elif 0.45 <= combined_risk < 0.70:
            final_verdict = "review"  # Adaptive intervention
        else:
            final_verdict = result["verdict"]  # Keep base verdict
            
        return {
            **result,
            "hoax_analysis": {
                "score": hoax_score.combined,
                "red_flags": hoax_score.red_flag_hits,
                "source_risk": hoax_score.source_score,
                "scale_risk": hoax_score.scale_score,
                "notes": hoax_score.notes
            },
            "combined_risk": combined_risk,
            "final_verdict": final_verdict
        }