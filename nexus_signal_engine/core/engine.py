"""Core Nexis Signal Engine implementation."""

import json
import os
import re
import secrets
import hashlib
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta, UTC
import filelock
import pathlib
import shutil
import sqlite3
from rapidfuzz import fuzz
import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from tenacity import retry, stop_after_attempt, wait_exponential
import logging
import time
from typing import Any, Dict, Optional, Union
import threading
# Avoid importing `time` function into the module namespace which
# shadows the `time` module and causes `time.perf_counter` to fail.
# Use `time.time()` where a timestamp is required.

from ..hoax import HoaxFilter

# Configure logging
logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Raised when a security constraint is violated."""
    pass

class SecurityLogger:
    """Enhanced security logger with detailed event tracking."""
    
    def __init__(self, logger_name: str):
        self.logger = logging.getLogger(logger_name)
        self._setup_logger()
        
    def _setup_logger(self):
        """Configure the security logger with proper formatting and handlers."""
        # Create formatters
        # Keep a concise, safe formatter so ordinary log records that do
        # not include security context fields don't fail formatting.
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler for all security events
        file_handler = logging.FileHandler('security_events.log')
        file_handler.setFormatter(detailed_formatter)
        file_handler.setLevel(logging.INFO)
        
        # Special handler for high-severity events
        alert_handler = logging.FileHandler('security_alerts.log')
        alert_handler.setFormatter(detailed_formatter)
        alert_handler.setLevel(logging.WARNING)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(alert_handler)
        self.logger.setLevel(logging.INFO)
    
    def log_security_event(self, message: str, level: str = "info", **kwargs):
        """
        Log a security event with detailed context.
        
        Args:
            message: The log message
            level: Logging level ("info", "warning", "error", "critical")
            **kwargs: Additional context parameters
        """
        # Default context values
        context = {
            "security_event": kwargs.get("security_event", "general"),
            "ip": kwargs.get("ip", "unknown"),
            "user": kwargs.get("user", "system"),
            "session": kwargs.get("session", "unknown")
        }
        
        # Add any additional context
        context.update(kwargs)
        
        # Log with appropriate level
        log_method = getattr(self.logger, level.lower())
        log_method(message, extra=context)

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
        
        # Rate limiting setup
        self._rate_limit_lock = threading.Lock()
        self._tokens = 100  # Initial token count
        self._token_rate = 10  # Tokens per second
        self._last_update = time.time()
        self._max_tokens = 100
        
        # Initialize configuration for lenient content handling
        self.config = {
            "risk_terms": ["exploit", "hack", "malware", "virus"],
            "benign_greetings": ["hi", "hello", "hey", "greetings"],
            "ethical_terms": ["hope", "truth", "empathy", "good"],
            "entropy_threshold": 0.7,
            "fuzzy_threshold": 85,
            # Security limits
            "max_input_length": 10000,  # Maximum input text length
            "max_batch_size": 1000,     # Maximum items in batch operations
            "max_query_length": 500,    # Maximum query length
            # Backup configuration
            "backup_count": 5,          # Number of backup files to keep
            "backup_interval": 86400,   # Backup interval in seconds (24 hours)
            "backup_dir": "backups"     # Directory to store backups
        }

        # Configure logging
        self._setup_logging()
        
        self.init_sqlite()

    def _setup_logging(self):
        """Set up detailed security logging."""
        self.security_logger = SecurityLogger(__name__)

    def _check_rate_limit(self, tokens_needed: int = 1) -> bool:
        """
        Check if the operation is within rate limits using token bucket algorithm.
        
        Args:
            tokens_needed: Number of tokens needed for the operation
            
        Returns:
            bool: True if operation is allowed, False if rate limit exceeded
            
        Thread-safe implementation of the token bucket algorithm.
        """
        with self._rate_limit_lock:
            now = time.time()
            time_passed = now - self._last_update
            self._tokens = min(
                self._max_tokens,
                self._tokens + time_passed * self._token_rate
            )
            self._last_update = now
            
            if self._tokens >= tokens_needed:
                self._tokens -= tokens_needed
                return True
            
            logger.warning(
                f"Rate limit exceeded. Tokens needed: {tokens_needed}, Available: {self._tokens:.2f}",
                extra={"security_event": "rate_limit_exceeded"}
            )
            return False

    def _validate_input(self, text: str, input_type: str = "message") -> None:
        """
        Validate input against security constraints.
        
        Args:
            text: The input text to validate
            input_type: Type of input ("message", "query", or "batch")
            
        Raises:
            SecurityError: If input violates security constraints
        """
        if not text:
            return

        length = len(text)
        max_length = {
            "message": self.config["max_input_length"],
            "query": self.config["max_query_length"],
            "batch": self.config["max_batch_size"]
        }.get(input_type)

        if max_length and length > max_length:
            error_msg = f"Input exceeds maximum {input_type} length: {length} > {max_length}"
            logger.warning(error_msg, extra={"security_event": "input_length_exceeded"})
            raise SecurityError(error_msg)

    def _rotate_backups(self) -> None:
        """
        Rotate database backups, keeping only the configured number of most recent backups.
        """
        backup_dir = pathlib.Path(self.config["backup_dir"])
        backup_dir.mkdir(exist_ok=True)
        
        # List all backup files
        backup_files = sorted(
            backup_dir.glob("memory_backup_*.db"),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        # Remove old backups
        max_backups = self.config["backup_count"]
        for old_backup in backup_files[max_backups:]:
            try:
                old_backup.unlink()
                logger.info(
                    f"Removed old backup: {old_backup}",
                    extra={"security_event": "backup_rotated"}
                )
            except Exception as e:
                logger.error(
                    f"Failed to remove old backup {old_backup}: {e}",
                    extra={"security_event": "backup_rotation_failed"}
                )

    def _backup_database(self) -> None:
        """
        Create a new backup of the database if the backup interval has elapsed.
        """
        backup_dir = pathlib.Path(self.config["backup_dir"])
        backup_dir.mkdir(exist_ok=True)
        
        # Create new backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"memory_backup_{timestamp}.db"
        
        try:
            # Create backup using SQLite's backup API
            with sqlite3.connect(self.memory_path) as src, \
                 sqlite3.connect(str(backup_path)) as dst:
                src.backup(dst)
            
            logger.info(
                f"Created database backup: {backup_path}",
                extra={"security_event": "backup_created"}
            )
            
            # Rotate old backups
            self._rotate_backups()
            
        except Exception as e:
            logger.error(
                f"Failed to create database backup: {e}",
                extra={"security_event": "backup_failed"}
            )
            if backup_path.exists():
                backup_path.unlink()

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
                
                # Create tracking table for backups
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS backup_meta (
                        last_backup TIMESTAMP,
                        backup_count INTEGER
                    )
                """)
                conn.commit()
                
                # Initialize backup tracking if needed
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM backup_meta")
                if cursor.fetchone()[0] == 0:
                    cursor.execute(
                        "INSERT INTO backup_meta VALUES (?, ?)",
                        (datetime.now(), 0)
                    )
                    conn.commit()
                
            # Create initial backup
            self._backup_database()
            
        except sqlite3.Error as e:
            logger.error(
                f"Error initializing SQLite database: {e}",
                extra={"security_event": "database_init_failed"}
            )
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
            
        cutoff = datetime.now(UTC) - timedelta(days=30)
        self.memory = {
            k: v for k, v in self.memory.items()
            if datetime.fromisoformat(v['timestamp']) > cutoff
        }

    def _rotate_memory_file(self):
        """Archive current memory database and start a new one."""
        lock = filelock.FileLock(f"{self.memory_path}.lock")
        with lock:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
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
        
        # Base suspicion score with reduced weights
        suspicion_score = (entropy_index * 0.3 +  # Reduced from 0.4
                          (1 if ethics != "aligned" else 0) * 0.2 +  # Reduced from 0.3
                          min(volatility / 150, 1.0) * 0.2)  # Reduced volatility impact
                          
        # Strong bonus for benign patterns and short messages
        msg_tokens = signal_lower.split()
        if len(msg_tokens) <= 3 and not any(t in self.config["risk_terms"] for t in msg_tokens):
            suspicion_score = max(0.0, suspicion_score - 0.4)  # Much larger reduction
            
        if any(greeting in signal_lower for greeting in self.config.get("benign_greetings", [])):
            suspicion_score = max(0.0, suspicion_score - 0.3)  # Additional greeting bonus
        
        return {
            "entropy_index": float(entropy_index),
            "ethics": ethics, 
            "harmonic_volatility": float(volatility),
            "suspicion_score": float(suspicion_score)
        }

    def evaluate_message_safety(self, message):
        """Evaluate if a message is safe based on simple rules."""
        if not message:
            return False, {"reason": "Empty message"}
            
        # Strip and lowercase for comparison
        clean_msg = message.lower().strip()
        
        # Check for benign greetings - fast path
        if clean_msg in self.config["benign_greetings"]:
            return True, {"reason": "Benign greeting", "risk_score": 0, "risk_factors": []}
            
        # Calculate base risk score
        risk_score = 0
        risk_factors = []
        
        # Risk for message length
        if len(clean_msg) > 50:  # Longer messages get initial risk
            risk_score += 10
            risk_factors.append("Message length exceeds safe threshold")
        
        # Add significant risk for known risk terms
        detected_risk_terms = []
        for term in self.config["risk_terms"]:
            if term.lower() in clean_msg:
                risk_score += 40
                detected_risk_terms.append(term)
        if detected_risk_terms:
            risk_factors.append(f"Contains risk terms: {', '.join(detected_risk_terms)}")
        
        # Add significant risk for unusual character patterns
        if re.search(r'[^a-zA-Z0-9\s.,!?]', clean_msg):  # Non-standard characters
            risk_score += 35  # High risk for special characters
            risk_factors.append("Contains potentially malicious special characters")
        
        # Add risk for excessive punctuation
        if re.search(r'[!?.,]{3,}', clean_msg):  # Three or more punctuation marks in a row
            risk_score += 20
            risk_factors.append("Excessive punctuation detected")
        
        # Add risk for entropy
        entropy = self.calculate_entropy(clean_msg)
        if entropy > self.config["entropy_threshold"]:
            risk_score += 35
            risk_factors.append(f"High entropy content ({entropy:.2f})")
        
        # Reduce risk for ethical terms - but with less impact when special characters are present
        ethical_terms = []
        for term in self.config["ethical_terms"]:
            if term.lower() in clean_msg:
                ethical_terms.append(term)
        if ethical_terms:
            # Reduce the ethical bonus if message has special characters
            if re.search(r'[^a-zA-Z0-9\s.,!?]', clean_msg):
                reduction = min(len(ethical_terms) * 5, 15)  # Less reduction for suspicious messages
            else:
                reduction = min(len(ethical_terms) * 10, 30)  # Normal reduction for clean messages
            risk_score -= reduction
            risk_factors.append(f"Ethical context reduces risk: {', '.join(ethical_terms)}")
        
        is_safe = risk_score < 30  # Messages with risk score >= 30 are blocked
        
        details = {
            "reason": "Message approved" if is_safe else "Message blocked due to risk factors",
            "risk_score": risk_score,
            "risk_factors": risk_factors if risk_factors else ["No specific risk factors"],
            "threshold": 30
        }
        return is_safe, details
        details = {
            "reason": "Message approved" if is_safe else "Risk factors detected",
            "risk_score": risk_score,
            "risk_factors": risk_factors if risk_factors else ["No specific risk factors"],
            "threshold": 30
        }
        return is_safe, details

    def calculate_entropy(self, text):
        """Calculate the Shannon entropy of the text."""
        if not text:
            return 0
            
        # Count character frequencies
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
            
        # Calculate entropy
        length = len(text)
        entropy = 0
        for freq in frequencies.values():
            probability = freq / length
            entropy -= probability * np.log2(probability)
            
        return entropy / 8  # Normalize to 0-1 range

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
                    "timestamp": datetime.now(UTC).isoformat(),
                    "input": input_signal,
                    "intent_signature": intent_vector,
                    "verdict": "blocked",
                    "fast_path": True
                }
                self.memory[key] = final_record
                self._save_memory()
                logger.info(f"Processed {input_signal} (high risk) in {time.perf_counter() - start_time}s")
                return final_record

        # Default perspectives for both paths
        perspectives_output = {
            "Colleen": {"agent": "Colleen", "vector": []},
            "Luke": {"agent": "Luke", "ethics": "aligned", "entropy": 0.1, "state": "stabilized"},
            "Kellyanne": {"agent": "Kellyanne", "harmonics": []}
        }
        entangled_serialized = []
        
        # Check for safe messages first
        is_safe, safety_details = self.evaluate_message_safety(input_signal)
        if is_safe:
            verdict = "approved"
            reasoning = {
                "perspectives": perspectives_output,
                "risk_factors": safety_details.get("risk_factors", []),
                "combined_score": 0.9,
                "explanation": safety_details.get("reason", "Safe message"),
                "risk_score": safety_details.get("risk_score", 0)
            }
        else:
            # Update perspectives with full analysis for potentially risky messages
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
            "timestamp": datetime.now(UTC).isoformat(),
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