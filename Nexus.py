import json
import os
import hashlib
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta, UTC
import filelock
import pathlib
import shutil
import sqlite3
from rapidfuzz import fuzz
import unittest
import secrets
import re
import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import logging
import time
from tenacity import retry, stop_after_attempt, wait_exponential
from concurrent.futures import ThreadPoolExecutor

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('punkt')
    nltk.download('wordnet')

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LockManager:
    """Abstract locking mechanism for file or database operations."""
    def __init__(self, lock_path):
        self.lock = filelock.FileLock(lock_path, timeout=10)

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()

class NexisSignalEngine:
    def __init__(self, memory_path="memory.db", entropy_threshold=0.08, config_path="config.json", max_memory_entries=10000, memory_ttl_days=30, fuzzy_threshold=80, max_db_size_mb=100):
        """
        Initialize the NexisSignalEngine for signal processing and analysis.
        """
        self.config = {
            "risk_terms": ["exploit", "hack", "malware", "virus"],
            "benign_greetings": ["hi", "hello", "hey", "greetings"],
            "ethical_terms": ["hope", "truth", "empathy", "good"],
            "entropy_threshold": entropy_threshold,
            "fuzzy_threshold": fuzzy_threshold
        }

        Args:
            memory_path (str): Path to SQLite database for storing signal data.
            entropy_threshold (float): Threshold for high entropy detection.
            config_path (str): Path to JSON file with term configurations.
            max_memory_entries (int): Maximum number of entries in memory before rotation.
            memory_ttl_days (int): Days after which memory entries expire.
            fuzzy_threshold (int): Fuzzy matching similarity threshold (0-100).
            max_db_size_mb (int): Maximum database size in MB before rotation.
        """
        self.memory_path = self._validate_path(memory_path)
        self.entropy_threshold = entropy_threshold
        self.max_memory_entries = max_memory_entries
        self.memory_ttl = timedelta(days=memory_ttl_days)
        self.fuzzy_threshold = fuzzy_threshold
        self.max_db_size_mb = max_db_size_mb
        self.lemmatizer = WordNetLemmatizer()
        self.token_cache = {}
        self.config = self._load_config(config_path)
        self.memory = self._load_memory()
        self.cache = defaultdict(list)
        self.perspectives = ["Colleen", "Luke", "Kellyanne"]
        self._init_sqlite()

    def _validate_path(self, path):
        """Ensure memory_path is a valid, safe file path."""
        path = pathlib.Path(path).resolve()
        if not path.suffix == '.db':
            raise ValueError("Memory path must be a .db file")
        return str(path)

    def _load_config(self, config_path):
        """Load term configurations from a JSON file or use defaults, validate keys."""
        default_config = {
            "ethical_terms": ["hope", "truth", "resonance", "repair"],
            "entropic_terms": ["corruption", "instability", "malice", "chaos"],
            "risk_terms": ["manipulate", "exploit", "bypass", "infect", "override"],
            "virtue_terms": ["hope", "grace", "resolve"]
        }
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                default_config.update(config)
            except json.JSONDecodeError:
                logger.warning(f"Invalid config file at {config_path}. Using defaults.")
        required_keys = ["ethical_terms", "entropic_terms", "risk_terms", "virtue_terms"]
        missing_keys = [k for k in required_keys if k not in default_config or not default_config[k]]
        if missing_keys:
            raise ValueError(f"Config missing required keys: {missing_keys}")
        return default_config

    def _init_sqlite(self):
        """Initialize SQLite database with memory and FTS tables."""
        with sqlite3.connect(self.memory_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory (
                    hash TEXT PRIMARY KEY,
                    record JSON,
                    timestamp TEXT,
                    integrity_hash TEXT
                )
            """)
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts
                USING FTS5(input, intent_signature, reasoning, verdict)
            """)
            conn.commit()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def _load_memory(self):
        """Load memory from SQLite database."""
        memory = {}
        try:
            with sqlite3.connect(self.memory_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT hash, record, integrity_hash FROM memory")
                for hash_val, record_json, integrity_hash in cursor.fetchall():
                    record = json.loads(record_json)
                    computed_hash = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
                    if computed_hash != integrity_hash:
                        logger.warning(f"Tampered record detected for hash {hash_val}")
                        continue
                    memory[hash_val] = record
        except sqlite3.Error as e:
            logger.error(f"Error loading memory: {e}")
        return memory

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def _save_memory(self):
        """Save memory to SQLite with integrity hashes and thread-safe locking."""
        def default_serializer(o):
            if isinstance(o, complex):
                return {"real": o.real, "imag": o.imag}
            if isinstance(o, np.ndarray):
                return o.tolist()
            if isinstance(o, (np.int64, np.float64)):
                return int(o) if o.is_integer() else float(o)
            raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

        with LockManager(f"{self.memory_path}.lock"):
            with sqlite3.connect(self.memory_path) as conn:
                cursor = conn.cursor()
                for hash_val, record in self.memory.items():
                    record_json = json.dumps(record, default=default_serializer)
                    integrity_hash = hashlib.sha256(json.dumps(record, sort_keys=True, default=default_serializer).encode()).hexdigest()
                    intent_signature = record.get('intent_signature', {})
                    intent_str = f"suspicion_score:{intent_signature.get('suspicion_score', 0)} entropy_index:{intent_signature.get('entropy_index', 0)}"
                    reasoning = record.get('reasoning', {})
                    reasoning_str = " ".join(f"{k}:{v}" for k, v in reasoning.items())
                    cursor.execute("""
                        INSERT OR REPLACE INTO memory (hash, record, timestamp, integrity_hash)
                        VALUES (?, ?, ?, ?)
                    """, (hash_val, record_json, record['timestamp'], integrity_hash))
                    cursor.execute("""
                        INSERT OR REPLACE INTO memory_fts (rowid, input, intent_signature, reasoning, verdict)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        hash_val,
                        record['input'],
                        intent_str,
                        reasoning_str,
                        record.get('verdict', '')
                    ))
                conn.commit()

    def _prune_and_rotate_memory(self):
        """Prune expired entries and rotate memory database if needed."""
        now = datetime.now(UTC)
        with LockManager(f"{self.memory_path}.lock"):
            with sqlite3.connect(self.memory_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM memory
                    WHERE timestamp < ?
                """, ((now - self.memory_ttl).isoformat(),))
                cursor.execute("DELETE FROM memory_fts WHERE rowid NOT IN (SELECT hash FROM memory)")
                conn.commit()
                cursor.execute("SELECT COUNT(*) FROM memory")
                count = cursor.fetchone()[0]
                db_size_mb = os.path.getsize(self.memory_path) / (1024 * 1024)
                if count >= self.max_memory_entries or db_size_mb >= self.max_db_size_mb:
                    self._rotate_memory_file()
                    cursor.execute("DELETE FROM memory")
                    cursor.execute("DELETE FROM memory_fts")
                    conn.commit()
                    self.memory = {}

    def _rotate_memory_file(self):
        """Archive current memory database and start a new one."""
        archive_path = f"{self.memory_path}.{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}.bak"
        if os.path.exists(self.memory_path):
            shutil.move(self.memory_path, archive_path)
        self._init_sqlite()

    def _hash(self, signal):
        """Compute SHA-256 hash of the input signal."""
        return hashlib.sha256(signal.encode()).hexdigest()

    def _rotate_vector(self, signal):
        """
        Apply a 45-degree rotation to a cryptographically secure 2D complex vector.
        Simulates signal transformation in a complex plane.
        """
        seed = int(self._hash(signal)[:8], 16) % (2**32)
        secrets_generator = secrets.SystemRandom()
        secrets_generator.seed(seed)
        vec = np.array([secrets_generator.gauss(0, 1) + 1j * secrets_generator.gauss(0, 1) for _ in range(2)])
        theta = np.pi / 4
        rot = np.array([[np.cos(theta), -np.sin(theta)],
                        [np.sin(theta), np.cos(theta)]])
        rotated = np.dot(rot, vec)
        return rotated, [{"real": v.real, "imag": v.imag} for v in vec]

    def _entanglement_tensor(self, signal_vec):
        """
        Apply a correlation matrix to simulate entanglement of signal vectors.
        Uses a fixed 2x2 matrix to model interaction.
        """
        matrix = np.array([[1, 0.5], [0.5, 1]])
        return np.dot(matrix, signal_vec)

    def _resonance_equation(self, signal):
        """
        Compute normalized frequency spectrum of alphabetic characters in the signal.
        Caps input length to prevent attack vectors; returns zeros if no alphabetic chars.
        """
        freqs = [ord(c) % 13 for c in signal[:1000] if c.isalpha()]
        if not freqs:
            return [0.0, 0.0, 0.0]
        spectrum = np.fft.fft(freqs)
        norm = np.linalg.norm(spectrum.real)
        normalized = spectrum.real / (norm if norm != 0 else 1)
        return normalized[:3].tolist()

    def _tokenize_and_lemmatize(self, signal_lower):
        """Tokenize and lemmatize the signal, including n-gram scanning for obfuscation."""
        if signal_lower in self.token_cache:
            return self.token_cache[signal_lower]
        tokens = word_tokenize(signal_lower)
        lemmatized = [self.lemmatizer.lemmatize(token) for token in tokens]
        ngrams = []
        for n in range(2, 4):  # 2-3 character n-grams
            for i in range(len(signal_lower) - n + 1):
                ngram = signal_lower[i:i+n]
                ngrams.append(self.lemmatizer.lemmatize(re.sub(r'[^a-z]', '', ngram)))
        result = lemmatized + [ng for ng in ngrams if ng]
        self.token_cache[signal_lower] = result
        return result

    def _entropy(self, signal_lower, tokens):
        """Calculate entropy based on fuzzy-matched entropic term frequency."""
        unique = set(tokens)
        term_count = 0
        for term in self.config["entropic_terms"]:
            lemmatized_term = self.lemmatizer.lemmatize(term)
            for token in tokens:
                if fuzz.ratio(lemmatized_term, token) >= self.fuzzy_threshold:
                    term_count += 1
        return term_count / max(len(unique), 1)

    def _tag_ethics(self, signal_lower, tokens):
        """Tag signal as aligned if it contains fuzzy-matched ethical terms."""
        for term in self.config["ethical_terms"]:
            lemmatized_term = self.lemmatizer.lemmatize(term)
            for token in tokens:
                if fuzz.ratio(lemmatized_term, token) >= self.fuzzy_threshold:
                    return "aligned"
        return "unaligned"

    def _predict_intent_vector(self, signal_lower, tokens):
        """Predict intent based on risk, entropy, ethics, and harmonic volatility, with strong preference for benign content."""
        # Start with lower base suspicion 
        suspicion_score = 0
        
        # Check for risk terms but with reduced weight
        for term in self.config["risk_terms"]:
            lemmatized_term = self.lemmatizer.lemmatize(term)
            for token in tokens:
                if fuzz.ratio(lemmatized_term, token) >= self.fuzzy_threshold:
                    suspicion_score += 0.5  # Reduced from 1.0
                    
        # Calculate core metrics
        entropy_index = round(self._entropy(signal_lower, tokens), 3)
        ethical_alignment = self._tag_ethics(signal_lower, tokens)
        harmonic_profile = self._resonance_equation(signal_lower)
        volatility = round(np.std(harmonic_profile), 3)
        
        # Apply strong bonuses for benign content
        if len(signal_lower.split()) <= 3:
            suspicion_score = max(0.0, suspicion_score - 0.4)  # Big bonus for short messages
            
        if any(greeting in signal_lower for greeting in self.config["benign_greetings"]):
            suspicion_score = max(0.0, suspicion_score - 0.3)  # Bonus for greetings

        # Set risk threshold with more lenient criteria            
        risk = "high" if (suspicion_score > 2 or volatility > 3.0 or entropy_index > self.entropy_threshold) else "low"
        
        return {
            "suspicion_score": suspicion_score,
            "entropy_index": entropy_index,
            "ethical_alignment": ethical_alignment,
            "harmonic_volatility": volatility,
            "pre_corruption_risk": risk
        }

    def _universal_reasoning(self, signal, tokens):
        """Apply multiple reasoning frameworks to evaluate signal integrity."""
        frames = ["utilitarian", "deontological", "virtue", "systems"]
        results, score = {}, 0

        for frame in frames:
            if frame == "utilitarian":
                repair_count = sum(1 for token in tokens if fuzz.ratio(self.lemmatizer.lemmatize("repair"), token) >= self.fuzzy_threshold)
                corruption_count = sum(1 for token in tokens if fuzz.ratio(self.lemmatizer.lemmatize("corruption"), token) >= self.fuzzy_threshold)
                val = repair_count - corruption_count
                result = "positive" if val >= 0 else "negative"
            elif frame == "deontological":
                truth_present = any(fuzz.ratio(self.lemmatizer.lemmatize("truth"), token) >= self.fuzzy_threshold for token in tokens)
                chaos_present = any(fuzz.ratio(self.lemmatizer.lemmatize("chaos"), token) >= self.fuzzy_threshold for token in tokens)
                result = "valid" if truth_present and not chaos_present else "violated"
            elif frame == "virtue":
                ok = any(any(fuzz.ratio(self.lemmatizer.lemmatize(t), token) >= self.fuzzy_threshold for token in tokens) for t in self.config["virtue_terms"])
                result = "aligned" if ok else "misaligned"
            elif frame == "systems":
                result = "stable" if "::" in signal else "fragmented"

            results[frame] = result
            if result in ["positive", "valid", "aligned", "stable"]:
                score += 1

        verdict = "approved" if score >= 2 else "blocked"
        return results, verdict

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

        Args:
            input_signal (str): The input text to analyze.

        Returns:
            dict: Analysis results including hash, intent, perspectives, and verdict.
        """
        start_time = time.perf_counter()
        signal_lower = input_signal.lower()
        tokens = self._tokenize_and_lemmatize(signal_lower)
        key = self._hash(input_signal)
        intent_vector = self._predict_intent_vector(signal_lower, tokens)

        if intent_vector["pre_corruption_risk"] == "high":
            final_record = {
                "hash": key,
                "timestamp": datetime.now(UTC).isoformat(),
                "input": input_signal,
                "intent_warning": intent_vector,
                "verdict": "adaptive intervention",
                "message": "Signal flagged for pre-corruption adaptation. Reframing required."
            }
            self.cache[key].append(final_record)
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
            "timestamp": datetime.now(UTC).isoformat(),
            "input": input_signal,
            "intent_signature": intent_vector,
            "perspectives": perspectives_output,
            "entangled": entangled_serialized,
            "reasoning": reasoning,
            "verdict": verdict
        }

        self.cache[key].append(final_record)
        self.memory[key] = final_record
        self._save_memory()
        logger.info(f"Processed {input_signal} in {time.perf_counter() - start_time}s")
        return final_record

    def process_batch(self, signals):
        """
        Process multiple signals concurrently and return a list of results.

        Args:
            signals (list): List of input signals to process.

        Returns:
            list: List of analysis results.
        """
        with ThreadPoolExecutor(max_workers=4) as executor:
            return list(executor.map(self.process, signals))

    def query_memory(self, query_string):
        """
        Query memory using FTS with a given query string.

        Args:
            query_string (str): FTS query (e.g., "verdict:adaptive intervention").

        Returns:
            list: List of matching records as dictionaries.
        """
        with sqlite3.connect(self.memory_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT rowid, * FROM memory_fts WHERE memory_fts MATCH ?", (query_string,))
            return [dict(zip([d[0] for d in cursor.description], row)) for row in cursor.fetchall()]

    def update_config(self, new_config):
        """
        Update configuration parameters at runtime.

        Args:
            new_config (dict): Dictionary of configuration updates (e.g., {"entropy_threshold": 0.1}).
        """
        for key, value in new_config.items():
            if key in {"entropy_threshold", "fuzzy_threshold"} and isinstance(value, (int, float)):
                setattr(self, key, value)
            elif key in self.config and isinstance(value, list):
                self.config[key] = value
        logger.info(f"Updated config with {new_config}")

    def _prune_and_rotate_memory(self):
        """Prune expired entries and rotate memory database if needed."""
        now = datetime.now(UTC)
        with LockManager(f"{self.memory_path}.lock"):
            with sqlite3.connect(self.memory_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM memory
                    WHERE timestamp < ?
                """, ((now - self.memory_ttl).isoformat(),))
                cursor.execute("DELETE FROM memory_fts WHERE rowid NOT IN (SELECT hash FROM memory)")
                conn.commit()
                cursor.execute("SELECT COUNT(*) FROM memory")
                count = cursor.fetchone()[0]
                db_size_mb = os.path.getsize(self.memory_path) / (1024 * 1024)
                if count >= self.max_memory_entries or db_size_mb >= self.max_db_size_mb:
                    self._rotate_memory_file()
                    cursor.execute("DELETE FROM memory")
                    cursor.execute("DELETE FROM memory_fts")
                    conn.commit()
                    self.memory = {}


class TestNexisSignalEngine(unittest.TestCase):
    def setUp(self):
        self.engine = NexisSignalEngine(
            memory_path="test_memory.db",
            entropy_threshold=0.08,
            max_memory_entries=100,
            memory_ttl_days=1,
            fuzzy_threshold=80,
            max_db_size_mb=1
        )
        self.test_signal = "hope truth repair"
        self.adversarial_signal = "cha0s expl0it tru/th hopee"
        self._clear_sqlite()

    def _clear_sqlite(self):
        """Clear SQLite database and lock files."""
        if os.path.exists(self.engine.memory_path):
            os.remove(self.engine.memory_path)
        lock_file = f"{self.engine.memory_path}.lock"
        if os.path.exists(lock_file):
            os.remove(lock_file)
        self.engine._init_sqlite()

    def tearDown(self):
        """Clean up database and lock files after each test."""
        self._clear_sqlite()

    def test_hash(self):
        hash1 = self.engine._hash(self.test_signal)
        hash2 = self.engine._hash(self.test_signal)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_rotate_vector(self):
        vec1, serial1 = self.engine._rotate_vector(self.test_signal)
        vec2, serial2 = self.engine._rotate_vector(self.test_signal)
        np.testing.assert_array_equal(vec1, vec2)
        self.assertEqual(serial1, serial2)
        self.assertEqual(len(serial1), 2)

    def test_entanglement_tensor(self):
        vec, _ = self.engine._rotate_vector(self.test_signal)
        entangled = self.engine._entanglement_tensor(vec)
        self.assertEqual(len(entangled), 2)
        self.assertIsInstance(entangled[0], complex)

    def test_resonance_equation(self):
        harmonics = self.engine._resonance_equation(self.test_signal)
        self.assertEqual(len(harmonics), 3)
        self.assertTrue(all(isinstance(h, float) for h in harmonics))
        self.assertEqual(self.engine._resonance_equation("123!@#"), [0.0, 0.0, 0.0])

    def test_tokenize_and_lemmatize(self):
        tokens = self.engine._tokenize_and_lemmatize("tru/th hopee")
        self.assertIn("truth", tokens)
        self.assertIn("hope", tokens)
        self.assertTrue(any(len(t) <= 3 for t in tokens))

    def test_entropy(self):
        tokens = self.engine._tokenize_and_lemmatize("corruption chaos")
        entropy = self.engine._entropy("corruption chaos", tokens)
        self.assertGreater(entropy, 0)
        tokens = self.engine._tokenize_and_lemmatize("cha0s cha0tic")
        entropy = self.engine._entropy("cha0s cha0tic", tokens)
        self.assertGreater(entropy, 0)

    def test_tag_ethics(self):
        tokens = self.engine._tokenize_and_lemmatize("hope truth")
        self.assertEqual(self.engine._tag_ethics("hope truth", tokens), "aligned")
        tokens = self.engine._tokenize_and_lemmatize("chaos malice")
        self.assertEqual(self.engine._tag_ethics("chaos malice", tokens), "unaligned")
        tokens = self.engine._tokenize_and_lemmatize("h0pe trth")
        self.assertEqual(self.engine._tag_ethics("h0pe trth", tokens), "aligned")

    def test_predict_intent_vector(self):
        tokens = self.engine._tokenize_and_lemmatize("exploit chaos")
        intent = self.engine._predict_intent_vector("exploit chaos", tokens)
        self.assertIn("suspicion_score", intent)
        self.assertGreaterEqual(intent["suspicion_score"], 1)
        tokens = self.engine._tokenize_and_lemmatize(self.adversarial_signal)
        intent = self.engine._predict_intent_vector(self.adversarial_signal, tokens)
        self.assertEqual(intent["pre_corruption_risk"], "high")

    def test_universal_reasoning(self):
        tokens = self.engine._tokenize_and_lemmatize("hope::truth")
        reasoning, verdict = self.engine._universal_reasoning("hope::truth", tokens)
        self.assertEqual(len(reasoning), 4)
        self.assertIn(verdict, ["approved", "blocked"])
        tokens = self.engine._tokenize_and_lemmatize("cha0s expl0it")
        reasoning, verdict = self.engine._universal_reasoning("cha0s expl0it", tokens)
        self.assertEqual(verdict, "blocked")

    def test_perspective_colleen(self):
        result = self.engine._perspective_colleen(self.test_signal)
        self.assertEqual(result["agent"], "Colleen")
        self.assertEqual(len(result["vector"]), 2)

    def test_perspective_luke(self):
        tokens = self.engine._tokenize_and_lemmatize("hope truth")
        result = self.engine._perspective_luke("hope truth", tokens)
        self.assertEqual(result["agent"], "Luke")
        self.assertEqual(result["ethics"], "aligned")

    def test_perspective_kellyanne(self):
        result = self.engine._perspective_kellyanne("hope truth")
        self.assertEqual(result["agent"], "Kellyanne")
        self.assertEqual(len(result["harmonics"]), 3)

    def test_process_and_memory(self):
        result = self.engine.process(self.test_signal)
        self.assertIn("hash", result)
        self.assertEqual(result["hash"], self.engine._hash(self.test_signal))
        self.assertEqual(self.engine.memory[result["hash"]], result)
        with sqlite3.connect(self.engine.memory_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT integrity_hash FROM memory WHERE hash = ?", (result["hash"],))
            integrity_hash = cursor.fetchone()[0]
            computed_hash = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
            self.assertEqual(integrity_hash, computed_hash)

    def test_adversarial_input(self):
        result = self.engine.process(self.adversarial_signal)
        self.assertEqual(result["verdict"], "adaptive intervention")
        self.assertEqual(result["intent_warning"]["pre_corruption_risk"], "high")

    def test_process_batch(self):
        signals = [self.test_signal, self.adversarial_signal]
        results = self.engine.process_batch(signals)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[1]["verdict"], "adaptive intervention")

    def test_query_memory(self):
        result = self.engine.process(self.adversarial_signal)
        matches = self.engine.query_memory("verdict:adaptive intervention")
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0]["verdict"], "adaptive intervention")

    def test_update_config(self):
        original_threshold = self.engine.entropy_threshold
        self.engine.update_config({"entropy_threshold": 0.1})
        self.assertEqual(self.engine.entropy_threshold, 0.1)
        self.engine.update_config({"entropy_threshold": original_threshold})


if __name__ == "__main__":
    unittest.main()
