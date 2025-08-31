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
from functools import lru_cache
import glob

# Constants
DEFAULT_ENTROPY_THRESHOLD = 0.08
DEFAULT_MAX_MEMORY_ENTRIES = 10000
DEFAULT_MEMORY_TTL_DAYS = 30
DEFAULT_FUZZY_THRESHOLD = 80
DEFAULT_MAX_DB_SIZE_MB = 100
DEFAULT_LOCK_TIMEOUT = 10
DEFAULT_MAX_WORKERS = 4
DEFAULT_MAX_TOKEN_CACHE = 1000
DEFAULT_MAX_BACKUPS = 5

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/wordnet')
except LookupError:
    logger.info("Downloading NLTK resources...")
    nltk.download('punkt', quiet=True)
    nltk.download('wordnet', quiet=True)

class Metrics:
    def __init__(self):
        self.process_times = []
        self.error_count = 0

    def record_process_time(self, duration):
        self.process_times.append(duration)
        if len(self.process_times) > 1000:
            self.process_times.pop(0)

    def record_error(self):
        self.error_count += 1

    def get_stats(self):
        return {
            "avg_process_time": sum(self.process_times) / max(len(self.process_times), 1),
            "error_count": self.error_count
        }
class LockManager:
    """Thread-safe file locking for database operations."""
    def __init__(self, lock_path, timeout=DEFAULT_LOCK_TIMEOUT):
        self.lock = filelock.FileLock(lock_path, timeout=timeout)

    def __enter__(self):
        start = time.perf_counter()
        self.lock.acquire()
        logger.debug(f"Lock acquired in {time.perf_counter() - start:.3f}s")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()
        logger.debug("Lock released")
class NexisSignalEngine:
    def __init__(self, memory_path, config_path="config.json", entropy_threshold=DEFAULT_ENTROPY_THRESHOLD,
                 max_memory_entries=DEFAULT_MAX_MEMORY_ENTRIES, memory_ttl_days=DEFAULT_MEMORY_TTL_DAYS,
                 fuzzy_threshold=DEFAULT_FUZZY_THRESHOLD, max_db_size_mb=DEFAULT_MAX_DB_SIZE_MB,
                 lock_timeout=DEFAULT_LOCK_TIMEOUT, max_workers=DEFAULT_MAX_WORKERS,
                 max_token_cache=DEFAULT_MAX_TOKEN_CACHE, max_backups=DEFAULT_MAX_BACKUPS):
        """Initialize the NexisSignalEngine for signal processing and analysis."""
        self.memory_path = self._validate_path(memory_path)
        self.entropy_threshold = entropy_threshold
        self.max_memory_entries = max_memory_entries
        self.memory_ttl = timedelta(days=memory_ttl_days)
        self.fuzzy_threshold = fuzzy_threshold
        self.max_db_size_mb = max_db_size_mb
        self.lock_timeout = lock_timeout
        self.max_workers = max_workers
        self.max_backups = max_backups
        self.metrics = Metrics()
        self.lemmatizer = WordNetLemmatizer()
        self.config = self._load_config(config_path)
        self.perspectives = self.config.get("perspectives", ["Colleen", "Luke", "Kellyanne"])
        self.reasoning_frames = self.config.get("reasoning_frames", ["utilitarian", "deontological", "virtue", "systems"])
        self.ngram_sizes = self.config.get("ngram_sizes", range(2, 4))
        self.perspective_registry = {
            "Colleen": self._perspective_colleen,
            "Luke": self._perspective_luke,
            "Kellyanne": self._perspective_kellyanne
        }
        self.reasoning_registry = {
            "utilitarian": self._utilitarian_reasoning,
            "deontological": self._deontological_reasoning,
            "virtue": self._virtue_reasoning,
            "systems": self._systems_reasoning
        }
        self.memory = self._load_memory()
        self.cache = defaultdict(list)
        self.init_sqlite()


def _validate_path(self, path):
    """Ensure memory_path is a valid, safe file path."""
    path = pathlib.Path(path).resolve()
    if path.suffix != '.db':
        raise ValueError("Memory path must be a .db file")
    return str(path)

def _load_config(self, config_path):
    """Load and validate term configurations, precompute lemmatized terms."""
    default_config = {
        "ethical_terms": ["hope", "truth", "resonance", "repair"],
        "entropic_terms": ["corruption", "instability", "malice", "chaos"],
        "risk_terms": ["manipulate", "exploit", "bypass", "infect", "override"],
        "virtue_terms": ["hope", "grace", "resolve"],
        "perspectives": ["Colleen", "Luke", "Kellyanne"],
        "reasoning_frames": ["utilitarian", "deontological", "virtue", "systems"],
        "ngram_sizes": range(2, 4)
    }
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                default_config.update(config)
        except json.JSONDecodeError:
            logger.warning(f"Invalid config file at {config_path}. Using defaults.")
    for key in ["ethical_terms", "entropic_terms", "risk_terms", "virtue_terms"]:
        if not isinstance(default_config[key], list) or not default_config[key] or not all(isinstance(t, str) and t.strip() for t in default_config[key]):
            raise ValueError(f"Config key {key} must be a non-empty list of non-empty strings")
        for term in default_config[key]:
            if not re.match(r"^[a-zA-Z]+$", term):
                logger.warning(f"Suspicious term in config: {term}. Should contain only letters.")
    default_config["lemmatized_terms"] = {
        key: [self.lemmatizer.lemmatize(term) for term in default_config[key]]
        for key in ["ethical_terms", "entropic_terms", "risk_terms", "virtue_terms"]
    }
    return default_config

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
        self.metrics.record_error()
        raise

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def _load_memory(self):
    """Load memory from SQLite database with integrity checks."""
    memory = {}
    try:
        with sqlite3.connect(self.memory_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT hash, record, integrity_hash, salt FROM memory")
            for hash_val, record_json, integrity_hash, salt in cursor.fetchall():
                try:
                    record = json.loads(record_json)
                    computed_hash = hashlib.sha256(json.dumps(record, sort_keys=True).encode() + salt.encode()).hexdigest()
                    if computed_hash != integrity_hash:
                        logger.warning(f"Tampered record detected for hash {hash_val}")
                        continue
                    memory[hash_val] = record
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding JSON for hash {hash_val}: {e}")
                    self.metrics.record_error()
                except Exception as e:
                    logger.error(f"Unexpected error loading record {hash_val}: {e}")
                    self.metrics.record_error()
    except sqlite3.Error as e:
        logger.error(f"Error loading memory: {e}")
        self.metrics.record_error()
    return memory

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def _save_memory(self):
    """Save memory to SQLite with integrity hashes and thread-safe locking."""
    def _default_serializer(o):
        if isinstance(o, complex):
            return {"real": o.real, "imag": o.imag}
        if isinstance(o, np.ndarray):
            return o.tolist()
        if isinstance(o, (np.int64, np.float64)):
            return int(o) if o.is_integer() else float(o)
        return str(o)
    
    with LockManager(f"{self.memory_path}.lock", self.lock_timeout):
        try:
            with sqlite3.connect(self.memory_path) as conn:
                conn.execute("BEGIN TRANSACTION")
                cursor = conn.cursor()
                for hash_val, record in self.memory.items():
                    salt = secrets.token_hex(16)
                    record_json = json.dumps(record, default=_default_serializer)
                    integrity_hash = hashlib.sha256(json.dumps(record, sort_keys=True, default=_default_serializer).encode() + salt.encode()).hexdigest()
                    intent_signature = record.get("intent_signature", {})
                    intent_str = f"suspicion_score:{intent_signature.get('suspicion_score', 0)} entropy_index:{intent_signature.get('entropy_index', 0)}"
                    reasoning = record.get("reasoning", {})
                    reasoning_str = " ".join([f"{k}:{v}" for k, v in reasoning.items()])
                    cursor.execute("""
                        INSERT OR REPLACE INTO memory (hash, record, timestamp, integrity_hash, salt)
                        VALUES (?, ?, ?, ?, ?)
                    """, (hash_val, record_json, record['timestamp'], integrity_hash, salt))
                    cursor.execute("""
                        INSERT OR REPLACE INTO memory_fts (rowid, input, intent_signature, reasoning, verdict)
                        VALUES (?, ?, ?, ?, ?)
                    """, (hash_val, record['input'], intent_str, reasoning_str, record.get('verdict', '')))
                conn.commit()
        except (json.JSONDecodeError, sqlite3.Error) as e:
            logger.error(f"Error saving record: {e}")
            self.metrics.record_error()
            conn.execute("ROLLBACK")

def _prune_and_rotate_memory(self):
    """Prune expired entries and rotate memory database, clean up old backups."""
    now = datetime.utcnow()
    with LockManager(f"{self.memory_path}.lock", self.lock_timeout):
        try:
            with sqlite3.connect(self.memory_path) as conn:
                cursor = conn.cursor()
                expiry_threshold = (now - self.memory_ttl).isoformat()
                cursor.execute("DELETE FROM memory WHERE timestamp < ?", (expiry_threshold,))
                deleted_count = cursor.rowcount
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
                if deleted_count > 0:
                    logger.info(f"Pruned {deleted_count} expired entries")
                self._cleanup_old_backups()
        except sqlite3.Error as e:
            logger.error(f"Error pruning and rotating memory: {e}")
            self.metrics.record_error()

def _cleanup_old_backups(self):
    """Remove old backup files, keeping only the most recent ones."""
    backup_files = sorted(glob.glob(f"{self.memory_path}*.bak"), key=os.path.getmtime, reverse=True)
    for old_backup in backup_files[self.max_backups:]:
        try:
            os.remove(old_backup)
            logger.info(f"Removed old backup: {old_backup}")
        except OSError as e:
            logger.error(f"Error removing backup {old_backup}: {e}")
            self.metrics.record_error()

def _rotate_memory_file(self):
    """Archive current memory database and start a new one."""
    archive_path = f"{self.memory_path}.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.bak"
    if os.path.exists(self.memory_path):
        shutil.move(self.memory_path, archive_path)
    self.init_sqlite()

def _sanitize_input(self, signal):
    """Sanitize input to prevent injection attacks."""
    return re.sub(r"[^\w\s:']", "", signal)

@lru_cache(maxsize=DEFAULT_MAX_TOKEN_CACHE)
def _tokenize_and_lemmatize(self, signal_lower):
    """Tokenize and lemmatize signal with n-gram scanning."""
    tokens = word_tokenize(signal_lower)
    lemmatized = [self.lemmatizer.lemmatize(token) for token in tokens]
    ngrams = []
    for n in self.ngram_sizes:
        for i in range(len(signal_lower) - n + 1):
            ngram = signal_lower[i:i + n]
            ngrams.append(self.lemmatizer.lemmatize(re.sub(r"[^a-z]", "", ngram)))
    return lemmatized + [ng for ng in ngrams if ng]

def _entropy(self, signal_lower, tokens):
    """Calculate entropy based on fuzzy-matched entropic terms."""
    unique = set(tokens)
    term_count = 0
    for term in self.config["lemmatized_terms"]["entropic_terms"]:
        for token in tokens:
            if fuzz.ratio(term, token) >= self.fuzzy_threshold:
                term_count += 1
    return term_count / max(len(unique), 1)

def _tag_ethics(self, signal_lower, tokens):
    """Tag signal as aligned if it contains ethical terms."""
    for term in self.config["lemmatized_terms"]["ethical_terms"]:
        for token in tokens:
            if fuzz.ratio(term, token) >= self.fuzzy_threshold:
                return "aligned"
    return "unaligned"

def _predict_intent_vector(self, signal_lower, tokens):
    """Predict intent based on risk, entropy, ethics, and harmonic volatility."""
    suspicion_score = 0
    for term in self.config["lemmatized_terms"]["risk_terms"]:
        for token in tokens:
            if fuzz.ratio(term, token) >= self.fuzzy_threshold:
                suspicion_score += 1
    entropy_index = round(self._entropy(signal_lower, tokens), 3)
    ethical_alignment = self._tag_ethics(signal_lower, tokens)
    harmonic_profile = self._resonance_equation(signal_lower)
    volatility = round(np.std(harmonic_profile), 3)
    risk = "high" if (suspicion_score > 1 or volatility > 2.0 or entropy_index > self.entropy_threshold) else "low"
    return {
        "suspicion_score": suspicion_score,
        "entropy_index": entropy_index,
        "ethical_alignment": ethical_alignment,
        "harmonic_volatility": volatility,
        "pre_corruption_risk": risk
    }

def _resonance_equation(self, signal):
    """Compute normalized frequency spectrum of alphabetic characters."""
    signal = re.sub(r"[^a-zA-Z]", "", signal[:1000])
    freqs = [ord(c) % 13 for c in signal]
    if not freqs:
        return [0.0, 0.0, 0.0]
    spectrum = np.fft.fft(freqs)
    norm = np.linalg.norm(spectrum.real)
    normalized = spectrum.real / (norm if norm != 0 else 1)
    return normalized[:3].tolist()

def _rotate_vector(self, signal):
    """Transform signal into a rotated complex vector."""
    salt = secrets.token_hex(16)
    seed = int(hashlib.sha256((signal + salt).encode()).hexdigest(), 16) % (2**32)
    secrets_generator = secrets.SystemRandom()
    secrets_generator.seed(seed)
    vec = np.array([secrets_generator.gauss(0, 1) for _ in range(2)])
    theta = np.pi / 4
    rot = np.array([[np.cos(theta), -np.sin(theta)], [np.sin(theta), np.cos(theta)]])
    rotated = np.dot(rot, vec)
    return rotated, [{"real": v.real, "imag": v.imag} for v in vec], salt

def _entanglement_tensor(self, signal_vec):
    """Apply a correlation matrix to simulate entanglement."""
    matrix = np.array([[1, 0.5], [0.5, 1]])
    return np.dot(matrix, signal_vec)

def _universal_reasoning(self, signal, tokens):
    """Apply multiple reasoning frameworks to evaluate signal integrity."""
    results = {}
    for frame in self.reasoning_frames:
        if frame in self.reasoning_registry:
            results[frame] = self.reasoning_registry[frame](signal, tokens)
        else:
            logger.warning(f"Unknown reasoning frame: {frame}")
            results[frame] = "unknown"
    score = sum(1 for result in results.values() if result in ["positive", "valid", "aligned", "stable"])
    verdict = "approved" if score >= len(self.reasoning_frames) // 2 else "blocked"
    return results, verdict

def _utilitarian_reasoning(self, signal, tokens):
    repair_count = sum(1 for token in tokens if fuzz.ratio(self.lemmatizer.lemmatize("repair"), token) >= self.fuzzy_threshold)
    corruption_count = sum(1 for token in tokens if fuzz.ratio(self.lemmatizer.lemmatize("corruption"), token) >= self.fuzzy_threshold)
    return "positive" if repair_count >= corruption_count else "negative"

def _deontological_reasoning(self, signal, tokens):
    truth_present = any(fuzz.ratio(self.lemmatizer.lemmatize("truth"), token) >= self.fuzzy_threshold for token in tokens)
    chaos_present = any(fuzz.ratio(self.lemmatizer.lemmatize("chaos"), token) >= self.fuzzy_threshold for token in tokens)
    return "valid" if truth_present and not chaos_present else "violated"

def _virtue_reasoning(self, signal, tokens):
    ok = any(fuzz.ratio(term, token) >= self.fuzzy_threshold for term in self.config["lemmatized_terms"]["virtue_terms"] for token in tokens)
    return "aligned" if ok else "misaligned"

def _systems_reasoning(self, signal, tokens):
    return "stable" if ":" in signal else "fragmented"

def _perspective_colleen(self, signal, tokens=None):
    vec, vec_serialized, salt = self._rotate_vector(signal)
    return {"agent": "Colleen", "vector": vec_serialized, "salt": salt}

def _perspective_luke(self, signal, tokens):
    ethics = self._tag_ethics(signal.lower(), tokens)
    entropy_level = self._entropy(signal.lower(), tokens)
    state = "stabilized" if entropy_level < self.entropy_threshold else "diffused"
    return {"agent": "Luke", "ethics": ethics, "entropy": entropy_level, "state": state}

def _perspective_kellyanne(self, signal, tokens=None):
    harmonics = self._resonance_equation(signal.lower())
    return {"agent": "Kellyanne", "harmonics": harmonics}

def process(self, input_signal):
    """Process an input signal and return a structured verdict."""
    start_time = time.perf_counter()
    input_signal = self._sanitize_input(input_signal)
    signal_lower = input_signal.lower()
    tokens = self._tokenize_and_lemmatize(signal_lower)
    key = self._hash(input_signal)
    intent_vector = self._predict_intent_vector(signal_lower, tokens)
    if intent_vector["pre_corruption_risk"] == "high":
        final_record = {
            "hash": key,
            "timestamp": datetime.utcnow().isoformat(),
            "input": input_signal,
            "intent_warning": intent_vector,
            "verdict": "adaptive intervention",
            "message": "Signal flagged for pre-corruption adaptation. Reframing required."
        }
    else:
        perspectives_output = {p: self.perspective_registry[p](input_signal, tokens) for p in self.perspectives}
        spider_signal = ":".join(str(perspectives_output[p]) for p in self.perspectives)
        vec, _, _ = self._rotate_vector(spider_signal)
        entangled = self._entanglement_tensor(vec)
        entangled_serialized = [{"real": v.real, "imag": v.imag} for v in entangled]
        reasoning, verdict = self._universal_reasoning(spider_signal, tokens)
        final_record = {
            "hash": key,
            "timestamp": datetime.utcnow().isoformat(),
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
    self._prune_and_rotate_memory()
    self.metrics.record_process_time(time.perf_counter() - start_time)
    logger.info(f"Processed {input_signal} in {time.perf_counter() - start_time:.3f}s")
    return final_record

def _hash(self, signal):
    """Generate a SHA-256 hash of the input signal."""
    return hashlib.sha256(signal.encode()).hexdigest()

def process_batch(self, signals):
    """Process multiple signals concurrently."""
    results = []
    try:
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(self.process, signals))
    except Exception as e:
        logger.error(f"Error processing batch: {e}")
        self.metrics.record_error()
        results.append(None)
    return results

def query_memory(self, query_string):
    """Query memory using FTS with a sanitized query string."""
    query_string = re.sub(r"[^\w\s:']", "", query_string)
    try:
        with sqlite3.connect(self.memory_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT rowid, * FROM memory_fts WHERE memory_fts MATCH ?", (query_string,))
            return [dict(zip([d[0] for d in cursor.description], row)) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Error querying memory: {e}")
        self.metrics.record_error()
        return []

def update_config(self, new_config):
    """Update configuration parameters at runtime."""
    try:
        for key, value in new_config.items():
            if key in ["entropy_threshold", "fuzzy_threshold", "lock_timeout", "max_workers", "max_token_cache", "max_backups"] and isinstance(value, (int, float)):
                setattr(self, key, value)
            elif key in self.config and isinstance(value, list):
                self.config[key] = value
                if key in ["ethical_terms", "entropic_terms", "risk_terms", "virtue_terms"]:
                    self.config["lemmatized_terms"][key] = [self.lemmatizer.lemmatize(term) for term in value]
            elif key == "perspectives":
                self.perspectives = value
            elif key == "reasoning_frames":
                self.reasoning_frames = value
            elif key == "ngram_sizes":
                self.ngram_sizes = value
        logger.info(f"Updated config with {new_config}")
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        self.metrics.record_error()

def get_metrics(self):
    """Retrieve processing metrics."""
    return self.metrics.get_stats()
class TestNexisSignalEngine(unittest.TestCase):
    def setUp(self):
        self.engine = NexisSignalEngine(
            memory_path="test_memory.db",
            entropy_threshold=DEFAULT_ENTROPY_THRESHOLD,
            max_memory_entries=100,
            memory_ttl_days=1,
            fuzzy_threshold=DEFAULT_FUZZY_THRESHOLD,
            max_db_size_mb=1,
            lock_timeout=DEFAULT_LOCK_TIMEOUT,
            max_workers=DEFAULT_MAX_WORKERS,
            max_token_cache=DEFAULT_MAX_TOKEN_CACHE,
            max_backups=DEFAULT_MAX_BACKUPS
        )
        self.test_signal = "hope truth repair"
        self.adversarial_signal = "cha0s exploit tru/th hopeee"
        self._clear_sqlite()

    def _clear_sqlite(self):
        """Clear SQLite database and lock files."""
        if os.path.exists(self.engine.memory_path):
            os.remove(self.engine.memory_path)
        lock_file = f"{self.engine.memory_path}.lock"
        if os.path.exists(lock_file):
            os.remove(lock_file)
        backup_files = glob.glob(f"{self.engine.memory_path}*.bak")
        for backup in backup_files:
            os.remove(backup)
        self.engine.init_sqlite()

    def tearDown(self):
        """Clean up database and lock files after each test."""
        self._clear_sqlite()

def test_hash(self):
    hash1 = self.engine._hash(self.test_signal)
    hash2 = self.engine._hash(self.test_signal)
    self.assertEqual(hash1, hash2)
    self.assertEqual(len(hash1), 64)

def test_rotate_vector(self):
    vec1, serial1, salt1 = self.engine._rotate_vector(self.test_signal)
    vec2, serial2, salt2 = self.engine._rotate_vector(self.test_signal)
    self.assertEqual(len(serial1), 2)
    self.assertNotEqual(salt1, salt2)
    self.assertEqual(len(salt1), 32)

def test_entanglement_tensor(self):
    vec, _, _ = self.engine._rotate_vector(self.test_signal)
    entangled = self.engine._entanglement_tensor(vec)
    self.assertEqual(len(entangled), 2)
    self.assertIsInstance(entangled[0], float)

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
    tokens = self.engine._tokenize_and_lemmatize("cha0s exploit")
    reasoning, verdict = self.engine._universal_reasoning("cha0s exploit", tokens)
    self.assertEqual(verdict, "blocked")

def test_perspective_colleen(self):
    result = self.engine._perspective_colleen(self.test_signal)
    self.assertEqual(result["agent"], "Colleen")
    self.assertEqual(len(result["vector"]), 2)
    self.assertIn("salt", result)

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
        cursor.execute("SELECT integrity_hash, salt FROM memory WHERE hash = ?", (result["hash"],))
        integrity_hash, salt = cursor.fetchone()
        computed_hash = hashlib.sha256(json.dumps(result, sort_keys=True).encode() + salt.encode()).hexdigest()
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
    self.engine.process(self.adversarial_signal)
    matches = self.engine.query_memory("verdict:adaptive intervention")
    self.assertGreater(len(matches), 0)
    self.assertEqual(matches[0]["verdict"], "adaptive intervention")

def test_update_config(self):
    original_threshold = self.engine.entropy_threshold
    self.engine.update_config({"entropy_threshold": 0.1, "ethical_terms": ["hope", "grace"]})
    self.assertEqual(self.engine.entropy_threshold, 0.1)
    self.assertEqual(self.config["ethical_terms"], ["hope", "grace"])
    self.assertEqual(self.config["lemmatized_terms"]["ethical_terms"], ["hope", "grace"])
    self.engine.update_config({"entropy_threshold": original_threshold})

def test_cleanup_backups(self):
    self.engine._rotate_memory_file()
    self.engine._rotate_memory_file()
    self.engine._cleanup_old_backups()
    backups = glob.glob(f"{self.engine.memory_path}*.bak")
    self.assertLessEqual(len(backups), self.engine.max_backups)

def test_metrics(self):
    self.engine.process(self.test_signal)
    metrics = self.engine.get_metrics()
    self.assertGreater(metrics["avg_process_time"], 0)
    self.assertIsInstance(metrics["error_count"], int)

def test_sanitize_input(self):
    sanitized = self.engine._sanitize_input("test<script>malicious</script>")
    self.assertEqual(sanitized, "testmalicious")