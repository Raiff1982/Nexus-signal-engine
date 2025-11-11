What is This?

The Nexus Signal Engine is a real-world, agent-driven, adversarially resilient AI signal### Multimodal Analysis Tests
- ✅ `test_content_features`: Validates content feature extraction and analysis
- ✅ `test_risk_score_bounds`: Tests risk score calculation boundaries

### Threat Detection Tests
- ✅ `test_model_persistence`: Ensures models save and load correctly
- ✅ `test_model_training`: Validates model training and prediction functionality

### Message Processing Tests
- ✅ Benign Messages: Properly identifies and approves safe content
  - Simple greetings (e.g., "hi") → Risk Score: 0
  - Ethical messages (e.g., "hope you have a good day") → Risk Score: -20
- ✅ Suspicious Messages: Correctly flags potential threats
  - Risk terms detection (e.g., "exploit")
  - Special character detection (e.g., obfuscated text)is and memory engine.
It is designed for those who demand verifiable AI trust, audit-ready reasoning, and full adversarial resistance—not academic fluff or theoretical “AI safety.”

⸻

Key Features
	•	Adversarial Obfuscation Defense:
Recognizes and flags manipulated or obfuscated signals (tru/th, cha0s, leetspeak, etc.) using lemmatization, n-gram, and fuzzy-matching.
	•	Agent Perspective Analysis:
Every input is evaluated through multiple simulated ethical agents (Colleen, Luke, Kellyanne), each with its own reasoning lens.
	•	Forensic, Immutable Memory:
All records are cryptographically hashed, integrity-checked, timestamped, and stored in a rotating, full-text-searchable SQLite database.
	•	Concurrency and Scale:
Thread-safe with batch processing, auto-retry, database size limits, and lock management. Built to run reliably under real-world load.
	•	Dynamic Configuration:
Change risk thresholds, terms, and filters at runtime—no restart required.
	•	Explainable, Auditable, and Tested:
Full unit test suite included. Every signal is traceable, reproducible, and forensically sound.

⸻

Why Is This Different?
	•	Not “just another AI filter.” This is the only open-source engine combining:
	•	Real NLP (tokenization, lemmatization, n-gram defense)
	•	Agent-lensed reasoning
	•	Integrity-hashed, auto-pruned, fully auditable memory
	•	Batch & concurrent processing
	•	Production logging, auto-retry, config hot-reload
	•	Tested for adversarial cases others ignore
	•	Already published and timestamped on Zenodo: 
Installation
------------

For installation:

```bash
git clone https://github.com/Raiff1982/Nexus-signal-engine.git
cd Nexus-signal-engine
pip install -e .
```

Usage Examples
-------------

### Basic Message Safety Check

```python
from nexus_signal_engine import NexisSignalEngine

engine = NexisSignalEngine()

# Check a safe message
result = engine.evaluate_message_safety("Hello world")
print(result)
# Output: (True, {'reason': 'Message approved', 'risk_score': 0, 'risk_factors': ['No specific risk factors'], 'threshold': 30})

# Check a message with potential risks
result = engine.evaluate_message_safety("Hello world! Some unicode: 你好世界 🌍")
print(result)
# Output: (False, {'reason': 'Message blocked due to risk factors', 'risk_score': 45, 
#         'risk_factors': ['Message length exceeds safe threshold', 'Contains potentially malicious special characters'], 
#         'threshold': 30})
```

### Processing Obfuscated Input

```python
engine = NexisSignalEngine(memory_path="signals.db")
result = engine.process("tru/th hopee cha0s")  # Obfuscated input
print(result)
```

Requirements
-----------
- Python 3.8+
- Dependencies (automatically installed):
  - numpy >= 1.22
  - rapidfuzz >= 3.0.0
  - nltk >= 3.8
  - filelock >= 3.13
  - tenacity >= 8.2.3
  - sqlite3 (standard lib)

Testing Status
-------------

The codebase is thoroughly tested with a comprehensive test suite. Latest test run (September 23, 2025) shows all 11 tests passing successfully in 0.374s.

### Recent Updates
- Upgraded to modern UTC datetime handling across all modules
- Enhanced security scanning and validation
- Improved test documentation and coverage

### Test Results by Category

### Behavior Detection Tests
- ✅ `test_behavior_pattern`: Validates behavior pattern creation and validation
- ✅ `test_confidence_bounds`: Tests confidence score validation

### Pattern Correlation Tests
- ✅ `test_correlation_pruning`: Validates correlation data management
- ✅ `test_temporal_correlation`: Tests detection of time-based correlations

### Multimodal Analysis Tests
- ✅ `test_content_features`: Validates content feature extraction and validation
- ✅ `test_risk_score_bounds`: Tests risk score validation boundaries

### Threat Detection Tests
- ✅ `test_model_persistence`: Ensures model saving and loading works correctly
- ✅ `test_model_training`: Validates model training and prediction functionality

### Threat Scoring Tests
- ✅ `test_benign_scoring`: Validates scoring of non-threatening content
- ✅ `test_component_weights`: Tests component weight calculations and thresholds
- ✅ `test_threat_scoring`: Validates scoring of potentially harmful content

### Test Coverage
The test suite provides comprehensive coverage across all major components:
- Input validation and sanitization
- Pattern detection and correlation
- Risk scoring and threat assessment
- Model persistence and training
- Concurrent processing and memory management
- Configuration hot-reloading
- Special character and Unicode handling

For detailed test documentation and guidelines for adding new tests, see `docs/testing.md`.

For information about how the Immortal Aegis interacts with Nexis and how to tune it, see `docs/aegis_behavior.md`.

⸻

Citation

If you use or build on this work, cite the Zenodo archive and this GitHub repo:

@software{jonathan_harrison_nexus_2025,
  author       = {Jonathan Harrison},
  title        = {Nexus Signal Engine},
  year         = 2025,
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.16269918},
  url          = {https://github.com/Raiff1982/Nexus-signal-engine}
}

FAQ

Q: Why all the agent names?
A: Each “agent” represents a different perspective in ethical or signal reasoning—making every decision more robust and auditable.

Q: Is this really adversarially robust?
A: Yes—try to break it with obfuscation, leetspeak, prompt injection, or high-entropy word salad. Then check the test suite.

### Aegis bridge behavior (important note)

The Immortal Aegis is not a per-sample moral overrider. The bridge between Nexis and Aegis only intervenes when Aegis reports a regenerative lifecycle event (action == "regenerated"). In practice this means:

- Nexis may label a single sample as "unaligned", "violated", or "misaligned" for moral/ethical signals and yet still return a non-blocking verdict for that sample.
- Aegis does not second-guess Nexis on single samples. It monitors long-term memory health (volatility, density, average virtue) and will only step in to change verdicts when the system-wide health triggers regeneration.
- The smoke-test control case (safe-ish text) demonstrates this: Nexis may mark the sample ethically "unaligned", but Aegis will take action "none" (no regeneration) when volatility is low — so the bridge will not override the original Nexis verdict.

This behavior prevents per-sample fluctuations from causing unnecessary human-review noise; Aegis acts as a systemic safety layer rather than a per-signal censor.

Q: Who built this?
A: Jonathan Harrison (Raiff1982), published on Zenodo and open-sourced for the world to audit, use, or improve.

⸻

License

MIT License
No hidden tricks. No “ethical” vaporware.
Fork it, use it, cite it—just don’t pretend you built it first.

⸻

Contact

Questions, feedback, or press inquiries:
Open a GitHub issue or reach out directly.

⸻

This project sets the bar for ethical AI signal integrity and memory. If you want to build trustworthy AI, start here—or play catch-up.
<details>
<summary>BibTeX (Zenodo DOI)</summary>
@software{jonathan_harrison_nexus_2025,
  author       = {Jonathan Harrison},
  title        = {Nexus Signal Engine},
  year         = 2025,
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.16269918},
  url          = {https://github.com/Raiff1982/Nexus-signal-engine}
}
</details>
