# Testing guide

This document explains how to run the project's tests and how to execute the focused Immortal Aegis ↔ Nexis integration test.

Running the full test suite
--------------------------

From the repository root (recommended inside your project's virtualenv):

```powershell
python -m pytest -q
```

Focused Immortal bridge test
----------------------------

To run only the focused integration test that exercises the bridge between Nexis and Aegis:

```powershell
python -m pytest -q tests/test_immortal_bridge.py
```

Notes
-----
- The focused bridge test may instantiate a temporary `.db` SQLite file to satisfy Nexis's memory path validation.
- If you have a full `immortal_aegis` implementation in the repo, the bridge will use it. If not, a small shim exists for demo/test purposes.
- See `docs/aegis_behavior.md` for details on Aegis behavior and tuning.
# Testing Guide

## Overview
This document outlines the testing procedures and results for the Nexus Signal Engine. It includes test cases, expected results, and guidelines for adding new tests.

## Test Categories

### 1. Basic Functionality Tests
- Simple message processing
- Configuration loading
- Memory system operation
- Basic API functionality

### 2. Security Tests

#### Special Character Detection
```python
test_cases = [
    ("Hello World", "approved"),              # ✅ Basic text
    ("H3llo W0rld!", "approved"),            # ✅ Numbers and basic punctuation
    ("H@ck3r", "blocked"),                   # ✅ Special characters
    ("@#$% Weird!", "blocked"),              # ✅ Multiple special chars
    ("Hello....!!!", "blocked"),             # ✅ Excessive punctuation
]
```

#### Risk Term Detection
```python
test_cases = [
    ("exploit detected", "blocked"),          # ✅ Direct match
    ("expl0it detect3d", "blocked"),         # ✅ Obfuscated
    ("harmless message", "approved"),         # ✅ No risk terms
    ("multiple exploit hack", "blocked"),     # ✅ Multiple terms
]
```

#### Ethical Content
```python
test_cases = [
    ("hope and good", "approved"),           # ✅ Multiple ethical terms
    ("hope hack", "blocked"),                # ✅ Mixed ethical/risk
    ("tr/ue h0pe", "blocked"),              # ✅ Special chars override
]
```

### 3. Edge Cases
- Empty messages
- Very long messages
- Unicode characters
- Mixed character sets
- Repeated characters

### Current Test Results (September 23, 2025)

All tests are currently passing (11 tests, 0.374s execution time)

#### Behavior Detection Tests
| Test Case | Description | Status | Details |
|-----------|-------------|--------|---------|
| test_behavior_pattern | Pattern creation and validation | ✅ | Validates creation and detection of behavior patterns |
| test_confidence_bounds | Confidence scoring | ✅ | Tests bounds and accuracy of confidence scoring |

#### Pattern Correlation Tests
| Test Case | Description | Status | Details |
|-----------|-------------|--------|---------|
| test_correlation_pruning | Correlation data management | ✅ | Validates pruning of old correlation data |
| test_temporal_correlation | Temporal pattern detection | ✅ | Tests detection of time-based correlations |

#### Multimodal Analysis Tests
| Test Case | Description | Status | Details |
|-----------|-------------|--------|---------|
| test_content_features | Feature extraction | ✅ | Validates content feature extraction |
| test_risk_score_bounds | Risk scoring validation | ✅ | Tests risk score calculation boundaries |

#### Threat Detection Tests
| Test Case | Description | Status | Details |
|-----------|-------------|--------|---------|
| test_model_persistence | Model I/O operations | ✅ | Ensures models save and load correctly |
| test_model_training | Model functionality | ✅ | Validates model training and predictions |

#### Threat Scoring Tests
| Test Case | Description | Status | Details |
|-----------|-------------|--------|---------|
| test_benign_scoring | Benign case handling | ✅ | Tests scoring of non-threatening content |
| test_component_weights | Weight calculations | ✅ | Validates component weight system |
| test_threat_scoring | Threat detection | ✅ | Tests scoring of potentially harmful content |

### Running Tests
```bash
# Run all tests with verbose output
python -m unittest discover -s tests -v

# Run specific test module
python -m unittest tests/test_behavior.py
python -m unittest tests/test_correlator.py
python -m unittest tests/test_multimodal.py
python -m unittest tests/test_threat_detector.py
python -m unittest tests/test_threat_scoring.py
```

### Test Coverage

Current test coverage includes:
- Behavioral pattern detection and analysis
- Temporal correlation detection and pruning
- Multimodal content analysis and feature extraction
- Threat detection model training and persistence
- Risk scoring and weight calculations

## Adding New Tests
1. Create test file in `tests/` directory
2. Inherit from `unittest.TestCase`
3. Include both positive and negative cases
4. Document expected results
5. Add to test suite

Example:
```python
class TestMessageSecurity(unittest.TestCase):
    def setUp(self):
        self.engine = NexisSignalEngine()
        
    def test_special_characters(self):
        result = self.engine.process("@#$% test")
        self.assertEqual(result["verdict"], "blocked")
        self.assertGreater(result["reasoning"]["risk_score"], 30)
```

## Common Test Issues
- Configuration not reset between tests
- Memory file locking
- Inconsistent results with entropy calculations
- Thread safety in concurrent tests

## Recent Fixes
- Special character detection improved
- Risk scoring rebalanced
- Ethical term processing fixed
- Added detailed risk factor reporting

## Future Test Additions
- More Unicode edge cases
- Additional pattern detection
- Performance benchmarks
- Concurrent processing tests