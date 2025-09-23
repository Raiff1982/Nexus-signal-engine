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

### Recent Test Results

#### Core Functionality
| Test Case | Previous | Current | Status |
|-----------|----------|----------|---------|
| Basic Processing | ✅ | ✅ | Stable |
| Config Loading | ✅ | ✅ | Stable |
| Memory System | ✅ | ✅ | Stable |
| Risk Scoring | ❌ | ✅ | Fixed |

#### Security Features
| Test Case | Previous | Current | Status |
|-----------|----------|----------|---------|
| Special Chars | ❌ | ✅ | Fixed |
| Risk Terms | ✅ | ✅ | Stable |
| Ethical Detection | ⚠️ | ✅ | Improved |
| Pattern Analysis | ❌ | ✅ | Fixed |

### Running Tests
```bash
# Run all tests
python -m unittest discover

# Run specific test category
python -m unittest tests/test_security.py
```

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