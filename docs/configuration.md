# Configuration Guide

## Overview
The Nexus Signal Engine uses a JSON-based configuration system that can be updated at runtime. This document details all available configuration options and their effects.

## Configuration Parameters

### Risk Terms
```json
{
    "risk_terms": [
        "exploit",
        "hack",
        "malware",
        "virus"
    ]
}
```
- Match against these terms triggers a +40 point risk increase per term
- Case-insensitive matching
- Fuzzy matching applied to detect obfuscation attempts

### Benign Greetings
```json
{
    "benign_greetings": [
        "hi",
        "hello",
        "hey",
        "greetings"
    ]
}
```
- Messages exactly matching these are fast-path approved
- Must be exact match after lowercase and whitespace trimming
- No fuzzy matching for security

### Ethical Terms
```json
{
    "ethical_terms": [
        "hope",
        "truth",
        "empathy",
        "good"
    ]
}
```
- Each match reduces risk by 10 points (max -30)
- When special characters present, reduces by 5 points (max -15)
- Case-insensitive matching

### Thresholds
```json
{
    "entropy_threshold": 0.7,
    "fuzzy_threshold": 85,
    "risk_threshold": 30
}
```
- `entropy_threshold`: Trigger high entropy detection (+35 points)
- `fuzzy_threshold`: Minimum score for fuzzy matching
- `risk_threshold`: Score at or above this is blocked

## Runtime Updates
The configuration can be updated while the engine is running:
```python
engine = NexisSignalEngine()
engine.config.update({
    "risk_terms": ["new", "terms", "here"],
    "ethical_terms": ["additional", "ethics"]
})
```

## Test Configuration
For testing, a minimal configuration might look like:
```json
{
    "risk_terms": ["test", "mock", "fake"],
    "benign_greetings": ["hi"],
    "ethical_terms": ["good"],
    "entropy_threshold": 0.7,
    "fuzzy_threshold": 85
}
```

## Validation Rules
- Terms must be non-empty strings
- No duplicates allowed in term lists
- Thresholds must be float between 0 and 1
- Fuzzy threshold must be integer 0-100
- Configuration updates are atomic