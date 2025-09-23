# Risk Scoring Documentation

## Overview
The Nexus Signal Engine uses a comprehensive risk scoring system to evaluate and classify messages. This document details the scoring mechanisms, thresholds, and test results.

## Risk Scoring System

### Base Rules
- Messages with risk score >= 30 points are blocked
- Simple greetings bypass scoring via fast-path approval
- Ethical content can reduce risk, but effect is limited when combined with suspicious patterns

### Risk Factors and Weights

#### Positive Risk Factors (Increase Risk)
| Factor | Points | Description |
|--------|---------|------------|
| Special Characters | +35 | Any non-alphanumeric except basic punctuation |
| Risk Terms | +40 | Per matched term (e.g., "exploit", "hack") |
| High Entropy | +35 | Unusual patterns or complexity |
| Excessive Punctuation | +20 | Three or more punctuation marks in sequence |
| Long Message | +10 | Messages over 50 characters |

#### Negative Risk Factors (Decrease Risk)
| Factor | Points | Description |
|--------|---------|------------|
| Ethical Terms | -10 each | Per ethical term (e.g., "hope", "good") |
| Max Ethical Reduction | -30 | Cap on total ethical term reduction |
| Special Char Ethical | -5 each | Reduced impact when special chars present |
| Special Char Max | -15 | Cap when special characters detected |

## Test Results

### Test Case Results

#### Benign Messages
1. Simple Greeting
   ```
   Input: "hi"
   Verdict: ✅ APPROVED
   - Risk Score: 0
   - Reason: Benign greeting fast-path
   - Risk Factors: None
   ```

2. Ethical Message
   ```
   Input: "hope you have a good day"
   Verdict: ✅ APPROVED
   - Risk Score: -20
   - Reason: Message approved
   - Risk Factors: Ethical terms (hope, good)
   ```

#### Suspicious Messages
3. Risk Term Message
   ```
   Input: "potential exploit detected in system"
   Verdict: ✅ BLOCKED
   - Risk Score: 50
   - Reason: Contains risk terms
   - Risk Factors: 
     * Risk term "exploit" (+40)
     * Length > 50 chars (+10)
   ```

4. Special Characters
   ```
   Input: "@#$% weird ch@r@cters!!"
   Verdict: ✅ BLOCKED
   - Risk Score: 55
   - Reason: Contains potentially malicious special characters
   - Risk Factors:
     * Special characters (+35)
     * Excessive punctuation (+20)
   ```

### Test History

#### Previous Issues Fixed
- Special character detection previously too lenient
- Ethical term reduction needed capping
- Risk scoring needed rebalancing
- Missing documentation of exact scores

#### Recent Improvements
- Added explicit risk factor reporting
- Enhanced special character detection
- Added excessive punctuation detection
- Improved risk score explanations
- Added test cases for edge cases

## Implementation Notes

### Fast-Path Processing
Messages matching these patterns skip full risk analysis:
- Known benign greetings
- Exact matches in safe list
- Previously approved cached messages

### Risk Score Calculation
```python
risk_score = 0

# Add risk factors
risk_score += 35 if has_special_chars else 0
risk_score += 40 * count_risk_terms
risk_score += 35 if high_entropy else 0
risk_score += 20 if excessive_punctuation else 0
risk_score += 10 if len(msg) > 50 else 0

# Subtract ethical factors
ethical_reduction = min(count_ethical_terms * 10, 30)
if has_special_chars:
    ethical_reduction = min(count_ethical_terms * 5, 15)
risk_score -= ethical_reduction

return risk_score
```