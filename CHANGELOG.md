# Changelog

All notable changes to the Nexis Signal Engine will be documented in this file.

## [1.1.0] - 2025-09-23

### Added
- Comprehensive test suite with 11 detailed test cases covering all core functionality
- UTC timezone support in all datetime handling
- Enhanced test documentation in README.md

### Changed
- Replaced all deprecated `datetime.utcnow()` calls with `datetime.now(UTC)`
- Updated test suite to use modern datetime handling

### Fixed
- Deprecated datetime usage in core modules and utilities:
  - core.py
  - engine.py
  - Nexus.py
  - webhooks.py
  - auth.py
  - compliance.py
  - unicode_threat_integration_patch2.py
  - nexus23.py
  - NexisSignalEngine_UnicodeHardened.py
  - NexisSignalEngineHoaxcheck.py
  - Aegis234567.py

### Test Results
#### Core Test Suite
- 11 tests executed in 0.374s - All passing ✅
- Coverage across all major components:
  - Behavior Detection (2 tests)
  - Pattern Correlation (2 tests)
  - Multimodal Analysis (2 tests)
  - Threat Detection (2 tests)
  - Threat Scoring (3 tests)

## [1.0.0] - 2025-09-22

### Added
- Enhanced risk scoring system with detailed explanations
- New risk factors for special characters and patterns
- Risk scoring adjustments for ethical content
- Detailed message analysis and verdicts
- Test suite for message validation

### Changed
- Increased risk weight for special characters from 15 to 35 points
- Added additional pattern detection for excessive punctuation
- Modified ethical term bonus reduction for suspicious messages
- Updated verdict explanations to be more detailed
- Improved benign greeting fast-path processing

### Fixed
- Special character messages now properly blocked (previously approved)
- Risk factor reporting in message processing output
- Configuration initialization issues
- Missing imports (secrets, re)
- Risk score threshold enforcement

### Security
- Strengthened special character detection
- Added excessive punctuation detection
- Reduced impact of ethical terms when combined with suspicious patterns
- Improved risk scoring for potentially malicious content

### Test Results
#### Benign Message Tests
- `hi` -> ✅ PASS
  - Verdict: approved
  - Risk Score: 0
  - Reason: Benign greeting
  - Risk Factors: None

- `hope you have a good day` -> ✅ PASS
  - Verdict: approved
  - Risk Score: -20
  - Reason: Message approved
  - Risk Factors: Contains ethical terms ("hope", "good")

#### Suspicious Message Tests
- `potential exploit detected in system` -> ✅ PASS
  - Verdict: blocked
  - Reason: Contains risk terms
  - Risk Factors: Risk term "exploit", length exceeds threshold

- `@#$% weird ch@r@cters!!` -> ✅ PASS
  - Verdict: blocked
  - Risk Factors: Special characters, excessive punctuation
  - Previously: ❌ incorrectly approved with Risk Score: 15

#### Risk Scoring System
- Base threshold: 30 points
- Risk Factors:
  - Special characters: +35 points
  - Excessive punctuation: +20 points
  - Message length > 50: +10 points
  - Risk terms: +40 points per term
  - High entropy: +35 points
  - Ethical terms: -10 points per term (max -30)
    - Reduced to -5 points per term (max -15) when special characters present