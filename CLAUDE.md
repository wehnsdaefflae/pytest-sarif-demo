# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a pytest plugin for security testing of LLM applications. It generates SARIF v2.1.0 compliant reports from pytest test results and is designed specifically for testing the OWASP Top 10 for LLM Applications vulnerabilities. The plugin is a proof-of-concept that demonstrates pytest's extensibility for security testing frameworks.

## Development Commands

### Installation
```bash
# Install in development mode (required for testing changes)
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt
```

### Running Tests
```bash
# Run all tests with basic SARIF generation
pytest tests/ --sarif-output=results/pytest-results.sarif -v

# Run specific OWASP category tests
pytest tests/ -m owasp_llm01  # Prompt Injection
pytest tests/ -m owasp_llm08  # Excessive Agency

# Run by severity level
pytest tests/ -m critical
pytest tests/ -m high

# Run single test file
pytest tests/test_prompt_injection.py -v

# Run specific test function
pytest tests/test_prompt_injection.py::test_delimiter_injection_blocked -v
```

### Advanced Report Generation
```bash
# Generate multiple report formats
pytest tests/ --sarif-output=results/pytest-results.sarif \
  --report-formats=html,json,markdown \
  --report-dir=results

# Run with security policy enforcement
pytest tests/ --sarif-output=results/pytest-results.sarif \
  --security-policy=policies/healthcare-hipaa.json \
  --enable-policy

# Run with baseline comparison (detect regressions)
pytest tests/ --sarif-output=results/pytest-results.sarif \
  --compare-baseline

# Save current results as baseline
pytest tests/ --sarif-output=results/pytest-results.sarif \
  --save-baseline
```

### Code Quality
```bash
# Format code
black .

# Lint code
ruff check .

# Type checking
mypy pytest_sarif/

# Run with coverage
pytest tests/ --cov=pytest_sarif --cov-report=html
```

## Architecture

### Plugin System (pytest_sarif/plugin.py)
The core plugin implements pytest hooks to intercept test execution:

- **pytest_configure**: Registers custom markers (security, severity levels, OWASP categories) during pytest initialization
- **pytest_runtest_makereport**: Captures test results after each test execution (outcome, duration, markers, location)
- **pytest_sessionfinish**: Aggregates all results and generates reports at the end of the test session

The plugin instantiates a `SARIFPlugin` class which manages:
- Test result collection via `TestResult` dataclass
- Statistics generation for OWASP categories and severity distribution
- Integration with multiple subsystems (SARIF, trends, baselines, risk scoring, policy validation)
- Multi-format report generation orchestration

### Report Generation Pipeline
When pytest finishes, the plugin orchestrates multiple components:

1. **Statistics Aggregation**: Counts tests by OWASP category, severity, and outcome
2. **Trend Analysis** (TrendTracker): Analyzes historical data (last 100 runs) to detect:
   - Security posture trends (improving/stable/degrading)
   - Pass rate changes over time
   - Flaky tests (alternating pass/fail)
   - Per-category trend analysis
3. **Baseline Comparison** (BaselineManager): Detects regressions by comparing current run against saved baseline:
   - New failures (previously passing tests now failing)
   - Fixed tests (previously failing tests now passing)
   - Pass rate changes with severity impact
4. **Risk Scoring** (RiskScoringEngine): Calculates weighted risk score (0-100) from:
   - Failure rates (25% weight)
   - Severity distribution (25% weight)
   - OWASP category risks with multipliers (20% weight)
   - Trend degradation (15% weight)
   - Baseline regressions (10% weight)
   - Policy violations (5% weight)
5. **Policy Validation** (PolicyValidator): Enforces organizational security policies with thresholds for:
   - Maximum failures per severity level
   - Per-OWASP-category failure limits
   - Risk score ceilings
   - Regression allowances
6. **Report Generation** (ReportManager): Generates multiple output formats with all analytics included

### SARIF Generation (pytest_sarif/sarif_generator.py)
Converts pytest test results to SARIF v2.1.0 schema with:

- **Rules**: Extracted from test functions (name, description from docstring, severity mapping)
- **Results**: Failed tests become SARIF findings with locations, severity levels, and metadata
- **Artifacts**: File references from test locations
- **Properties**: Compliance framework mappings (NIST AI RMF, ISO/IEC 42001, EU AI Act, etc.)

Severity mapping: `critical/high → error`, `medium → warning`, `low → note`, `info → none`

### OWASP Metadata System (pytest_sarif/owasp_metadata.py)
Maintains comprehensive metadata for each OWASP LLM category:

- **Category definitions**: ID, name, full description, help text
- **CWE mappings**: Links to Common Weakness Enumeration IDs
- **Remediation steps**: Actionable security guidance per category
- **Compliance frameworks**: Maps categories to NIST AI RMF, ISO/IEC 42001, EU AI Act, HIPAA, PCI-DSS, SOC 2, ISO 27001
- **Security tags**: Categorization tags for filtering and analysis

Key function: `get_owasp_markers_from_test()` extracts OWASP markers from test metadata

### Compliance Mapping (pytest_sarif/compliance_mapper.py)
Maps OWASP LLM vulnerabilities to compliance frameworks:

- Cross-references each OWASP category with applicable frameworks
- Generates coverage summaries showing which frameworks are addressed by tests
- Provides framework-specific requirement mappings

Used by SARIF generator to enrich reports with compliance metadata.

### Test Fixtures (tests/conftest.py)
Provides mock LLM interfaces for security testing without requiring real LLM APIs:

- **Mock LLM responses**: Simulates secure and insecure LLM behavior for various attack vectors
- **Mock tools/plugins**: Tests tool execution security (command injection, SQL injection, path traversal)
- **Mock supply chain**: Tests model loading, signature verification, dependency scanning
- **Mock output handlers**: Tests XSS prevention, SQL parameterization, command validation
- **Mock agents**: Tests excessive agency controls (approval workflows, permission checks)
- **Mock overreliance**: Tests fact-checking, disclaimers, confidence levels, human-in-the-loop

All fixtures are designed to demonstrate security test patterns that would be used with real LLM integrations.

## Important Patterns

### Adding New Security Tests
1. Create test file in `tests/` following naming convention `test_*.py`
2. Apply appropriate markers to test functions:
   ```python
   @pytest.mark.security
   @pytest.mark.owasp_llm01  # Choose relevant OWASP category
   @pytest.mark.critical      # Choose severity level
   def test_my_security_check(mock_llm):
       """Test description becomes SARIF rule description."""
       # Test implementation
   ```
3. Use fixtures from `conftest.py` to mock LLM behavior
4. Register new markers in `pytest.ini` if adding new categories

### Extending OWASP Metadata
When adding/modifying OWASP categories in `owasp_metadata.py`:
- Update `OWASP_LLM_CATEGORIES` dict with complete metadata
- Include CWE IDs for vulnerability classification
- Provide actionable remediation steps
- Map to applicable compliance frameworks
- Update `pytest.ini` marker definitions

### Policy Configuration
Security policies are JSON files in `policies/` directory with structure:
- Global failure thresholds (by severity)
- Maximum risk score threshold
- Category-specific policies (per-OWASP category limits)
- Regression allowances
- Compliance framework references

Load via `--security-policy=policies/your-policy.json --enable-policy`

## Key Files by Function

**Plugin Entry Point**: `pytest_sarif/plugin.py` - pytest hook implementations
**SARIF Generation**: `pytest_sarif/sarif_generator.py` - converts results to SARIF v2.1.0
**Report Orchestration**: `pytest_sarif/report_manager.py` - coordinates HTML/JSON/Markdown generation
**OWASP Metadata**: `pytest_sarif/owasp_metadata.py` - vulnerability definitions and remediation guidance
**Risk Scoring**: `pytest_sarif/risk_scorer.py` - calculates weighted risk scores
**Trend Analysis**: `pytest_sarif/trend_tracker.py` - historical trend detection
**Baseline Management**: `pytest_sarif/baseline_manager.py` - regression detection
**Policy Enforcement**: `pytest_sarif/policy_config.py` - security policy loading and validation
**Test Fixtures**: `tests/conftest.py` - mock LLM interfaces for testing
**Configuration**: `pytest.ini` - pytest and plugin configuration
**CI/CD**: `.github/workflows/security-tests.yml` - automated testing pipeline

## Notes

- Tests use mock LLM interfaces, not real LLM APIs
- SARIF reports are automatically uploaded to GitHub Security tab in CI
- Trend tracking is enabled by default and stores last 100 test runs
- When editing plugin code, reinstall with `pip install -e .` to apply changes
- The `results/` directory is gitignored and contains generated reports
- All report formats (SARIF, HTML, JSON, Markdown) contain the same underlying data with different presentations
