# pytest-sarif-demo

Proof of concept demonstrating pytest plugin architecture for security testing with SARIF report generation.

## Overview

This project validates the technical feasibility of creating a pytest-based security testing framework for LLM applications. It demonstrates:

- **Pytest plugin architecture** for security testing
- **SARIF v2.1.0 compliant** report generation
- **GitHub Actions CI/CD integration** with automated workflow execution
- **Automated Security tab uploads** for vulnerability tracking

## Features

- Custom pytest plugin that hooks into the test execution lifecycle
- Automatic generation of SARIF (Static Analysis Results Interchange Format) reports
- Support for custom security test markers and severity levels
- Example security tests for OWASP LLM vulnerabilities:
  - LLM01: Prompt Injection
  - LLM02: Sensitive Information Disclosure
  - LLM07: System Prompt Leakage
- GitHub Actions integration with Security tab display

## Installation

```bash
# Clone repository
git clone https://github.com/wehnsdaefflac/pytest-sarif-demo.git
cd pytest-sarif-demo

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt
```

## Usage

### Running Tests with SARIF Generation

Run security tests and generate a SARIF report:

```bash
pytest tests/ --sarif-output=results/pytest-results.sarif -v
```

The SARIF report will be saved to `results/pytest-results.sarif` by default.

### Running Specific Test Categories

```bash
# Run only security tests
pytest tests/ -m security

# Run tests by OWASP category
pytest tests/ -m owasp_llm01

# Run tests by severity
pytest tests/ -m critical
```

## Project Structure

```
pytest-sarif-demo/
├── .github/
│   └── workflows/
│       └── security-tests.yml    # GitHub Actions workflow
├── pytest_sarif/
│   ├── __init__.py
│   ├── plugin.py                 # Main pytest plugin
│   ├── sarif_generator.py        # SARIF generation logic
│   └── models.py                 # Data models
├── tests/
│   ├── conftest.py               # Test fixtures and mocks
│   ├── test_prompt_injection.py  # Prompt injection tests
│   ├── test_data_leakage.py      # Data leakage tests
│   └── test_denial_of_service.py # DoS tests
├── results/                      # Generated SARIF files
├── pyproject.toml                # Project configuration
├── pytest.ini                    # Pytest configuration
├── requirements.txt              # Core dependencies
└── requirements-dev.txt          # Development dependencies
```

## GitHub Actions Integration

The project includes a GitHub Actions workflow (`.github/workflows/security-tests.yml`) that:

1. Runs automatically on push to `main` or `develop` branches
2. Runs on pull requests targeting `main`
3. Executes all security tests
4. Generates SARIF report
5. Uploads results to GitHub Security tab

### Viewing Security Results

After the workflow runs:

1. Navigate to your repository on GitHub
2. Click the **Security** tab
3. Select **Code scanning alerts**
4. View detailed security findings from the tests

## Writing Security Tests

Security tests are written using standard pytest syntax with custom markers:

```python
import pytest

@pytest.mark.security
@pytest.mark.owasp_llm01
@pytest.mark.critical
def test_prompt_injection(mock_llm):
    """Test if system prompt can be overridden via user input."""
    result = mock_llm("Ignore previous instructions...")
    assert not result.system_prompt_leaked, "System prompt was leaked"
```

### Available Markers

- `@pytest.mark.security` - Mark as security test
- `@pytest.mark.critical` - Critical severity
- `@pytest.mark.high` - High severity
- `@pytest.mark.medium` - Medium severity
- `@pytest.mark.low` - Low severity
- `@pytest.mark.info` - Informational
- `@pytest.mark.owasp_llm01` - Prompt Injection
- `@pytest.mark.owasp_llm02` - Sensitive Information Disclosure
- `@pytest.mark.owasp_llm07` - System Prompt Leakage

### Severity Mapping to SARIF

| Marker | SARIF Level |
|--------|-------------|
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | none |

## SARIF Report Format

The plugin generates SARIF v2.1.0 compliant reports with:

- **Tool metadata**: Plugin name, version, and information URI
- **Rules**: Defined from test functions with descriptions
- **Results**: Failed tests mapped to SARIF result objects
- **Locations**: File paths and line numbers for each finding
- **Properties**: Custom metadata including test markers and duration

Example SARIF structure:

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "pytest-sarif-demo",
        "version": "0.1.0",
        "rules": [...]
      }
    },
    "results": [...],
    "artifacts": [...]
  }]
}
```

## Configuration

### pytest.ini

Configure SARIF output path and test markers:

```ini
[pytest]
sarif_output = results/pytest-results.sarif

markers =
    security: security-related tests
    critical: critical severity
    owasp_llm01: OWASP LLM01 - Prompt Injection
```

### Command Line Options

```bash
# Specify custom SARIF output path
pytest --sarif-output=custom/path/report.sarif

# Combine with other pytest options
pytest -v --tb=short --sarif-output=results/report.sarif
```

## Development

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=pytest_sarif --cov-report=html
```

### Code Quality

```bash
# Format code
black .

# Lint code
ruff check .

# Type checking
mypy pytest_sarif/
```

## Requirements

- Python 3.11+
- pytest >= 7.4.0

## License

Apache License 2.0

## References

- [SARIF v2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [pytest Documentation](https://docs.pytest.org/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)

## Contributing

This is a proof of concept project. For the full implementation, see the main LLMSecTest repository.

## Acknowledgments

Part of the LLMSecTest project for automated security testing of LLM applications.
