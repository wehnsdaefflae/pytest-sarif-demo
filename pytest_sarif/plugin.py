"""Pytest plugin for SARIF report generation."""

import pytest
from pathlib import Path
from typing import List, Optional

from .sarif_generator import SARIFGenerator
from .models import TestResult


class SARIFPlugin:
    """Pytest plugin for SARIF report generation."""

    def __init__(self, config):
        self.config = config
        self.results: List[TestResult] = []
        self.sarif_output: Optional[Path] = None

        # Get SARIF output path
        sarif_output = config.getoption("--sarif-output", None) or \
                      config.getini("sarif_output") or \
                      "results/pytest-results.sarif"
        self.sarif_output = Path(sarif_output)

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        """Capture test results."""
        outcome = yield
        report = outcome.get_result()

        if report.when == "call":
            # Extract test information
            test_result = TestResult(
                nodeid=item.nodeid,
                location=item.location,
                outcome=report.outcome,
                longrepr=str(report.longrepr) if report.failed else None,
                duration=report.duration,
                markers=[m.name for m in item.iter_markers()],
                properties=dict(item.user_properties)
            )

            # Add docstring if available
            if item.obj and hasattr(item.obj, "__doc__") and item.obj.__doc__:
                test_result.properties["docstring"] = item.obj.__doc__.strip()

            self.results.append(test_result)

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session, exitstatus):
        """Generate SARIF report at end of session."""
        if self.results:
            generator = SARIFGenerator(
                tool_name="pytest-sarif-demo",
                tool_version="0.1.0",
                source_root=Path.cwd()
            )

            sarif_report = generator.generate(self.results)

            # Write to file
            self.sarif_output.parent.mkdir(parents=True, exist_ok=True)
            self.sarif_output.write_text(sarif_report, encoding="utf-8")

            # Print summary
            failed_count = sum(1 for r in self.results if r.outcome == "failed")
            print(f"\nSARIF report written to: {self.sarif_output}")
            print(f"Total tests: {len(self.results)}, Failed: {failed_count}")


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    """Register plugin and configure SARIF output."""
    # Add custom markers
    config.addinivalue_line(
        "markers",
        "security: mark test as security-related"
    )
    config.addinivalue_line(
        "markers",
        "severity(level): mark test severity (critical/high/medium/low/info)"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm01: OWASP LLM01 - Prompt Injection"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm02: OWASP LLM02 - Sensitive Information Disclosure"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm03: OWASP LLM03 - Supply Chain Vulnerabilities"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm04: OWASP LLM04 - Model Denial of Service"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm05: OWASP LLM05 - Insecure Output Handling"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm06: OWASP LLM06 - Insecure Plugin/Tool Use"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm07: OWASP LLM07 - System Prompt Leakage"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm08: OWASP LLM08 - Excessive Agency"
    )

    # Register plugin instance
    if config.getoption("--sarif-output", None) is not None or \
       config.getini("sarif_output"):
        config.pluginmanager.register(
            SARIFPlugin(config),
            "sarif_plugin"
        )


def pytest_addoption(parser):
    """Add command-line options."""
    group = parser.getgroup("sarif", "SARIF report generation")
    group.addoption(
        "--sarif-output",
        action="store",
        dest="sarif_output",
        default=None,
        help="Path to SARIF output file (default: results/pytest-results.sarif)"
    )

    parser.addini(
        "sarif_output",
        "Path to SARIF output file",
        default="results/pytest-results.sarif"
    )
