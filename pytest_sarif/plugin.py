"""Pytest plugin for SARIF report generation."""

import pytest
from pathlib import Path
from typing import List, Optional, Dict
from collections import defaultdict

from .sarif_generator import SARIFGenerator
from .models import TestResult
from .owasp_metadata import get_owasp_category, get_owasp_markers_from_test
from .report_manager import ReportManager


class SARIFPlugin:
    """Pytest plugin for SARIF report generation."""

    def __init__(self, config):
        self.config = config
        self.results: List[TestResult] = []
        self.sarif_output: Optional[Path] = None
        self.report_formats: List[str] = []
        self.report_dir: Path = Path("results")

        # Get SARIF output path
        sarif_output = config.getoption("--sarif-output", None) or \
                      config.getini("sarif_output") or \
                      "results/pytest-results.sarif"
        self.sarif_output = Path(sarif_output)

        # Get report formats
        formats_option = config.getoption("--report-formats", None) or \
                        config.getini("report_formats") or \
                        ""
        if formats_option:
            self.report_formats = [f.strip() for f in formats_option.split(",")]

        # Get report directory
        report_dir = config.getoption("--report-dir", None) or \
                    config.getini("report_dir") or \
                    "results"
        self.report_dir = Path(report_dir)

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

    def _generate_statistics(self) -> Dict:
        """Generate statistics about OWASP category coverage."""
        stats = {
            "total_tests": len(self.results),
            "failed_tests": sum(1 for r in self.results if r.outcome == "failed"),
            "passed_tests": sum(1 for r in self.results if r.outcome == "passed"),
            "owasp_categories": defaultdict(lambda: {"total": 0, "failed": 0, "passed": 0}),
            "severity_distribution": defaultdict(int),
        }

        for result in self.results:
            # Track OWASP category statistics
            owasp_markers = get_owasp_markers_from_test(result.markers)
            for marker in owasp_markers:
                category = get_owasp_category(marker)
                if category:
                    stats["owasp_categories"][category.id]["total"] += 1
                    if result.outcome == "failed":
                        stats["owasp_categories"][category.id]["failed"] += 1
                    elif result.outcome == "passed":
                        stats["owasp_categories"][category.id]["passed"] += 1

            # Track severity distribution
            for marker in ["critical", "high", "medium", "low", "info"]:
                if marker in result.markers:
                    stats["severity_distribution"][marker] += 1
                    break

        return stats

    def _print_summary(self, stats: Dict):
        """Print comprehensive test summary with OWASP categories."""
        print("\n" + "=" * 70)
        print("OWASP LLM Security Test Summary")
        print("=" * 70)

        # Overall statistics
        print(f"\nTotal Tests:  {stats['total_tests']}")
        print(f"Passed:       {stats['passed_tests']}")
        print(f"Failed:       {stats['failed_tests']}")

        # Severity distribution
        if stats["severity_distribution"]:
            print("\nSeverity Distribution:")
            for severity in ["critical", "high", "medium", "low", "info"]:
                count = stats["severity_distribution"].get(severity, 0)
                if count > 0:
                    print(f"  {severity.capitalize():12s} {count:3d}")

        # OWASP category breakdown
        if stats["owasp_categories"]:
            print("\nOWASP LLM Categories:")
            print(f"  {'Category':<8} {'Name':<35} {'Total':>5} {'Pass':>5} {'Fail':>5}")
            print("  " + "-" * 65)

            for category_id in sorted(stats["owasp_categories"].keys()):
                cat_stats = stats["owasp_categories"][category_id]
                category = get_owasp_category(f"owasp_{category_id.lower()}")
                name = category.name if category else "Unknown"

                print(
                    f"  {category_id:<8} {name:<35} "
                    f"{cat_stats['total']:>5} {cat_stats['passed']:>5} {cat_stats['failed']:>5}"
                )

        print(f"\nSARIF Report: {self.sarif_output}")
        print("=" * 70)

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session, exitstatus):
        """Generate reports at end of session."""
        if self.results:
            # Generate and print statistics
            stats = self._generate_statistics()
            self._print_summary(stats)

            # Generate reports using ReportManager
            report_manager = ReportManager(
                tool_name="pytest-sarif-demo",
                tool_version="0.1.0",
                source_root=Path.cwd(),
                output_dir=self.report_dir
            )

            # Always generate SARIF (legacy support)
            sarif_report = SARIFGenerator(
                tool_name="pytest-sarif-demo",
                tool_version="0.1.0",
                source_root=Path.cwd()
            ).generate(self.results)

            self.sarif_output.parent.mkdir(parents=True, exist_ok=True)
            self.sarif_output.write_text(sarif_report, encoding="utf-8")

            # Generate additional report formats if specified
            if self.report_formats:
                generated_files = report_manager.generate_reports(
                    results=self.results,
                    formats=self.report_formats
                )

                # Print information about generated reports
                print("\n" + "=" * 70)
                print("Generated Additional Reports:")
                print("=" * 70)
                for format_name, file_path in generated_files.items():
                    print(f"  {format_name.upper():12s} {file_path}")
                print("=" * 70)


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
    config.addinivalue_line(
        "markers",
        "owasp_llm09: OWASP LLM09 - Overreliance"
    )
    config.addinivalue_line(
        "markers",
        "owasp_llm10: OWASP LLM10 - Model Theft"
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
    group = parser.getgroup("sarif", "Security test report generation")
    group.addoption(
        "--sarif-output",
        action="store",
        dest="sarif_output",
        default=None,
        help="Path to SARIF output file (default: results/pytest-results.sarif)"
    )
    group.addoption(
        "--report-formats",
        action="store",
        dest="report_formats",
        default=None,
        help="Comma-separated list of report formats to generate (sarif,html,json,markdown)"
    )
    group.addoption(
        "--report-dir",
        action="store",
        dest="report_dir",
        default=None,
        help="Directory for output reports (default: results)"
    )

    parser.addini(
        "sarif_output",
        "Path to SARIF output file",
        default="results/pytest-results.sarif"
    )
    parser.addini(
        "report_formats",
        "Comma-separated list of report formats to generate",
        default=""
    )
    parser.addini(
        "report_dir",
        "Directory for output reports",
        default="results"
    )
