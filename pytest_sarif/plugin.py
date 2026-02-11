"""Pytest plugin for SARIF report generation."""

import pytest
from pathlib import Path
from typing import List, Optional

from .sarif_generator import SARIFGenerator
from .models import TestResult
from .report_manager import ReportManager
from .trend_tracker import TrendTracker
from .baseline_manager import BaselineManager
from .policy_config import PolicyLoader, PolicyValidator
from .risk_scorer import RiskScoringEngine
from .statistics import calculate_statistics
from .console_summary import generate_console_summary


class SARIFPlugin:
    """Pytest plugin for SARIF report generation."""

    def __init__(self, config):
        self.config = config
        self.results: List[TestResult] = []
        self.sarif_output: Optional[Path] = None
        self.report_formats: List[str] = []
        self.report_dir: Path = Path("results")
        self.enable_trends: bool = True

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

        # Enable/disable trend tracking
        self.enable_trends = config.getoption("--enable-trends", True)
        if self.enable_trends:
            trend_file = self.report_dir / "test-history.json"
            self.trend_tracker = TrendTracker(trend_file)
        else:
            self.trend_tracker = None

        # Baseline management
        baseline_file = self.report_dir / "baseline.json"
        self.baseline_manager = BaselineManager(baseline_file)
        self.baseline_save = config.getoption("--save-baseline", False)
        self.baseline_compare = config.getoption("--compare-baseline", False)
        self.baseline_update = config.getoption("--update-baseline", False)

        # Security policy management
        policy_file = config.getoption("--security-policy", None)
        if policy_file:
            self.security_policy = PolicyLoader.load_from_file(Path(policy_file))
        else:
            # Load default balanced policy
            self.security_policy = PolicyLoader.load_default()

        self.enable_policy = config.getoption("--enable-policy", False)
        self.risk_threshold = config.getoption("--risk-threshold", None)
        self.risk_scorer = RiskScoringEngine()

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
        """Generate reports at end of session."""
        if self.results:
            # Generate statistics
            stats = calculate_statistics(self.results)

            # Get trend analytics if enabled
            trend_analytics = None
            if self.trend_tracker:
                trend_analytics = self.trend_tracker.get_trend_analytics(self.results)

            # Baseline comparison
            baseline_analysis = None
            if self.baseline_compare or self.baseline_update:
                baseline_analysis = self.baseline_manager.compare_with_baseline(self.results)
                if baseline_analysis is None:
                    print("\n⚠ Warning: No baseline found for comparison. Use --save-baseline to create one.")

            # Calculate risk score
            risk_score = self.risk_scorer.calculate_risk(
                results=self.results,
                statistics=stats,
                trend_data=trend_analytics,
                baseline_analysis=baseline_analysis.__dict__ if baseline_analysis else None,
            )
            stats["risk_score"] = risk_score.overall_score

            # Validate against security policy
            policy_violations = None
            if self.enable_policy:
                validator = PolicyValidator(self.security_policy)
                policy_compliant = validator.validate(self.results, stats)
                policy_violations = validator.violations

                # Add policy info to stats
                stats["policy_compliant"] = policy_compliant
                stats["policy_violations"] = len(policy_violations)

            print(generate_console_summary(
                self.results,
                risk_score=risk_score,
                trend_analytics=trend_analytics,
                baseline_analysis=baseline_analysis,
                policy_violations=policy_violations,
                sarif_path=str(self.sarif_output),
            ))

            # Save or update baseline if requested
            if self.baseline_save or (self.baseline_update and baseline_analysis):
                baseline_path = self.baseline_manager.save_baseline(self.results)
                action = "Updated" if self.baseline_update else "Saved"
                print(f"\n{action} baseline: {baseline_path}")

            # Save test results to history for trend tracking
            if self.trend_tracker:
                self.trend_tracker.save_test_run(self.results)

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
            ).generate(self.results, baseline_analysis)

            self.sarif_output.parent.mkdir(parents=True, exist_ok=True)
            self.sarif_output.write_text(sarif_report, encoding="utf-8")

            # Generate additional report formats if specified
            if self.report_formats:
                # Pass trend analytics and baseline analysis to report manager
                generated_files = report_manager.generate_reports(
                    results=self.results,
                    formats=self.report_formats,
                    trend_analytics=trend_analytics,
                    baseline_analysis=baseline_analysis,
                    risk_score=risk_score,
                    policy_violations=policy_violations,
                    security_policy=self.security_policy if self.enable_policy else None,
                )

                # Print information about generated reports
                print("\n" + "=" * 70)
                print("Generated Additional Reports:")
                print("=" * 70)
                for format_name, file_path in generated_files.items():
                    print(f"  {format_name.upper():12s} {file_path}")
                print("=" * 70)

            # Exit with error if risk score exceeds threshold
            if self.risk_threshold is not None and risk_score.overall_score > self.risk_threshold:
                print("\n" + "=" * 70)
                print(
                    f"❌ BUILD FAILED: Risk score {risk_score.overall_score:.1f} "
                    f"exceeds threshold {self.risk_threshold:.1f}"
                )
                print("=" * 70)
                session.exitstatus = 1

            # Exit with error if policy violations and enforcement is enabled
            if self.enable_policy and policy_violations:
                if self.security_policy.fail_on_policy_violation and not self.security_policy.warning_only:
                    print("\n" + "=" * 70)
                    print("❌ BUILD FAILED: Security policy violations detected")
                    print("=" * 70)
                    session.exitstatus = 1


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
    group.addoption(
        "--enable-trends",
        action="store_true",
        dest="enable_trends",
        default=True,
        help="Enable historical trend tracking (default: True)"
    )
    group.addoption(
        "--disable-trends",
        action="store_false",
        dest="enable_trends",
        help="Disable historical trend tracking"
    )
    group.addoption(
        "--save-baseline",
        action="store_true",
        dest="save_baseline",
        default=False,
        help="Save current test results as baseline for future comparisons"
    )
    group.addoption(
        "--compare-baseline",
        action="store_true",
        dest="compare_baseline",
        default=False,
        help="Compare current results with saved baseline and report regressions"
    )
    group.addoption(
        "--update-baseline",
        action="store_true",
        dest="update_baseline",
        default=False,
        help="Update baseline with current results after comparison"
    )
    group.addoption(
        "--security-policy",
        action="store",
        dest="security_policy",
        default=None,
        help="Path to security policy JSON file (e.g., policies/healthcare-hipaa.json)"
    )
    group.addoption(
        "--enable-policy",
        action="store_true",
        dest="enable_policy",
        default=False,
        help="Enable security policy validation and enforcement"
    )
    group.addoption(
        "--risk-threshold",
        action="store",
        dest="risk_threshold",
        type=float,
        default=None,
        help="Maximum acceptable risk score (0-100). Build fails if exceeded."
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
