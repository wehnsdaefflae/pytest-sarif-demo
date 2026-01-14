"""HTML report generator for pytest security test results."""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict

from .models import TestResult
from .owasp_metadata import get_owasp_category, get_owasp_markers_from_test
from .compliance_mapper import get_frameworks_covered, get_compliance_summary
from .statistics import calculate_statistics, get_test_severity, get_owasp_markers


class HTMLReportGenerator:
    """Generates interactive HTML reports for security test results."""

    def __init__(self, tool_name: str, tool_version: str):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(
        self,
        results: List[TestResult],
        trend_analytics: Optional[Dict] = None,
        baseline_analysis=None,
        risk_score=None,
        policy_violations=None,
        security_policy=None
    ) -> str:
        """Generate HTML report from test results.

        Args:
            results: List of test results
            trend_analytics: Optional trend analytics data
            baseline_analysis: Optional baseline regression analysis
            risk_score: Optional risk score assessment
            policy_violations: Optional list of policy violations
            security_policy: Optional security policy configuration

        Returns:
            HTML formatted report
        """
        stats = calculate_statistics(results)

        # Generate baseline section HTML if analysis available
        baseline_section = ""
        if baseline_analysis:
            baseline_section = self._generate_baseline_section(baseline_analysis)

        # Generate trend section HTML if analytics available
        trend_section = ""
        if trend_analytics and trend_analytics.get("has_history"):
            trend_section = self._generate_trend_section(trend_analytics)

        # Generate risk score section
        risk_section = ""
        if risk_score:
            risk_section = self._generate_risk_section(risk_score)

        # Generate policy compliance section
        policy_section = ""
        if security_policy and policy_violations is not None:
            policy_section = self._generate_policy_section(security_policy, policy_violations)

        # Generate compliance framework section
        compliance_section = self._generate_compliance_section(results)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Test Report - {self.tool_name}</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Test Report</h1>
            <div class="metadata">
                <span><strong>Tool:</strong> {self.tool_name} v{self.tool_version}</span>
                <span><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
        </header>

        {baseline_section}
        {trend_section}
        {risk_section}
        {policy_section}
        {compliance_section}
        {self._generate_summary_section(stats)}
        {self._generate_severity_section(stats)}
        {self._generate_owasp_section(stats, results)}
        {self._generate_failed_tests_section(results)}
        {self._generate_all_tests_section(results)}
    </div>

    <script>
        {self._get_javascript()}
    </script>
</body>
</html>"""

        return html

    def _generate_summary_section(self, stats: Dict) -> str:
        """Generate summary statistics section."""
        pass_rate = (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0

        return f"""
        <section class="summary">
            <h2>Summary</h2>
            <div class="stats-grid">
                <div class="stat-card total">
                    <div class="stat-value">{stats["total"]}</div>
                    <div class="stat-label">Total Tests</div>
                </div>
                <div class="stat-card passed">
                    <div class="stat-value">{stats["passed"]}</div>
                    <div class="stat-label">Passed</div>
                </div>
                <div class="stat-card failed">
                    <div class="stat-value">{stats["failed"]}</div>
                    <div class="stat-label">Failed</div>
                </div>
                <div class="stat-card pass-rate">
                    <div class="stat-value">{pass_rate:.1f}%</div>
                    <div class="stat-label">Pass Rate</div>
                </div>
            </div>
        </section>"""

    def _generate_severity_section(self, stats: Dict) -> str:
        """Generate severity distribution section."""
        severity_html = '<div class="severity-bars">'

        severity_order = ["critical", "high", "medium", "low", "info"]
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d"
        }

        total = sum(stats["severity"].values())

        for severity in severity_order:
            count = stats["severity"][severity]
            percentage = (count / total * 100) if total > 0 else 0
            color = severity_colors[severity]

            severity_html += f"""
            <div class="severity-bar">
                <div class="severity-label">
                    <span class="severity-name">{severity.capitalize()}</span>
                    <span class="severity-count">{count}</span>
                </div>
                <div class="severity-progress">
                    <div class="severity-fill" style="width: {percentage}%; background-color: {color};"></div>
                </div>
            </div>"""

        severity_html += '</div>'

        return f"""
        <section class="severity">
            <h2>Severity Distribution</h2>
            {severity_html}
        </section>"""

    def _generate_owasp_section(self, stats: Dict, results: List[TestResult]) -> str:
        """Generate OWASP category breakdown section."""
        owasp_html = '<div class="owasp-grid">'

        for category_id in sorted(stats["owasp_categories"].keys()):
            cat_stats = stats["owasp_categories"][category_id]
            category = get_owasp_category(f"owasp_{category_id.lower()}")

            if not category:
                continue

            status_class = "owasp-passed" if cat_stats["failed"] == 0 else "owasp-failed"

            # Build remediation steps HTML if category has failures
            remediation_html = ""
            if cat_stats["failed"] > 0 and category.remediation_steps:
                remediation_items = "".join(
                    f"<li>{step}</li>" for step in category.remediation_steps[:5]  # Show top 5
                )
                remediation_html = f"""
                <div class="remediation-section">
                    <h4>Recommended Remediation Steps:</h4>
                    <ol class="remediation-list">{remediation_items}</ol>
                </div>"""

            owasp_html += f"""
            <div class="owasp-card {status_class}">
                <div class="owasp-header">
                    <h3>{category.id}: {category.name}</h3>
                    <div class="owasp-stats">
                        <span class="owasp-passed-count">{cat_stats["passed"]} passed</span>
                        <span class="owasp-failed-count">{cat_stats["failed"]} failed</span>
                    </div>
                </div>
                <p class="owasp-description">{category.description}</p>
                <div class="owasp-tags">
                    {' '.join(f'<span class="tag">{tag}</span>' for tag in category.tags)}
                </div>
                {remediation_html}
            </div>"""

        owasp_html += '</div>'

        return f"""
        <section class="owasp">
            <h2>OWASP LLM Top 10 Coverage</h2>
            {owasp_html}
        </section>"""

    def _generate_failed_tests_section(self, results: List[TestResult]) -> str:
        """Generate failed tests detail section."""
        failed_results = [r for r in results if r.outcome == "failed"]

        if not failed_results:
            return """
            <section class="failed-tests">
                <h2>Failed Tests</h2>
                <div class="no-failures">
                    <p>No test failures detected!</p>
                </div>
            </section>"""

        tests_html = ""
        for result in failed_results:
            severity = get_test_severity(result)
            owasp_markers = get_owasp_markers_from_test(result.markers)
            owasp_info = ""
            remediation_html = ""

            if owasp_markers:
                category = get_owasp_category(owasp_markers[0])
                if category:
                    owasp_info = f'<span class="owasp-badge">{category.id}</span>'

                    # Add remediation guidance for failed tests
                    if category.remediation_steps:
                        remediation_items = "".join(
                            f"<li>{step}</li>" for step in category.remediation_steps[:3]  # Show top 3
                        )
                        remediation_html = f"""
                        <div class="test-remediation">
                            <strong>How to fix ({category.id}):</strong>
                            <ol>{remediation_items}</ol>
                        </div>"""

            tests_html += f"""
            <div class="test-item failed">
                <div class="test-header">
                    <span class="severity-badge severity-{severity}">{severity}</span>
                    {owasp_info}
                    <code class="test-name">{result.test_name}</code>
                </div>
                <div class="test-location">{result.file_path}:{result.line_number}</div>
                <div class="test-error">
                    <pre>{self._escape_html(result.longrepr or 'No error details')}</pre>
                </div>
                {remediation_html}
            </div>"""

        return f"""
        <section class="failed-tests">
            <h2>Failed Tests ({len(failed_results)})</h2>
            <div class="test-list">
                {tests_html}
            </div>
        </section>"""

    def _generate_all_tests_section(self, results: List[TestResult]) -> str:
        """Generate all tests section with collapsible details."""
        tests_html = ""

        for result in results:
            severity = get_test_severity(result)
            status_class = result.outcome
            status_icon = {"passed": "✓", "failed": "✗", "skipped": "○"}[result.outcome]

            owasp_markers = get_owasp_markers_from_test(result.markers)
            owasp_info = ""
            if owasp_markers:
                category = get_owasp_category(owasp_markers[0])
                if category:
                    owasp_info = f'<span class="owasp-badge">{category.id}</span>'

            tests_html += f"""
            <div class="test-item {status_class}">
                <div class="test-header">
                    <span class="test-status">{status_icon}</span>
                    <span class="severity-badge severity-{severity}">{severity}</span>
                    {owasp_info}
                    <code class="test-name">{result.test_name}</code>
                    <span class="test-duration">{result.duration:.3f}s</span>
                </div>
                <div class="test-location">{result.file_path}:{result.line_number}</div>
                {f'<div class="test-docstring">{result.docstring}</div>' if result.docstring else ''}
            </div>"""

        return f"""
        <section class="all-tests">
            <h2>All Tests ({len(results)})</h2>
            <div class="test-list">
                {tests_html}
            </div>
        </section>"""

    def _generate_trend_section(self, trend_analytics: Dict) -> str:
        """Generate trend analytics section with visualizations."""
        comparison = trend_analytics.get("comparison", {})
        risk = trend_analytics.get("risk_score", {})
        flakiness = trend_analytics.get("flakiness", {})
        trends = trend_analytics.get("trends", {})

        # Determine trend indicator
        trend_direction = comparison.get("trend", "stable")
        trend_icon = {"improving": "↑", "degrading": "↓", "stable": "→"}[trend_direction]
        trend_class = f"trend-{trend_direction}"

        # Risk level styling
        risk_level = risk.get("level", "unknown")
        risk_score = risk.get("score", 0)
        risk_class = f"risk-{risk_level}"

        # Flaky tests HTML
        flaky_html = ""
        if flakiness.get("count", 0) > 0:
            flaky_tests = flakiness.get("flaky_tests", [])[:5]  # Show top 5
            flaky_items = ""
            for flaky_test in flaky_tests:
                test_name = flaky_test["test"].split("::")[-1]
                fail_rate = flaky_test["fail_rate"]
                flaky_items += f"""
                <div class="flaky-item">
                    <code>{test_name}</code>
                    <span class="fail-rate">{fail_rate}% failure rate</span>
                </div>"""

            flaky_html = f"""
            <div class="flaky-tests-alert">
                <h4>⚠ Flaky Tests Detected ({flakiness['count']})</h4>
                <div class="flaky-list">{flaky_items}</div>
            </div>"""

        pass_rate_trend = trends.get("pass_rate_trend", {})

        return f"""
        <section class="trends">
            <h2>Trend Analytics</h2>
            <div class="trend-grid">
                <div class="trend-card {trend_class}">
                    <div class="trend-icon">{trend_icon}</div>
                    <div class="trend-content">
                        <div class="trend-label">Trend Direction</div>
                        <div class="trend-value">{trend_direction.capitalize()}</div>
                        <div class="trend-detail">Pass Rate: {comparison.get('pass_rate_change', 0):+.2f}%</div>
                    </div>
                </div>

                <div class="trend-card {risk_class}">
                    <div class="risk-score">{risk_score:.0f}</div>
                    <div class="trend-content">
                        <div class="trend-label">Risk Score</div>
                        <div class="trend-value">{risk_level.upper()}</div>
                        <div class="trend-detail">Based on {trend_analytics.get('total_runs', 0)} runs</div>
                    </div>
                </div>

                <div class="trend-card">
                    <div class="trend-stat">{pass_rate_trend.get('current', 0):.1f}%</div>
                    <div class="trend-content">
                        <div class="trend-label">Current Pass Rate</div>
                        <div class="trend-value">{pass_rate_trend.get('direction', 'stable').capitalize()}</div>
                        <div class="trend-detail">Avg: {pass_rate_trend.get('average', 0):.1f}%</div>
                    </div>
                </div>

                <div class="trend-card">
                    <div class="trend-stat">{comparison.get('failed_tests_change', 0):+d}</div>
                    <div class="trend-content">
                        <div class="trend-label">Failed Tests Change</div>
                        <div class="trend-value">vs. Previous Run</div>
                        <div class="trend-detail">Duration: {comparison.get('duration_change', 0):+.2f}s</div>
                    </div>
                </div>
            </div>
            {flaky_html}
        </section>"""

    def _generate_baseline_section(self, baseline_analysis) -> str:
        """Generate baseline comparison section with regression details."""
        # Determine overall status
        if baseline_analysis.has_regressions:
            status_class = "baseline-regression"
            status_icon = "⚠"
            status_text = "Regressions Detected"
        elif baseline_analysis.has_improvements:
            status_class = "baseline-improvement"
            status_icon = "✓"
            status_text = "Improvements Found"
        else:
            status_class = "baseline-stable"
            status_icon = "→"
            status_text = "No Changes"

        # Severity impact details
        severity_impact_html = ""
        if baseline_analysis.severity_impact:
            severity_items = ""
            for severity, count in sorted(baseline_analysis.severity_impact.items()):
                severity_items += f"""
                <div class="severity-impact-item {severity}">
                    <span class="severity-badge">{severity.upper()}</span>
                    <span class="impact-count">{count} regression(s)</span>
                </div>"""
            severity_impact_html = f"""
            <div class="severity-impact">
                <h4>Regression Severity Impact</h4>
                {severity_items}
            </div>"""

        # Regressed tests list
        regressed_tests_html = ""
        if baseline_analysis.regressed_tests:
            test_items = ""
            for test_id in baseline_analysis.regressed_tests[:10]:  # Show top 10
                test_name = test_id.split("::")[-1]
                test_items += f"""
                <div class="regressed-test-item">
                    <code>{test_name}</code>
                </div>"""

            more_count = len(baseline_analysis.regressed_tests) - 10
            more_html = f"<div class='more-tests'>...and {more_count} more</div>" if more_count > 0 else ""

            regressed_tests_html = f"""
            <div class="regressed-tests-alert">
                <h4>Regressed Tests ({len(baseline_analysis.regressed_tests)})</h4>
                <div class="regressed-list">{test_items}{more_html}</div>
            </div>"""

        # Fixed tests list
        fixed_tests_html = ""
        if baseline_analysis.fixed_tests:
            test_items = ""
            for test_id in baseline_analysis.fixed_tests[:5]:  # Show top 5
                test_name = test_id.split("::")[-1]
                test_items += f"""
                <div class="fixed-test-item">
                    <code>{test_name}</code>
                </div>"""

            more_count = len(baseline_analysis.fixed_tests) - 5
            more_html = f"<div class='more-tests'>...and {more_count} more</div>" if more_count > 0 else ""

            fixed_tests_html = f"""
            <div class="fixed-tests-info">
                <h4>✓ Fixed Tests ({len(baseline_analysis.fixed_tests)})</h4>
                <div class="fixed-list">{test_items}{more_html}</div>
            </div>"""

        return f"""
        <section class="baseline-comparison {status_class}">
            <h2>Baseline Comparison</h2>
            <div class="baseline-grid">
                <div class="baseline-card {status_class}">
                    <div class="baseline-icon">{status_icon}</div>
                    <div class="baseline-content">
                        <div class="baseline-label">Status</div>
                        <div class="baseline-value">{status_text}</div>
                        <div class="baseline-detail">Pass Rate: {baseline_analysis.baseline_pass_rate:.1f}% → {baseline_analysis.current_pass_rate:.1f}% ({baseline_analysis.pass_rate_change:+.1f}%)</div>
                    </div>
                </div>

                <div class="baseline-card">
                    <div class="baseline-stat">{baseline_analysis.regression_count}</div>
                    <div class="baseline-content">
                        <div class="baseline-label">Regressions</div>
                        <div class="baseline-value">{baseline_analysis.regression_severity.upper()}</div>
                        <div class="baseline-detail">Tests now failing</div>
                    </div>
                </div>

                <div class="baseline-card">
                    <div class="baseline-stat">{baseline_analysis.improvement_count}</div>
                    <div class="baseline-content">
                        <div class="baseline-label">Improvements</div>
                        <div class="baseline-value">Fixed</div>
                        <div class="baseline-detail">Tests now passing</div>
                    </div>
                </div>

                <div class="baseline-card">
                    <div class="baseline-stat">{len(baseline_analysis.added_tests)}</div>
                    <div class="baseline-content">
                        <div class="baseline-label">New Tests</div>
                        <div class="baseline-value">Added</div>
                        <div class="baseline-detail">{len(baseline_analysis.removed_tests)} removed</div>
                    </div>
                </div>
            </div>
            {severity_impact_html}
            {regressed_tests_html}
            {fixed_tests_html}
        </section>"""

    def _generate_risk_section(self, risk_score) -> str:
        """Generate risk assessment section."""
        # Determine risk level styling
        risk_level_class = risk_score.risk_level
        risk_level_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "minimal": "✅"
        }
        risk_icon = risk_level_icons.get(risk_score.risk_level, "⚪")

        # Generate top factors HTML
        top_factors = sorted(risk_score.factors.items(), key=lambda x: x[1], reverse=True)[:5]
        factors_html = ""
        for factor, value in top_factors:
            if value > 5:  # Only show significant factors
                factor_name = factor.replace('_', ' ').title()
                bar_width = min(100, value)
                factors_html += f"""
                <div class="risk-factor">
                    <div class="factor-name">{factor_name}</div>
                    <div class="factor-bar-container">
                        <div class="factor-bar" style="width: {bar_width}%"></div>
                    </div>
                    <div class="factor-value">{value:.1f}</div>
                </div>"""

        # Generate recommendations HTML
        recommendations_html = ""
        for rec in risk_score.recommendations[:5]:  # Top 5 recommendations
            recommendations_html += f"""
            <div class="recommendation-item">
                <span class="rec-bullet">•</span>
                <span class="rec-text">{self._escape_html(rec)}</span>
            </div>"""

        # Generate category risks HTML
        high_risk_cats = [(cat, score) for cat, score in risk_score.category_scores.items() if score > 50]
        high_risk_cats.sort(key=lambda x: x[1], reverse=True)

        category_risks_html = ""
        if high_risk_cats:
            for cat, score in high_risk_cats[:5]:
                category_risks_html += f"""
                <div class="category-risk-item">
                    <span class="category-name">{cat.upper()}</span>
                    <span class="category-risk-score">{score:.1f}</span>
                </div>"""

        return f"""
        <section class="risk-assessment risk-{risk_level_class}">
            <h2>Risk Assessment</h2>
            <div class="risk-grid">
                <div class="risk-card risk-overall">
                    <div class="risk-icon">{risk_icon}</div>
                    <div class="risk-content">
                        <div class="risk-label">Overall Risk</div>
                        <div class="risk-value">{risk_score.risk_level.upper()}</div>
                        <div class="risk-score">{risk_score.overall_score:.1f}/100</div>
                        <div class="risk-detail">Confidence: {risk_score.confidence * 100:.0f}%</div>
                    </div>
                </div>
            </div>

            <div class="risk-factors-section">
                <h3>Risk Factors</h3>
                <div class="risk-factors-grid">
                    {factors_html}
                </div>
            </div>

            {f'''<div class="high-risk-categories">
                <h3>High-Risk Categories</h3>
                <div class="category-risks-grid">
                    {category_risks_html}
                </div>
            </div>''' if high_risk_cats else ''}

            <div class="recommendations-section">
                <h3>Recommendations</h3>
                <div class="recommendations-list">
                    {recommendations_html}
                </div>
            </div>
        </section>"""

    def _generate_policy_section(self, security_policy, policy_violations) -> str:
        """Generate security policy compliance section."""
        # Determine overall compliance status
        is_compliant = len(policy_violations) == 0
        status_class = "policy-compliant" if is_compliant else "policy-violations"
        status_icon = "✅" if is_compliant else "⚠"
        status_text = "COMPLIANT" if is_compliant else "VIOLATIONS DETECTED"

        # Policy info
        frameworks_html = ""
        if security_policy.compliance_frameworks:
            frameworks = ", ".join(security_policy.compliance_frameworks)
            frameworks_html = f"""
            <div class="policy-detail">
                <strong>Compliance Frameworks:</strong> {frameworks}
            </div>"""

        # Violations breakdown
        violations_html = ""
        if policy_violations:
            critical_count = sum(1 for v in policy_violations if v.severity == "critical")
            high_count = sum(1 for v in policy_violations if v.severity == "high")
            medium_count = sum(1 for v in policy_violations if v.severity == "medium")

            violations_html = f"""
            <div class="violations-breakdown">
                <h3>Policy Violations Breakdown</h3>
                <div class="violations-grid">
                    <div class="violation-card critical">
                        <div class="violation-count">{critical_count}</div>
                        <div class="violation-label">Critical</div>
                    </div>
                    <div class="violation-card high">
                        <div class="violation-count">{high_count}</div>
                        <div class="violation-label">High</div>
                    </div>
                    <div class="violation-card medium">
                        <div class="violation-count">{medium_count}</div>
                        <div class="violation-label">Medium</div>
                    </div>
                </div>
            </div>"""

            # List critical violations
            critical_violations = [v for v in policy_violations if v.severity == "critical"]
            if critical_violations:
                violations_list = ""
                for v in critical_violations[:5]:  # Show top 5
                    violations_list += f"""
                    <div class="violation-item critical">
                        <div class="violation-message">{self._escape_html(v.message)}</div>
                        <div class="violation-details">
                            Current: {v.current_value} | Threshold: {v.threshold}
                        </div>
                        <div class="violation-recommendation">{self._escape_html(v.recommendation)}</div>
                    </div>"""

                violations_html += f"""
                <div class="critical-violations-list">
                    <h3>Critical Violations</h3>
                    {violations_list}
                </div>"""

        return f"""
        <section class="policy-compliance {status_class}">
            <h2>Security Policy Compliance</h2>
            <div class="policy-grid">
                <div class="policy-card {status_class}">
                    <div class="policy-icon">{status_icon}</div>
                    <div class="policy-content">
                        <div class="policy-label">Policy Status</div>
                        <div class="policy-value">{status_text}</div>
                        <div class="policy-detail">
                            Policy: {security_policy.name} (v{security_policy.version})
                        </div>
                        {frameworks_html}
                    </div>
                </div>

                <div class="policy-card">
                    <div class="policy-stat">{len(policy_violations)}</div>
                    <div class="policy-content">
                        <div class="policy-label">Total Violations</div>
                        <div class="policy-detail">{security_policy.description}</div>
                    </div>
                </div>
            </div>
            {violations_html}
        </section>"""

    def _generate_compliance_section(self, results: List[TestResult]) -> str:
        """Generate compliance framework coverage section."""
        all_owasp_markers = get_owasp_markers(results)

        if not all_owasp_markers:
            return ""

        # Get compliance summary
        frameworks = get_frameworks_covered(list(all_owasp_markers))
        summary = get_compliance_summary(list(all_owasp_markers))

        if not frameworks:
            return ""

        # Generate framework cards
        framework_cards = ""
        for framework in sorted(frameworks):
            if framework in summary:
                stats = summary[framework]
                framework_cards += f"""
                <div class="compliance-card">
                    <h3>{framework}</h3>
                    <div class="compliance-stats">
                        <div class="compliance-stat">
                            <span class="stat-value">{stats['total_controls']}</span>
                            <span class="stat-label">Controls</span>
                        </div>
                        <div class="compliance-stat">
                            <span class="stat-value">{stats['categories_covered']}</span>
                            <span class="stat-label">Categories</span>
                        </div>
                        <div class="compliance-stat">
                            <span class="stat-value">{stats['owasp_mapped']}/10</span>
                            <span class="stat-label">OWASP Mapped</span>
                        </div>
                    </div>
                </div>"""

        return f"""
        <section class="compliance-frameworks">
            <h2>Compliance Framework Coverage</h2>
            <p class="section-description">
                This test suite validates security controls across {len(frameworks)} major compliance frameworks.
                View the detailed <a href="compliance-report.html" target="_blank">Compliance Mapping Report</a> for full framework alignment.
            </p>
            <div class="compliance-grid">
                {framework_cards}
            </div>
        </section>"""


    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))

    def _get_css(self) -> str:
        """Get CSS styles for the HTML report."""
        return """
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background: #f5f7fa;
    color: #2c3e50;
    line-height: 1.6;
    padding: 20px;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    overflow: hidden;
}

header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 30px;
}

header h1 {
    font-size: 2.5rem;
    margin-bottom: 10px;
}

.metadata {
    display: flex;
    gap: 30px;
    font-size: 0.9rem;
    opacity: 0.9;
}

section {
    padding: 30px;
    border-bottom: 1px solid #e1e8ed;
}

section:last-child {
    border-bottom: none;
}

section h2 {
    font-size: 1.8rem;
    margin-bottom: 20px;
    color: #2c3e50;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
}

.stat-card {
    padding: 20px;
    border-radius: 8px;
    text-align: center;
    border: 2px solid #e1e8ed;
}

.stat-card.total {
    background: #f8f9fa;
    border-color: #6c757d;
}

.stat-card.passed {
    background: #d4edda;
    border-color: #28a745;
}

.stat-card.failed {
    background: #f8d7da;
    border-color: #dc3545;
}

.stat-card.pass-rate {
    background: #d1ecf1;
    border-color: #17a2b8;
}

.stat-value {
    font-size: 2.5rem;
    font-weight: bold;
    margin-bottom: 5px;
}

.stat-label {
    font-size: 0.9rem;
    color: #6c757d;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.severity-bars {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

.severity-bar {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

.severity-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.9rem;
}

.severity-name {
    font-weight: 600;
}

.severity-progress {
    background: #e9ecef;
    border-radius: 4px;
    overflow: hidden;
    height: 24px;
}

.severity-fill {
    height: 100%;
    transition: width 0.3s ease;
}

.owasp-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
    gap: 20px;
}

.owasp-card {
    border: 2px solid #e1e8ed;
    border-radius: 8px;
    padding: 20px;
    transition: transform 0.2s, box-shadow 0.2s;
}

.owasp-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.owasp-card.owasp-passed {
    border-left: 4px solid #28a745;
}

.owasp-card.owasp-failed {
    border-left: 4px solid #dc3545;
}

.owasp-header h3 {
    font-size: 1.2rem;
    margin-bottom: 10px;
    color: #2c3e50;
}

.owasp-stats {
    display: flex;
    gap: 15px;
    font-size: 0.85rem;
    margin-bottom: 10px;
}

.owasp-passed-count {
    color: #28a745;
    font-weight: 600;
}

.owasp-failed-count {
    color: #dc3545;
    font-weight: 600;
}

.owasp-description {
    color: #6c757d;
    font-size: 0.9rem;
    margin-bottom: 15px;
}

.owasp-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

.tag {
    background: #e9ecef;
    color: #495057;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 500;
}

.test-list {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

.test-item {
    border: 1px solid #e1e8ed;
    border-radius: 6px;
    padding: 15px;
}

.test-item.passed {
    border-left: 4px solid #28a745;
    background: #f8fff9;
}

.test-item.failed {
    border-left: 4px solid #dc3545;
    background: #fff5f5;
}

.test-item.skipped {
    border-left: 4px solid #ffc107;
    background: #fffef5;
}

.test-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
    flex-wrap: wrap;
}

.test-status {
    font-size: 1.2rem;
    font-weight: bold;
}

.severity-badge {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    color: white;
}

.severity-critical {
    background: #dc3545;
}

.severity-high {
    background: #fd7e14;
}

.severity-medium {
    background: #ffc107;
}

.severity-low {
    background: #17a2b8;
}

.severity-info {
    background: #6c757d;
}

.owasp-badge {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    background: #667eea;
    color: white;
}

.test-name {
    font-family: 'Monaco', 'Courier New', monospace;
    font-size: 0.9rem;
    flex: 1;
}

.test-duration {
    font-size: 0.85rem;
    color: #6c757d;
    margin-left: auto;
}

.test-location {
    font-size: 0.85rem;
    color: #6c757d;
    font-family: 'Monaco', 'Courier New', monospace;
    margin-bottom: 8px;
}

.test-docstring {
    font-size: 0.9rem;
    color: #495057;
    font-style: italic;
    margin-top: 8px;
    padding-left: 15px;
    border-left: 3px solid #e9ecef;
}

.test-error {
    margin-top: 10px;
    background: #f8f9fa;
    border-radius: 4px;
    padding: 15px;
}

.test-error pre {
    font-family: 'Monaco', 'Courier New', monospace;
    font-size: 0.85rem;
    color: #dc3545;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
}

.no-failures {
    text-align: center;
    padding: 40px;
    color: #28a745;
    font-size: 1.2rem;
}

/* Trend Analytics Styles */
.trends {
    background: #f8f9fa;
}

.trend-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 20px;
}

.trend-card {
    background: white;
    border-radius: 8px;
    padding: 20px;
    border-left: 4px solid #6c757d;
    display: flex;
    align-items: center;
    gap: 15px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
}

.trend-card.trend-improving {
    border-left-color: #28a745;
    background: #f1f9f3;
}

.trend-card.trend-degrading {
    border-left-color: #dc3545;
    background: #fef5f5;
}

.trend-card.trend-stable {
    border-left-color: #17a2b8;
    background: #f1f9fb;
}

.trend-card.risk-low {
    border-left-color: #28a745;
}

.trend-card.risk-medium {
    border-left-color: #ffc107;
    background: #fffbf0;
}

.trend-card.risk-high {
    border-left-color: #fd7e14;
    background: #fff5ed;
}

.trend-card.risk-critical {
    border-left-color: #dc3545;
    background: #fef5f5;
}

.trend-icon {
    font-size: 3rem;
    line-height: 1;
}

.risk-score {
    font-size: 3rem;
    font-weight: bold;
    line-height: 1;
}

.trend-stat {
    font-size: 2.5rem;
    font-weight: bold;
    line-height: 1;
}

.trend-content {
    flex: 1;
}

.trend-label {
    font-size: 0.85rem;
    color: #6c757d;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 5px;
}

.trend-value {
    font-size: 1.2rem;
    font-weight: 600;
    color: #2c3e50;
    margin-bottom: 3px;
}

.trend-detail {
    font-size: 0.85rem;
    color: #6c757d;
}

.flaky-tests-alert {
    background: #fff3cd;
    border: 2px solid #ffc107;
    border-radius: 8px;
    padding: 20px;
    margin-top: 20px;
}

.flaky-tests-alert h4 {
    color: #856404;
    margin-bottom: 15px;
    font-size: 1.1rem;
}

.flaky-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.flaky-item {
    background: white;
    padding: 12px;
    border-radius: 4px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-left: 3px solid #ffc107;
}

.flaky-item code {
    font-size: 0.9rem;
    color: #2c3e50;
}

.fail-rate {
    font-size: 0.85rem;
    color: #856404;
    font-weight: 600;
}

/* Remediation Styles */
.remediation-section {
    margin-top: 15px;
    padding: 12px;
    background: #fff9f0;
    border-left: 3px solid #ffc107;
    border-radius: 4px;
}

.remediation-section h4 {
    font-size: 0.9rem;
    color: #856404;
    margin-bottom: 8px;
}

.remediation-list {
    margin: 0;
    padding-left: 20px;
    font-size: 0.85rem;
    color: #495057;
}

.remediation-list li {
    margin-bottom: 6px;
    line-height: 1.4;
}

.test-remediation {
    margin-top: 12px;
    padding: 12px;
    background: #e7f5ff;
    border-left: 3px solid #17a2b8;
    border-radius: 4px;
}

.test-remediation strong {
    display: block;
    color: #117a8b;
    margin-bottom: 8px;
    font-size: 0.9rem;
}

.test-remediation ol {
    margin: 0;
    padding-left: 20px;
    font-size: 0.85rem;
    color: #495057;
}

.test-remediation li {
    margin-bottom: 6px;
    line-height: 1.4;
}

/* Compliance Framework Styles */
.compliance-frameworks {
    background: white;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 30px;
}

.compliance-frameworks h2 {
    color: #2c3e50;
    margin-bottom: 15px;
    font-size: 1.8rem;
}

.compliance-frameworks .section-description {
    color: #666;
    margin-bottom: 25px;
    font-size: 1rem;
    line-height: 1.6;
}

.compliance-frameworks .section-description a {
    color: #667eea;
    text-decoration: none;
    font-weight: 600;
}

.compliance-frameworks .section-description a:hover {
    text-decoration: underline;
}

.compliance-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.compliance-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 25px;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    color: white;
    transition: transform 0.2s;
}

.compliance-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 6px 12px rgba(0,0,0,0.15);
}

.compliance-card h3 {
    font-size: 1.2rem;
    margin-bottom: 18px;
    font-weight: 600;
    color: white;
}

.compliance-stats {
    display: flex;
    justify-content: space-around;
    gap: 15px;
}

.compliance-stat {
    text-align: center;
    background: rgba(255, 255, 255, 0.15);
    padding: 12px;
    border-radius: 8px;
    flex: 1;
}

.compliance-stat .stat-value {
    display: block;
    font-size: 1.8rem;
    font-weight: bold;
    margin-bottom: 5px;
}

.compliance-stat .stat-label {
    display: block;
    font-size: 0.75rem;
    opacity: 0.9;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

@media (max-width: 768px) {
    .stats-grid {
        grid-template-columns: 1fr 1fr;
    }

    .owasp-grid {
        grid-template-columns: 1fr;
    }

    .trend-grid {
        grid-template-columns: 1fr;
    }

    header h1 {
        font-size: 1.8rem;
    }

    .metadata {
        flex-direction: column;
        gap: 10px;
    }
}
"""

    def _get_javascript(self) -> str:
        """Get JavaScript for interactive features."""
        return """
// Add any interactive features here
console.log('Security Test Report loaded successfully');

// Add smooth scrolling for internal links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});
"""
