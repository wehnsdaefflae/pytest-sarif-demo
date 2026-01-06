"""Compliance report generator for mapping test results to regulatory frameworks."""

from typing import List, Dict, Set
from collections import defaultdict
import json

from .models import TestResult
from .owasp_metadata import get_owasp_markers_from_test, get_owasp_category
from .compliance_mapper import (
    get_compliance_mappings,
    get_frameworks_covered,
    get_framework_coverage,
    get_compliance_summary,
    ComplianceMapping,
)


class ComplianceReportGenerator:
    """Generates comprehensive compliance framework mapping reports."""

    def __init__(self, tool_name: str, tool_version: str):
        """Initialize compliance report generator.

        Args:
            tool_name: Name of the testing tool
            tool_version: Version of the testing tool
        """
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, results: List[TestResult]) -> str:
        """Generate HTML compliance report.

        Args:
            results: List of test results

        Returns:
            HTML content as string
        """
        # Collect OWASP markers from all tests
        all_owasp_markers = set()
        failed_owasp_markers = set()
        passed_owasp_markers = set()

        for result in results:
            owasp_markers = get_owasp_markers_from_test(result.markers)
            all_owasp_markers.update(owasp_markers)
            if result.outcome == "failed":
                failed_owasp_markers.update(owasp_markers)
            elif result.outcome == "passed":
                passed_owasp_markers.update(owasp_markers)

        # Get compliance summary
        summary = get_compliance_summary(list(all_owasp_markers))
        frameworks = get_frameworks_covered(list(all_owasp_markers))

        # Build HTML report
        html = self._generate_html_header()
        html += self._generate_executive_summary(summary, results, frameworks)
        html += self._generate_framework_sections(
            frameworks, all_owasp_markers, failed_owasp_markers, results
        )
        html += self._generate_owasp_mapping_matrix(all_owasp_markers, frameworks)
        html += self._generate_html_footer()

        return html

    def _generate_html_header(self) -> str:
        """Generate HTML header with styling."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Framework Mapping Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .content {
            padding: 40px;
        }

        .section {
            margin-bottom: 50px;
        }

        .section h2 {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }

        .executive-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .metric-card h3 {
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .metric-card .value {
            font-size: 2.5em;
            font-weight: bold;
        }

        .framework-card {
            background: white;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }

        .framework-card h3 {
            font-size: 1.5em;
            color: #667eea;
            margin-bottom: 15px;
        }

        .framework-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }

        .stat .label {
            font-size: 0.85em;
            color: #666;
            margin-bottom: 5px;
        }

        .stat .number {
            font-size: 1.8em;
            font-weight: bold;
            color: #667eea;
        }

        .control-list {
            margin-top: 20px;
        }

        .control-item {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .control-item .control-id {
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }

        .control-item .control-name {
            font-weight: 600;
            margin-bottom: 5px;
        }

        .control-item .control-desc {
            font-size: 0.9em;
            color: #666;
        }

        .control-item .owasp-link {
            display: inline-block;
            margin-top: 8px;
            padding: 4px 10px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 0.85em;
        }

        .control-item .owasp-link:hover {
            background: #5568d3;
        }

        .matrix-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 0.9em;
        }

        .matrix-table th,
        .matrix-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }

        .matrix-table th {
            background: #667eea;
            color: white;
            font-weight: 600;
            position: sticky;
            top: 0;
        }

        .matrix-table tr:nth-child(even) {
            background: #f8f9fa;
        }

        .matrix-table tr:hover {
            background: #e9ecef;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin: 2px;
        }

        .badge-success {
            background: #d4edda;
            color: #155724;
        }

        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }

        .badge-info {
            background: #d1ecf1;
            color: #0c5460;
        }

        .coverage-bar {
            width: 100%;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }

        .coverage-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
            transition: width 0.3s ease;
        }

        .footer {
            background: #f8f9fa;
            padding: 20px 40px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #e0e0e0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Compliance Framework Mapping Report</h1>
            <p>OWASP LLM Top 10 Security Testing to Regulatory Framework Alignment</p>
            <p style="margin-top: 10px; opacity: 0.8;">Generated by """ + self.tool_name + """ v""" + self.tool_version + """</p>
        </div>
        <div class="content">
"""

    def _generate_executive_summary(
        self, summary: Dict, results: List[TestResult], frameworks: Set[str]
    ) -> str:
        """Generate executive summary section."""
        total_tests = len(results)
        failed_tests = sum(1 for r in results if r.outcome == "failed")
        passed_tests = sum(1 for r in results if r.outcome == "passed")

        # Count unique controls
        total_controls = sum(s["total_controls"] for s in summary.values())

        html = """
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="executive-summary">
                    <div class="metric-card">
                        <h3>Frameworks Covered</h3>
                        <div class="value">""" + str(len(frameworks)) + """</div>
                    </div>
                    <div class="metric-card">
                        <h3>Controls Mapped</h3>
                        <div class="value">""" + str(total_controls) + """</div>
                    </div>
                    <div class="metric-card">
                        <h3>Tests Executed</h3>
                        <div class="value">""" + str(total_tests) + """</div>
                    </div>
                    <div class="metric-card">
                        <h3>Compliance Status</h3>
                        <div class="value">""" + str(int((passed_tests / total_tests * 100) if total_tests > 0 else 0)) + """%</div>
                    </div>
                </div>
                <p style="margin-top: 20px; font-size: 1.1em; line-height: 1.8;">
                    This report demonstrates how the OWASP Top 10 for LLM Applications security tests
                    align with major AI governance and cybersecurity compliance frameworks. The testing
                    coverage spans <strong>""" + str(len(frameworks)) + """ frameworks</strong> and
                    validates compliance with <strong>""" + str(total_controls) + """ security controls</strong>.
                </p>
            </div>
"""
        return html

    def _generate_framework_sections(
        self,
        frameworks: Set[str],
        all_owasp_markers: Set[str],
        failed_owasp_markers: Set[str],
        results: List[TestResult],
    ) -> str:
        """Generate detailed sections for each framework."""
        html = """
            <div class="section">
                <h2>Framework-Specific Compliance Coverage</h2>
"""

        for framework in sorted(frameworks):
            coverage = get_framework_coverage(list(all_owasp_markers), framework)
            unique_controls = list(set((m.control_id, m.control_name, m.description) for m in coverage))
            unique_categories = set(m.category for m in coverage)
            owasp_categories = set()

            # Group controls by OWASP category
            controls_by_owasp = defaultdict(list)
            for marker in all_owasp_markers:
                mappings = [m for m in get_compliance_mappings(marker) if m.framework == framework]
                if mappings:
                    owasp_categories.add(marker)
                    category = get_owasp_category(marker)
                    for mapping in mappings:
                        controls_by_owasp[marker].append(mapping)

            # Calculate coverage percentage
            coverage_pct = int((len(owasp_categories) / 10) * 100)  # 10 OWASP categories total

            html += """
                <div class="framework-card">
                    <h3>""" + framework + """</h3>
                    <div class="framework-stats">
                        <div class="stat">
                            <div class="label">Controls Covered</div>
                            <div class="number">""" + str(len(unique_controls)) + """</div>
                        </div>
                        <div class="stat">
                            <div class="label">Categories</div>
                            <div class="number">""" + str(len(unique_categories)) + """</div>
                        </div>
                        <div class="stat">
                            <div class="label">OWASP Mapped</div>
                            <div class="number">""" + str(len(owasp_categories)) + """/10</div>
                        </div>
                    </div>
                    <div class="coverage-bar">
                        <div class="coverage-fill" style="width: """ + str(coverage_pct) + """%">
                            """ + str(coverage_pct) + """% OWASP Coverage
                        </div>
                    </div>
                    <div class="control-list">
"""

            # List controls grouped by OWASP category
            for marker in sorted(controls_by_owasp.keys()):
                category = get_owasp_category(marker)
                if category:
                    status_badge = ""
                    if marker in failed_owasp_markers:
                        status_badge = '<span class="badge badge-danger">Tests Failed - Requires Attention</span>'
                    else:
                        status_badge = '<span class="badge badge-success">Tests Passed - Compliant</span>'

                    html += f"""
                        <h4 style="margin-top: 25px; color: #333; font-size: 1.1em;">
                            {category.name} ({category.id})
                            {status_badge}
                        </h4>
"""

                    for mapping in controls_by_owasp[marker]:
                        html += f"""
                        <div class="control-item">
                            <div class="control-id">{mapping.control_id} - {mapping.category}</div>
                            <div class="control-name">{mapping.control_name}</div>
                            <div class="control-desc">{mapping.description}</div>
                        </div>
"""

            html += """
                    </div>
                </div>
"""

        html += """
            </div>
"""
        return html

    def _generate_owasp_mapping_matrix(
        self, all_owasp_markers: Set[str], frameworks: Set[str]
    ) -> str:
        """Generate OWASP to framework mapping matrix."""
        html = """
            <div class="section">
                <h2>OWASP LLM Top 10 Framework Mapping Matrix</h2>
                <table class="matrix-table">
                    <thead>
                        <tr>
                            <th>OWASP Category</th>
                            <th>Frameworks</th>
                            <th>Control Count</th>
                        </tr>
                    </thead>
                    <tbody>
"""

        for marker in sorted(all_owasp_markers):
            category = get_owasp_category(marker)
            if category:
                mappings = get_compliance_mappings(marker)
                mapped_frameworks = set(m.framework for m in mappings)

                framework_badges = " ".join(
                    f'<span class="badge badge-info">{fw}</span>'
                    for fw in sorted(mapped_frameworks)
                )

                html += f"""
                        <tr>
                            <td><strong>{category.id}: {category.name}</strong></td>
                            <td>{framework_badges}</td>
                            <td><strong>{len(mappings)}</strong></td>
                        </tr>
"""

        html += """
                    </tbody>
                </table>
            </div>
"""
        return html

    def _generate_html_footer(self) -> str:
        """Generate HTML footer."""
        return """
        </div>
        <div class="footer">
            <p>This compliance mapping report demonstrates alignment between OWASP LLM security testing and major regulatory frameworks.</p>
            <p>Frameworks: NIST AI RMF, ISO/IEC 42001, EU AI Act, NIST CSF 2.0, SOC 2, ISO/IEC 27001</p>
        </div>
    </div>
</body>
</html>
"""
