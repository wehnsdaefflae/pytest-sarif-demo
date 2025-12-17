"""JSON summary report generator for pytest security test results."""

import json
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict

from .models import TestResult
from .owasp_metadata import get_owasp_category, get_owasp_markers_from_test, get_cwe_tags


class JSONSummaryGenerator:
    """Generates comprehensive JSON summary reports for security test results."""

    def __init__(self, tool_name: str, tool_version: str):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, results: List[TestResult]) -> str:
        """Generate JSON summary from test results."""
        summary = {
            "metadata": {
                "tool": self.tool_name,
                "version": self.tool_version,
                "generated_at": datetime.now().isoformat(),
                "report_format": "json-summary-v1.0"
            },
            "summary": self._generate_summary(results),
            "severity_distribution": self._generate_severity_distribution(results),
            "owasp_coverage": self._generate_owasp_coverage(results),
            "test_results": self._generate_test_results(results),
            "failures": self._generate_failures(results)
        }

        return json.dumps(summary, indent=2, ensure_ascii=False)

    def _generate_summary(self, results: List[TestResult]) -> Dict[str, Any]:
        """Generate overall summary statistics."""
        total = len(results)
        passed = sum(1 for r in results if r.outcome == "passed")
        failed = sum(1 for r in results if r.outcome == "failed")
        skipped = sum(1 for r in results if r.outcome == "skipped")

        return {
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "pass_rate": round((passed / total * 100), 2) if total > 0 else 0,
            "fail_rate": round((failed / total * 100), 2) if total > 0 else 0,
            "total_duration": round(sum(r.duration for r in results), 3)
        }

    def _generate_severity_distribution(self, results: List[TestResult]) -> Dict[str, int]:
        """Generate severity distribution statistics."""
        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unspecified": 0}

        for result in results:
            severity_found = False
            for severity in ["critical", "high", "medium", "low", "info"]:
                if severity in result.markers:
                    severity_dist[severity] += 1
                    severity_found = True
                    break

            if not severity_found:
                severity_dist["unspecified"] += 1

        return severity_dist

    def _generate_owasp_coverage(self, results: List[TestResult]) -> Dict[str, Any]:
        """Generate OWASP category coverage statistics."""
        owasp_stats = defaultdict(lambda: {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "category_name": "",
            "description": "",
            "cwe_ids": [],
            "tags": []
        })

        for result in results:
            owasp_markers = get_owasp_markers_from_test(result.markers)
            for marker in owasp_markers:
                category = get_owasp_category(marker)
                if category:
                    cat_id = category.id
                    owasp_stats[cat_id]["category_name"] = category.name
                    owasp_stats[cat_id]["description"] = category.description
                    owasp_stats[cat_id]["cwe_ids"] = category.cwe_ids
                    owasp_stats[cat_id]["tags"] = category.tags
                    owasp_stats[cat_id]["total_tests"] += 1

                    if result.outcome == "passed":
                        owasp_stats[cat_id]["passed"] += 1
                    elif result.outcome == "failed":
                        owasp_stats[cat_id]["failed"] += 1
                    elif result.outcome == "skipped":
                        owasp_stats[cat_id]["skipped"] += 1

        # Calculate pass rates for each category
        for cat_id, stats in owasp_stats.items():
            total = stats["total_tests"]
            if total > 0:
                stats["pass_rate"] = round((stats["passed"] / total * 100), 2)
            else:
                stats["pass_rate"] = 0

        return dict(owasp_stats)

    def _generate_test_results(self, results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate detailed test results."""
        test_results = []

        for result in results:
            owasp_markers = get_owasp_markers_from_test(result.markers)
            owasp_categories = []

            for marker in owasp_markers:
                category = get_owasp_category(marker)
                if category:
                    owasp_categories.append({
                        "id": category.id,
                        "name": category.name
                    })

            severity = self._get_test_severity(result)
            cwe_ids = get_cwe_tags(result.markers)

            test_results.append({
                "name": result.test_name,
                "file": result.file_path,
                "line": result.line_number,
                "outcome": result.outcome,
                "duration": round(result.duration, 3),
                "severity": severity,
                "owasp_categories": owasp_categories,
                "cwe_ids": cwe_ids,
                "docstring": result.docstring,
                "markers": result.markers
            })

        return test_results

    def _generate_failures(self, results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate detailed failure information."""
        failures = []

        for result in results:
            if result.outcome == "failed":
                owasp_markers = get_owasp_markers_from_test(result.markers)
                owasp_category = None

                if owasp_markers:
                    category = get_owasp_category(owasp_markers[0])
                    if category:
                        owasp_category = {
                            "id": category.id,
                            "name": category.name,
                            "description": category.description
                        }

                failures.append({
                    "test_name": result.test_name,
                    "file": result.file_path,
                    "line": result.line_number,
                    "severity": self._get_test_severity(result),
                    "owasp_category": owasp_category,
                    "error_message": result.longrepr,
                    "duration": round(result.duration, 3)
                })

        return failures

    def _get_test_severity(self, result: TestResult) -> str:
        """Extract severity from test markers."""
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in result.markers:
                return severity
        return "unspecified"
