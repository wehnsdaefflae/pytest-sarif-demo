"""Centralized statistics calculation for test results."""

from typing import List, Dict
from collections import defaultdict
from .models import TestResult
from .owasp_metadata import get_owasp_category, get_owasp_markers_from_test


def get_test_severity(result: TestResult) -> str:
    """Extract severity level from test markers."""
    for severity in ["critical", "high", "medium", "low", "info"]:
        if severity in result.markers:
            return severity
    return "medium"


def calculate_statistics(results: List[TestResult]) -> Dict:
    """Calculate comprehensive statistics from test results.

    Returns a unified statistics dictionary used by all report generators.
    """
    stats = {
        "total": len(results),
        "passed": sum(1 for r in results if r.outcome == "passed"),
        "failed": sum(1 for r in results if r.outcome == "failed"),
        "skipped": sum(1 for r in results if r.outcome == "skipped"),
        "owasp_categories": defaultdict(lambda: {"total": 0, "failed": 0, "passed": 0}),
        "severity_distribution": defaultdict(int),
        "by_severity": defaultdict(lambda: {"total": 0, "failed": 0, "passed": 0}),
    }

    for result in results:
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
        severity = get_test_severity(result)
        stats["severity_distribution"][severity] += 1
        stats["by_severity"][severity]["total"] += 1
        if result.outcome == "failed":
            stats["by_severity"][severity]["failed"] += 1
        elif result.outcome == "passed":
            stats["by_severity"][severity]["passed"] += 1

    return stats
