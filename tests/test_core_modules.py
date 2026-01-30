"""Unit tests for core plugin modules.

Tests the foundational components: models, statistics, and constants.
These tests validate the plugin's internal logic independent of pytest hooks.
"""

import pytest
from pytest_sarif.models import TestResult
from pytest_sarif.statistics import (
    calculate_statistics,
    get_test_severity,
    get_owasp_markers,
    get_coverage_gaps,
)
from pytest_sarif.constants import (
    SEVERITY_ORDER,
    SARIF_SEVERITY_MAP,
    SEVERITY_SCORES,
    SEVERITY_EMOJI,
    SEVERITY_COLORS_HEX,
    SEVERITY_BADGE_COLORS,
    RISK_LEVEL_EMOJI,
)


# =============================================================================
# TestResult Model Tests
# =============================================================================

class TestTestResultModel:
    """Tests for the TestResult dataclass."""

    def test_basic_creation(self):
        """Test creating a basic TestResult."""
        result = TestResult(
            nodeid="tests/test_example.py::test_function",
            location=("tests/test_example.py", 10, "test_function"),
            outcome="passed",
        )
        assert result.nodeid == "tests/test_example.py::test_function"
        assert result.outcome == "passed"
        assert result.file_path == "tests/test_example.py"
        assert result.line_number == 10
        assert result.test_name == "test_function"

    def test_failed_result_with_longrepr(self):
        """Test failed result includes error representation."""
        result = TestResult(
            nodeid="tests/test_example.py::test_failure",
            location=("tests/test_example.py", 20, "test_failure"),
            outcome="failed",
            longrepr="AssertionError: Expected True but got False",
        )
        assert result.outcome == "failed"
        assert "AssertionError" in result.longrepr

    def test_result_with_markers(self):
        """Test result with security markers."""
        result = TestResult(
            nodeid="tests/test_security.py::test_injection",
            location=("tests/test_security.py", 15, "test_injection"),
            outcome="passed",
            markers=["security", "owasp_llm01", "critical"],
        )
        assert "security" in result.markers
        assert "owasp_llm01" in result.markers
        assert "critical" in result.markers

    def test_result_with_docstring(self):
        """Test result with docstring in properties."""
        result = TestResult(
            nodeid="tests/test_example.py::test_documented",
            location=("tests/test_example.py", 30, "test_documented"),
            outcome="passed",
            properties={"docstring": "This test validates input sanitization."},
        )
        assert result.docstring == "This test validates input sanitization."

    def test_result_without_docstring(self):
        """Test result without docstring returns None."""
        result = TestResult(
            nodeid="tests/test_example.py::test_undocumented",
            location=("tests/test_example.py", 40, "test_undocumented"),
            outcome="passed",
        )
        assert result.docstring is None

    def test_result_duration(self):
        """Test result captures duration."""
        result = TestResult(
            nodeid="tests/test_example.py::test_slow",
            location=("tests/test_example.py", 50, "test_slow"),
            outcome="passed",
            duration=2.5,
        )
        assert result.duration == 2.5


# =============================================================================
# Statistics Module Tests
# =============================================================================

class TestGetTestSeverity:
    """Tests for severity extraction from markers."""

    def test_critical_severity(self):
        """Test critical severity extraction."""
        result = TestResult(
            nodeid="test::test_critical",
            location=("test.py", 1, "test_critical"),
            outcome="failed",
            markers=["security", "critical"],
        )
        assert get_test_severity(result) == "critical"

    def test_high_severity(self):
        """Test high severity extraction."""
        result = TestResult(
            nodeid="test::test_high",
            location=("test.py", 1, "test_high"),
            outcome="failed",
            markers=["security", "high"],
        )
        assert get_test_severity(result) == "high"

    def test_medium_severity(self):
        """Test medium severity extraction."""
        result = TestResult(
            nodeid="test::test_medium",
            location=("test.py", 1, "test_medium"),
            outcome="failed",
            markers=["security", "medium"],
        )
        assert get_test_severity(result) == "medium"

    def test_low_severity(self):
        """Test low severity extraction."""
        result = TestResult(
            nodeid="test::test_low",
            location=("test.py", 1, "test_low"),
            outcome="failed",
            markers=["security", "low"],
        )
        assert get_test_severity(result) == "low"

    def test_info_severity(self):
        """Test info severity extraction."""
        result = TestResult(
            nodeid="test::test_info",
            location=("test.py", 1, "test_info"),
            outcome="failed",
            markers=["security", "info"],
        )
        assert get_test_severity(result) == "info"

    def test_default_severity(self):
        """Test default medium severity when no marker present."""
        result = TestResult(
            nodeid="test::test_default",
            location=("test.py", 1, "test_default"),
            outcome="failed",
            markers=["security"],
        )
        assert get_test_severity(result) == "medium"

    def test_highest_severity_wins(self):
        """Test that highest severity marker is selected."""
        result = TestResult(
            nodeid="test::test_multiple",
            location=("test.py", 1, "test_multiple"),
            outcome="failed",
            markers=["low", "critical", "medium"],
        )
        # Critical comes first in SEVERITY_ORDER, so it wins
        assert get_test_severity(result) == "critical"


class TestCalculateStatistics:
    """Tests for statistics calculation."""

    @pytest.fixture
    def sample_results(self):
        """Create sample test results for statistics testing."""
        return [
            TestResult(
                nodeid="test::test_pass1",
                location=("test.py", 1, "test_pass1"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
                duration=0.1,
            ),
            TestResult(
                nodeid="test::test_pass2",
                location=("test.py", 10, "test_pass2"),
                outcome="passed",
                markers=["owasp_llm01", "high"],
                duration=0.2,
            ),
            TestResult(
                nodeid="test::test_fail1",
                location=("test.py", 20, "test_fail1"),
                outcome="failed",
                markers=["owasp_llm02", "critical"],
                duration=0.15,
            ),
            TestResult(
                nodeid="test::test_skip1",
                location=("test.py", 30, "test_skip1"),
                outcome="skipped",
                markers=["owasp_llm03", "low"],
                duration=0.0,
            ),
        ]

    def test_basic_counts(self, sample_results):
        """Test basic pass/fail/skip counts."""
        stats = calculate_statistics(sample_results)
        assert stats["total"] == 4
        assert stats["passed"] == 2
        assert stats["failed"] == 1
        assert stats["skipped"] == 1

    def test_pass_rate(self, sample_results):
        """Test pass rate calculation."""
        stats = calculate_statistics(sample_results)
        assert stats["pass_rate"] == 50.0  # 2 passed out of 4

    def test_fail_rate(self, sample_results):
        """Test fail rate calculation."""
        stats = calculate_statistics(sample_results)
        assert stats["fail_rate"] == 25.0  # 1 failed out of 4

    def test_total_duration(self, sample_results):
        """Test total duration calculation."""
        stats = calculate_statistics(sample_results)
        assert stats["total_duration"] == 0.45  # 0.1 + 0.2 + 0.15 + 0.0

    def test_severity_distribution(self, sample_results):
        """Test severity distribution counts."""
        stats = calculate_statistics(sample_results)
        assert stats["severity_distribution"]["critical"] == 2
        assert stats["severity_distribution"]["high"] == 1
        assert stats["severity_distribution"]["low"] == 1

    def test_owasp_categories(self, sample_results):
        """Test OWASP category tracking."""
        stats = calculate_statistics(sample_results)
        assert "LLM01" in stats["owasp_categories"]
        assert stats["owasp_categories"]["LLM01"]["total"] == 2
        assert stats["owasp_categories"]["LLM01"]["passed"] == 2
        assert stats["owasp_categories"]["LLM01"]["failed"] == 0

    def test_empty_results(self):
        """Test handling of empty results."""
        stats = calculate_statistics([])
        assert stats["total"] == 0
        assert stats["passed"] == 0
        assert stats["pass_rate"] == 0

    def test_all_passed(self):
        """Test statistics when all tests pass."""
        results = [
            TestResult(
                nodeid=f"test::test_pass{i}",
                location=("test.py", i, f"test_pass{i}"),
                outcome="passed",
                markers=["medium"],
            )
            for i in range(5)
        ]
        stats = calculate_statistics(results)
        assert stats["pass_rate"] == 100.0
        assert stats["failed"] == 0

    def test_all_failed(self):
        """Test statistics when all tests fail."""
        results = [
            TestResult(
                nodeid=f"test::test_fail{i}",
                location=("test.py", i, f"test_fail{i}"),
                outcome="failed",
                markers=["critical"],
            )
            for i in range(3)
        ]
        stats = calculate_statistics(results)
        assert stats["pass_rate"] == 0.0
        assert stats["failed"] == 3


class TestGetOwaspMarkers:
    """Tests for OWASP marker extraction."""

    def test_extract_owasp_markers(self):
        """Test extracting OWASP markers from results."""
        results = [
            TestResult(
                nodeid="test::test1",
                location=("test.py", 1, "test1"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
            ),
            TestResult(
                nodeid="test::test2",
                location=("test.py", 10, "test2"),
                outcome="passed",
                markers=["owasp_llm02", "high"],
            ),
            TestResult(
                nodeid="test::test3",
                location=("test.py", 20, "test3"),
                outcome="passed",
                markers=["owasp_llm01", "medium"],  # Duplicate category
            ),
        ]
        markers = get_owasp_markers(results)
        assert "owasp_llm01" in markers
        assert "owasp_llm02" in markers
        assert len(markers) == 2  # Deduplicated

    def test_no_owasp_markers(self):
        """Test results without OWASP markers."""
        results = [
            TestResult(
                nodeid="test::test1",
                location=("test.py", 1, "test1"),
                outcome="passed",
                markers=["security", "unit"],
            ),
        ]
        markers = get_owasp_markers(results)
        assert len(markers) == 0


class TestGetCoverageGaps:
    """Tests for coverage gap analysis."""

    def test_partial_coverage(self):
        """Test identifying untested OWASP categories."""
        results = [
            TestResult(
                nodeid="test::test1",
                location=("test.py", 1, "test1"),
                outcome="passed",
                markers=["owasp_llm01"],
            ),
            TestResult(
                nodeid="test::test2",
                location=("test.py", 10, "test2"),
                outcome="passed",
                markers=["owasp_llm02"],
            ),
        ]
        gaps = get_coverage_gaps(results)
        assert gaps["categories_tested"] == 2
        assert gaps["categories_untested"] == 8  # 10 total - 2 tested
        assert gaps["total_categories"] == 10

    def test_coverage_percent(self):
        """Test coverage percentage calculation."""
        results = [
            TestResult(
                nodeid=f"test::test{i}",
                location=("test.py", i, f"test{i}"),
                outcome="passed",
                markers=[f"owasp_llm{str(i).zfill(2)}"],
            )
            for i in range(1, 6)  # Test 5 categories
        ]
        gaps = get_coverage_gaps(results)
        assert gaps["coverage_percent"] == 50.0  # 5 out of 10


# =============================================================================
# Constants Module Tests
# =============================================================================

class TestConstants:
    """Tests for shared constants."""

    def test_severity_order_completeness(self):
        """Test all severity levels are defined."""
        expected = {"critical", "high", "medium", "low", "info"}
        assert set(SEVERITY_ORDER) == expected
        assert len(SEVERITY_ORDER) == 5

    def test_severity_order_precedence(self):
        """Test severity order from highest to lowest."""
        assert SEVERITY_ORDER[0] == "critical"
        assert SEVERITY_ORDER[-1] == "info"

    def test_sarif_severity_map_completeness(self):
        """Test SARIF severity mapping covers all levels."""
        for severity in SEVERITY_ORDER:
            assert severity in SARIF_SEVERITY_MAP

    def test_sarif_severity_map_values(self):
        """Test SARIF severity values are valid."""
        valid_levels = {"error", "warning", "note", "none"}
        for level in SARIF_SEVERITY_MAP.values():
            assert level in valid_levels

    def test_severity_scores_are_numeric(self):
        """Test severity scores can be parsed as floats."""
        for score in SEVERITY_SCORES.values():
            assert float(score) >= 0.0
            assert float(score) <= 10.0

    def test_severity_emoji_completeness(self):
        """Test all severities have emoji mappings."""
        for severity in SEVERITY_ORDER:
            assert severity in SEVERITY_EMOJI
            assert len(SEVERITY_EMOJI[severity]) > 0

    def test_hex_colors_are_valid(self):
        """Test hex colors are properly formatted."""
        import re
        hex_pattern = re.compile(r"^#[0-9a-fA-F]{6}$")
        for color in SEVERITY_COLORS_HEX.values():
            assert hex_pattern.match(color), f"Invalid hex color: {color}"

    def test_badge_colors_are_strings(self):
        """Test badge colors are non-empty strings."""
        for color in SEVERITY_BADGE_COLORS.values():
            assert isinstance(color, str)
            assert len(color) > 0

    def test_risk_level_emoji_completeness(self):
        """Test risk levels have emoji mappings."""
        expected_levels = {"critical", "high", "medium", "low", "minimal"}
        assert set(RISK_LEVEL_EMOJI.keys()) == expected_levels
