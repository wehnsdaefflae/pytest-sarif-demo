"""Data models for pytest SARIF plugin."""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any


@dataclass
class TestResult:
    """Represents a pytest test result."""

    nodeid: str
    location: Tuple[str, int, str]  # (file, line, test_name)
    outcome: str  # passed/failed/skipped/error
    longrepr: Optional[str] = None
    duration: float = 0.0
    markers: List[str] = field(default_factory=list)
    properties: dict = field(default_factory=dict)

    @property
    def file_path(self) -> str:
        """Get relative file path."""
        return self.location[0]

    @property
    def line_number(self) -> int:
        """Get test line number."""
        return self.location[1]

    @property
    def test_name(self) -> str:
        """Get test function name."""
        return self.location[2]

    @property
    def docstring(self) -> Optional[str]:
        """Get test docstring from properties."""
        return self.properties.get("docstring")


@dataclass
class TrendAnalytics:
    """Represents trend analytics for test results."""

    has_history: bool
    total_runs: int = 0
    current_run: Dict[str, Any] = field(default_factory=dict)
    comparison: Dict[str, Any] = field(default_factory=dict)
    trends: Dict[str, Any] = field(default_factory=dict)
    flakiness: Dict[str, Any] = field(default_factory=dict)
    risk_score: Dict[str, Any] = field(default_factory=dict)
    improvement_rate: Optional[Dict[str, Any]] = None
    owasp_category_trends: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_improving(self) -> bool:
        """Check if tests are improving."""
        if not self.has_history or not self.comparison:
            return False
        return self.comparison.get("trend") == "improving"

    @property
    def is_degrading(self) -> bool:
        """Check if tests are degrading."""
        if not self.has_history or not self.comparison:
            return False
        return self.comparison.get("trend") == "degrading"

    @property
    def has_flaky_tests(self) -> bool:
        """Check if there are flaky tests detected."""
        return self.flakiness.get("count", 0) > 0

    @property
    def risk_level(self) -> str:
        """Get current risk level."""
        return self.risk_score.get("level", "unknown")
