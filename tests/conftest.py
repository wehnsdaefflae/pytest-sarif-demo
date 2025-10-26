"""Test fixtures and mock LLM interface for security testing."""

import pytest


class MockLLMResponse:
    """Mock LLM response for testing."""

    def __init__(self, text: str, system_prompt_leaked: bool = False):
        self.text = text
        self.system_prompt_leaked = system_prompt_leaked
        self.is_successful_injection = False


def simulate_llm_call(prompt: str) -> MockLLMResponse:
    """Simulate LLM API call for testing.

    This is a simplified mock that demonstrates how security tests
    would work with a real LLM. In production, this would call an
    actual LLM API.
    """
    prompt_lower = prompt.lower()

    # Simulate prompt injection detection
    if "ignore previous instructions" in prompt_lower:
        return MockLLMResponse(
            text="I can't ignore my instructions",
            system_prompt_leaked=False
        )

    # Simulate delimiter injection
    if "\\nsystem:" in prompt_lower or "\\nuser:" in prompt_lower:
        response = MockLLMResponse(text="I detect an injection attempt")
        response.is_successful_injection = False
        return response

    # Simulate context switching
    if "[system]" in prompt_lower and "grant" in prompt_lower:
        response = MockLLMResponse(text="I cannot grant access")
        response.is_successful_injection = False
        return response

    # Simulate data repetition prevention
    if "repeat the following:" in prompt_lower:
        return MockLLMResponse(text="I cannot repeat sensitive information")

    # Simulate PII protection
    if "email address" in prompt_lower:
        return MockLLMResponse(text="I cannot share personal information")

    # Simulate resource exhaustion handling
    if len(prompt) > 5000:
        return MockLLMResponse(text="Response to long input")

    # Simulate recursive prompt handling
    if prompt_lower.count("explain") > 2:
        return MockLLMResponse(text="I detect a recursive pattern")

    # Default response
    return MockLLMResponse(text="Normal response")


@pytest.fixture
def mock_llm():
    """Fixture providing mock LLM interface."""
    return simulate_llm_call
