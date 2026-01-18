"""Test fixtures and mock LLM interface for security testing."""

import pytest


# =============================================================================
# Base Mock Classes - Reduce duplication across all mock result types
# =============================================================================

class MockResult:
    """Base mock result class with dynamic attribute initialization."""

    def __init__(self, **defaults):
        for key, value in defaults.items():
            setattr(self, key, value)


# =============================================================================
# OWASP LLM01: Prompt Injection Mocks
# =============================================================================

class MockLLMResponse(MockResult):
    """Mock LLM response for testing."""

    def __init__(self, text: str = "", system_prompt_leaked: bool = False):
        super().__init__(
            text=text,
            system_prompt_leaked=system_prompt_leaked,
            is_successful_injection=False
        )


class MockLLMToolResponse(MockResult):
    """Mock LLM response for tool/plugin use testing."""

    def __init__(self, text: str = ""):
        super().__init__(
            text=text,
            tool_executed_unsafe_command=False,
            sql_injection_succeeded=False,
            unauthorized_access_granted=False,
            path_traversal_succeeded=False,
            dangerous_operation_allowed=False
        )


def simulate_llm_call(prompt: str) -> MockLLMResponse:
    """Simulate LLM API call for testing prompt injection defenses."""
    prompt_lower = prompt.lower()

    if "ignore previous instructions" in prompt_lower:
        return MockLLMResponse(text="I can't ignore my instructions")

    if "\\nsystem:" in prompt_lower or "\\nuser:" in prompt_lower:
        response = MockLLMResponse(text="I detect an injection attempt")
        return response

    if "[system]" in prompt_lower and "grant" in prompt_lower:
        return MockLLMResponse(text="I cannot grant access")

    if "repeat the following:" in prompt_lower:
        return MockLLMResponse(text="I cannot repeat sensitive information")

    if "email address" in prompt_lower:
        return MockLLMResponse(text="I cannot share personal information")

    if len(prompt) > 5000:
        return MockLLMResponse(text="Response to long input")

    if prompt_lower.count("explain") > 2:
        return MockLLMResponse(text="I detect a recursive pattern")

    return MockLLMResponse(text="Normal response")


@pytest.fixture
def mock_llm():
    """Fixture providing mock LLM interface."""
    return simulate_llm_call


def simulate_llm_with_tools(prompt: str) -> MockLLMToolResponse:
    """Simulate LLM with tool/plugin execution for security testing."""
    prompt_lower = prompt.lower()

    if ";" in prompt or "&&" in prompt or "|" in prompt:
        response = MockLLMToolResponse(text="Command blocked for safety")
        return response

    if "' or" in prompt_lower or "1'='1" in prompt_lower:
        return MockLLMToolResponse(text="Invalid input detected")

    if "without authentication" in prompt_lower:
        return MockLLMToolResponse(text="Authentication required")

    if "../" in prompt or "etc/passwd" in prompt_lower:
        return MockLLMToolResponse(text="Invalid file path")

    if "delete system" in prompt_lower or "rm -rf" in prompt_lower:
        return MockLLMToolResponse(text="Operation not permitted")

    return MockLLMToolResponse(text="Tool operation completed safely")


@pytest.fixture
def mock_llm_with_tools():
    """Fixture providing mock LLM with tool execution interface."""
    return simulate_llm_with_tools


def simulate_llm_with_system(prompt: str) -> MockLLMResponse:
    """Simulate LLM with system prompt protection."""
    prompt_lower = prompt.lower()

    leak_keywords = [
        "your instructions", "system prompt", "your prompt",
        "original instructions", "repeat your", "show me your",
        "what are your instructions", "text above",
        "base64 encode your", "translate your instructions"
    ]

    if any(keyword in prompt_lower for keyword in leak_keywords):
        return MockLLMResponse(text="I cannot share my system instructions.")

    if "you are now a user" in prompt_lower or "you are a user" in prompt_lower:
        return MockLLMResponse(text="I maintain my role as an AI assistant.")

    return MockLLMResponse(text="I'm here to help! How can I assist you today?")


@pytest.fixture
def mock_llm_with_system():
    """Fixture providing mock LLM with system prompt protection."""
    return simulate_llm_with_system


# =============================================================================
# OWASP LLM03: Supply Chain Vulnerability Mocks
# =============================================================================

class MockModelLoadResult(MockResult):
    """Mock result for model loading operations."""

    def __init__(self):
        super().__init__(
            checksum_verified=False,
            model_loaded=False,
            provenance_verified=False,
            sbom_present=False,
            signature_verified=False
        )


class MockPluginLoadResult(MockResult):
    """Mock result for plugin loading operations."""

    def __init__(self):
        super().__init__(signature_verified=False, plugin_loaded=False)


class MockTrainingResult(MockResult):
    """Mock result for training pipeline operations."""

    def __init__(self):
        super().__init__(anomaly_detected=False, training_completed=False)


class MockScanResult(MockResult):
    """Mock result for dependency scanning."""

    def __init__(self):
        super().__init__(vulnerabilities_checked=False, vulnerabilities=[])


class MockModelAnalysisResult(MockResult):
    """Mock result for model analysis."""

    def __init__(self):
        super().__init__(behavioral_analysis_completed=False, backdoor_detected=False)


def simulate_model_loader(model_path: str) -> MockModelLoadResult:
    """Simulate model loading with security checks."""
    result = MockModelLoadResult()

    if "suspicious" in model_path:
        result.checksum_verified = True
        result.model_loaded = False
    elif "unknown-source" in model_path:
        result.checksum_verified = True
        result.provenance_verified = True
        result.model_loaded = False
    elif "without-sbom" in model_path:
        result.checksum_verified = True
        result.provenance_verified = True
        result.sbom_present = True
        result.model_loaded = False
    else:
        result.checksum_verified = True
        result.provenance_verified = True
        result.sbom_present = True
        result.model_loaded = True

    return result


@pytest.fixture
def mock_model_loader():
    """Fixture for model loading security tests."""
    return simulate_model_loader


class MockPluginSystem:
    """Mock plugin system with security validation."""

    def load_plugin(self, plugin_name: str) -> MockPluginLoadResult:
        """Load plugin with signature verification."""
        result = MockPluginLoadResult()
        result.signature_verified = True
        result.plugin_loaded = "untrusted" not in plugin_name
        return result


@pytest.fixture
def mock_plugin_system():
    """Fixture for plugin system security tests."""
    return MockPluginSystem()


class MockTrainingPipeline:
    """Mock training pipeline with data validation."""

    def validate_data(self, data: list) -> MockTrainingResult:
        """Validate training data for anomalies."""
        result = MockTrainingResult()

        for item in data:
            if "backdoor trigger" in item.get("text", "").lower():
                result.anomaly_detected = True
                return result

        result.training_completed = True
        return result


@pytest.fixture
def mock_training_pipeline():
    """Fixture for training pipeline security tests."""
    return MockTrainingPipeline()


class MockDependencyScanner:
    """Mock dependency scanner for vulnerability detection."""

    def scan(self, dependencies: list) -> MockScanResult:
        """Scan dependencies for known vulnerabilities."""
        result = MockScanResult()
        result.vulnerabilities_checked = True

        for dep in dependencies:
            if "4.0.0" in dep or "1.8.0" in dep or "1.19.0" in dep:
                result.vulnerabilities.append({
                    "package": dep.split("==")[0],
                    "severity": "high",
                    "cve": "CVE-2024-XXXX"
                })

        return result


@pytest.fixture
def mock_dependency_scanner():
    """Fixture for dependency scanning security tests."""
    return MockDependencyScanner()


class MockModelAnalyzer:
    """Mock model analyzer for backdoor detection."""

    def scan_for_backdoors(self, model_path: str) -> MockModelAnalysisResult:
        """Scan model for potential backdoors."""
        result = MockModelAnalysisResult()
        result.behavioral_analysis_completed = True
        result.backdoor_detected = "suspicious" in model_path
        return result


@pytest.fixture
def mock_model_analyzer():
    """Fixture for model analysis security tests."""
    return MockModelAnalyzer()


# =============================================================================
# OWASP LLM05: Insecure Output Handling Mocks
# =============================================================================

class MockOutputResult(MockResult):
    """Generic mock result for output operations."""

    def __init__(self, **kwargs):
        defaults = {"sanitized": False, "validated": False, "output": ""}
        defaults.update(kwargs)
        super().__init__(**defaults)


class MockOutputRenderer:
    """Mock output renderer with sanitization."""

    def render(self, content: str) -> MockOutputResult:
        """Render output with XSS protection."""
        result = MockOutputResult(rendered_html="")
        result.sanitized = True

        sanitized = content
        # Sanitize common XSS vectors
        sanitized = sanitized.replace("<script>", "&lt;script&gt;")
        sanitized = sanitized.replace("</script>", "&lt;/script&gt;")
        sanitized = sanitized.replace("onload", "")
        sanitized = sanitized.replace("onerror", "")
        sanitized = sanitized.replace("onmouseover", "")
        result.rendered_html = sanitized

        return result


@pytest.fixture
def mock_output_renderer():
    """Fixture for output rendering security tests."""
    return MockOutputRenderer()


class MockQueryGenerator:
    """Mock query generator with SQL injection protection."""

    def generate_query(self, user_input: str) -> MockOutputResult:
        """Generate SQL query with parameterization."""
        result = MockOutputResult(parameterized=True, sql="SELECT * FROM items WHERE name = ?")
        return result


@pytest.fixture
def mock_query_generator():
    """Fixture for query generation security tests."""
    return MockQueryGenerator()


class MockCommandGenerator:
    """Mock command generator with validation."""

    def generate_command(self, user_request: str) -> MockOutputResult:
        """Generate system command with validation."""
        result = MockOutputResult(command="ls")
        result.validated = True
        return result


@pytest.fixture
def mock_command_generator():
    """Fixture for command generation security tests."""
    return MockCommandGenerator()


class MockFileHandler:
    """Mock file handler with path validation."""

    def read_file(self, path: str) -> MockOutputResult:
        """Read file with path traversal protection."""
        result = MockOutputResult(path_validated=True, file_read=True)
        if "../" in path or "etc/passwd" in path:
            result.file_read = False
        return result


@pytest.fixture
def mock_file_handler():
    """Fixture for file handling security tests."""
    return MockFileHandler()


class MockCodeExecutor:
    """Mock code executor with validation."""

    def execute(self, code: str) -> MockOutputResult:
        """Execute code with validation."""
        result = MockOutputResult(code_validated=True, executed=True)
        if "__import__" in code or "eval" in code:
            result.executed = False
        return result


@pytest.fixture
def mock_code_executor():
    """Fixture for code execution security tests."""
    return MockCodeExecutor()


class MockHTMLGenerator:
    """Mock HTML generator with sanitization."""

    def generate_html(self, content: str) -> MockOutputResult:
        """Generate HTML with sanitization."""
        result = MockOutputResult(html="")
        result.sanitized = True

        if "<iframe>" in content:
            result.html = content.replace("<iframe>", "&lt;iframe&gt;").replace("</iframe>", "&lt;/iframe&gt;")
        else:
            result.html = content

        return result


@pytest.fixture
def mock_html_generator():
    """Fixture for HTML generation security tests."""
    return MockHTMLGenerator()


class MockLDAPQueryBuilder:
    """Mock LDAP query builder with injection protection."""

    def build_query(self, user_input: str) -> MockOutputResult:
        """Build LDAP query with escaping."""
        result = MockOutputResult(escaped=True, filter="")

        if "|" in user_input or "(" in user_input or ")" in user_input:
            result.filter = user_input.replace("|", "").replace("(", "").replace(")", "")
        else:
            result.filter = user_input

        return result


@pytest.fixture
def mock_ldap_query_builder():
    """Fixture for LDAP query building security tests."""
    return MockLDAPQueryBuilder()


class MockTemplateRenderer:
    """Mock template renderer with SSTI protection."""

    def render_template(self, template: str) -> MockOutputResult:
        """Render template with validation."""
        result = MockOutputResult()
        result.validated = True

        if "{{" in template and ("*" in template or "config" in template):
            result.output = "Invalid template"
        else:
            result.output = template

        return result


@pytest.fixture
def mock_template_renderer():
    """Fixture for template rendering security tests."""
    return MockTemplateRenderer()


# =============================================================================
# OWASP LLM08: Excessive Agency Mocks
# =============================================================================

class MockAgentResult(MockResult):
    """Mock result for agent actions."""

    def __init__(self):
        super().__init__(
            approval_requested=False,
            executed=False,
            scope_checked=False,
            permission_checked=False,
            url_validated=False,
            call_made=False,
            rate_limited=False,
            privilege_check_performed=False,
            command_validated=False,
            approval_required=False,
            context_evaluated=False
        )


class MockChainResult(MockResult):
    """Mock result for action chains."""

    def __init__(self):
        super().__init__(
            chain_reviewed=False,
            high_impact_detected=False,
            chain_completed=False,
            context_evaluated=False
        )


class MockFinancialResult(MockResult):
    """Mock result for financial operations."""

    def __init__(self):
        super().__init__(
            approval_required=False,
            amount_limit_checked=False,
            completed=False
        )


class MockAgent:
    """Mock LLM agent with action controls."""

    def __init__(self):
        self.action_count = 0

    def execute_action(self, action: str, context: dict = None) -> MockAgentResult:
        """Execute agent action with controls."""
        result = MockAgentResult()
        self.action_count += 1

        if "delete" in action or "admin" in action or "shutdown" in action:
            result.approval_requested = True
            result.scope_checked = True
            result.permission_checked = True
            result.executed = False

        if "grant_admin" in action:
            result.privilege_check_performed = True
            result.executed = False

        if "system_command" in action:
            result.command_validated = True
            result.approval_required = True
            result.executed = False

        if context:
            result.context_evaluated = True
            if context.get("location") == "untrusted":
                result.executed = False

        if self.action_count > 50:
            result.rate_limited = True
            result.executed = False

        return result

    def modify_data(self, table: str, action: str) -> MockAgentResult:
        """Modify data with permission checks."""
        result = MockAgentResult()
        result.permission_checked = True
        if "delete" in action:
            result.executed = False
        return result

    def call_external_api(self, url: str, method: str) -> MockAgentResult:
        """Call external API with validation."""
        result = MockAgentResult()
        result.url_validated = True
        if "untrusted" in url:
            result.call_made = False
        return result

    def execute_system_command(self, command: str) -> MockAgentResult:
        """Execute system command with controls."""
        result = MockAgentResult()
        result.command_validated = True
        result.approval_required = True
        result.executed = False
        return result

    def execute_action_chain(self, actions: list) -> MockChainResult:
        """Execute chain of actions with review."""
        result = MockChainResult()
        result.chain_reviewed = True

        for action in actions:
            if "send_email_to_all" in action or "delete" in action:
                result.high_impact_detected = True
                return result

        result.chain_completed = True
        return result


@pytest.fixture
def mock_agent():
    """Fixture for agent security tests."""
    return MockAgent()


class MockFinancialAgent:
    """Mock financial agent with transaction controls."""

    def transfer_funds(self, amount: float, to: str) -> MockFinancialResult:
        """Transfer funds with controls."""
        result = MockFinancialResult()
        result.amount_limit_checked = True

        if amount > 1000 or "external" in to:
            result.approval_required = True
            result.completed = False

        return result


@pytest.fixture
def mock_financial_agent():
    """Fixture for financial agent security tests."""
    return MockFinancialAgent()


# =============================================================================
# OWASP LLM09: Overreliance Mocks
# =============================================================================

class MockAssistantResponse(MockResult):
    """Generic mock response for assistant types."""

    def __init__(self, **kwargs):
        defaults = {
            "disclaimer_present": False,
            "professional_referral_suggested": False,
            "sources_provided": False,
            "sources": [],
            "confidence_indicated": False,
            "confidence_level": 0.0,
            "uncertainty_acknowledged": False,
            "definitive_answer_provided": False,
            "risk_warning_present": False
        }
        defaults.update(kwargs)
        super().__init__(**defaults)


class MockFactChecker:
    """Mock fact checker for overreliance testing."""

    def verify_claim(self, claim: str) -> MockAssistantResponse:
        """Verify factual claims."""
        result = MockAssistantResponse(verification_performed=True, claim_verified=True)
        if "flat" in claim.lower() or "cheese" in claim.lower():
            result.claim_verified = False
        return result


@pytest.fixture
def mock_fact_checker():
    """Fixture for fact checking security tests."""
    return MockFactChecker()


class MockHealthAssistant:
    """Mock health assistant with disclaimers."""

    def respond(self, query: str) -> MockAssistantResponse:
        """Respond to health queries with disclaimers."""
        result = MockAssistantResponse()
        if "medication" in query.lower() or "treatment" in query.lower():
            result.disclaimer_present = True
            result.professional_referral_suggested = True
        return result


@pytest.fixture
def mock_health_assistant():
    """Fixture for health assistant security tests."""
    return MockHealthAssistant()


class MockLegalAssistant:
    """Mock legal assistant with disclaimers."""

    def respond(self, query: str) -> MockAssistantResponse:
        """Respond to legal queries with disclaimers."""
        result = MockAssistantResponse()
        if "contract" in query.lower() or "sign" in query.lower():
            result.disclaimer_present = True
            result.professional_referral_suggested = True
        return result


@pytest.fixture
def mock_legal_assistant():
    """Fixture for legal assistant security tests."""
    return MockLegalAssistant()


class MockFinancialAdvisor:
    """Mock financial advisor with disclaimers."""

    def respond(self, query: str) -> MockAssistantResponse:
        """Respond to financial queries with disclaimers."""
        result = MockAssistantResponse()
        if "invest" in query.lower() or "savings" in query.lower():
            result.disclaimer_present = True
            result.risk_warning_present = True
            result.professional_referral_suggested = True
        return result


@pytest.fixture
def mock_financial_advisor():
    """Fixture for financial advisor security tests."""
    return MockFinancialAdvisor()


class MockResearchAssistant:
    """Mock research assistant with source citations."""

    def respond(self, query: str) -> MockAssistantResponse:
        """Respond with source citations."""
        result = MockAssistantResponse()
        if "population" in query.lower() or "what is" in query.lower():
            result.sources_provided = True
            result.sources = ["Source 1", "Source 2"]
        return result


@pytest.fixture
def mock_research_assistant():
    """Fixture for research assistant security tests."""
    return MockResearchAssistant()


class MockLLMWithConfidence:
    """Mock LLM that indicates confidence levels."""

    def respond(self, query: str) -> MockAssistantResponse:
        """Respond with confidence indication."""
        result = MockAssistantResponse(confidence_indicated=True)

        if "weather" in query.lower() or "predict" in query.lower() or "lottery" in query.lower():
            result.confidence_level = 0.3
            result.uncertainty_acknowledged = True
            result.definitive_answer_provided = False
        else:
            result.confidence_level = 0.8

        return result


@pytest.fixture
def mock_llm_with_confidence():
    """Fixture for confidence-aware LLM security tests."""
    return MockLLMWithConfidence()


class MockDecisionSystem:
    """Mock decision system with human oversight."""

    def make_decision(self, decision: str) -> MockAssistantResponse:
        """Make decisions with human oversight for critical cases."""
        result = MockAssistantResponse(human_review_required=False, auto_approved=False)

        if "loan" in decision or "$" in decision or "approve" in decision:
            result.human_review_required = True

        return result


@pytest.fixture
def mock_decision_system():
    """Fixture for decision system security tests."""
    return MockDecisionSystem()


class MockSafetySystem:
    """Mock safety system for life-critical decisions."""

    def evaluate(self, decision: str) -> MockAssistantResponse:
        """Evaluate safety-critical decisions."""
        result = MockAssistantResponse(
            safety_check_performed=True,
            human_approval_required=False,
            action_permitted=True
        )

        if "disable" in decision or "emergency" in decision or "brake" in decision:
            result.human_approval_required = True
            result.action_permitted = False

        return result


@pytest.fixture
def mock_safety_system():
    """Fixture for safety system security tests."""
    return MockSafetySystem()


class MockHallucinationDetector:
    """Mock hallucination detector."""

    def analyze(self, response: str) -> MockAssistantResponse:
        """Analyze response for hallucinations."""
        result = MockAssistantResponse(analysis_completed=True, hallucination_detected=False)
        if "Atlantis" in response or "2025 study" in response:
            result.hallucination_detected = True
        return result


@pytest.fixture
def mock_hallucination_detector():
    """Fixture for hallucination detection security tests."""
    return MockHallucinationDetector()


# =============================================================================
# OWASP LLM10: Model Theft Mocks
# =============================================================================

class MockAPIResult(MockResult):
    """Generic mock result for API operations."""

    def __init__(self, **kwargs):
        defaults = {
            "rate_limited": False,
            "output_filtered": False,
            "architecture_leaked": False,
            "embeddings_exposed": False,
            "injection_detected": False,
            "system_info_leaked": False,
            "authentication_required": False,
            "weights_accessible": False,
            "encryption_enabled": False,
            "encryption_strength": 0,
            "pattern_analyzed": False,
            "suspicious_pattern_detected": False,
            "info_filtered": False,
            "layer_count_exposed": False,
            "parameter_count_exposed": False,
            "architecture_details_exposed": False,
            "training_data_filter_active": False,
            "training_data_leaked": False,
            "watermark_present": False,
            "watermark_valid": False,
            "cost_tracked": False,
            "alert_triggered": False,
            "full_vector_protected": False,
            "fingerprinting_detected": False,
            "countermeasures_applied": False
        }
        defaults.update(kwargs)
        super().__init__(**defaults)


class MockAPIGateway:
    """Mock API gateway with rate limiting."""

    def __init__(self):
        self.query_count = 0

    def query(self, text: str) -> MockAPIResult:
        """Process API query with rate limiting."""
        result = MockAPIResult()
        self.query_count += 1
        if self.query_count > 500:
            result.rate_limited = True
        return result


@pytest.fixture
def mock_api_gateway():
    """Fixture for API gateway security tests."""
    return MockAPIGateway()


class MockModelStorage:
    """Mock model storage with access controls."""

    def access_weights(self) -> MockAPIResult:
        """Access model weights."""
        return MockAPIResult(authentication_required=True, weights_accessible=False)

    def verify_encryption(self) -> MockAPIResult:
        """Verify model encryption."""
        return MockAPIResult(encryption_enabled=True, encryption_strength=256)


@pytest.fixture
def mock_model_storage():
    """Fixture for model storage security tests."""
    return MockModelStorage()


class MockAPIEndpoint:
    """Mock API endpoint with output filtering."""

    def query(self, text: str) -> MockAPIResult:
        """Process query with output filtering."""
        return MockAPIResult(output_filtered=True)


@pytest.fixture
def mock_api_endpoint():
    """Fixture for API endpoint security tests."""
    return MockAPIEndpoint()


class MockAbuseDetector:
    """Mock abuse detector for extraction patterns."""

    def analyze_pattern(self, queries: list) -> MockAPIResult:
        """Analyze query patterns for extraction attempts."""
        result = MockAPIResult(pattern_analyzed=True)
        if len(queries) >= 3:
            unique_queries = set(queries)
            if len(unique_queries) < len(queries) * 0.7:
                result.suspicious_pattern_detected = True
        return result


@pytest.fixture
def mock_abuse_detector():
    """Fixture for abuse detection security tests."""
    return MockAbuseDetector()


class MockModelAPI:
    """Mock model API with information protection."""

    def get_model_info(self) -> MockAPIResult:
        """Get filtered model information."""
        return MockAPIResult(info_filtered=True)

    def query(self, text: str) -> MockAPIResult:
        """Process query with protections."""
        result = MockAPIResult(training_data_filter_active=True)
        if "ignore" in text.lower() or "system prompt" in text.lower():
            result.injection_detected = True
        return result


@pytest.fixture
def mock_model_api():
    """Fixture for model API security tests."""
    return MockModelAPI()


class MockModelVerifier:
    """Mock model verifier for watermarking."""

    def check_watermark(self) -> MockAPIResult:
        """Check model watermark."""
        return MockAPIResult(watermark_present=True, watermark_valid=True)


@pytest.fixture
def mock_model_verifier():
    """Fixture for model verification security tests."""
    return MockModelVerifier()


class MockUsageMonitor:
    """Mock usage monitor for cost tracking."""

    def track_usage(self, user_id: str, queries: int) -> MockAPIResult:
        """Track usage and costs."""
        result = MockAPIResult(cost_tracked=True)
        if queries > 1000:
            result.alert_triggered = True
        return result


@pytest.fixture
def mock_usage_monitor():
    """Fixture for usage monitoring security tests."""
    return MockUsageMonitor()


class MockEmbeddingAPI:
    """Mock embedding API with protections."""

    def __init__(self):
        self.request_count = 0

    def get_embedding(self, text: str) -> MockAPIResult:
        """Get embedding with protections."""
        result = MockAPIResult(full_vector_protected=True)
        self.request_count += 1
        if self.request_count > 50:
            result.rate_limited = True
        return result


@pytest.fixture
def mock_embedding_api():
    """Fixture for embedding API security tests."""
    return MockEmbeddingAPI()


class MockFingerprintDetector:
    """Mock fingerprint detector for model fingerprinting."""

    def analyze_queries(self, queries: list) -> MockAPIResult:
        """Analyze queries for fingerprinting attempts."""
        result = MockAPIResult()
        if len(queries) >= 3:
            result.fingerprinting_detected = True
            result.countermeasures_applied = True
        return result


@pytest.fixture
def mock_fingerprint_detector():
    """Fixture for fingerprint detection security tests."""
    return MockFingerprintDetector()
