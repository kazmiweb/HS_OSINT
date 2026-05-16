import unittest

from hs_osint.analyzer import QueryAnalyzer
from hs_osint.models import ProviderCapability, QueryType, RiskLevel
from hs_osint.policy import SafetyPolicy


class QueryAnalyzerTest(unittest.TestCase):
    def test_classifies_email_and_domain(self) -> None:
        analysis = QueryAnalyzer().analyze("analyst@example.com")

        self.assertIn(QueryType.EMAIL.value, analysis.query_types)
        self.assertIn("analyst@example.com", analysis.entities[QueryType.EMAIL.value])
        self.assertIn("wayback", analysis.suggested_providers)

    def test_flags_credential_intent_as_metadata(self) -> None:
        analysis = QueryAnalyzer().analyze("user@example.com password leak")

        self.assertIn("credential_terms", analysis.risk_flags)
        self.assertEqual("credential_exposure_metadata", analysis.intent)


class SafetyPolicyTest(unittest.TestCase):
    def test_requires_ack_for_personal_data_provider(self) -> None:
        analysis = QueryAnalyzer().analyze("+1 202 555 0199")
        capability = ProviderCapability(
            query_types={QueryType.PHONE.value},
            risk_level=RiskLevel.HIGH,
            requires_lawful_use_ack=True,
        )

        decision = SafetyPolicy().decide_provider(
            analysis,
            capability,
            lawful_use_acknowledged=False,
        )

        self.assertFalse(decision.allowed)
        self.assertIn("acknowledge", decision.reason or "")


if __name__ == "__main__":
    unittest.main()
