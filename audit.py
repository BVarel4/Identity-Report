"""Audit collection for unsupported risks, parser failures and raw samples."""

from collections import defaultdict
from typing import Any


class AuditCollector:
    """Collect audit artifacts without interrupting the main reporting flow."""
    def __init__(self, sample_limit_per_risk: int = 3):
        self.sample_limit_per_risk = sample_limit_per_risk
        self.unknown_risk_types = defaultdict(int)
        self.parser_errors: list[dict] = []
        self.structure_issues: list[dict] = []
        self.raw_samples: dict[str, list[dict]] = defaultdict(list)

    def register_unknown_risk_type(
        self,
        risk_type: str,
        entity: dict,
        risk_factor: dict,
    ) -> None:
        self.unknown_risk_types[risk_type] += 1
        self.collect_raw_sample(
            risk_type=risk_type,
            entity=entity,
            risk_factor=risk_factor,
            parser_name="unknown",
            sample_category="unknown_risk_type",
        )

    def register_parser_error(
        self,
        risk_type: str,
        parser_name: str,
        entity: dict,
        risk_factor: dict,
        error_message: str,
    ) -> None:
        self.parser_errors.append(
            {
                "issue_type": "parser_error",
                "risk_type": risk_type,
                "parser_name": parser_name,
                "entity_name": entity.get("primaryDisplayName", ""),
                "secondary_name": entity.get("secondaryDisplayName", ""),
                "entity_type": entity.get("type", ""),
                "severity": entity.get("riskScoreSeverity", ""),
                "message": error_message,
            }
        )

        self.collect_raw_sample(
            risk_type=risk_type,
            entity=entity,
            risk_factor=risk_factor,
            parser_name=parser_name,
            sample_category="parser_error",
        )

    def register_structure_issue(
        self,
        risk_type: str,
        parser_name: str,
        entity: dict,
        risk_factor: dict,
        issue_message: str,
    ) -> None:
        self.structure_issues.append(
            {
                "issue_type": "structure_issue",
                "risk_type": risk_type,
                "parser_name": parser_name,
                "entity_name": entity.get("primaryDisplayName", ""),
                "secondary_name": entity.get("secondaryDisplayName", ""),
                "entity_type": entity.get("type", ""),
                "severity": entity.get("riskScoreSeverity", ""),
                "message": issue_message,
            }
        )

        self.collect_raw_sample(
            risk_type=risk_type,
            entity=entity,
            risk_factor=risk_factor,
            parser_name=parser_name,
            sample_category="structure_issue",
        )

    def collect_raw_sample(
        self,
        risk_type: str,
        entity: dict,
        risk_factor: dict,
        parser_name: str,
        sample_category: str = "general",
    ) -> None:
        current_samples = self.raw_samples[risk_type]
        if len(current_samples) >= self.sample_limit_per_risk:
            return

        current_samples.append(
            {
                "sample_category": sample_category,
                "parser_name": parser_name,
                "entity": {
                    "entityId": entity.get("entityId", ""),
                    "type": entity.get("type", ""),
                    "primaryDisplayName": entity.get("primaryDisplayName", ""),
                    "secondaryDisplayName": entity.get("secondaryDisplayName", ""),
                    "riskScoreSeverity": entity.get("riskScoreSeverity", ""),
                },
                "risk_factor": risk_factor,
            }
        )

    def build_unknown_risk_rows(self) -> list[dict]:
        rows = []

        for risk_type, count in sorted(
            self.unknown_risk_types.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            rows.append(
                {
                    "risk_type": risk_type,
                    "count": count,
                    "action_required": "Create or assign parser",
                }
            )

        return rows

    def build_parser_error_rows(self) -> list[dict]:
        return list(self.parser_errors)

    def build_structure_issue_rows(self) -> list[dict]:
        return list(self.structure_issues)

    def build_combined_error_rows(self) -> list[dict]:
        return self.build_parser_error_rows() + self.build_structure_issue_rows()

    def build_raw_samples_rows(self) -> list[dict]:
        rows = []

        for risk_type, samples in self.raw_samples.items():
            for index, sample in enumerate(samples, start=1):
                entity = sample.get("entity", {})
                rows.append(
                    {
                        "risk_type": risk_type,
                        "sample_number": index,
                        "sample_category": sample.get("sample_category", ""),
                        "parser_name": sample.get("parser_name", ""),
                        "entity_name": entity.get("primaryDisplayName", ""),
                        "secondary_name": entity.get("secondaryDisplayName", ""),
                        "entity_type": entity.get("type", ""),
                        "severity": entity.get("riskScoreSeverity", ""),
                    }
                )

        return rows

    def export_raw_samples_json(self) -> dict[str, Any]:
        return dict(self.raw_samples)

    @staticmethod
    def validate_risk_factor_structure(
        risk_type: str,
        risk_factor: dict,
    ) -> tuple[bool, str]:
        """Apply lightweight schema checks for high-value risk structures."""
        typename = str(risk_factor.get("__typename", "") or "")

        if not str(risk_factor.get("type", "") or ""):
            return False, "Risk factor without type"

        if not typename:
            return False, "Risk factor without __typename"

        expected_typenames = {
            "HAS_ATTACK_PATH": "AttackPathBasedRiskFactor",
            "STEALTHY_PRIVILEGES": "AttackPathBasedRiskFactor",
            "DUPLICATE_PASSWORD": "DuplicatePasswordRiskEntityFactor",
            "RISKY_LINKED_ACCOUNT": "LinkedAccountsRiskEntityFactor",
            "CERTIFICATE_TEMPLATE_ALLOWS_AUTHENTICATION_AS_ANY_DOMAIN_USER": "CertificateTemplateAuthenticationBasedRiskFactor",
        }
        expected_typename = expected_typenames.get(risk_type)
        if expected_typename and typename != expected_typename:
            return False, (
                f"{risk_type} expected __typename {expected_typename} "
                f"but received {typename}"
            )

        if typename == "AttackPathBasedRiskFactor":
            if "attackPath" not in risk_factor:
                return False, f"{risk_type} without attackPath"

            if not isinstance(risk_factor.get("attackPath"), list):
                return False, f"{risk_type} attackPath is not a list"

        return True, ""
