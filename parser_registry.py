SPECIFIC_PARSERS = {
    "HAS_ATTACK_PATH": "attack_path",
}

GENERIC_RISK_TYPES = {
    "CREDENTIAL_SCANNING",
    "CREDENTIAL_THEFT",
    "DUPLICATE_PASSWORD",
    "INACTIVE_ACCOUNT",
    "INSUFFICIENT_PASSWORD_ROTATION",
    "LDAP_RECONNAISSANCE",
    "LDAP_SIGNING_DISABLED",
    "LDAPS_CHANNEL_BINDING",
    "NEW_SERVER_ACCESS",
    "PASSWORD_BRUTE_FORCE",
    "RISKY_LINKED_ACCOUNT",
    "SHARED_ENDPOINT",
    "SHARED_USER",
    "SMB_SIGNING_DISABLED",
    "STALE_ACCOUNT",
    "STALE_ACCOUNT_USAGE",
    "STALE_HOST_USAGE",
    "STEALTHY_PRIVILEGES",
    "VULNERABLE_OS",
    "WEAK_PASSWORD",
    "WEAK_PASSWORD_POLICY",
}

UNKNOWN_PARSER = "unknown"


def select_parser_for_risk(risk_type: str) -> str:
    if risk_type in SPECIFIC_PARSERS:
        return SPECIFIC_PARSERS[risk_type]

    if risk_type in GENERIC_RISK_TYPES:
        return "generic"

    return UNKNOWN_PARSER


def build_parser_inventory(risk_inventory: list[dict]) -> list[dict]:
    rows = []

    for item in risk_inventory:
        risk_type = item["risk_type"]
        rows.append(
            {
                "risk_type": risk_type,
                "count": item["count"],
                "percentage": item["percentage"],
                "selected_parser": select_parser_for_risk(risk_type),
            }
        )

    return rows
