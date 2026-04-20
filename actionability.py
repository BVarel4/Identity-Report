"""Operational triage rules for actionability and review priority."""

ACTIONABILITY_DIRECT = "Accion directa"
ACTIONABILITY_VALIDATE = "Validacion en Falcon"
ACTIONABILITY_INVESTIGATE = "Investigacion guiada"

PRIORITY_P1 = "P1"
PRIORITY_P2 = "P2"
PRIORITY_P3 = "P3"

DIRECT_RISK_TYPES = {
    "WEAK_PASSWORD_POLICY",
    "WEAK_PASSWORD",
    "DUPLICATE_PASSWORD",
    "INACTIVE_ACCOUNT",
    "STALE_ACCOUNT",
    "INSUFFICIENT_PASSWORD_ROTATION",
    "SMB_SIGNING_DISABLED",
    "LDAP_SIGNING_DISABLED",
    "LDAPS_CHANNEL_BINDING",
    "VULNERABLE_OS",
    "SHARED_USER",
    "SHARED_ENDPOINT",
    "CERTIFICATE_TEMPLATE_ALLOWS_AUTHENTICATION_AS_ANY_DOMAIN_USER",
}

VALIDATE_RISK_TYPES = {
    "NEW_SERVER_ACCESS",
    "STALE_ACCOUNT_USAGE",
    "STALE_HOST_USAGE",
    "RISKY_LINKED_ACCOUNT",
    "HAS_SPNS",
    "KRBTGT_AGED_PASSWORD",
    "PRIVILEGED_MACHINE",
    "PRIVILEGED_USER_USING_UNMANAGED_ENDPOINT",
    "SHARED_ENDPOINT_USED_BY_PRIVILEGED_USER",
}

INVESTIGATE_RISK_TYPES = {
    "CREDENTIAL_THEFT",
    "CREDENTIAL_SCANNING",
    "PASSWORD_BRUTE_FORCE",
    "LDAP_RECONNAISSANCE",
    "DAILY_VOLUME_ANOMALY",
    "ANOMALOUS_RPC",
    "LATERAL_MOVEMENT",
    "PASS_THE_HASH",
    "HAS_ATTACK_PATH",
    "STEALTHY_PRIVILEGES",
    "NTLM_MOVEMENTS",
}

ACTIONABILITY_NOTES = {
    ACTIONABILITY_DIRECT: (
        "El hallazgo ya permite planificar remediacion directa. "
        "Validar ventana de cambio y aplicar la accion recomendada."
    ),
    ACTIONABILITY_VALIDATE: (
        "Antes de remediar, confirmar en Falcon el activo, contraparte o "
        "contexto exacto del hallazgo y luego ejecutar la accion recomendada."
    ),
    ACTIONABILITY_INVESTIGATE: (
        "Tratar como hallazgo de investigacion. Confirmar legitimidad, alcance "
        "y posible abuso antes de aplicar cambios correctivos."
    ),
}

ACTIONABILITY_PRIORITY_BASE = {
    ACTIONABILITY_INVESTIGATE: 1,
    ACTIONABILITY_VALIDATE: 2,
    ACTIONABILITY_DIRECT: 3,
}

ACTIONABILITY_SORT_ORDER = {
    ACTIONABILITY_INVESTIGATE: 0,
    ACTIONABILITY_VALIDATE: 1,
    ACTIONABILITY_DIRECT: 2,
}

PRIORITY_LABELS = {
    1: PRIORITY_P1,
    2: PRIORITY_P2,
    3: PRIORITY_P3,
}

PRIORITY_SORT_ORDER = {
    PRIORITY_P1: 0,
    PRIORITY_P2: 1,
    PRIORITY_P3: 2,
}


def determine_actionability_level(risk_type: str) -> str:
    """Map a risk type to its default operational treatment model."""
    if risk_type in DIRECT_RISK_TYPES:
        return ACTIONABILITY_DIRECT
    if risk_type in VALIDATE_RISK_TYPES:
        return ACTIONABILITY_VALIDATE
    if risk_type in INVESTIGATE_RISK_TYPES:
        return ACTIONABILITY_INVESTIGATE
    return ACTIONABILITY_VALIDATE


def determine_review_priority(actionability_level: str, severity: str, entity_risk_type_count) -> str:
    """Compute P1/P2/P3 priority from actionability, severity and correlation."""
    base_priority = ACTIONABILITY_PRIORITY_BASE.get(actionability_level, 2)
    severity_upper = str(severity or "").upper()

    if severity_upper in {"MEDIUM", "HIGH", "CRITICAL"}:
        base_priority -= 1

    try:
        risk_count = int(entity_risk_type_count or 0)
    except (TypeError, ValueError):
        risk_count = 0

    if risk_count >= 3:
        base_priority -= 1

    base_priority = max(1, min(3, base_priority))
    return PRIORITY_LABELS[base_priority]


def build_actionability_note(actionability_level: str) -> str:
    """Return the analyst-facing next step for a given actionability tier."""
    return ACTIONABILITY_NOTES.get(
        actionability_level,
        ACTIONABILITY_NOTES[ACTIONABILITY_VALIDATE],
    )


def actionability_sort_rank(actionability_level: str) -> int:
    return ACTIONABILITY_SORT_ORDER.get(actionability_level, 99)


def priority_sort_rank(priority_label: str) -> int:
    return PRIORITY_SORT_ORDER.get(priority_label, 99)


def enrich_parsed_risks_with_actionability(parsed_risks: list[dict]) -> list[dict]:
    """Append actionability and priority fields to parsed risk rows."""
    enriched_rows = []

    for row in parsed_risks:
        risk_type = str(row.get("risk_type", "") or "")
        actionability_level = determine_actionability_level(risk_type)
        review_priority = determine_review_priority(
            actionability_level=actionability_level,
            severity=str(row.get("severity", "") or ""),
            entity_risk_type_count=row.get("entity_risk_type_count", 0),
        )
        actionability_note = build_actionability_note(actionability_level)

        enriched_rows.append(
            {
                **row,
                "actionability_level": actionability_level,
                "review_priority": review_priority,
                "actionability_note": actionability_note,
            }
        )

    return enriched_rows
