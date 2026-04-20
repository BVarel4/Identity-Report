"""Registry helpers that map CrowdStrike risk types to parser names."""

from risk_catalog import RISK_CATALOG, build_parser_name, get_risk_metadata

SPECIFIC_PARSERS = {
    "HAS_ATTACK_PATH": "attack_path",
}

UNKNOWN_PARSER = "unknown"


def select_parser_for_risk(risk_type: str) -> str:
    """Resolve the parser name for a risk type or fall back to unknown."""
    if risk_type in SPECIFIC_PARSERS:
        return SPECIFIC_PARSERS[risk_type]

    if risk_type in RISK_CATALOG:
        return build_parser_name(risk_type)

    return UNKNOWN_PARSER


def build_parser_inventory(risk_inventory: list[dict]) -> list[dict]:
    """Build the parser inventory used by CSV and Excel summary outputs."""
    rows = []

    for item in risk_inventory:
        risk_type = item["risk_type"]
        metadata = get_risk_metadata(risk_type)
        rows.append(
            {
                "risk_type": risk_type,
                "risk_title": metadata["title"],
                "risk_family": metadata["family"],
                "count": item["count"],
                "percentage": item["percentage"],
                "selected_parser": select_parser_for_risk(risk_type),
            }
        )

    return rows
