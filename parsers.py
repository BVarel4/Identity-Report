from audit import AuditCollector
from parser_registry import UNKNOWN_PARSER, select_parser_for_risk
from utils import build_falcon_entity_link, format_entity_label, safe_text


def parse_entities(
    nodes: list[dict],
    audit: AuditCollector,
    falcon_base_url: str,
) -> tuple[list[dict], list[dict]]:
    parsed_rows: list[dict] = []
    attack_path_rows: list[dict] = []

    for entity in nodes:
        risk_factors = entity.get("riskFactors", []) or []

        for risk_factor in risk_factors:
            risk_type = risk_factor.get("type") or "UNKNOWN"
            parser_name = select_parser_for_risk(risk_type)

            is_valid, issue_message = audit.validate_risk_factor_structure(
                risk_type=risk_type,
                risk_factor=risk_factor,
            )
            if not is_valid:
                audit.register_structure_issue(
                    risk_type=risk_type,
                    parser_name=parser_name,
                    entity=entity,
                    risk_factor=risk_factor,
                    issue_message=issue_message,
                )

            try:
                result = dispatch_parser(
                    parser_name=parser_name,
                    entity=entity,
                    risk_factor=risk_factor,
                    audit=audit,
                    falcon_base_url=falcon_base_url,
                    structure_is_valid=is_valid,
                )
            except Exception as exc:
                audit.register_parser_error(
                    risk_type=risk_type,
                    parser_name=parser_name,
                    entity=entity,
                    risk_factor=risk_factor,
                    error_message=str(exc),
                )
                parsed_rows.append(
                    build_parsed_row(
                        entity=entity,
                        risk_type=risk_type,
                        parser_name=parser_name,
                        parse_status="error",
                        detail=f"Parser error: {exc}",
                        falcon_base_url=falcon_base_url,
                    )
                )
                continue

            parsed_rows.extend(result["parsed_rows"])
            attack_path_rows.extend(result["attack_path_rows"])

    return parsed_rows, attack_path_rows


def dispatch_parser(
    parser_name: str,
    entity: dict,
    risk_factor: dict,
    audit: AuditCollector,
    falcon_base_url: str,
    structure_is_valid: bool,
) -> dict[str, list[dict]]:
    if parser_name == "attack_path":
        return parse_attack_path(
            entity=entity,
            risk_factor=risk_factor,
            falcon_base_url=falcon_base_url,
            structure_is_valid=structure_is_valid,
        )

    if parser_name == "generic":
        return parse_generic(
            entity=entity,
            risk_factor=risk_factor,
            falcon_base_url=falcon_base_url,
        )

    if parser_name == UNKNOWN_PARSER:
        audit.register_unknown_risk_type(
            risk_type=risk_factor.get("type") or "UNKNOWN",
            entity=entity,
            risk_factor=risk_factor,
        )
        return parse_unknown(
            entity=entity,
            risk_factor=risk_factor,
            falcon_base_url=falcon_base_url,
        )

    raise ValueError(f"Parser no soportado: {parser_name}")


def parse_attack_path(
    entity: dict,
    risk_factor: dict,
    falcon_base_url: str,
    structure_is_valid: bool,
) -> dict[str, list[dict]]:
    attack_path = risk_factor.get("attackPath") or []
    risk_type = risk_factor.get("type") or "HAS_ATTACK_PATH"

    source_entity = attack_path[0].get("entity", {}) if attack_path else entity
    related_entity = (
        next(
            (
                step.get("nextEntity", {})
                for step in reversed(attack_path)
                if step.get("nextEntity")
            ),
            {},
        )
        if attack_path
        else {}
    )

    if attack_path:
        attack_chain = build_attack_chain(attack_path)
        parse_status = "parsed" if structure_is_valid else "structure_issue"
        detail = f"Attack path detected: {attack_chain}"
    else:
        attack_chain = ""
        parse_status = "structure_issue" if not structure_is_valid else "parsed_empty"
        detail = "Attack path risk without path steps available."

    parsed_row = build_parsed_row(
        entity=entity,
        risk_type=risk_type,
        parser_name="attack_path",
        parse_status=parse_status,
        detail=detail,
        falcon_base_url=falcon_base_url,
        related_entity=related_entity,
    )

    attack_path_rows = []
    if attack_path:
        attack_path_rows.append(
            {
                "source_entity": format_entity_label(source_entity),
                "related_entity": format_entity_label(related_entity),
                "attack_chain": attack_chain,
                "severity": safe_text(entity.get("riskScoreSeverity")),
                "source_link": build_falcon_entity_link(
                    falcon_base_url,
                    source_entity,
                ),
                "related_link": build_falcon_entity_link(
                    falcon_base_url,
                    related_entity,
                ),
            }
        )

    return {
        "parsed_rows": [parsed_row],
        "attack_path_rows": attack_path_rows,
    }


def parse_generic(
    entity: dict,
    risk_factor: dict,
    falcon_base_url: str,
) -> dict[str, list[dict]]:
    risk_type = risk_factor.get("type") or "UNKNOWN"
    entity_name = safe_text(entity.get("primaryDisplayName"))
    secondary_name = safe_text(entity.get("secondaryDisplayName"))

    detail_parts = [f"Risk factor {risk_type} detected on {entity_name or 'unknown entity'}."]
    if secondary_name:
        detail_parts.append(f"Secondary identifier: {secondary_name}.")

    return {
        "parsed_rows": [
            build_parsed_row(
                entity=entity,
                risk_type=risk_type,
                parser_name="generic",
                parse_status="parsed",
                detail=" ".join(detail_parts),
                falcon_base_url=falcon_base_url,
            )
        ],
        "attack_path_rows": [],
    }


def parse_unknown(
    entity: dict,
    risk_factor: dict,
    falcon_base_url: str,
) -> dict[str, list[dict]]:
    risk_type = risk_factor.get("type") or "UNKNOWN"

    return {
        "parsed_rows": [
            build_parsed_row(
                entity=entity,
                risk_type=risk_type,
                parser_name="unknown",
                parse_status="requires_review",
                detail="Risk factor without assigned parser. Review raw sample and define parser.",
                falcon_base_url=falcon_base_url,
            )
        ],
        "attack_path_rows": [],
    }


def build_attack_chain(attack_path: list[dict]) -> str:
    if not attack_path:
        return ""

    path_tokens = [format_entity_label(attack_path[0].get("entity", {}))]

    for step in attack_path:
        relation = safe_text(step.get("relation")) or "RELATED_TO"
        next_entity = step.get("nextEntity", {})
        path_tokens.append(relation)
        path_tokens.append(format_entity_label(next_entity))

    return " -> ".join(token for token in path_tokens if token)


def build_parsed_row(
    entity: dict,
    risk_type: str,
    parser_name: str,
    parse_status: str,
    detail: str,
    falcon_base_url: str,
    related_entity: dict | None = None,
) -> dict:
    return {
        "entity": safe_text(entity.get("primaryDisplayName")),
        "secondary_identifier": safe_text(entity.get("secondaryDisplayName")),
        "entity_type": safe_text(entity.get("type")),
        "severity": safe_text(entity.get("riskScoreSeverity")),
        "risk_type": risk_type,
        "detail": detail,
        "related_entity": format_entity_label(related_entity or {}),
        "parser_used": parser_name,
        "parse_status": parse_status,
        "falcon_link": build_falcon_entity_link(falcon_base_url, entity),
    }
