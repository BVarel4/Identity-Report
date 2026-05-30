"""Aggregations and correlation helpers used by executive and technical views."""

from collections import Counter


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
    "": 5,
}


def build_executive_analytics(
    risk_summary_rows: list[dict],
    parsed_risks: list[dict],
    attack_paths: list[dict],
    unknown_rows: list[dict],
    error_rows: list[dict],
) -> dict:
    """Build the aggregated metrics and narrative used by the executive sheet."""
    total_risks = sum(int(row.get("count", 0) or 0) for row in risk_summary_rows)
    total_risk_types = len(risk_summary_rows)
    attack_path_count = len(attack_paths)
    audit_count = len(unknown_rows) + len(error_rows)
    parsed_count = len(parsed_risks)

    family_counter = Counter()
    risk_counter = []
    for row in risk_summary_rows:
        count = int(row.get("count", 0) or 0)
        family = str(row.get("risk_family", "Sin clasificar"))
        family_counter[family] += count
        risk_counter.append(
            {
                "risk_type": row.get("risk_type", ""),
                "risk_title": row.get("risk_title", row.get("risk_type", "")),
                "risk_family": family,
                "count": count,
                "percentage": float(row.get("percentage", 0) or 0),
                "selected_parser": row.get("selected_parser", ""),
            }
        )

    severity_counter = Counter()
    entity_type_counter = Counter()
    parse_status_counter = Counter()
    for row in parsed_risks:
        severity_counter[str(row.get("severity", "") or "UNKNOWN")] += 1
        entity_type_counter[str(row.get("entity_type", "") or "UNKNOWN")] += 1
        parse_status_counter[str(row.get("parse_status", "") or "unknown")] += 1

    top_risks = sorted(risk_counter, key=lambda item: item["count"], reverse=True)[:5]
    top_families = family_counter.most_common(6)
    condensed_families = condense_families_for_chart(top_families)
    top_severities = severity_counter.most_common()
    top_entity_types = entity_type_counter.most_common(4)

    lead_family, lead_family_count = top_families[0] if top_families else ("Sin datos", 0)
    lead_risk = top_risks[0] if top_risks else {
        "risk_title": "Sin datos",
        "count": 0,
        "percentage": 0.0,
    }
    top3_share = round(sum(item["percentage"] for item in top_risks[:3]), 2)

    key_findings = [
        (
            f"El dominio de atencion principal es {lead_family} con {lead_family_count:,} hallazgos, "
            f"lo que concentra la mayor parte de la exposicion observada."
        ),
        (
            f"El riesgo mas frecuente es {lead_risk['risk_title']} con "
            f"{lead_risk['count']:,} eventos ({lead_risk['percentage']:.2f}%)."
        ),
        (
            f"Los tres riesgos mas frecuentes concentran {top3_share:.2f}% del total, "
            "lo que permite priorizar remediacion de forma muy focalizada."
        ),
    ]

    operational_highlights = [
        (
            f"Se identificaron {attack_path_count:,} rutas de ataque listas para "
            "revision de movimiento lateral y privilegios."
        ),
        (
            f"Quedan {parse_status_counter.get('requires_review', 0):,} casos que requieren "
            "confirmacion manual antes de cerrar la atencion."
        ),
        (
            "La priorizacion combina volumen, criticidad, accionabilidad y correlacion por entidad."
        ),
    ]

    suggested_actions = build_suggested_actions(
        top_risks=top_risks,
        top_families=top_families,
        attack_path_count=attack_path_count,
        audit_count=audit_count,
    )

    return {
        "metrics": {
            "total_risks": total_risks,
            "total_risk_types": total_risk_types,
            "attack_path_count": attack_path_count,
            "audit_count": audit_count,
            "parsed_count": parsed_count,
            "lead_family": lead_family,
            "lead_family_count": lead_family_count,
            "lead_risk_title": lead_risk["risk_title"],
            "lead_risk_percentage": lead_risk["percentage"],
            "top3_share": top3_share,
        },
        "top_risks": top_risks,
        "top_risk_chart_labels": [shorten_label(item["risk_title"], 28) for item in top_risks],
        "top_families": top_families,
        "condensed_families": condensed_families,
        "family_chart_labels": [shorten_label(label, 24) for label, _ in condensed_families],
        "top_severities": top_severities,
        "top_entity_types": top_entity_types,
        "key_findings": key_findings,
        "operational_highlights": operational_highlights,
        "suggested_actions": suggested_actions,
    }


def build_suggested_actions(
    top_risks: list[dict],
    top_families: list[tuple[str, int]],
    attack_path_count: int,
    audit_count: int,
) -> list[str]:
    actions = []

    if top_families:
        actions.append(
            f"Priorizar el dominio {top_families[0][0]} como frente principal de remediacion."
        )

    if top_risks:
        actions.append(
            f"Atacar primero el riesgo {top_risks[0]['risk_title']} para reducir volumen rapidamente."
        )

    if attack_path_count:
        actions.append(
            "Revisar las rutas de ataque para cortar relaciones de acceso y privilegios heredados."
        )

    if audit_count:
        actions.append(
            "Validar internamente los casos no normalizados antes de cerrar la version de entrega."
        )
    else:
        actions.append(
            "El reporte esta listo para revision tecnica y coordinacion de remediacion."
        )

    return actions[:4]


def build_entity_correlation_rows(
    parsed_risks: list[dict],
    family_filter: set[str] | None = None,
    min_distinct_risks: int = 2,
) -> list[dict]:
    """Create entity-level correlation rows from parsed risks."""
    grouped = {}

    for row in parsed_risks:
        family = str(row.get("risk_family", "") or "")
        if family_filter and family not in family_filter:
            continue

        key = (
            str(row.get("entity", "") or ""),
            str(row.get("secondary_identifier", "") or ""),
            str(row.get("entity_type", "") or ""),
        )
        grouped.setdefault(key, []).append(row)

    correlation_rows = []
    for (entity, secondary_identifier, entity_type), rows in grouped.items():
        risk_titles = sorted(
            {
                str(row.get("risk_title", row.get("risk_type", "")) or "")
                for row in rows
                if str(row.get("risk_title", row.get("risk_type", "")) or "")
            }
        )
        risk_types = sorted(
            {
                str(row.get("risk_type", "") or "")
                for row in rows
                if str(row.get("risk_type", "") or "")
            }
        )
        families = sorted(
            {
                str(row.get("risk_family", "") or "")
                for row in rows
                if str(row.get("risk_family", "") or "")
            }
        )

        if len(risk_types) < min_distinct_risks:
            continue

        highest_row = min(
            rows,
            key=lambda row: SEVERITY_ORDER.get(
                str(row.get("severity", "") or "UNKNOWN").upper(),
                5,
            ),
        )
        correlation_rows.append(
            {
                "entity": entity,
                "secondary_identifier": secondary_identifier,
                "entity_type": entity_type,
                "highest_severity": highest_row.get("severity", ""),
                "total_findings": len(rows),
                "distinct_risk_types": len(risk_types),
                "distinct_families": len(families),
                "risk_titles": human_join(risk_titles, max_items=6),
                "risk_families": human_join(families, max_items=4),
                "correlation_note": build_correlation_note(risk_types, families),
                "falcon_link": highest_row.get("falcon_link", ""),
            }
        )

    return sorted(
        correlation_rows,
        key=lambda row: (
            SEVERITY_ORDER.get(str(row.get("highest_severity", "") or "UNKNOWN").upper(), 5),
            -int(row.get("distinct_risk_types", 0) or 0),
            -int(row.get("total_findings", 0) or 0),
            str(row.get("entity", "") or ""),
        ),
    )


def build_parsed_risk_correlation_index(parsed_risks: list[dict]) -> dict[tuple[str, str, str], dict]:
    grouped = {}
    for row in parsed_risks:
        key = (
            str(row.get("entity", "") or ""),
            str(row.get("secondary_identifier", "") or ""),
            str(row.get("entity_type", "") or ""),
        )
        grouped.setdefault(key, []).append(row)

    index = {}
    for key, rows in grouped.items():
        risk_titles = sorted(
            {
                str(row.get("risk_title", row.get("risk_type", "")) or "")
                for row in rows
                if str(row.get("risk_title", row.get("risk_type", "")) or "")
            }
        )
        risk_types = sorted(
            {
                str(row.get("risk_type", "") or "")
                for row in rows
                if str(row.get("risk_type", "") or "")
            }
        )
        families = sorted(
            {
                str(row.get("risk_family", "") or "")
                for row in rows
                if str(row.get("risk_family", "") or "")
            }
        )

        if len(risk_types) > 1:
            summary = (
                f"La entidad concentra {len(risk_types)} tipos de riesgo "
                f"({human_join(risk_titles, max_items=4)})."
            )
        else:
            summary = "La entidad no muestra otros tipos de riesgo en este dataset."

        index[key] = {
            "entity_risk_type_count": len(risk_types),
            "entity_total_findings": len(rows),
            "entity_risk_overview": summary,
            "entity_family_overview": human_join(families, max_items=4),
        }

    return index


def enrich_parsed_risks_with_entity_correlation(parsed_risks: list[dict]) -> list[dict]:
    """Attach correlation counters and summaries to each parsed risk row."""
    index = build_parsed_risk_correlation_index(parsed_risks)
    enriched = []
    for row in parsed_risks:
        key = (
            str(row.get("entity", "") or ""),
            str(row.get("secondary_identifier", "") or ""),
            str(row.get("entity_type", "") or ""),
        )
        extras = index.get(key, {})
        enriched.append({**row, **extras})
    return enriched


def build_correlation_note(risk_types: list[str], families: list[str]) -> str:
    """Generate a short analyst-facing interpretation for correlated findings."""
    risk_set = set(risk_types)
    family_set = set(families)

    if {"STALE_ACCOUNT", "STALE_ACCOUNT_USAGE"}.issubset(risk_set):
        return (
            "La entidad aparece como obsoleta y ademas presenta uso observado; "
            "conviene validar owner, ultima actividad y necesidad operativa."
        )

    if {"INACTIVE_ACCOUNT", "STALE_ACCOUNT"}.issubset(risk_set):
        return (
            "La entidad combina indicadores de inactividad y obsolescencia; "
            "la validacion de ciclo de vida debe ser prioritaria."
        )

    if {"INACTIVE_ACCOUNT", "NEW_SERVER_ACCESS"}.issubset(risk_set):
        return (
            "La entidad figura inactiva pero registra acceso reciente; "
            "esto amerita confirmar reactivacion legitima o uso no esperado."
        )

    if "Account Lifecycle" in family_set and "Access Change" in family_set:
        return (
            "Se observan cambios de acceso sobre una entidad con debilidades de ciclo de vida; "
            "conviene revisar si el acceso reciente explica la exposicion."
        )

    if len(risk_set) >= 3:
        return (
            "La entidad acumula multiples tipos de riesgo y debe tratarse como caso priorizado "
            "para revision integral."
        )

    return (
        "La entidad presenta mas de un tipo de riesgo; revisar relacion temporal y operativa "
        "entre los hallazgos antes de remediar cada uno por separado."
    )


def condense_families_for_chart(top_families: list[tuple[str, int]]) -> list[tuple[str, int]]:
    if len(top_families) <= 5:
        return top_families

    visible = top_families[:4]
    remainder = sum(count for _, count in top_families[4:])
    if remainder:
        visible.append(("Otras", remainder))
    return visible


def human_join(items: list[str], max_items: int = 5) -> str:
    cleaned = [str(item) for item in items if str(item)]
    if not cleaned:
        return ""

    visible = cleaned[:max_items]
    if len(cleaned) > max_items:
        visible.append(f"{len(cleaned) - max_items} mas")

    if len(visible) == 1:
        return visible[0]
    if len(visible) == 2:
        return f"{visible[0]} y {visible[1]}"
    return f"{', '.join(visible[:-1])} y {visible[-1]}"


def shorten_label(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return value[: max_length - 1].rstrip() + "..."
