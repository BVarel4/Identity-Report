"""Parsing logic that turns CrowdStrike risk payloads into report-friendly rows."""

from audit import AuditCollector
from parser_registry import UNKNOWN_PARSER, select_parser_for_risk
from risk_catalog import get_risk_metadata
from utils import (
    build_falcon_entity_link,
    build_falcon_entity_page_link,
    format_entity_label,
    normalize_entity_severity,
    safe_text,
)

RELATION_MAP = {
    "ADMIN": "es administrador de",
    "ALLOWED_TO_ADD_TO_GROUP": "puede agregar miembros a",
    "ALLOWED_TO_ENROLL_CA_TEMPLATE": "puede inscribir plantillas de certificado en",
    "ALLOWED_TO_MODIFY_PERMISSIONS": "puede modificar permisos sobre",
    "ADMIN_REPLICATOR": "puede replicar objetos del dominio en",
    "ADMIN_UNCONSTRAINED_SVC_DELEGATION": "es vulnerable a delegacion de servicio no restringida hacia",
    "ALLOWED_TO_WRITE_KEY_CREDENTIAL": "tiene permiso para escribir credenciales en",
    "DUPLICATE_PASSWORD": "comparte la misma contrasena con",
    "DUPLICATED_LOCAL_ADMIN": "es administrador local en multiples endpoints que comparten",
    "IN_GROUP": "pertenece al grupo",
    "LOCAL_ADMIN": "tiene privilegios de administrador local en",
    "LOGGED_ON_TO_EP": "ha iniciado sesion en",
    "PASSWORD_RESETTER": "puede restablecer la contrasena de",
}

TECHNIQUE_MAP = {
    "ADMIN": "administracion sobre",
    "ALLOWED_TO_ADD_TO_GROUP": "agregado de miembros en",
    "ALLOWED_TO_ENROLL_CA_TEMPLATE": "inscripcion de plantillas de certificado en",
    "ALLOWED_TO_MODIFY_PERMISSIONS": "modificacion de permisos sobre",
    "ADMIN_REPLICATOR": "replicacion administrativa sobre",
    "ADMIN_UNCONSTRAINED_SVC_DELEGATION": "delegacion de servicio no restringida hacia",
    "ALLOWED_TO_WRITE_KEY_CREDENTIAL": "escritura de credenciales sobre",
    "DUPLICATE_PASSWORD": "reutilizacion de contrasena con",
    "DUPLICATED_LOCAL_ADMIN": "administracion local duplicada con",
    "IN_GROUP": "pertenencia a grupo",
    "LOCAL_ADMIN": "administracion local sobre",
    "LOGGED_ON_TO_EP": "sesion activa en",
    "PASSWORD_RESETTER": "restablecimiento de contrasena sobre",
}

INVERT_RELATIONS = {"HAS_SESSION", "LOGGED_ON_TO_EP", "USED_CREDENTIAL"}

SHAPE_LABELS = {
    "AttackPathBasedRiskFactor": "Ruta de ataque enriquecida",
    "DuplicatePasswordRiskEntityFactor": "Riesgo especializado de reutilizacion de contrasena",
    "LinkedAccountsRiskEntityFactor": "Riesgo especializado de cuentas vinculadas",
    "CertificateTemplateAuthenticationBasedRiskFactor": "Riesgo especializado de plantilla de certificado",
    "EntityRiskFactorImpl": "Indicador base de CrowdStrike",
}


def parse_entities(
    nodes: list[dict],
    audit: AuditCollector,
    falcon_base_url: str,
) -> tuple[list[dict], list[dict]]:
    """Parse every risk factor from the detail payload into report rows."""
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
                        risk_title=f"{risk_type.replace('_', ' ').title()}",
                        risk_family="Unclassified",
                        risk_typename=safe_text(risk_factor.get("__typename")),
                        structure_profile="Error de parser",
                        context_summary="No fue posible interpretar este riesgo durante el procesamiento.",
                        technical_observation=f"El parser asignado fallo con el mensaje: {exc}",
                        likely_impact="El hallazgo requiere revision manual antes de ser usado como base de remediacion.",
                        evidence_available="Entidad, severidad, tipo de riesgo y payload bruto preservado en auditoria.",
                        parser_name=parser_name,
                        parse_status="error",
                        detail=f"Parser error: {exc}",
                        recommended_action="Revisar este riesgo manualmente antes de generar reporte final.",
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
    """Dispatch a risk factor to its dedicated parser implementation."""
    if parser_name == "attack_path":
        return parse_attack_path(
            entity=entity,
            risk_factor=risk_factor,
            falcon_base_url=falcon_base_url,
            structure_is_valid=structure_is_valid,
        )

    if parser_name != UNKNOWN_PARSER:
        return parse_risk_template(
            entity=entity,
            risk_factor=risk_factor,
            parser_name=parser_name,
            falcon_base_url=falcon_base_url,
        )

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


def parse_attack_path(
    entity: dict,
    risk_factor: dict,
    falcon_base_url: str,
    structure_is_valid: bool,
) -> dict[str, list[dict]]:
    """Parse CrowdStrike attack-path payloads into technical and summary rows."""
    attack_path = risk_factor.get("attackPath") or []
    risk_type = risk_factor.get("type") or "HAS_ATTACK_PATH"
    metadata = get_risk_metadata(risk_type)

    source_entity = attack_path[0].get("entity", {}) if attack_path else entity
    related_entity, related_page = determine_related_attack_entity(
        root_entity=source_entity,
        attack_path=attack_path,
    )

    if attack_path:
        attack_steps = build_attack_steps(attack_path)
        attack_chain = build_attack_chain(attack_steps)
        attack_summary = build_attack_summary(
            source_entity=source_entity,
            related_entity=related_entity,
            attack_steps=attack_steps,
        )
        attack_techniques = build_attack_techniques(attack_steps)
        attack_outcome = build_attack_outcome(
            related_entity=related_entity,
            attack_steps=attack_steps,
        )
        attack_stages = build_attack_stages(attack_steps)
        parse_status = "parsed" if structure_is_valid else "structure_issue"
        detail = build_attack_path_detail(
            metadata=metadata,
            source_entity=source_entity,
            related_entity=related_entity,
            attack_summary=attack_summary,
            attack_techniques=attack_techniques,
            attack_outcome=attack_outcome,
            attack_stages=attack_stages,
            attack_chain=attack_chain,
            risk_factor=risk_factor,
        )
    else:
        attack_steps = []
        attack_chain = ""
        attack_summary = "No fue posible interpretar una ruta de ataque porque CrowdStrike no devolvio pasos en attackPath."
        attack_techniques = ""
        attack_outcome = "La ruta requiere revision manual para confirmar el objetivo final."
        attack_stages = ""
        parse_status = "structure_issue" if not structure_is_valid else "parsed_empty"
        detail = (
            "Contexto: riesgo de ruta de ataque detectado sin pasos disponibles en attackPath.\n"
            f"Impacto: {metadata['impact']}\n"
            f"Accion recomendada: {metadata['recommended_action']}"
        )

    parsed_row = build_parsed_row(
        entity=entity,
        risk_type=risk_type,
        risk_title=metadata["title"],
        risk_family=metadata["family"],
        risk_typename=safe_text(risk_factor.get("__typename")),
        structure_profile=describe_risk_factor_shape(risk_factor),
        context_summary=metadata["technical_summary"],
        technical_observation=build_attack_path_observation(
            attack_summary=attack_summary,
            attack_techniques=attack_techniques,
            attack_outcome=attack_outcome,
            attack_stages=attack_stages,
        ),
        likely_impact=metadata["impact"],
        evidence_available=build_attack_evidence_summary(risk_factor, attack_steps),
        parser_name="attack_path",
        parse_status=parse_status,
        detail=detail,
        recommended_action=metadata["recommended_action"],
        falcon_base_url=falcon_base_url,
        related_entity=related_entity,
        related_falcon_link=build_falcon_entity_page_link(
            falcon_base_url,
            related_entity,
            related_page,
        ),
    )

    attack_path_rows = []
    if attack_path:
        attack_path_rows.append(
            {
                "source_entity": format_entity_label(source_entity),
                "related_entity": format_entity_label(related_entity),
                "risk_title": metadata["title"],
                "attack_summary": attack_summary,
                "attack_techniques": attack_techniques,
                "attack_outcome": attack_outcome,
                "attack_stage_count": len(attack_steps),
                "attack_stages": attack_stages,
                "attack_chain": attack_chain,
                "severity": normalize_entity_severity(entity.get("riskScoreSeverity")),
                "source_link": build_falcon_entity_page_link(
                    falcon_base_url,
                    source_entity,
                    "risk",
                ),
                "related_link": build_falcon_entity_page_link(
                    falcon_base_url,
                    related_entity,
                    related_page,
                ),
            }
        )

    return {
        "parsed_rows": [parsed_row],
        "attack_path_rows": attack_path_rows,
    }


def parse_risk_template(
    entity: dict,
    risk_factor: dict,
    parser_name: str,
    falcon_base_url: str,
) -> dict[str, list[dict]]:
    """Parse non-attack-path risks using the generic metadata-driven template."""
    risk_type = risk_factor.get("type") or "UNKNOWN"
    metadata = get_risk_metadata(risk_type)
    entity_name = safe_text(entity.get("primaryDisplayName"))
    secondary_name = safe_text(entity.get("secondaryDisplayName"))
    entity_type = safe_text(entity.get("type"))
    severity = normalize_entity_severity(entity.get("riskScoreSeverity"))
    risk_typename = safe_text(risk_factor.get("__typename"))
    structure_profile = describe_risk_factor_shape(risk_factor)
    context_summary = build_risk_context_summary(
        entity=entity,
        metadata=metadata,
        risk_factor=risk_factor,
    )
    technical_observation = build_risk_technical_observation(
        entity=entity,
        metadata=metadata,
        risk_factor=risk_factor,
    )
    evidence_available = build_risk_evidence_summary(risk_factor)
    likely_impact = metadata["impact"]

    detail_parts = build_risk_detail_parts(
        entity=entity,
        risk_factor=risk_factor,
        context_summary=context_summary,
        technical_observation=technical_observation,
        structure_profile=structure_profile,
        secondary_name=secondary_name,
        severity=severity,
        evidence_available=evidence_available,
        likely_impact=likely_impact,
        recommended_action=metadata["recommended_action"],
    )
    return {
        "parsed_rows": [
            build_parsed_row(
                entity=entity,
                risk_type=risk_type,
                risk_title=metadata["title"],
                risk_family=metadata["family"],
                risk_typename=risk_typename,
                structure_profile=structure_profile,
                context_summary=context_summary,
                technical_observation=technical_observation,
                likely_impact=likely_impact,
                evidence_available=evidence_available,
                parser_name=parser_name,
                parse_status="parsed",
                detail="\n".join(detail_parts),
                recommended_action=metadata["recommended_action"],
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
    """Emit a safe row for risks that do not yet have explicit parser support."""
    risk_type = risk_factor.get("type") or "UNKNOWN"
    risk_typename = safe_text(risk_factor.get("__typename"))

    return {
        "parsed_rows": [
            build_parsed_row(
                entity=entity,
                risk_type=risk_type,
                risk_title="Unknown risk type",
                risk_family="Unclassified",
                risk_typename=risk_typename,
                structure_profile=describe_risk_factor_shape(risk_factor),
                context_summary="CrowdStrike reporto un tipo de riesgo sin plantilla dedicada en este proyecto.",
                technical_observation=(
                    "El hallazgo se identifico correctamente, pero no existe aun una "
                    "interpretacion tecnica especifica para este tipo."
                ),
                likely_impact="Debe revisarse manualmente antes de tomar decisiones de remediacion.",
                evidence_available=build_risk_evidence_summary(risk_factor),
                parser_name="unknown",
                parse_status="requires_review",
                detail=(
                    "Contexto: este riesgo no tiene parser dedicado.\n"
                    "Impacto: el pipeline pudo identificar el tipo pero no cuenta aun con interpretacion especifica.\n"
                    f"Tipo GraphQL: {risk_typename or 'N/A'}\n"
                    "Accion recomendada: revisar muestra raw y registrar una plantilla dedicada."
                ),
                recommended_action="Revisar muestra raw y registrar nueva plantilla de riesgo.",
                falcon_base_url=falcon_base_url,
            )
        ],
        "attack_path_rows": [],
    }


def build_attack_steps(attack_path: list[dict]) -> list[dict]:
    normalized_steps = []

    for step in attack_path:
        from_entity = ensure_dict(step.get("entity"))
        next_entity = ensure_dict(step.get("nextEntity"))
        relation = safe_text(step.get("relation")).upper() or "RELATED_TO"
        relation_es = RELATION_MAP.get(relation, relation)
        from_label = format_entity_label(from_entity) or "Entidad desconocida"
        to_label = format_entity_label(next_entity) or "Entidad desconocida"
        is_terminal = not bool(next_entity)

        if is_terminal:
            step_text = f"{from_label} mantiene privilegios relevantes o acceso de alto impacto"
        elif relation in INVERT_RELATIONS:
            step_text = f"{to_label} {relation_es} {from_label}"
        else:
            step_text = f"{from_label} {relation_es} {to_label}"

        normalized_steps.append(
            {
                "from_entity": from_entity,
                "to_entity": next_entity,
                "relation": relation,
                "relation_es": relation_es,
                "from_label": from_label,
                "to_label": to_label,
                "is_terminal": is_terminal,
                "text": step_text,
            }
        )

    return normalized_steps


def build_attack_chain(attack_steps: list[dict]) -> str:
    return " -> ".join(
        step.get("text", "") for step in attack_steps if step.get("text")
    )


def describe_risk_factor_shape(risk_factor: dict) -> str:
    typename = safe_text(risk_factor.get("__typename"))
    if typename == "AttackPathBasedRiskFactor":
        attack_path = risk_factor.get("attackPath")
        if isinstance(attack_path, list) and attack_path:
            return "Ruta de ataque enriquecida con pasos observables"
        return "Tipo compatible con ruta de ataque, pero sin pasos detallados en este payload"

    return SHAPE_LABELS.get(typename, f"Estructura no clasificada ({typename or 'sin typename'})")


def build_attack_path_observation(
    attack_summary: str,
    attack_techniques: str,
    attack_outcome: str,
    attack_stages: str,
) -> str:
    parts = [attack_summary]
    if attack_techniques:
        parts.append(f"Tecnicas observadas: {attack_techniques}.")
    parts.append(attack_outcome)
    if attack_stages:
        parts.append(f"Ruta por etapas:\n{attack_stages}")
    return "\n".join(parts)


def build_attack_evidence_summary(risk_factor: dict, attack_steps: list[dict]) -> str:
    step_count = len(attack_steps)
    if step_count:
        return (
            "Entidad afectada, severidad y "
            f"attackPath con {step_count} {pluralize(step_count, 'etapa', 'etapas')} observables."
        )
    return (
        "Entidad afectada, severidad y senal de ruta de ataque, "
        "sin etapas visibles en este payload."
    )


def build_attack_summary(
    source_entity: dict,
    related_entity: dict,
    attack_steps: list[dict],
) -> str:
    source_label = format_entity_label(source_entity) or "La entidad origen"
    target_label = infer_attack_target_label(related_entity, attack_steps)
    step_count = len(attack_steps)
    first_transition = build_attack_transition_phrase(attack_steps[0]) if attack_steps else ""

    summary = (
        f"{source_label} puede alcanzar {target_label} en {step_count} "
        f"{pluralize(step_count, 'paso', 'pasos')}."
    )
    if first_transition:
        summary += f" La ruta inicia cuando {first_transition}."
    if attack_steps and attack_steps[-1].get("is_terminal"):
        summary += f" El recorrido termina en {target_label} con privilegios relevantes o alto impacto."
    return summary


def build_attack_techniques(attack_steps: list[dict], limit: int = 4) -> str:
    techniques = []
    seen = set()

    for step in attack_steps:
        if step.get("is_terminal"):
            continue

        technique_phrase = build_step_technique_phrase(step)
        if not technique_phrase:
            continue

        normalized = technique_phrase.lower()
        if normalized in seen:
            continue

        seen.add(normalized)
        techniques.append(technique_phrase)

    if not techniques:
        return ""

    return human_join(techniques[:limit])


def build_attack_outcome(
    related_entity: dict,
    attack_steps: list[dict],
) -> str:
    target_label = infer_attack_target_label(related_entity, attack_steps)
    if attack_steps and attack_steps[-1].get("is_terminal"):
        return (
            f"La ruta culmina en {target_label}, identificado por CrowdStrike como "
            "un punto con privilegios relevantes o de alto impacto operativo."
        )

    return f"La ruta termina sobre {target_label} y debe revisarse como posible pivot o destino sensible."


def build_risk_context_summary(
    entity: dict,
    metadata: dict,
    risk_factor: dict,
) -> str:
    risk_type = safe_text(risk_factor.get("type")).upper()
    entity_label = format_entity_label(entity) or "La entidad evaluada"
    structure_profile = describe_risk_factor_shape(risk_factor)

    if risk_type == "KRBTGT_AGED_PASSWORD":
        return (
            f"CrowdStrike detecta que la cuenta KRBTGT asociada a {entity_label} mantiene "
            "una contrasena con antiguedad superior a la recomendada para una identidad critica "
            f"de Kerberos. El hallazgo se recibe bajo el perfil estructural '{structure_profile}'."
        )

    return (
        f"{metadata['technical_summary']} Este hallazgo afecta a {entity_label} y se recibe "
        f"bajo el perfil estructural '{structure_profile}'."
    )


def build_risk_technical_observation(
    entity: dict,
    metadata: dict,
    risk_factor: dict,
) -> str:
    """Generate the analyst-facing technical observation for a parsed risk."""
    risk_type = safe_text(risk_factor.get("type")).upper()
    risk_typename = safe_text(risk_factor.get("__typename"))
    entity_label = format_entity_label(entity) or "la entidad evaluada"

    if risk_typename == "DuplicatePasswordRiskEntityFactor":
        return (
            f"CrowdStrike confirma reutilizacion de contrasena sobre {entity_label}. "
            "En esta consulta el payload no expone la identidad par, por lo que el hallazgo "
            "debe tratarse como reutilizacion confirmada con detalle limitado."
        )

    if risk_typename == "LinkedAccountsRiskEntityFactor":
        return (
            f"CrowdStrike marca una relacion de cuentas vinculadas de riesgo para {entity_label}. "
            "El payload disponible no detalla la cuenta asociada especifica, por lo que se "
            "debe complementar con revision en Falcon."
        )

    if risk_typename == "CertificateTemplateAuthenticationBasedRiskFactor":
        return (
            f"El riesgo se origina en una configuracion de plantilla de certificado con impacto "
            f"sobre autenticacion. La entidad asociada en este registro es {entity_label}."
        )

    if risk_typename == "AttackPathBasedRiskFactor":
        attack_path = risk_factor.get("attackPath")
        if isinstance(attack_path, list) and attack_path:
            source_entity = attack_path[0].get("entity", {}) if attack_path else entity
            related_entity, _ = determine_related_attack_entity(
                root_entity=source_entity,
                attack_path=attack_path,
            )
            attack_steps = build_attack_steps(attack_path)
            return build_attack_path_observation(
                attack_summary=build_attack_summary(source_entity, related_entity, attack_steps),
                attack_techniques=build_attack_techniques(attack_steps),
                attack_outcome=build_attack_outcome(related_entity, attack_steps),
                attack_stages=build_attack_stages(attack_steps),
            )
        return (
            f"{entity_label} presenta un riesgo de tipo AttackPathBasedRiskFactor, pero este "
            "payload no incluye la ruta detallada."
        )

    generic_observations = {
        "KRBTGT_AGED_PASSWORD": (
            f"{entity_label} corresponde a la cuenta KRBTGT del dominio. KRBTGT es utilizada por "
            "Active Directory para firmar y proteger tickets Kerberos; cuando su secreto permanece "
            "sin rotacion durante demasiado tiempo, aumenta el riesgo residual ante compromisos "
            "previos y se dificulta invalidar tickets potencialmente forjados."
        ),
        "WEAK_PASSWORD_POLICY": (
            f"CrowdStrike reporta una condicion de politica de contrasena debil asociada con {entity_label}. "
            "El payload actual no incluye el parametro exacto que incumple, por lo que la validacion "
            "debe completarse contra la politica efectiva."
        ),
        "WEAK_PASSWORD": (
            f"CrowdStrike identifica una contrasena debil para {entity_label}. "
            "La consulta no expone el atributo especifico de debilidad, pero el riesgo debe "
            "atenderse como hallazgo confirmado."
        ),
        "INACTIVE_ACCOUNT": (
            f"{entity_label} aparece como cuenta inactiva. El payload no agrega ultima actividad, "
            "por lo que la confirmacion operativa debe hacerse con inventario y owner de la cuenta."
        ),
        "STALE_ACCOUNT": (
            f"{entity_label} figura como cuenta obsoleta o sin uso reciente suficiente. "
            "El detalle temporal no viene en esta consulta, por lo que se requiere validacion con el equipo owner."
        ),
        "STALE_ACCOUNT_USAGE": (
            f"{entity_label} muestra uso a pesar de ser clasificada como stale. "
            "Esto debe revisarse como reactivacion inesperada o control deficiente del ciclo de vida."
        ),
        "SMB_SIGNING_DISABLED": (
            f"{entity_label} se encuentra asociado a una condicion donde SMB signing no esta habilitado. "
            "El payload actual confirma el hallazgo, aunque no detalla el parametro de configuracion puntual."
        ),
        "VULNERABLE_OS": (
            f"{entity_label} presenta exposicion por sistema operativo vulnerable. "
            "La consulta no incluye version o CVE, por lo que el versionado debe complementarse fuera de este reporte."
        ),
        "NEW_SERVER_ACCESS": (
            f"{entity_label} registra acceso a un servidor no habitual o recientemente observado. "
            "La consulta actual confirma el cambio, aunque no incluye el nombre del servidor destino."
        ),
        "SHARED_ENDPOINT": (
            f"{entity_label} participa en un patron de endpoint compartido. "
            "El payload no lista las otras identidades involucradas, por lo que la corroboracion se realiza en Falcon."
        ),
        "SHARED_USER": (
            f"{entity_label} presenta caracteristicas compatibles con uso compartido. "
            "La consulta no expone las identidades humanas relacionadas, pero el hallazgo debe tratarse como problema de trazabilidad."
        ),
        "PRIVILEGED_USER_USING_UNMANAGED_ENDPOINT": (
            f"{entity_label} se relaciona con uso privilegiado desde un endpoint no gestionado. "
            "La consulta confirma el hallazgo, aunque no expone el endpoint especifico en este payload."
        ),
        "SHARED_ENDPOINT_USED_BY_PRIVILEGED_USER": (
            f"{entity_label} forma parte de un endpoint compartido usado por una identidad privilegiada. "
            "El payload no enumera la contraparte privilegiada, pero el riesgo debe asumirse como exposicion administrativa."
        ),
        "RISKY_LINKED_ACCOUNT": (
            f"{entity_label} esta correlacionada con una cuenta vinculada de riesgo. "
            "El payload disponible confirma la correlacion, aunque no detalla la contraparte."
        ),
    }

    if risk_type in generic_observations:
        return generic_observations[risk_type]

    return (
        f"{entity_label} presenta el riesgo {metadata['title']}. "
        "En esta consulta CrowdStrike lo expone como indicador confirmado de tipo base, "
        "sin campos tecnicos adicionales mas alla del tipo de riesgo y la entidad afectada."
    )


def build_risk_detail_parts(
    entity: dict,
    risk_factor: dict,
    context_summary: str,
    technical_observation: str,
    structure_profile: str,
    secondary_name: str,
    severity: str,
    evidence_available: str,
    likely_impact: str,
    recommended_action: str,
) -> list[str]:
    risk_type = safe_text(risk_factor.get("type")).upper()

    if risk_type == "KRBTGT_AGED_PASSWORD":
        detail_parts = [f"Contexto: {context_summary}"]
        detail_parts.append(f"Observacion tecnica: {technical_observation}")
        detail_parts.append(f"Perfil estructural: {structure_profile}")
        if secondary_name:
            detail_parts.append(f"Cuenta afectada: {secondary_name}")
        if severity:
            detail_parts.append(f"Severidad reportada: {severity}")
        detail_parts.append(
            "Evidencia disponible: entidad afectada, severidad de entidad y tipo de riesgo "
            "KRBTGT_AGED_PASSWORD; CrowdStrike no expone en este payload la fecha exacta de la "
            "ultima rotacion ni atributos adicionales del secreto."
        )
        detail_parts.append(
            "Impacto: una antiguedad excesiva del secreto KRBTGT prolonga la exposicion residual "
            "del componente mas sensible para emision de tickets Kerberos y complica la contencion "
            "efectiva ante un compromiso historico."
        )
        detail_parts.append(f"Accion recomendada: {recommended_action}")
        return detail_parts

    detail_parts = [f"Contexto: {context_summary}"]
    detail_parts.append(f"Observacion tecnica: {technical_observation}")
    detail_parts.append(f"Perfil estructural: {structure_profile}")
    if secondary_name:
        detail_parts.append(f"Identificador secundario: {secondary_name}")
    if severity:
        detail_parts.append(f"Severidad reportada: {severity}")
    detail_parts.append(f"Evidencia disponible: {evidence_available}")
    detail_parts.append(f"Impacto: {likely_impact}")
    detail_parts.append(f"Accion recomendada: {recommended_action}")
    return detail_parts


def build_risk_evidence_summary(risk_factor: dict) -> str:
    risk_type = safe_text(risk_factor.get("type")) or "N/A"
    evidence_parts = [
        "Entidad afectada",
        "severidad",
        f"tipo de riesgo {risk_type}",
    ]

    attack_path = risk_factor.get("attackPath")
    if isinstance(attack_path, list):
        evidence_parts.append(
            f"attackPath con {len(attack_path)} {pluralize(len(attack_path), 'etapa', 'etapas')}"
        )
    elif safe_text(risk_factor.get("__typename")) == "EntityRiskFactorImpl":
        evidence_parts.append("sin detalle tecnico adicional en este payload")

    return ", ".join(evidence_parts) + "."


def build_attack_stages(attack_steps: list[dict]) -> str:
    stage_lines = []
    for index, step in enumerate(attack_steps, start=1):
        stage_lines.append(f"{index}. {step.get('text', '')}")
    return "\n".join(stage_lines)


def build_attack_transition_phrase(step: dict) -> str:
    if not step:
        return ""
    if step.get("is_terminal"):
        return safe_text(step.get("text"))

    from_label = safe_text(step.get("from_label"))
    relation_es = safe_text(step.get("relation_es"))
    to_label = safe_text(step.get("to_label"))

    if step.get("relation") in INVERT_RELATIONS:
        return f"{to_label} {relation_es} {from_label}"
    return f"{from_label} {relation_es} {to_label}"


def build_step_technique_phrase(step: dict) -> str:
    relation = safe_text(step.get("relation")).upper()
    target_label = safe_text(step.get("to_label"))
    if not relation or not target_label or step.get("is_terminal"):
        return ""

    technique = TECHNIQUE_MAP.get(relation)
    if technique:
        return f"{technique} {target_label}"

    relation_es = safe_text(step.get("relation_es"))
    if relation_es:
        return f"{relation_es} {target_label}"

    return ""


def infer_attack_target_label(related_entity: dict, attack_steps: list[dict]) -> str:
    for step in reversed(attack_steps):
        if step.get("is_terminal"):
            terminal_label = safe_text(step.get("from_label"))
            if terminal_label:
                return terminal_label

        candidate = safe_text(step.get("to_label"))
        if candidate and candidate != "Entidad desconocida":
            return candidate

    related_label = format_entity_label(related_entity)
    if related_label:
        return related_label

    return "el objetivo final de la ruta"


def human_join(items: list[str]) -> str:
    cleaned = [safe_text(item) for item in items if safe_text(item)]
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return cleaned[0]
    if len(cleaned) == 2:
        return f"{cleaned[0]} y {cleaned[1]}"
    return f"{', '.join(cleaned[:-1])} y {cleaned[-1]}"


def pluralize(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def determine_related_attack_entity(
    root_entity: dict,
    attack_path: list[dict],
) -> tuple[dict, str]:
    if not attack_path:
        return {}, "risk"

    root_type = safe_text(root_entity.get("type")).upper()
    root_id = safe_text(root_entity.get("entityId"))

    if root_type == "ENDPOINT":
        for step in attack_path:
            candidate = ensure_dict(step.get("entity"))
            if (
                safe_text(candidate.get("type")).upper() == "ENDPOINT"
                and safe_text(candidate.get("entityId"))
                and safe_text(candidate.get("entityId")) != root_id
            ):
                return candidate, "about"

    if root_type == "USER":
        duplicate_candidate = {}
        for step in attack_path:
            step_entity = ensure_dict(step.get("entity"))
            next_entity = ensure_dict(step.get("nextEntity"))
            relation = safe_text(step.get("relation")).upper()

            if safe_text(step_entity.get("type")).upper() == "ENDPOINT" and safe_text(step_entity.get("entityId")):
                return step_entity, "about"

            if safe_text(next_entity.get("type")).upper() == "ENDPOINT" and safe_text(next_entity.get("entityId")):
                return next_entity, "about"

            if relation == "DUPLICATE_PASSWORD" and safe_text(next_entity.get("type")).upper() == "USER":
                duplicate_candidate = next_entity

        if duplicate_candidate:
            return duplicate_candidate, "risk"

    for step in reversed(attack_path):
        for candidate in (ensure_dict(step.get("nextEntity")), ensure_dict(step.get("entity"))):
            if safe_text(candidate.get("entityId")):
                page = "about" if safe_text(candidate.get("type")).upper() == "ENDPOINT" else "risk"
                return candidate, page

    return {}, "risk"


def build_attack_path_detail(
    metadata: dict,
    source_entity: dict,
    related_entity: dict,
    attack_summary: str,
    attack_techniques: str,
    attack_outcome: str,
    attack_stages: str,
    attack_chain: str,
    risk_factor: dict,
) -> str:
    detail_lines = [
        f"Contexto: {metadata['technical_summary']}",
        f"Entidad principal: {format_entity_label(source_entity) or 'Entidad desconocida'}",
    ]

    if related_entity:
        detail_lines.append(
            f"Entidad relacionada priorizada: {format_entity_label(related_entity)}"
        )

    detail_lines.append(f"Resumen de exposicion: {attack_summary}")
    if attack_techniques:
        detail_lines.append(f"Tecnicas observadas: {attack_techniques}")
    detail_lines.append(f"Resultado esperado: {attack_outcome}")
    detail_lines.append(
        f"Ruta por etapas:\n{attack_stages or 'Sin pasos interpretables'}"
    )
    detail_lines.append(f"Cadena compacta: {attack_chain or 'Sin pasos interpretables'}")
    detail_lines.append(f"Impacto: {metadata['impact']}")

    detail_lines.append(f"Accion recomendada: {metadata['recommended_action']}")
    return "\n".join(detail_lines)


def ensure_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def build_parsed_row(
    entity: dict,
    risk_type: str,
    risk_title: str,
    risk_family: str,
    risk_typename: str,
    structure_profile: str,
    context_summary: str,
    technical_observation: str,
    likely_impact: str,
    evidence_available: str,
    parser_name: str,
    parse_status: str,
    detail: str,
    recommended_action: str,
    falcon_base_url: str,
    related_entity: dict | None = None,
    related_falcon_link: str = "",
) -> dict:
    return {
        "entity": safe_text(entity.get("primaryDisplayName")),
        "secondary_identifier": safe_text(entity.get("secondaryDisplayName")),
        "entity_type": safe_text(entity.get("type")),
        "severity": normalize_entity_severity(entity.get("riskScoreSeverity")),
        "risk_type": risk_type,
        "risk_title": risk_title,
        "risk_family": risk_family,
        "risk_typename": risk_typename,
        "structure_profile": structure_profile,
        "context_summary": context_summary,
        "technical_observation": technical_observation,
        "likely_impact": likely_impact,
        "evidence_available": evidence_available,
        "detail": detail,
        "recommended_action": recommended_action,
        "related_entity": format_entity_label(related_entity or {}),
        "parser_used": parser_name,
        "parse_status": parse_status,
        "falcon_link": build_falcon_entity_page_link(falcon_base_url, entity, "risk"),
        "related_falcon_link": related_falcon_link,
    }
