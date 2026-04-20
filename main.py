"""
Identity Protection Reporting Pipeline

Desarrollado por Bryan Varela Vargas (Aka. W4rded).
"""

from audit import AuditCollector
from config import load_settings
from discovery import build_risk_inventory, discover_risk_types, fetch_risk_details
from parser_registry import build_parser_inventory
from parsers import parse_entities
from reporting import save_report_outputs
from utils import print_banner, print_metric_list, print_section, print_status


def main() -> None:
    settings = load_settings(validate=True)

    print_banner(
        "CrowdStrike Identity Protection Reporter",
        f"Dominio objetivo: {settings.target_domain}",
    )
    print_section("Pipeline", "Discovery, detalle, parseo y reporting tecnico")
    print_status("Config", f"Salida base: {settings.output_dir}", "info")
    print_status("Config", f"Reporte: {settings.report_name}", "info")
    print_status("Config", f"Artefactos: {settings.artifact_mode}", "info")

    discovery_nodes, risk_counter, discovery_pages = discover_risk_types(settings)
    risk_inventory = build_risk_inventory(risk_counter)
    parser_inventory = build_parser_inventory(risk_inventory)

    detail_nodes, detail_pages = fetch_risk_details(settings)

    audit = AuditCollector(sample_limit_per_risk=settings.sample_limit_per_risk)
    parsed_risks, attack_paths = parse_entities(
        nodes=detail_nodes,
        audit=audit,
        falcon_base_url=settings.falcon_base_url,
    )

    output_files, warnings = save_report_outputs(
        settings=settings,
        discovery_raw_nodes=discovery_nodes,
        detail_raw_nodes=detail_nodes,
        risk_inventory=risk_inventory,
        parser_inventory=parser_inventory,
        parsed_risks=parsed_risks,
        attack_paths=attack_paths,
        audit=audit,
    )

    total_risk_factors = sum(item["count"] for item in risk_inventory)

    print_metric_list(
        "Resumen Final",
        [
            ("Paginas discovery", str(len(discovery_pages))),
            ("Paginas detail", str(len(detail_pages))),
            ("Entidades discovery", str(len(discovery_nodes))),
            ("Entidades detail", str(len(detail_nodes))),
            ("Riesgos detectados", str(total_risk_factors)),
            ("Riesgos parseados", str(len(parsed_risks))),
            ("Attack paths", str(len(attack_paths))),
        ],
        "success",
    )

    unknown_count = sum(audit.unknown_risk_types.values())
    parser_error_count = len(audit.build_parser_error_rows())
    structure_issue_count = len(audit.build_structure_issue_rows())
    requires_review_count = sum(
        1 for row in parsed_risks if str(row.get("parse_status", "")).lower() == "requires_review"
    )

    print_section("Auditoria del Parseo", "Visibilidad inmediata de fallos y eventos sin parser")
    print_status(
        "Unknown risk types",
        str(unknown_count),
        "error" if unknown_count else "success",
    )
    print_status(
        "Parser errors",
        str(parser_error_count),
        "error" if parser_error_count else "success",
    )
    print_status(
        "Structure issues",
        str(structure_issue_count),
        "error" if structure_issue_count else "success",
    )
    print_status(
        "Requires review",
        str(requires_review_count),
        "error" if requires_review_count else "success",
    )
    if unknown_count or parser_error_count or structure_issue_count or requires_review_count:
        print_status(
            "Audit Alert",
            "Revisar las hojas de auditoria y los CSV de corrida antes de compartir el reporte.",
            "error",
        )

    print_section("Top Riesgos", "Principales hallazgos por frecuencia")
    for item in parser_inventory[:12]:
        print_status(
            item["risk_type"],
            (
                f"{item['risk_title']} | "
                f"count={item['count']} | "
                f"{item['percentage']}% | "
                f"parser={item['selected_parser']}"
            ),
            "info",
        )
    remaining = max(0, len(parser_inventory) - 12)
    if remaining:
        print_status("Top Riesgos", f"{remaining} tipos adicionales omitidos en consola", "warning")

    print_section("Archivos Generados")
    for name, path in output_files.items():
        print_status(name, path, "success")

    if warnings:
        print_section("Advertencias")
        for warning in warnings:
            print_status("Warning", warning, "warning")


if __name__ == "__main__":
    main()
