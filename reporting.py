from pathlib import Path

from audit import AuditCollector
from config import Settings
from utils import ensure_output_dir, get_timestamp, save_csv, save_json

RISK_INVENTORY_FIELDS = ["risk_type", "count", "percentage"]
PARSER_INVENTORY_FIELDS = ["risk_type", "count", "percentage", "selected_parser"]
PARSED_RISK_FIELDS = [
    "entity",
    "secondary_identifier",
    "entity_type",
    "severity",
    "risk_type",
    "detail",
    "related_entity",
    "parser_used",
    "parse_status",
    "falcon_link",
]
ATTACK_PATH_FIELDS = [
    "source_entity",
    "related_entity",
    "attack_chain",
    "severity",
    "source_link",
    "related_link",
]
UNKNOWN_RISK_FIELDS = ["risk_type", "count", "action_required"]
ERROR_FIELDS = [
    "issue_type",
    "risk_type",
    "parser_name",
    "entity_name",
    "secondary_name",
    "entity_type",
    "severity",
    "message",
]
RAW_SAMPLE_FIELDS = [
    "risk_type",
    "sample_number",
    "sample_category",
    "parser_name",
    "entity_name",
    "secondary_name",
    "entity_type",
    "severity",
]


def save_report_outputs(
    settings: Settings,
    discovery_raw_nodes: list[dict],
    detail_raw_nodes: list[dict],
    risk_inventory: list[dict],
    parser_inventory: list[dict],
    parsed_risks: list[dict],
    attack_paths: list[dict],
    audit: AuditCollector,
) -> tuple[dict, list[str]]:
    output_dir = ensure_output_dir(settings.output_dir)
    timestamp = get_timestamp()
    base_name = f"{settings.report_name}_{timestamp}"

    unknown_rows = audit.build_unknown_risk_rows()
    parser_error_rows = audit.build_parser_error_rows()
    structure_issue_rows = audit.build_structure_issue_rows()
    error_rows = parser_error_rows + structure_issue_rows
    raw_sample_rows = audit.build_raw_samples_rows()
    raw_samples_json = audit.export_raw_samples_json()

    output_files = {
        "discovery_raw_json": str(output_dir / f"{base_name}_discovery_raw.json"),
        "detail_raw_json": str(output_dir / f"{base_name}_detail_raw.json"),
        "risk_inventory_csv": str(output_dir / f"{base_name}_risk_inventory.csv"),
        "parser_inventory_csv": str(output_dir / f"{base_name}_parser_inventory.csv"),
        "parsed_risks_csv": str(output_dir / f"{base_name}_parsed_risks.csv"),
        "attack_paths_csv": str(output_dir / f"{base_name}_attack_paths.csv"),
        "unknown_risk_types_csv": str(output_dir / f"{base_name}_unknown_risk_types.csv"),
        "parser_errors_csv": str(output_dir / f"{base_name}_parser_errors.csv"),
        "structure_issues_csv": str(output_dir / f"{base_name}_structure_issues.csv"),
        "raw_samples_csv": str(output_dir / f"{base_name}_raw_samples_overview.csv"),
        "raw_samples_json": str(output_dir / f"{base_name}_raw_samples.json"),
        "technical_excel": str(output_dir / f"{base_name}_technical_report.xlsx"),
    }

    save_json(discovery_raw_nodes, output_files["discovery_raw_json"])
    save_json(detail_raw_nodes, output_files["detail_raw_json"])
    save_csv(risk_inventory, output_files["risk_inventory_csv"], RISK_INVENTORY_FIELDS)
    save_csv(
        parser_inventory,
        output_files["parser_inventory_csv"],
        PARSER_INVENTORY_FIELDS,
    )
    save_csv(parsed_risks, output_files["parsed_risks_csv"], PARSED_RISK_FIELDS)
    save_csv(attack_paths, output_files["attack_paths_csv"], ATTACK_PATH_FIELDS)
    save_csv(
        unknown_rows,
        output_files["unknown_risk_types_csv"],
        UNKNOWN_RISK_FIELDS,
    )
    save_csv(parser_error_rows, output_files["parser_errors_csv"], ERROR_FIELDS)
    save_csv(
        structure_issue_rows,
        output_files["structure_issues_csv"],
        ERROR_FIELDS,
    )
    save_csv(raw_sample_rows, output_files["raw_samples_csv"], RAW_SAMPLE_FIELDS)
    save_json(raw_samples_json, output_files["raw_samples_json"])

    warnings = []
    excel_error = save_technical_excel(
        filepath=Path(output_files["technical_excel"]),
        risk_summary_rows=parser_inventory,
        parsed_risks=parsed_risks,
        attack_paths=attack_paths,
        unknown_rows=unknown_rows,
        error_rows=error_rows,
    )
    if excel_error:
        warnings.append(excel_error)
        output_files.pop("technical_excel", None)

    return output_files, warnings


def save_technical_excel(
    filepath: Path,
    risk_summary_rows: list[dict],
    parsed_risks: list[dict],
    attack_paths: list[dict],
    unknown_rows: list[dict],
    error_rows: list[dict],
) -> str | None:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError:
        return (
            "No se genero el Excel tecnico porque falta la dependencia "
            "'openpyxl'."
        )

    workbook = Workbook()

    sheet_specs = [
        ("Risk Summary", risk_summary_rows, PARSER_INVENTORY_FIELDS),
        ("Parsed Risks", parsed_risks, PARSED_RISK_FIELDS),
        ("Attack Paths", attack_paths, ATTACK_PATH_FIELDS),
        ("Audit - Unknown", unknown_rows, UNKNOWN_RISK_FIELDS),
        ("Audit - Errors", error_rows, ERROR_FIELDS),
    ]

    for index, (title, rows, fieldnames) in enumerate(sheet_specs):
        worksheet = workbook.active if index == 0 else workbook.create_sheet(title=title)
        worksheet.title = title
        write_sheet(worksheet, rows, fieldnames, Font)

    workbook.save(filepath)
    return None


def write_sheet(worksheet, rows: list[dict], fieldnames: list[str], font_cls) -> None:
    worksheet.append(fieldnames)

    for cell in worksheet[1]:
        cell.font = font_cls(bold=True)

    for row in rows:
        worksheet.append([row.get(field, "") for field in fieldnames])

    worksheet.freeze_panes = "A2"
    worksheet.auto_filter.ref = worksheet.dimensions

    for column_cells in worksheet.columns:
        values = [str(cell.value or "") for cell in column_cells]
        max_length = max(len(value) for value in values) if values else 0
        worksheet.column_dimensions[column_cells[0].column_letter].width = min(
            max(max_length + 2, 12),
            60,
        )
