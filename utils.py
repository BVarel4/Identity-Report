import csv
import json
from datetime import datetime
from pathlib import Path


def ensure_output_dir(path: str | Path) -> Path:
    output_path = Path(path)
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def save_json(data, filepath: str | Path) -> None:
    with Path(filepath).open("w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle, indent=2, ensure_ascii=False)


def save_csv(
    rows: list[dict],
    filepath: str | Path,
    fieldnames: list[str] | None = None,
) -> None:
    csv_path = Path(filepath)

    if not rows and not fieldnames:
        csv_path.touch()
        return

    effective_fieldnames = fieldnames or list(rows[0].keys())

    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=effective_fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def get_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_text(value) -> str:
    if value is None:
        return ""
    return str(value)


def format_entity_label(entity: dict) -> str:
    if not entity:
        return ""

    primary_name = safe_text(entity.get("primaryDisplayName"))
    entity_type = safe_text(entity.get("type"))

    if primary_name and entity_type:
        return f"{primary_name} ({entity_type})"
    if primary_name:
        return primary_name
    if entity_type:
        return entity_type
    return ""


def build_falcon_entity_link(base_url: str, entity: dict) -> str:
    entity_id = safe_text(entity.get("entityId"))
    entity_type = safe_text(entity.get("type")).lower()

    if not entity_id:
        return ""

    if entity_type:
        return f"{base_url}/identity-protection/entities/{entity_type}/{entity_id}"

    return f"{base_url}/identity-protection/entities/{entity_id}"
