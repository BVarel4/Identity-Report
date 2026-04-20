"""Helpers compartidos para IO, enlaces Falcon y salida en consola."""

import csv
import json
import os
import shutil
import stat
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


ANSI_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "gray": "\033[90m",
    "magenta": "\033[35m",
}

TONE_LABELS = {
    "info": "SIGNAL",
    "success": "SYNCED",
    "warning": "DRIFT",
    "error": "ALERT",
}

SECTION_THEMES = {
    "pipeline": ("STAGE 0/6", "PRE-FLIGHT CHECK", "cyan"),
    "fase discovery": ("PHASE 1/6", "DISCOVERY MATRIX", "magenta"),
    "fase detail": ("PHASE 2/6", "DETAIL EXTRACTION", "cyan"),
    "render final": ("PHASE 3/6", "REPORT SYNTHESIS", "yellow"),
    "auditoria del parseo": ("PHASE 4/6", "AUDIT TRACE", "red"),
    "top riesgos": ("PANEL", "TOP RISK SIGNALS", "blue"),
    "archivos generados": ("PANEL", "ARTIFACT MANIFEST", "green"),
    "advertencias": ("PANEL", "WARNING BUS", "yellow"),
    "resumen final": ("PHASE 5/6", "MISSION DEBRIEF", "green"),
}

SESSION_BOOT_TIME = datetime.now()
STATUS_LABEL_WIDTH = 24
PROGRESS_LABEL_WIDTH = 14
PROGRESS_METER_WIDTH = 22


def ensure_output_dir(path: str | Path) -> Path:
    """Create the target directory tree when it does not already exist."""
    output_path = Path(path)
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def remove_file_if_exists(path: str | Path) -> bool:
    """Remove a file if present and report whether it was deleted."""
    target = Path(path)
    if not target.exists() or not target.is_file():
        return False

    for attempt in range(5):
        try:
            target.unlink()
            return True
        except PermissionError:
            try:
                os.chmod(target, stat.S_IWRITE)
            except OSError:
                pass
            time.sleep(0.2 * (attempt + 1))

    return not target.exists()


def _handle_remove_error(func, path, exc_info) -> None:
    """Best-effort retry for read-only files encountered during recursive removal."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def remove_dir_if_exists(path: str | Path) -> bool:
    """Remove a directory tree if present and report whether it was deleted."""
    target = Path(path)
    if not target.exists() or not target.is_dir():
        return False

    for attempt in range(6):
        try:
            shutil.rmtree(target, onerror=_handle_remove_error)
            return True
        except PermissionError:
            time.sleep(0.35 * (attempt + 1))

    return not target.exists()


def save_json(data, filepath: str | Path) -> None:
    """Persist a JSON document using UTF-8 and stable indentation."""
    with Path(filepath).open("w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle, indent=2, ensure_ascii=False)


def save_csv(
    rows: list[dict],
    filepath: str | Path,
    fieldnames: list[str] | None = None,
) -> None:
    """Persist a CSV file, optionally using explicit field order."""
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
    """Return a filesystem-safe timestamp for artifacts and reports."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_text(value) -> str:
    """Convert nullable values to string without raising on None."""
    if value is None:
        return ""
    return str(value)


def normalize_entity_severity(value) -> str:
    """Map CrowdStrike entity severity values to a stable human-readable scale."""
    raw = safe_text(value).strip().upper()
    severity_map = {
        "NORMAL": "LOW",
        "INFO": "LOW",
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    }
    return severity_map.get(raw, raw)


def format_entity_label(entity: dict) -> str:
    """Build a short display label using entity name and type when present."""
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
    """Build the default Falcon risk page for an entity."""
    entity_id = safe_text(entity.get("entityId"))

    if not entity_id:
        return ""

    console_base_url = resolve_falcon_console_base_url(base_url)
    return f"{console_base_url}/identity-protection/entities/{entity_id}/risk"


def build_falcon_entity_page_link(base_url: str, entity: dict, page: str = "risk") -> str:
    """Build a Falcon entity link targeting a supported console page."""
    entity_id = safe_text(entity.get("entityId"))
    if not entity_id:
        return ""

    console_base_url = resolve_falcon_console_base_url(base_url)
    safe_page = page if page in {"risk", "about"} else "risk"
    return f"{console_base_url}/identity-protection/entities/{entity_id}/{safe_page}"


def resolve_falcon_console_base_url(base_url: str) -> str:
    """Convert a Falcon API base URL into the matching Falcon console URL."""
    raw_base_url = safe_text(base_url).strip()
    if not raw_base_url:
        return "https://falcon.crowdstrike.com"

    if not raw_base_url.startswith(("http://", "https://")):
        raw_base_url = f"https://{raw_base_url}"

    parsed = urlparse(raw_base_url)
    hostname = (parsed.netloc or parsed.path).lower()

    if hostname.startswith("api.us-2."):
        return "https://falcon.us-2.crowdstrike.com"

    if hostname.startswith("api."):
        return "https://falcon.crowdstrike.com"

    if hostname.startswith("falcon.us-2."):
        return "https://falcon.us-2.crowdstrike.com"

    if hostname.startswith("falcon."):
        return "https://falcon.crowdstrike.com"

    return "https://falcon.crowdstrike.com"


def supports_color() -> bool:
    """Return whether ANSI colors should be used for console output."""
    return sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def supports_unicode_output() -> bool:
    """Return whether the current console encoding supports Unicode glyphs."""
    encoding = (sys.stdout.encoding or "").lower()
    return "utf" in encoding or "65001" in encoding


def colorize(text: str, color: str, bold: bool = False) -> str:
    """Apply ANSI color and optional bold formatting when supported."""
    if not supports_color():
        return text

    prefix = ANSI_CODES.get(color, "")
    if bold:
        prefix = ANSI_CODES["bold"] + prefix

    return f"{prefix}{text}{ANSI_CODES['reset']}"


def console_width(default: int = 96) -> int:
    """Return a safe terminal width for framed console output."""
    detected = shutil.get_terminal_size((default, 20)).columns
    return max(72, min(detected, 108))


def glyph(unicode_text: str, ascii_text: str) -> str:
    """Choose a Unicode glyph when supported, otherwise use ASCII fallback."""
    return unicode_text if supports_unicode_output() else ascii_text


def make_rule(width: int = 42, char: str = "=") -> str:
    """Build a decorative console rule with Unicode fallback."""
    safe_width = max(12, width)
    if supports_unicode_output():
        neon_char = {
            "=": "═",
            "-": "─",
            "#": "▓",
        }.get(char, char)
        return neon_char * safe_width
    return char * safe_width


def make_panel_prefix(label: str) -> str:
    """Render a short cyberpunk-style panel tag."""
    if supports_unicode_output():
        return f"⟦ {label} ⟧"
    return f"[[ {label} ]]"


def format_runtime() -> str:
    """Return elapsed runtime in HH:MM:SS since console session start."""
    elapsed = datetime.now() - SESSION_BOOT_TIME
    total_seconds = max(0, int(elapsed.total_seconds()))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def build_trace_code(seed_text: str) -> str:
    """Build a compact pseudo-trace identifier for visual console context."""
    seed = sum((index + 1) * ord(char) for index, char in enumerate(seed_text.upper()))
    block_a = seed & 0xFFFF
    block_b = (seed * 3 + len(seed_text) * 97) & 0xFFFF
    block_c = (seed * 7 + 0x3716) & 0xFFFF
    return f"{block_a:04X}:{block_b:04X}:{block_c:04X}"


def fit_text(text: str, width: int) -> str:
    """Fit plain text into a console panel width with a compact ellipsis."""
    clean = safe_text(text)
    if len(clean) <= width:
        return clean
    if width <= 3:
        return clean[:width]
    return clean[: width - 3] + "..."


def box_row(text: str, width: int) -> str:
    """Render one framed row using the current console glyph set."""
    left = glyph("║", "|")
    right = glyph("║", "|")
    inner_width = max(10, width - 4)
    payload = fit_text(text, inner_width).ljust(inner_width)
    return f"{left} {payload} {right}"


def box_border(width: int, top: bool) -> str:
    """Render the top or bottom border for a framed panel."""
    horizontal = make_rule(width - 2, "=")
    if supports_unicode_output():
        return f"{'╔' if top else '╚'}{horizontal}{'╗' if top else '╝'}"
    return f"+{horizontal}+"


def resolve_section_theme(title: str) -> tuple[str, str, str]:
    """Map a section title to its visual theme and display label."""
    normalized = safe_text(title).strip().lower()
    return SECTION_THEMES.get(normalized, ("PANEL", safe_text(title).upper(), "magenta"))


def build_status_chip(text: str, width: int = 9) -> str:
    """Render a fixed-width status chip for aligned console rows."""
    return f"[{safe_text(text)[:width].ljust(width)}]"


def resolve_flow_color(label: str) -> str:
    """Return the display color associated with a pipeline flow label."""
    normalized = safe_text(label).strip().lower()
    color_map = {
        "discovery": "magenta",
        "detail": "cyan",
        "render final": "yellow",
        "pipeline": "cyan",
        "resumen final": "green",
    }
    return color_map.get(normalized, "cyan")


def print_banner(title: str, subtitle: str = "") -> None:
    """Render the top-level banner shown at the beginning of execution."""
    width = console_width()
    print(colorize(box_border(width, top=True), "magenta", bold=True))
    print(colorize(box_row("MERCURY // IDENTITY REPORT SEQUENCE", width), "cyan", bold=True))
    print(colorize(box_row(title, width), "blue", bold=True))
    print(colorize(box_row("Built by Bryan Varela Vargas (W4rded)", width), "gray"))
    if subtitle:
        print(colorize(box_row(subtitle, width), "gray"))
    print(colorize(box_row("SESSION > IDENTITY_REPORT  |  MODE > CYBERPUNK OPS", width), "yellow"))
    print(colorize(box_row(f"RUNTIME > {format_runtime()}  |  TRACE > {build_trace_code(title)}", width), "gray"))
    print(colorize(box_border(width, top=False), "magenta", bold=True))


def print_section(title: str, subtitle: str = "") -> None:
    """Render a section title with a short colored separator."""
    print()
    width = console_width()
    phase_label, display_title, color = resolve_section_theme(title)
    branch = glyph("◆", "*")
    header = (
        f"{build_status_chip(phase_label, 11)}  {display_title}  "
        f"---  {build_trace_code(display_title)}"
    )
    print(colorize(f"{branch} {fit_text(header, width - 2)}", color, bold=True))
    if subtitle:
        guide = glyph("└", "\\-")
        print(colorize(f"{guide} {fit_text(subtitle, width - 3)}", "gray"))


def print_status(label: str, message: str, tone: str = "info") -> None:
    """Render a one-line status message using a severity color and marker."""
    tone_color = {
        "info": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "red",
    }.get(tone, "cyan")

    marker = {
        "info": glyph("├", "|-"),
        "success": glyph("├", "|-"),
        "warning": glyph("├", "|-"),
        "error": glyph("└", "\\-"),
    }.get(tone, glyph("├", "|-"))

    tone_label = TONE_LABELS.get(tone, "SIGNAL")
    chip = colorize(build_status_chip(tone_label), tone_color, bold=True)
    label_block = colorize(
        fit_text(label, STATUS_LABEL_WIDTH).ljust(STATUS_LABEL_WIDTH),
        "gray",
        bold=False,
    )
    print(f"{colorize(marker, 'gray')} {chip} {label_block} {message}")


def build_meter(current: int, total: int, width: int = 18) -> str:
    """Build a compact progress bar for paginated fetch operations."""
    if total <= 0:
        total = 1
    ratio = current / total
    filled = round(ratio * width)
    if current > 0:
        filled = max(2, filled)
    filled = max(0, min(width, filled))
    if supports_unicode_output():
        return "\u2588" * filled + "\u2591" * (width - filled)
    return "#" * filled + "-" * (width - filled)


def print_progress(
    label: str,
    page_number: int,
    nodes_in_page: int,
    page_size: int,
    total_nodes: int,
) -> None:
    """Render progress feedback for paginated CrowdStrike GraphQL phases."""
    flow_color = resolve_flow_color(label)
    meter = build_meter(nodes_in_page, page_size, PROGRESS_METER_WIDTH)
    filled_width = len(meter.rstrip(glyph("\u2591", "-")))
    filled = meter[:filled_width]
    empty = meter[filled_width:]
    branch = colorize(glyph("├", "|-"), "gray")
    label_block = colorize(
        fit_text(label.upper(), PROGRESS_LABEL_WIDTH).ljust(PROGRESS_LABEL_WIDTH),
        flow_color,
        bold=True,
    )
    page_text = colorize(f"page={page_number:02d}", "blue", bold=True)
    nodes_text = colorize(f"signal={nodes_in_page}", "green", bold=True)
    total_text = colorize(f"aggregate={total_nodes}", "gray")
    meter_text = (
        "["
        + colorize(filled, flow_color, bold=True)
        + colorize(empty, "gray")
        + "]"
    )
    print(f"{branch} {label_block} {meter_text} {page_text} {nodes_text} {total_text}")


def print_metric_list(title: str, items: list[tuple[str, str]], tone: str = "success") -> None:
    """Render a short key-value summary block in the console."""
    print_section(title)
    max_label = max((len(label) for label, _ in items), default=0)
    for label, value in items:
        padded = f"{label}:".ljust(max_label + 1)
        print_status(padded, value, tone)
    if title.strip().lower() == "resumen final":
        width = console_width()
        footer = (
            f"SEQUENCE COMPLETE  |  runtime={format_runtime()}  |  "
            f"trace={build_trace_code(title)}  |  report-ready"
        )
        print(colorize(box_border(width, top=True), "magenta", bold=True))
        print(colorize(box_row(footer, width), "green", bold=True))
        print(colorize(box_border(width, top=False), "magenta", bold=True))
