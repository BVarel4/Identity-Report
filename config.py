"""Central configuration and environment-driven settings for the pipeline."""

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_AUTHOR = "Bryan Varela Vargas"
PROJECT_NICKNAME = "Aka. W4rded"
PROJECT_SIGNATURE = f"{PROJECT_AUTHOR} ({PROJECT_NICKNAME})"


@dataclass(frozen=True)
class Settings:
    """Runtime settings required to query Falcon and generate the report."""
    client_id: str
    client_secret: str
    target_domain: str
    deliverable_name: str
    page_size: int
    output_dir: Path
    report_name: str
    sample_limit_per_risk: int
    falcon_base_url: str
    artifact_mode: str

    def validate(self) -> None:
        """Validate required values and supported execution modes."""
        missing = []

        if not self.client_id:
            missing.append("FALCON_CLIENT_ID")
        if not self.client_secret:
            missing.append("FALCON_CLIENT_SECRET")
        if not self.target_domain:
            missing.append("FALCON_TARGET_DOMAIN")

        if missing:
            raise ValueError(
                "Faltan variables de entorno obligatorias: "
                + ", ".join(sorted(missing))
            )

        if self.page_size <= 0:
            raise ValueError("FALCON_PAGE_SIZE debe ser mayor que 0")

        if self.sample_limit_per_risk <= 0:
            raise ValueError("FALCON_SAMPLE_LIMIT_PER_RISK debe ser mayor que 0")

        if self.artifact_mode not in {"final_only", "standard", "debug"}:
            raise ValueError(
                "FALCON_ARTIFACT_MODE debe ser uno de: final_only, standard, debug"
            )


def load_settings(validate: bool = True) -> Settings:
    """Load settings from environment variables and optionally validate them."""
    settings = Settings(
        client_id=os.getenv("FALCON_CLIENT_ID", "").strip(),
        client_secret=os.getenv("FALCON_CLIENT_SECRET", "").strip(),
        target_domain=os.getenv("FALCON_TARGET_DOMAIN", "").strip(),
        deliverable_name=os.getenv("FALCON_DELIVERABLE_NAME", "").strip(),
        page_size=int(os.getenv("FALCON_PAGE_SIZE", "1000")),
        output_dir=Path(os.getenv("FALCON_OUTPUT_DIR", "output")).resolve(),
        report_name=os.getenv("FALCON_REPORT_NAME", "identity_risk_report").strip(),
        sample_limit_per_risk=int(os.getenv("FALCON_SAMPLE_LIMIT_PER_RISK", "3")),
        falcon_base_url=os.getenv(
            "FALCON_BASE_URL",
            "https://api.crowdstrike.com",
        ).rstrip("/"),
        artifact_mode=os.getenv("FALCON_ARTIFACT_MODE", "final_only").strip().lower(),
    )

    if validate:
        settings.validate()

    if not settings.deliverable_name:
        settings = Settings(
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            target_domain=settings.target_domain,
            deliverable_name=settings.target_domain,
            page_size=settings.page_size,
            output_dir=settings.output_dir,
            report_name=settings.report_name,
            sample_limit_per_risk=settings.sample_limit_per_risk,
            falcon_base_url=settings.falcon_base_url,
            artifact_mode=settings.artifact_mode,
        )

    return settings
