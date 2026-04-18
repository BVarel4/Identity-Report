import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    client_id: str
    client_secret: str
    target_domain: str
    page_size: int
    output_dir: Path
    report_name: str
    sample_limit_per_risk: int
    falcon_base_url: str

    def validate(self) -> None:
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


def load_settings(validate: bool = True) -> Settings:
    settings = Settings(
        client_id=os.getenv("FALCON_CLIENT_ID", "").strip(),
        client_secret=os.getenv("FALCON_CLIENT_SECRET", "").strip(),
        target_domain=os.getenv("FALCON_TARGET_DOMAIN", "").strip(),
        page_size=int(os.getenv("FALCON_PAGE_SIZE", "1000")),
        output_dir=Path(os.getenv("FALCON_OUTPUT_DIR", "output")).resolve(),
        report_name=os.getenv("FALCON_REPORT_NAME", "identity_risk_report").strip(),
        sample_limit_per_risk=int(os.getenv("FALCON_SAMPLE_LIMIT_PER_RISK", "3")),
        falcon_base_url=os.getenv(
            "FALCON_BASE_URL",
            "https://falcon.crowdstrike.com",
        ).rstrip("/"),
    )

    if validate:
        settings.validate()

    return settings
