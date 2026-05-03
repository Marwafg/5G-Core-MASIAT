from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    app_host: str = os.getenv("APP_HOST", "0.0.0.0")
    app_port: int = int(os.getenv("APP_PORT", "8000"))
    app_version: str = os.getenv("APP_VERSION", "1.1.0")
    demo_api_key: str = os.getenv("DEMO_API_KEY", "5GC-SECURE-2026")
    db_path: Path = Path(os.getenv("DB_PATH", "core_security_lab.db")).resolve()
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()

    @property
    def docs_enabled(self) -> bool:
        return self.app_env != "production"


settings = Settings()
