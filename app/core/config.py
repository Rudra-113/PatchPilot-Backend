from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PatchPilot AI"
    app_version: str = "0.1.0"
    debug: bool = True
    upload_dir: str = "uploads"
    scan_dir: str = "scans"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
