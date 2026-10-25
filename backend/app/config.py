"""Configuration manager for AegisDNS.

Loads, validates, and updates configuration settings from config.yaml,
resolving paths relative to the project root directory regardless of CWD.
"""

from pathlib import Path
from typing import Dict, Any, List
import yaml
from pydantic import BaseModel, Field

# Project root resolution relative to this file (backend/app/config.py -> project root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.yaml"
CONFIG_VALIDATED_PATH = PROJECT_ROOT / "config.validated.yaml"


class ThresholdsConfig(BaseModel):
    entropy_threshold: float = Field(default=3.8, ge=2.0, le=5.5)
    subdomain_length_threshold: int = Field(default=30, ge=10, le=63)
    qname_length_threshold: int = Field(default=60, ge=20, le=200)
    digit_ratio_threshold: float = Field(default=0.30, ge=0.10, le=0.80)
    hex_ratio_threshold: float = Field(default=0.40, ge=0.10, le=0.85)
    txt_ratio_threshold: float = Field(default=0.30, ge=0.10, le=0.80)
    c2_jitter_threshold: float = Field(default=0.20, ge=0.05, le=0.60)
    c2_min_queries: int = Field(default=5, ge=3, le=100)
    exfil_cardinality_threshold: int = Field(default=15, ge=5, le=200)
    exfil_bytes_threshold: int = Field(default=3000, ge=500, le=50000)
    ml_anomaly_threshold: float = Field(default=0.15, ge=0.05, le=0.75)
    fused_threshold: float = Field(default=0.50, ge=0.20, le=0.85)


class WeightsConfig(BaseModel):
    rule_weight: float = Field(default=0.30, ge=0.0, le=1.0)
    beacon_weight: float = Field(default=0.25, ge=0.0, le=1.0)
    exfil_weight: float = Field(default=0.25, ge=0.0, le=1.0)
    ml_weight: float = Field(default=0.20, ge=0.0, le=1.0)


class SeverityLevelsConfig(BaseModel):
    critical: float = Field(default=80.0, ge=0.0, le=100.0)
    high: float = Field(default=60.0, ge=0.0, le=100.0)
    medium: float = Field(default=35.0, ge=0.0, le=100.0)
    low: float = Field(default=0.0, ge=0.0, le=100.0)


class ServerConfig(BaseModel):
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000, ge=1024, le=65535)
    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"])
    max_upload_size_mb: int = Field(default=50, ge=1, le=50)


class SyntheticDataConfig(BaseModel):
    default_sample_size: int = Field(default=1000, ge=10, le=100000)
    labeled_synthetic: bool = Field(default=True)


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    weights: WeightsConfig = Field(default_factory=WeightsConfig)
    severity_levels: SeverityLevelsConfig = Field(default_factory=SeverityLevelsConfig)
    synthetic_data: SyntheticDataConfig = Field(default_factory=SyntheticDataConfig)


# Global config instance cache
_current_config: AppConfig = None


def get_project_root() -> Path:
    """Return the absolute Path to the project root directory."""
    return PROJECT_ROOT


def load_config(config_file: Path = None) -> AppConfig:
    """Load config.yaml from project root and return validated AppConfig model."""
    global _current_config
    target_path = config_file or CONFIG_PATH

    # Ensure config.validated.yaml exists as read-only defaults
    if not CONFIG_VALIDATED_PATH.exists():
        default_cfg = AppConfig()
        data = default_cfg.model_dump()
        with open(CONFIG_VALIDATED_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False)

    if not target_path.exists():
        _current_config = AppConfig()
        save_config(_current_config, config_file=CONFIG_PATH)
        return _current_config

    with open(target_path, "r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f) or {}

    _current_config = AppConfig(**raw_data)
    return _current_config


def get_config() -> AppConfig:
    """Get currently loaded AppConfig or load if not initialized."""
    global _current_config
    if _current_config is None:
        return load_config()
    return _current_config


def save_config(config: AppConfig, config_file: Path = None) -> None:
    """Save AppConfig back to target config file."""
    global _current_config
    target_path = config_file or CONFIG_PATH
    data = config.model_dump()
    with open(target_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    if target_path == CONFIG_PATH:
        _current_config = config


def reset_config_to_defaults() -> AppConfig:
    """Reset runtime config.yaml back to read-only validated defaults (config.validated.yaml)."""
    global _current_config
    if CONFIG_VALIDATED_PATH.exists():
        with open(CONFIG_VALIDATED_PATH, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}
        default_config = AppConfig(**raw_data)
    else:
        default_config = AppConfig()
        save_config(default_config, config_file=CONFIG_VALIDATED_PATH)

    save_config(default_config, config_file=CONFIG_PATH)
    _current_config = default_config
    return _current_config
