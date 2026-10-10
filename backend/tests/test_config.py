"""Unit tests for config.py and project-root resolution."""

from pathlib import Path
from backend.app.config import get_config, load_config, get_project_root, AppConfig


def test_project_root_resolution():
    root = get_project_root()
    assert isinstance(root, Path)
    assert (root / "config.yaml").exists()


def test_load_config():
    config = get_config()
    assert isinstance(config, AppConfig)
    assert config.server.host == "127.0.0.1"
    assert config.thresholds.entropy_threshold > 0.0
    assert config.server.max_upload_size_mb == 50
