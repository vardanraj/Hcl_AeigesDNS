"""Configuration management API endpoint.

Provides threshold view, bounded validation update, and reset endpoints for runtime config.yaml.
"""

from fastapi import APIRouter, HTTPException, Depends
from backend.app.config import get_config, save_config, reset_config_to_defaults, AppConfig, ThresholdsConfig
from backend.app.core.session import verify_session_token

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("")
async def get_configuration():
    """Retrieve active system configuration and detection thresholds."""
    config = get_config()
    return config.model_dump()


@router.put("", dependencies=[Depends(verify_session_token)])
async def update_thresholds(new_thresholds: ThresholdsConfig):
    """Validate and update detection thresholds in config.yaml."""
    current_config = get_config()
    current_config.thresholds = new_thresholds
    try:
        save_config(current_config)
        return {
            "status": "success",
            "message": "Thresholds updated and saved to config.yaml.",
            "thresholds": new_thresholds.model_dump()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to update config.yaml: {str(e)}")


@router.post("/reset", dependencies=[Depends(verify_session_token)])
async def reset_configuration():
    """Reset runtime config.yaml back to read-only validated defaults (config.validated.yaml)."""
    try:
        reset_cfg = reset_config_to_defaults()
        return {
            "status": "success",
            "message": "Configuration successfully reset to validated defaults.",
            "config": reset_cfg.model_dump()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset configuration: {str(e)}")
