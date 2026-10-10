"""FastAPI application entry point for AegisDNS.

Configures CORS restrictions, binds to 127.0.0.1, registers API endpoints,
and provides WebSocket /ws/live for live incident push notifications.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from backend.app.config import get_config
from backend.app.core.session import router as session_router
from backend.app.api.upload import router as upload_router
from backend.app.api.capture import router as capture_router, ws_manager
from backend.app.api.alerts import router as alerts_router
from backend.app.api.synthetic import router as synthetic_router
from backend.app.api.config_api import router as config_router

config = get_config()

app = FastAPI(
    title="AegisDNS - DNS Tunneling Incident Detection API",
    description="Backend API for detecting DNS tunneling, exfiltration, and C2 beaconing.",
    version="1.0.0",
)

# Security Requirement: Restrict CORS to designated frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.server.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(session_router)
app.include_router(upload_router)
app.include_router(capture_router)
app.include_router(alerts_router)
app.include_router(synthetic_router)
app.include_router(config_router)


# Requirement: WebSocket /ws/live for pushing live incidents with origin check
@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    """WebSocket endpoint for streaming live DNS incidents and packet updates."""
    origin = websocket.headers.get("origin")
    if origin and origin not in config.server.cors_origins:
        await websocket.close(code=1008, reason="CORS origin not allowed")
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection open and receive optional ping messages from client
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@app.get("/")
async def root():
    return {
        "system": "AegisDNS",
        "status": "online",
        "version": "1.0.0",
        "is_synthetic": True,
        "docs_url": "/docs",
    }


if __name__ == "__main__":
    # Security Requirement: Bind strictly to 127.0.0.1
    uvicorn.run(
        "backend.app.main:app",
        host=config.server.host,
        port=config.server.port,
        reload=False,
    )
