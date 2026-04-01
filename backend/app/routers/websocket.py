"""
WebSocket router: real-time streaming of alerts, log ingestion simulation,
and live anomaly notifications.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.services.alert_service import subscribe_to_alerts, unsubscribe_from_alerts
from app.core.security import decode_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["WebSocket"])


class ConnectionManager:
    """Manages active WebSocket connections for broadcasting."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast a message to all active connections."""
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/alerts")
async def alert_stream(
    websocket: WebSocket,
    token: str = Query(...),
):
    """
    WebSocket endpoint for real-time alert notifications.
    Requires JWT token as query parameter: /ws/alerts?token=<jwt>
    """
    # Validate JWT token
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid authentication token")
        return

    await manager.connect(websocket)
    alert_queue = subscribe_to_alerts()

    try:
        # Send initial connection acknowledgment
        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "Connected to real-time alert stream",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        # Main loop: forward alerts from queue to WebSocket
        while True:
            try:
                alert_data = await asyncio.wait_for(alert_queue.get(), timeout=30.0)
                await websocket.send_text(json.dumps(alert_data))
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive
                await websocket.send_text(json.dumps({
                    "type": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected normally")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        unsubscribe_from_alerts(alert_queue)
        manager.disconnect(websocket)


@router.websocket("/logs/stream")
async def log_stream_simulation(
    websocket: WebSocket,
    token: str = Query(...),
):
    """
    WebSocket endpoint that simulates real-time log streaming.
    Generates and broadcasts synthetic log events every second.
    """
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid authentication token")
        return

    await websocket.accept()

    import random
    sample_ips = ["192.168.1.100", "10.0.0.5", "203.0.113.45", "185.220.101.5"]
    event_types = ["login_success", "login_failed", "web_request", "firewall_block", "port_scan"]

    try:
        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "Connected to log stream simulation",
        }))

        while True:
            log_event = {
                "type": "log_entry",
                "data": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": random.choice(sample_ips),
                    "destination_port": random.choice([22, 80, 443, 3306, 8080]),
                    "event_type": random.choice(event_types),
                    "severity": random.choice(["info", "low", "medium", "high"]),
                    "bytes_sent": random.randint(100, 50000),
                },
            }
            await websocket.send_text(json.dumps(log_event))
            await asyncio.sleep(1.0)  # Simulate 1 event per second

    except WebSocketDisconnect:
        logger.info("Log stream client disconnected")
    except Exception as e:
        logger.error(f"Log stream WebSocket error: {e}")
