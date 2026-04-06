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
async def log_stream_live(
    websocket: WebSocket,
    token: str = Query(...),
):
    """
    WebSocket endpoint that streams real log entries from the Event Viewer feed.
    Sends the latest event every poll cycle; no synthetic data.
    """
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid authentication token")
        return

    await websocket.accept()

    from app.services.event_viewer_service import event_viewer_service

    last_seen = 0   # index into _recent_events we last sent

    try:
        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "Connected to live Windows Event log stream",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        while True:
            events = event_viewer_service._recent_events
            if len(events) > last_seen:
                new_events = events[last_seen:]
                last_seen = len(events)
                for ev in new_events:
                    await websocket.send_text(json.dumps({
                        "type": "log_entry",
                        "data": ev,
                    }))
            else:
                # Heartbeat so the connection stays alive
                await websocket.send_text(json.dumps({
                    "type": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            await asyncio.sleep(5.0)

    except WebSocketDisconnect:
        logger.info("Log stream client disconnected")
    except Exception as e:
        logger.error(f"Log stream WebSocket error: {e}")
