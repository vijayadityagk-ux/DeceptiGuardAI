import asyncio
from typing import Dict, Set
from fastapi import WebSocket
from datetime import datetime
import json

class ConnectionManager:
    def __init__(self):
        # job_id -> set of active WebSockets
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, job_id: str):
        await websocket.accept()
        if job_id not in self.active_connections:
            self.active_connections[job_id] = set()
        self.active_connections[job_id].add(websocket)

    def disconnect(self, websocket: WebSocket, job_id: str):
        if job_id in self.active_connections:
            self.active_connections[job_id].discard(websocket)
            if not self.active_connections[job_id]:
                del self.active_connections[job_id]

    async def broadcast(self, job_id: str, step: str, progress_percent: int, message: str, payload: dict = None):
        if payload is None:
            payload = {}

        event_data = {
            "job_id": job_id,
            "step": step,
            "progress_percent": progress_percent,
            "message": message,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "payload": payload
        }

        if job_id in self.active_connections:
            websockets = list(self.active_connections[job_id])
            for ws in websockets:
                try:
                    await ws.send_text(json.dumps(event_data))
                except Exception:
                    self.disconnect(ws, job_id)

manager = ConnectionManager()
