from fastapi import FastAPI, WebSocket
from api.simulation_ws import run_simulation

app = FastAPI()


@app.websocket("/ws/simulate/{scenario_id}")
async def simulate(ws: WebSocket, scenario_id: int):
    await run_simulation(ws, scenario_id)
