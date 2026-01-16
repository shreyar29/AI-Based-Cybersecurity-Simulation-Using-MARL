from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from api.simulation_ws import run_simulation

app = FastAPI(title="AI Cybersecurity Simulation")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.websocket("/ws/simulate/{scenario_id}")
async def simulate(ws: WebSocket, scenario_id: int):
    await run_simulation(ws, scenario_id)
