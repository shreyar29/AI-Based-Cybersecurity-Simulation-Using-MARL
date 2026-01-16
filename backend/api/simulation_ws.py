import asyncio
from starlette.websockets import WebSocketDisconnect
from scenarios.scenarios import SCENARIOS

async def run_simulation(ws, scenario_id: int):
    await ws.accept()

    if scenario_id not in SCENARIOS:
        await ws.send_json({
            "error": "Invalid scenario ID"
        })
        await ws.close()
        return

    scenario = SCENARIOS[scenario_id]
    steps = scenario["steps"]

    try:
        for step in steps:
            payload = {
                "scenario": scenario["name"],
                "step": step.get("step"),
                "narration": step["narration"],
                "actor": step.get("actor"),
                "target": step.get("target")
            }

            await ws.send_json(payload)
            await asyncio.sleep(3)
            print(" Sending to frontend:", payload)

    except WebSocketDisconnect:
        print(" Client disconnected")
