import asyncio
import random
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
        # Wait for "START" command from frontend
        await ws.receive_text()

        for step in steps:
            # PROBABILISTIC LOGIC
            prob = step.get("prob", 1.0)
            roll = random.random()
            
            outcome = "success"
            narration = step["narration"]

            if roll > prob:
                outcome = "failed"
                narration = f"ATTEMPT FAILED: {step['narration']} (Defenses held)"
                # If an attack fails, we can optionally skip the next step if it assumes success,
                # but for V1 we will just mark this step as failed and let the simulation proceed 
                # to show the 'response' (which might now seem like a successful block).

            payload = {
                "scenario": scenario["name"],
                "step": step.get("step"),
                "narration": narration,
                "actor": step.get("actor"),
                "target": step.get("target"),
                "outcome": outcome,   # Explicit outcome for frontend
                "roll": roll,
                "prob": prob
            }

            await ws.send_json(payload)
            
            # Wait for frontend to acknowledge (finish speech/animation)
            try:
                await ws.receive_text()
            except WebSocketDisconnect:
                break
            
            print(" Sending to frontend:", payload)

    except WebSocketDisconnect:
        print(" Client disconnected")
