import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from scenarios.scenarios import SCENARIOS

router = APIRouter()

@router.websocket("/ws/interactive/{scenario_id}")
async def run_interactive_simulation(ws: WebSocket, scenario_id: int):
    await ws.accept()

    if scenario_id not in SCENARIOS:
        await ws.close()
        return

    scenario = SCENARIOS[scenario_id]
    steps = scenario["steps"]

    try:
        # Initial Briefing
        await ws.send_json({
            "type": "briefing",
            "title": f"MISSION: {scenario['name']}",
            "description": "Commander, hostile activity detected. Take command of the defense grid."
        })
        # Wait for frontend to read/speak briefing
        await ws.receive_text()

        for step in steps:
            actor = step.get("actor", "").lower()
            interactive_data = step.get("interactive")

            # === INTERACTIVE DECISION STEP ===
            if interactive_data:
                # 1. Send Question & Options
                req = {
                    "type": "decision_request",
                    "step_id": step.get("step"),
                    "question": interactive_data["question"],
                    "options": interactive_data["options"], # List of {id, label}
                    "narration": "Awaiting Command..."
                }
                await ws.send_json(req)

                # 2. Wait for User Decision
                try:
                    response_text = await ws.receive_text()
                    user_choice = json.loads(response_text).get("choice_id")
                except:
                   user_choice = None

                # 3. Validate Choice
                selected_option = next((opt for opt in interactive_data["options"] if opt["id"] == user_choice), None)
                
                is_correct = selected_option and selected_option.get("is_correct", False)
                feedback = interactive_data["feedback_correct"] if is_correct else interactive_data["feedback_incorrect"]

                # 4. Send Outcome
                outcome_payload = {
                    "type": "decision_result",
                    "step": step.get("step"),
                    "is_correct": is_correct,
                    "feedback": feedback,
                    "score_delta": 100 if is_correct else -50,
                    "narration": f"RESULT: {feedback}",
                    "summary_insight": step.get("summary_insight", "")
                }
                await ws.send_json(outcome_payload)
                
                # Wait for frontend to finish speaking result
                await ws.receive_text()

            # === NARRATIVE STEP (Auto-play) ===
            else:
                formatted_narration = f"ATTACK DETECTED: {step['narration']}" if actor == "attacker" else step["narration"]
                
                payload = {
                    "type": "narration",
                    "scenario": scenario["name"],
                    "step": step.get("step"),
                    "narration": formatted_narration,
                    "actor": actor,
                    "target": step.get("target"),
                    "summary_insight": step.get("summary_insight", "")
                }
                await ws.send_json(payload)
                
                # Wait for frontend to speak narration
                await ws.receive_text()

        # === END OF MISSION ===
        await ws.send_json({
            "type": "game_over",
            "message": "Mission Complete. Generating Report..."
        })
        await ws.close()

    except WebSocketDisconnect:
        print("CISO Mode Client Disconnected")
