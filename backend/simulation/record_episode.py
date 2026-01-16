import sys
import os
import threading

# ✅ Add backend to Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from env.cyber_env import CyberEnv
from agents.attacker_agent import AttackerAgent
from agents.defender_agent import DefenderAgent
from agents.insider_agent import InsiderAgent
from agents.soc_agent import SOCAgent
from simulation.visualizer import SimulationVisualizer
from simulation.video_generator import VideoGenerator
from scenarios.scenario_loader import ScenarioLoader
from config import STATE_SIZE, ACTION_SIZE, MAX_STEPS

from simulation.action_explainer import ActionExplainer
from simulation.voice_narrator import VoiceNarrator

from simulation.narration_recorder import NarrationRecorder

def record_episode(scenario_id=4):
    os.makedirs("outputs/videos", exist_ok=True)

    # ---------------------------
    # Environment & scenario
    # ---------------------------
    env = CyberEnv()
    scenario = ScenarioLoader().load(scenario_id)
    env.set_scenario(scenario)

    # ---------------------------
    # Agents
    # ---------------------------
    agents = {
        "attacker": AttackerAgent(STATE_SIZE, ACTION_SIZE),
        "defender": DefenderAgent(STATE_SIZE, ACTION_SIZE),
        "insider": InsiderAgent(STATE_SIZE, ACTION_SIZE),
        "soc": SOCAgent(STATE_SIZE, ACTION_SIZE),
    }

    # ---------------------------
    # Visual + Voice
    # ---------------------------
    narrator = VoiceNarrator()
    visualizer = SimulationVisualizer()

    video = VideoGenerator(
        output_path=f"outputs/videos/scenario_{scenario_id}.avi",
        fps=5
    )

    state, _ = env.reset()
    frames = []
    all_messages = []

    # ---------------------------
    # Simulation loop
    # ---------------------------
    for step in range(MAX_STEPS):
        actions = {
            name: agent.act(state, epsilon=0.0)  # deterministic replay
            for name, agent in agents.items()
        }

        state, _, terminated, truncated, _ = env.step(actions)

        # 🧠 Explain actions
        messages = ActionExplainer.explain(actions, env.scenario)

        # 🔊 Speak asynchronously (NON-BLOCKING)
        all_messages.extend(messages)

        # 🎥 Visual frame
        frame = visualizer.draw(state, env.scenario, step)
        frames.append(frame)

        if terminated or truncated:
            break

    if not frames:
        raise RuntimeError("No frames generated!")

    # ---------------------------
    # Write video
    # ---------------------------
    video.start(frames[0].shape)
    for frame in frames:
        video.add_frame(frame)
    video.close()

    print(f"✅ Video generated: outputs/videos/scenario_{scenario_id}.avi")

    narrator.stop()

    # Save narration audio
    audio_path = f"outputs/videos/scenario_{scenario_id}.wav"
    recorder = NarrationRecorder(audio_path)
    recorder.record(all_messages)

    print(f"🔊 Narration saved: {audio_path}")


if __name__ == "__main__":
    record_episode()
