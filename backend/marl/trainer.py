import os
from config import EPISODES, MAX_STEPS
from utils.metrics import MetricsTracker
from utils.logger import CSVLogger

class MARLTrainer:
    def __init__(self, agents, env):
        self.agents = agents
        self.env = env

        # Create logger ONCE
        self.metrics = MetricsTracker()
        self.logger = CSVLogger(
            filepath=os.path.join("outputs", "logs", "training_log.csv")
        )
        
    def train(self):
        epsilon = 1.0

        for ep in range(EPISODES):
            state, _ = self.env.reset()

            # RESET rewards EVERY episode
            episode_rewards = {
                "attacker": 0,
                "defender": 0,
                "insider": 0,
                "soc": 0
            }

            for _ in range(MAX_STEPS):
                actions = {
                    name: agent.act(state, epsilon)
                    for name, agent in self.agents.items()
                }

                next_state, rewards, terminated, truncated, _ = self.env.step(actions)

                for k in episode_rewards:
                    episode_rewards[k] += rewards[k]

                state = next_state

                if terminated or truncated:
                    break

            # 🔥 THIS MUST RUN EVERY EPISODE
            self.logger.log(ep, episode_rewards)
            self.metrics.record(episode_rewards)

            epsilon = max(0.01, epsilon * 0.995)

            print(f"Episode {ep} logged → {episode_rewards}")
