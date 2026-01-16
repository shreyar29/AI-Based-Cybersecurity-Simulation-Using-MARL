class MetricsTracker:
    def __init__(self):
        self.episode_rewards = {
            "attacker": [],
            "defender": [],
            "insider": [],
            "soc": []
        }

    def record(self, rewards: dict):
        for agent, reward in rewards.items():
            self.episode_rewards[agent].append(reward)

    def get_average_rewards(self):
        return {
            agent: sum(values) / len(values)
            for agent, values in self.episode_rewards.items()
            if len(values) > 0
        }
