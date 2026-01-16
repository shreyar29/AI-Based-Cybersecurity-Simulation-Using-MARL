class CyberEnv:
    def __init__(self):
        self.reset()

    def reset(self):
        self.step_count = 0
        self.insider_active = False

    def step(self, actions):
        self.step_count += 1

        if actions.get("insider") == "exfiltrate":
            self.insider_active = True

        return {
            "step": self.step_count,
            "insider_active": self.insider_active
        }
