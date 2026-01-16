class InsiderAgent:
    def act(self, step):
        if step == 3:
            return "exfiltrate"
        return "idle"
