class AttackerAgent:
    def act(self, step):
        if step == 1:
            return "scan"
        if step == 2:
            return "attack"
        return "idle"
