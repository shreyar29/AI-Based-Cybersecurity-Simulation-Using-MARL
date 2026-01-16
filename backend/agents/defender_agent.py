class DefenderAgent:
    def act(self, step):
        if step == 2:
            return "block"
        return "monitor"
