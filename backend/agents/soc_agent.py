class SOCAgent:
    def act(self, step):
        if step >= 4:
            return "alert"
        return "observe"
