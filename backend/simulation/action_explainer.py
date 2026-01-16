class ActionExplainer:

    @staticmethod
    def explain(actions, scenario):
        messages = []

        # Attacker
        if actions["attacker"] == 1:
            messages.append("The attacker is scanning the network for open ports.")
        elif actions["attacker"] == 2:
            messages.append("The attacker is attempting a privilege escalation attack.")

        # Defender
        if actions["defender"] == 1:
            messages.append("The defender is monitoring network traffic for anomalies.")
        elif actions["defender"] == 2:
            messages.append("The defender blocks a suspicious IP address.")

        # Insider
        if scenario["insider_active"]:
            messages.append("An insider threat is attempting unauthorized data access.")

        # SOC
        if actions["soc"] == 1:
            messages.append("The security operations center is correlating alerts.")
        elif actions["soc"] == 2:
            messages.append("The security operations center applies a global defense policy.")

        # Fallback
        if not messages:
            messages.append("The system is in a stable monitoring state.")

        return messages
