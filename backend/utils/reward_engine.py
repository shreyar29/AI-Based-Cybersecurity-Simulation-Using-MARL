class RewardEngine:

    @staticmethod
    def attacker(success, detected):
        if success and not detected:
            return 10
        elif success and detected:
            return 3
        elif detected:
            return -8
        return -1

    @staticmethod
    def defender(blocked, false_positive):
        if blocked:
            return 8
        if false_positive:
            return -4
        return -2

    @staticmethod
    def insider(exfiltration, detected):
        if exfiltration and not detected:
            return 10
        if detected:
            return -10
        return -2

    @staticmethod
    def soc(correct_decision, overload):
        if correct_decision:
            return 6
        if overload:
            return -8
        return -1
