from scenarios.scenarios import SCENARIOS

class ScenarioLoader:
    def load(self, scenario_id: int):
        if scenario_id not in SCENARIOS:
            raise ValueError("Invalid Scenario ID")
        return SCENARIOS[scenario_id]
