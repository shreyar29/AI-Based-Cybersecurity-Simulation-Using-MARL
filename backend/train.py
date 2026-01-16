from env.cyber_env import CyberEnv
from agents.attacker_agent import AttackerAgent
from agents.defender_agent import DefenderAgent
from agents.insider_agent import InsiderAgent
from agents.soc_agent import SOCAgent
from marl.trainer import MARLTrainer
from config import *
from scenarios.scenario_loader import ScenarioLoader

def main():
    env = CyberEnv()

    agents = {
        "attacker": AttackerAgent(STATE_SIZE, ACTION_SIZE),
        "defender": DefenderAgent(STATE_SIZE, ACTION_SIZE),
        "insider": InsiderAgent(STATE_SIZE, ACTION_SIZE),
        "soc": SOCAgent(STATE_SIZE, ACTION_SIZE),
    }

    trainer = MARLTrainer(agents, env)
    trainer.train()

    scenario_loader = ScenarioLoader()
    scenario = scenario_loader.load(4)
    env.set_scenario(scenario)

    print("Running Scenario:", scenario["name"])

if __name__ == "__main__":
    main()
