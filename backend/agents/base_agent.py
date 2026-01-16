import torch
import random
import numpy as np
from marl.dqn import DQN
from marl.replay_buffer import ReplayBuffer

class BaseAgent:
    def __init__(self, state_size, action_size):
        self.model = DQN(state_size, action_size)
        self.target_model = DQN(state_size, action_size)
        self.memory = ReplayBuffer()
        self.action_size = action_size

    def act(self, state, epsilon):
        if random.random() < epsilon:
            return random.randint(0, self.action_size - 1)
        state = torch.FloatTensor(state)
        with torch.no_grad():
            return torch.argmax(self.model(state)).item()
