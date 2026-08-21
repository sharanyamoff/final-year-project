import torch
import torch.nn as nn
import os
import numpy as np

class DQN(nn.Module):
    def __init__(self, input_dim=7, hidden_dim=32, num_actions=3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, num_actions)
        )
        
    def forward(self, x):
        return self.net(x)

class DQNAgent:
    def __init__(self, artifact_dir):
        self.model_path = os.path.join(artifact_dir, 'dqn_model.pt')
        self.model = None
        self.actions = ['ALLOW', 'ALERT', 'BLOCK']
        
    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError("DQN artifact missing")
        self.model = DQN()
        self.model.load_state_dict(torch.load(self.model_path))
        self.model.eval()
        return True
        
    def get_action(self, state):
        if self.model is None:
            raise RuntimeError("DQN not loaded")
        state_t = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            q_vals = self.model(state_t).squeeze(0).numpy()
            
        action_idx = int(np.argmax(q_vals))
        return self.actions[action_idx], {a: float(q) for a, q in zip(self.actions, q_vals)}
