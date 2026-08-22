import os
import numpy as np
import torch
import torch.nn as nn


class DQN(nn.Module):
    def __init__(self, input_dim, hidden_dim=32, num_actions=3):
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
    def __init__(self, artifact_dir=None):
        """
        DQN agent.

        If artifact_dir is not supplied, automatically use:
        <project_root>/ml_engine/artifacts
        """

        if artifact_dir is None:
            project_root = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..")
            )
            artifact_dir = os.path.join(
                project_root,
                "ml_engine",
                "artifacts"
            )

        self.artifact_dir = artifact_dir
        self.model_path = os.path.join(
            self.artifact_dir,
            "dqn_model.pt"
        )

        self.model = None

        self.actions = [
            "ALLOW",
            "ALERT",
            "BLOCK"
        ]

    def load(self):
        """
        Load the trained DQN model.

        The network dimensions are inferred from the saved
        PyTorch state dictionary so that the architecture
        matches the trained artifact.
        """

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"DQN model not found: {self.model_path}"
            )

        try:
            state_dict = torch.load(
                self.model_path,
                map_location="cpu"
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to load DQN artifact: {e}"
            )

        # Handle checkpoints saved as {"state_dict": ...}
        if isinstance(state_dict, dict) and "state_dict" in state_dict:
            state_dict = state_dict["state_dict"]

        if not isinstance(state_dict, dict):
            raise RuntimeError(
                "Invalid DQN artifact format."
            )

        # Infer architecture from saved weights.
        #
        # net.0.weight shape:
        # [hidden_dim, input_dim]
        #
        # net.4.weight shape:
        # [num_actions, hidden_dim]

        try:
            first_weight = state_dict["net.0.weight"]
            last_weight = state_dict["net.4.weight"]

            hidden_dim = first_weight.shape[0]
            input_dim = first_weight.shape[1]
            num_actions = last_weight.shape[0]

        except KeyError as e:
            raise RuntimeError(
                f"DQN artifact has unexpected structure. Missing: {e}"
            )

        self.model = DQN(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            num_actions=num_actions
        )

        try:
            self.model.load_state_dict(state_dict)
        except Exception as e:
            raise RuntimeError(
                f"Failed to load DQN weights: {e}"
            )

        self.model.eval()

        # Make sure action list matches output size.
        if num_actions != len(self.actions):
            self.actions = [
                f"ACTION_{i}"
                for i in range(num_actions)
            ]

        print(
            f"DQN model loaded successfully: "
            f"input_dim={input_dim}, "
            f"hidden_dim={hidden_dim}, "
            f"actions={num_actions}"
        )

        return True

    def get_action(self, state):
        """
        Predict an action from the supplied state.
        """

        if self.model is None:
            raise RuntimeError(
                "DQN model is not loaded. Call load() first."
            )

        state = np.asarray(
            state,
            dtype=np.float32
        ).reshape(-1)

        # Check input dimension.
        expected_dim = self.model.net[0].in_features

        if len(state) != expected_dim:
            raise ValueError(
                f"DQN expected {expected_dim} features, "
                f"but received {len(state)} features."
            )

        state_tensor = torch.tensor(
            state,
            dtype=torch.float32
        ).unsqueeze(0)

        with torch.no_grad():
            q_values = self.model(
                state_tensor
            ).squeeze(0).cpu().numpy()

        action_idx = int(
            np.argmax(q_values)
        )

        action = self.actions[action_idx]

        q_value_dict = {
            action_name: float(q_value)
            for action_name, q_value
            in zip(self.actions, q_values)
        }

        return action, q_value_dict