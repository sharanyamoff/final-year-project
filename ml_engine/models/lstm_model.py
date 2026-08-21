import torch
import torch.nn as nn
import os
import joblib

class TemporalLSTM(nn.Module):
    def __init__(self, input_dim=10, hidden_dim=64, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.2)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])
        return self.sigmoid(out)

class LSTMWrapper:
    def __init__(self, artifact_dir):
        self.model_path = os.path.join(artifact_dir, 'lstm_model.pt')
        self.meta_path = os.path.join(artifact_dir, 'lstm_meta.joblib')
        self.model = None
        
    def load(self):
        if not os.path.exists(self.model_path) or not os.path.exists(self.meta_path):
            raise FileNotFoundError("LSTM artifacts missing")
            
        meta = joblib.load(self.meta_path)
        self.model = TemporalLSTM(input_dim=meta['input_dim'], hidden_dim=meta['hidden_dim'])
        self.model.load_state_dict(torch.load(self.model_path))
        self.model.eval()
        return True
        
    def predict(self, sequence_scaled):
        if self.model is None:
            raise RuntimeError("Model not loaded")
        seq_tensor = torch.tensor(sequence_scaled, dtype=torch.float32)
        with torch.no_grad():
            score = self.model(seq_tensor).item()
        return score
