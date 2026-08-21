import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Endpoints for Intrusion Detection & Autonomous Response System
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'operational',
      project: 'Explainable RL-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)',
      institution: 'VTU - JSS Academy of Technical Education, Bengaluru',
      timestamp: new Date().toISOString()
    });
  });

  // System Architecture metadata endpoint
  app.get('/api/architecture', (req, res) => {
    res.json({
      layers: [
        { id: 1, name: 'Network Traffic Layer', description: 'LAN packet stream capturing user browsing, file transfer, and attack patterns' },
        { id: 2, name: 'Packet Capture Layer', technology: 'Scapy (Python) / Node Engine', fields: ['Source IP', 'Destination IP', 'Protocol', 'Port', 'Packet Size'] },
        { id: 3, name: 'Feature Extraction Layer', metrics: ['Packets/sec', 'Unique Ports', 'Connection Duration', 'Failed Connections', 'SYN/ACK Ratio'] },
        { id: 4, name: 'Machine Learning Layer', model: 'Random Forest Classifier (50 Estimators)', output: 'Static Attack Probability Score' },
        { id: 5, name: 'Deep Learning Layer', model: 'LSTM Recurrent Neural Network (T=5)', output: 'Temporal Behavior Anomaly Score' },
        { id: 6, name: 'Risk Scoring Layer', formula: 'W_ML * P_RF + W_DL * P_LSTM + Heuristic', levels: ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'] },
        { id: 7, name: 'Explainable AI (XAI) Layer', framework: 'SHAP (TreeSHAP / KernelSHAP)', output: 'Feature Contribution Weights and Root-Cause Narrative' },
        { id: 8, name: 'Reinforcement Learning Layer', algorithm: 'Deep Q-Network (DQN - Hossain et al., 2025)', actions: ['ALLOW (0)', 'ALERT (1)', 'BLOCK (2)'] },
        { id: 9, name: 'Processing & Control Module', role: 'Central orchestrator managing data flow, model coordination, and decision execution' },
        { id: 10, name: 'Action Execution Layer', targets: ['Firewall IP drop table', 'Webhook payload', 'Email/SMS notification'] },
        { id: 11, name: 'Database Layer', schema: ['PostgreSQL (structured security audit logs & decisions)', 'InfluxDB (real-time telemetry)'] },
        { id: 12, name: 'Dashboard Layer', ui: 'Real-time SOC Monitoring (Grafana Style)' }
      ]
    });
  });

  // Vite middleware for dev or static server for production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[XRL-IDARS Backend] Running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
