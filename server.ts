import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { exec, spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';
import { EventEmitter } from 'events';
import os from 'os';

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const packetEmitter = new EventEmitter();
let tcpdumpProcess: ChildProcess | null = null;
let trackedDevices: string[] = [];

function getWifiInfo(): { prefix: string | null; iface: string; hostIp: string | null; hostMac: string | null } {
  const interfaces = os.networkInterfaces();
  
  for (const [name, nets] of Object.entries(interfaces)) {
    if (!nets) continue;
    
    // Look for common active Wi-Fi or Ethernet interfaces, skipping loopback and docker
    if (
      !name.startsWith('lo') && 
      !name.startsWith('docker') && 
      !name.startsWith('br-') &&
      !name.startsWith('veth')
    ) {
      for (const net of nets) {
        if (net.family === 'IPv4' && !net.internal) {
          const segments = net.address.split('.');
          return {
            prefix: `${segments[0]}.${segments[1]}.${segments[2]}.`,
            iface: name,
            hostIp: net.address,
            hostMac: net.mac
          };
        }
      }
    }
  }
  return { prefix: null, iface: 'any', hostIp: null, hostMac: null };
}

function startPacketCapture() {
  if (tcpdumpProcess) {
    tcpdumpProcess.kill();
    tcpdumpProcess = null;
  }

  const { iface } = getWifiInfo();
  
  // Construct BPF filter for tracked IPs
  let filter = '';
  if (trackedDevices.length > 0) {
    filter = trackedDevices.map(ip => `host ${ip}`).join(' or ');
  }

  // Use Python Scapy script instead of tcpdump directly
  const scapyScript = path.join(process.cwd(), 'scapy_sniffer.py');
  const args = ['python3', scapyScript, '-i', iface];
  if (filter) {
    args.push('-f', filter);
  }

  tcpdumpProcess = spawn('sudo', args);
  
  tcpdumpProcess.stdout?.on('data', (data: Buffer) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (!line.trim()) continue;
      
      try {
        const pkt = JSON.parse(line);
        // If it's a status or error message from our scapy script
        if (pkt.status || pkt.error) {
          console.log(`[Scapy Sniffer]`, pkt);
          continue;
        }
        // Otherwise it's a parsed packet, send to frontend
        packetEmitter.emit('packet', pkt);
      } catch (err) {
        // Not a JSON line, probably debug/warning output from scapy
      }
    }
  });

  tcpdumpProcess.stderr?.on('data', (data) => {
    console.error(`[Scapy Sniffer] ${data}`);
  });

  tcpdumpProcess.on('close', (code) => {
    console.log(`[Scapy Sniffer] python process exited with code ${code}`);
    tcpdumpProcess = null;
  });

  console.log(`[Packet Capture] Started real-time Scapy python sniffer on ${iface}${filter ? ' with filter' : ''}.`);
}


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

  // Real LAN Discovery Endpoint
  app.get('/api/lan-devices', async (req, res) => {
    try {
      const { prefix, iface, hostIp, hostMac } = getWifiInfo();
      
      let gatewayIp: string | null = null;
      try {
        const routeResult = await execAsync('ip route | grep default');
        const gwMatch = routeResult.stdout.match(/default via ([\d\.]+)/);
        if (gwMatch) gatewayIp = gwMatch[1];
      } catch (e) {
        // ignore
      }

      // Use arp-scan for active probing rather than stale cache
      const { stdout } = await execAsync(`sudo arp-scan --interface=${iface} --localnet`);
      const lines = stdout.split('\n');
      const devices = [];
      
      const newlyTracked: string[] = [];

      // Add Host machine explicitly, as arp-scan doesn't return the local interface
      if (hostIp && prefix && hostIp.startsWith(prefix)) {
        devices.push({ 
          ip: hostIp, 
          mac: hostMac, 
          vendor: 'Host Machine', 
          isHost: true 
        });
        newlyTracked.push(hostIp);
      }

      for (const line of lines) {
        // Example: 192.168.0.1    00:11:22:33:44:55    Apple, Inc.
        const match = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:]+)(?:\s+(.*))?/);
        if (match) {
          const ip = match[1];
          const mac = match[2];
          const vendor = match[3] || 'Unknown';
          
          if (prefix && ip.startsWith(prefix) && ip !== hostIp) {
            devices.push({ 
              ip, 
              mac, 
              vendor, 
              isGateway: ip === gatewayIp 
            });
            newlyTracked.push(ip);
          }
        }
      }
      
      // Update tracked IPs and restart tcpdump filter if needed
      if (newlyTracked.length > 0) {
        trackedDevices = newlyTracked;
        if (tcpdumpProcess) {
          startPacketCapture(); // Restart with new filter
        }
      }

      res.json({ devices, prefix, hostIp, gatewayIp });
    } catch (error) {
      console.error('Error scanning LAN with arp-scan:', error);
      res.status(500).json({ error: 'Failed to scan LAN devices. Ensure arp-scan is installed and you have sudo privileges.' });
    }
  });

  // Real Packet Stream Endpoint (SSE)
  app.get('/api/packets/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    startPacketCapture(); // Start capturing if not already

    const onPacket = (pkt: any) => {
      res.write(`data: ${JSON.stringify(pkt)}\n\n`);
    };

    packetEmitter.on('packet', onPacket);

    req.on('close', () => {
      packetEmitter.off('packet', onPacket);
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
