import React, { useState } from 'react';
import { Flame, Play, ShieldAlert, Cpu, Sparkles, Send, RefreshCw, CheckCircle2 } from 'lucide-react';
import { controlModule } from '../services/controlModule';
import { AttackType, ProtocolType, RawPacket } from '../types';

export const AttackSimulator: React.FC = () => {
  const [customSrcIp, setCustomSrcIp] = useState('192.168.1.240');
  const [customDstIp, setCustomDstIp] = useState('192.168.1.10');
  const [customProtocol, setCustomProtocol] = useState<ProtocolType>('TCP');
  const [customPort, setCustomPort] = useState(80);
  const [customSize, setCustomSize] = useState(60);
  const [customFlagSyn, setCustomFlagSyn] = useState(true);
  const [customFlagAck, setCustomFlagAck] = useState(false);
  const [customPayload, setCustomPayload] = useState('TCP SYN [Seq=0 Win=1024 Len=0 MSS=1460]');
  const [burstCount, setBurstCount] = useState(1);
  const [statusMessage, setStatusMessage] = useState('');

  const handleLaunchScenario = (type: AttackType, title: string) => {
    const event = controlModule.injectCustomAttack(type);
    setStatusMessage(`Triggered ${title}! Event ID: ${event.id} • Action: ${event.actionExecuted}`);
    setTimeout(() => setStatusMessage(''), 4500);
  };

  const handleInjectCustomPacket = (e: React.FormEvent) => {
    e.preventDefault();
    for (let i = 0; i < burstCount; i++) {
      const pkt: RawPacket = {
        id: 'cust_' + Math.random().toString(36).substring(2, 8),
        timestamp: Date.now() + i * 50,
        sourceIp: customSrcIp.trim(),
        destinationIp: customDstIp.trim(),
        protocol: customProtocol,
        sourcePort: 49152 + Math.floor(Math.random() * 10000),
        destinationPort: customPort,
        packetSize: customSize,
        tcpFlags: customProtocol === 'TCP' ? {
          syn: customFlagSyn,
          ack: customFlagAck,
          fin: false,
          rst: false,
          psh: true
        } : undefined,
        payloadSummary: customPayload,
        simulatedLabel: customFlagSyn && !customFlagAck ? 'DOS_SYN_FLOOD' : 'BENIGN'
      };
      controlModule.injectRawPacket(pkt);
    }

    setStatusMessage(`Injected ${burstCount} custom packet(s) from ${customSrcIp} into live Scapy ingestion engine.`);
    setTimeout(() => setStatusMessage(''), 4500);
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-2xs">
        <div>
          <span className="text-xs font-semibold px-2.5 py-1 rounded bg-slate-100 border border-slate-200 text-slate-800">
            Live Testing Workbench & Scenario Generator
          </span>
          <h2 className="text-xl font-bold text-slate-900 mt-2 flex items-center gap-2">
            <Flame className="w-5 h-5 text-slate-900" />
            Network Traffic & Intrusion Attack Injector
          </h2>
          <p className="text-xs text-slate-500 mt-1 max-w-2xl">
            Simulate real-world network attacks on a campus LAN environment to observe how Random Forest, LSTM, SHAP XAI, and the DQN autonomous response agent react in real time.
          </p>
        </div>

        {statusMessage && (
          <div className="mt-3 p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>{statusMessage}</span>
          </div>
        )}
      </div>

      {/* Preset Attack Scenarios Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Scenario 1: DoS SYN Flood */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs hover:border-slate-300 transition flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
                DoS / DDoS Attack
              </span>
              <span className="text-xs text-slate-400">Port 80 HTTP</span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">TCP SYN Flood Attack</h3>
            <p className="text-xs text-slate-500 mb-3">
              Sends rapid stream of TCP SYN packets with no ACKs to exhaust web server backlog queue.
            </p>
            <div className="text-[11px] text-slate-600 space-y-1 mb-4 bg-slate-50 p-2.5 rounded border border-slate-200">
              <div>Expected PPS: <strong className="text-slate-900">450 - 750 pps</strong></div>
              <div>Expected SHAP: <strong className="text-rose-700">Packets/Sec (+0.38)</strong></div>
              <div>Expected Action: <strong className="text-rose-700">BLOCK IP (Quarantine)</strong></div>
            </div>
          </div>
          <button
            onClick={() => handleLaunchScenario('DOS_SYN_FLOOD', 'TCP SYN Flood')}
            className="w-full flex items-center justify-center gap-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold py-2 rounded-lg transition shadow-2xs"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Inject SYN Flood Attack</span>
          </button>
        </div>

        {/* Scenario 2: Nmap Port Scan */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs hover:border-slate-300 transition flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200">
                Reconnaissance
              </span>
              <span className="text-xs text-slate-400">Multi-Port</span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">Nmap Stealth SYN Port Scan</h3>
            <p className="text-xs text-slate-500 mb-3">
              Scans 15+ destination ports on the target host (21, 22, 80, 443, 3306, 8080) to map services.
            </p>
            <div className="text-[11px] text-slate-600 space-y-1 mb-4 bg-slate-50 p-2.5 rounded border border-slate-200">
              <div>Expected Port Diversity: <strong className="text-slate-900">&gt; 12 ports</strong></div>
              <div>Expected SHAP: <strong className="text-amber-700">Port Diversity (+0.34)</strong></div>
              <div>Expected Action: <strong className="text-rose-700">BLOCK IP (Quarantine)</strong></div>
            </div>
          </div>
          <button
            onClick={() => handleLaunchScenario('PORT_SCAN', 'Nmap Port Scan')}
            className="w-full flex items-center justify-center gap-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold py-2 rounded-lg transition shadow-2xs"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Inject Port Scan Probe</span>
          </button>
        </div>

        {/* Scenario 3: SSH Brute Force */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs hover:border-slate-300 transition flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200">
                Unauthorized Access
              </span>
              <span className="text-xs text-slate-400">Port 22 SSH</span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">SSH Dictionary Brute Force</h3>
            <p className="text-xs text-slate-500 mb-3">
              Repeated credential attempts causing high connection resets (RSTs) and failed handshakes.
            </p>
            <div className="text-[11px] text-slate-600 space-y-1 mb-4 bg-slate-50 p-2.5 rounded border border-slate-200">
              <div>Failed Connections: <strong className="text-slate-900">&gt; 8 resets</strong></div>
              <div>Expected SHAP: <strong className="text-purple-700">Failed Resets (+0.28)</strong></div>
              <div>Expected Action: <strong className="text-rose-700">BLOCK IP (Quarantine)</strong></div>
            </div>
          </div>
          <button
            onClick={() => handleLaunchScenario('SSH_BRUTE_FORCE', 'SSH Brute Force')}
            className="w-full flex items-center justify-center gap-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold py-2 rounded-lg transition shadow-2xs"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Inject SSH Brute Force</span>
          </button>
        </div>

        {/* Scenario 4: Normal Benign Traffic */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs hover:border-slate-300 transition flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                Benign Traffic
              </span>
              <span className="text-xs text-slate-400">HTTPS 443</span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">Standard Campus LAN Browsing</h3>
            <p className="text-xs text-slate-500 mb-3">
              Simulates ordinary student browsing, video streaming, and normal TLS handshakes.
            </p>
            <div className="text-[11px] text-slate-600 space-y-1 mb-4 bg-slate-50 p-2.5 rounded border border-slate-200">
              <div>Traffic Rate: <strong className="text-slate-900">15 - 30 pps</strong></div>
              <div>Expected Risk: <strong className="text-emerald-700">&lt; 15% (Safe)</strong></div>
              <div>Expected Action: <strong className="text-emerald-700">ALLOW (Forward)</strong></div>
            </div>
          </div>
          <button
            onClick={() => handleLaunchScenario('BENIGN', 'Benign LAN Traffic')}
            className="w-full flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold py-2 rounded-lg transition shadow-2xs"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Inject Normal Traffic</span>
          </button>
        </div>

        {/* Scenario 5: ICMP Flood */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs hover:border-slate-300 transition flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-cyan-50 text-cyan-700 border border-cyan-200">
                ICMP Ping Flood
              </span>
              <span className="text-xs text-slate-400">Protocol ICMP</span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">Ping of Death Anomaly</h3>
            <p className="text-xs text-slate-500 mb-3">
              Rapid oversized ICMP echo requests targeting network gateway.
            </p>
            <div className="text-[11px] text-slate-600 space-y-1 mb-4 bg-slate-50 p-2.5 rounded border border-slate-200">
              <div>Packet Size: <strong className="text-slate-900">1400 bytes</strong></div>
              <div>Expected SHAP: <strong className="text-cyan-700">Avg Packet Size (+0.14)</strong></div>
              <div>Expected Action: <strong className="text-amber-700">ALERT / BLOCK</strong></div>
            </div>
          </div>
          <button
            onClick={() => handleLaunchScenario('ICMP_FLOOD', 'ICMP Flood')}
            className="w-full flex items-center justify-center gap-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold py-2 rounded-lg transition shadow-2xs"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Inject ICMP Flood</span>
          </button>
        </div>

        {/* Scenario 6: Malware C2 */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs hover:border-slate-300 transition flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-800 border border-slate-200">
                Malware Probe
              </span>
              <span className="text-xs text-slate-400">Port 4444</span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">C2 Beaconing Exfiltration</h3>
            <p className="text-xs text-slate-500 mb-3">
              Low-frequency periodic payload beaconing to unknown external control address.
            </p>
            <div className="text-[11px] text-slate-600 space-y-1 mb-4 bg-slate-50 p-2.5 rounded border border-slate-200">
              <div>Flow Entropy: <strong className="text-slate-900">High (0.85)</strong></div>
              <div>Expected Model: <strong className="text-slate-900">Random Forest Class</strong></div>
              <div>Expected Action: <strong className="text-rose-700">BLOCK IP (Quarantine)</strong></div>
            </div>
          </div>
          <button
            onClick={() => handleLaunchScenario('MALWARE_C2_PROBE', 'Malware C2 Beacon')}
            className="w-full flex items-center justify-center gap-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold py-2 rounded-lg transition shadow-2xs"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Inject Malware Probe</span>
          </button>
        </div>
      </div>

      {/* Custom Raw Packet Builder Form */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-2xs">
        <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 mb-1">
          <Send className="w-4 h-4 text-slate-900" />
          Custom Raw Packet Builder & Scapy Injector
        </h3>
        <p className="text-xs text-slate-500 mb-4">
          Craft custom packet headers and payload byte sequences for custom penetration testing.
        </p>

        <form onSubmit={handleInjectCustomPacket} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="text-xs text-slate-700 font-medium block mb-1">Source IPv4</label>
            <input
              type="text"
              value={customSrcIp}
              onChange={(e) => setCustomSrcIp(e.target.value)}
              className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-slate-400"
            />
          </div>

          <div>
            <label className="text-xs text-slate-700 font-medium block mb-1">Destination IPv4</label>
            <input
              type="text"
              value={customDstIp}
              onChange={(e) => setCustomDstIp(e.target.value)}
              className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-slate-400"
            />
          </div>

          <div>
            <label className="text-xs text-slate-700 font-medium block mb-1">Protocol</label>
            <select
              value={customProtocol}
              onChange={(e) => setCustomProtocol(e.target.value as ProtocolType)}
              className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-slate-400"
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="HTTP">HTTP</option>
              <option value="HTTPS">HTTPS</option>
              <option value="SSH">SSH</option>
              <option value="DNS">DNS</option>
            </select>
          </div>

          <div>
            <label className="text-xs text-slate-700 font-medium block mb-1">Destination Port</label>
            <input
              type="number"
              value={customPort}
              onChange={(e) => setCustomPort(Number(e.target.value))}
              className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-slate-400"
            />
          </div>

          <div>
            <label className="text-xs text-slate-700 font-medium block mb-1">Packet Size (Bytes)</label>
            <input
              type="number"
              value={customSize}
              onChange={(e) => setCustomSize(Number(e.target.value))}
              className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-slate-400"
            />
          </div>

          <div>
            <label className="text-xs text-slate-700 font-medium block mb-1">Burst Packet Count</label>
            <input
              type="number"
              min="1"
              max="20"
              value={burstCount}
              onChange={(e) => setBurstCount(Number(e.target.value))}
              className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-slate-400"
            />
          </div>

          <div className="sm:col-span-2">
            <label className="text-xs text-slate-700 font-medium block mb-1">Payload Summary String</label>
            <input
              type="text"
              value={customPayload}
              onChange={(e) => setCustomPayload(e.target.value)}
              className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-slate-400"
            />
          </div>

          <div className="sm:col-span-2 lg:col-span-4 flex items-center justify-between pt-2">
            <div className="flex items-center gap-4 text-xs">
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-700">
                <input
                  type="checkbox"
                  checked={customFlagSyn}
                  onChange={(e) => setCustomFlagSyn(e.target.checked)}
                  className="rounded bg-slate-100 border-slate-300 text-slate-900 focus:ring-0"
                />
                <span>SYN Flag</span>
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-700">
                <input
                  type="checkbox"
                  checked={customFlagAck}
                  onChange={(e) => setCustomFlagAck(e.target.checked)}
                  className="rounded bg-slate-100 border-slate-300 text-slate-900 focus:ring-0"
                />
                <span>ACK Flag</span>
              </label>
            </div>

            <button
              type="submit"
              className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold py-2 px-5 rounded-lg transition shadow-2xs"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Inject Into Ingestion Pipeline</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
