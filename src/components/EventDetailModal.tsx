import React from 'react';
import { 
  X, 
  Activity, 
  Cpu, 
  BrainCircuit, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle,
  Layers,
  Smartphone,
  Wifi,
  HardDrive
} from 'lucide-react';
import { ProcessedSecurityEvent } from '../types';

interface EventDetailModalProps {
  event: ProcessedSecurityEvent | null;
  onClose: () => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  const isAttack = event.attackType !== 'BENIGN';
  const dev = event.flowFeatures.deviceInfo || event.rawPacket.deviceInfo;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4 overflow-y-auto">
      <div className="bg-white border border-slate-200 rounded-xl w-full max-w-3xl shadow-xl overflow-hidden my-8 animate-in fade-in zoom-in-95 duration-150 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg border ${isAttack ? 'bg-rose-50 text-rose-700 border-rose-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200'}`}>
              {isAttack ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                Security Incident Inspection: <span className="font-mono text-slate-700">{event.id}</span>
              </h3>
              <p className="text-xs text-slate-500">
                Timestamp: {new Date(event.timestamp).toLocaleString()} • Protocol: {event.protocol}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1.5 rounded-lg hover:bg-slate-200/60 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Scrollable */}
        <div className="p-6 space-y-5 overflow-y-auto text-xs text-slate-800">
          {/* Device & Phone Fingerprint Card */}
          {dev && (
            <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-2.5">
              <span className="font-bold text-slate-900 flex items-center gap-1.5 text-xs">
                <Smartphone className="w-4 h-4 text-slate-800" />
                Originating Device & Phone Identification Details (IP Analysis)
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-slate-700 font-mono text-[11px] pt-1">
                <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                  <span className="text-[10px] text-slate-500 font-sans block">Device / Phone Model</span>
                  <strong className="text-slate-900 text-xs font-sans">{dev.deviceName}</strong>
                </div>
                <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                  <span className="text-[10px] text-slate-500 font-sans block">Hardware Vendor</span>
                  <strong className="text-slate-900 font-sans text-xs">{dev.vendor}</strong>
                </div>
                <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                  <span className="text-[10px] text-slate-500 font-sans block">Operating System</span>
                  <strong className="text-slate-900">{dev.operatingSystem}</strong>
                </div>
                <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                  <span className="text-[10px] text-slate-500 font-sans block">MAC Address (OUI)</span>
                  <strong className="text-slate-900">{dev.macAddress}</strong>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-slate-600 font-mono text-[11px]">
                <div className="bg-white px-3 py-1.5 rounded border border-slate-200 flex items-center justify-between">
                  <span>DHCP Host:</span>
                  <span className="text-slate-900 font-semibold">{dev.dhcpHostname}</span>
                </div>
                <div className="bg-white px-3 py-1.5 rounded border border-slate-200 flex items-center justify-between">
                  <span>Subnet Segment:</span>
                  <span className="text-slate-900">{dev.networkSegment}</span>
                </div>
                <div className="bg-white px-3 py-1.5 rounded border border-slate-200 flex items-center justify-between">
                  <span>TCP TTL Fingerprint:</span>
                  <span className="text-slate-900 font-semibold">{dev.ttlFingerprint}</span>
                </div>
              </div>
            </div>
          )}

          {/* Section 1: Raw Packet & Extracted Flow */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-2">
              <span className="font-bold text-slate-900 flex items-center gap-1.5 text-xs">
                <Activity className="w-3.5 h-3.5 text-slate-800" />
                1 & 2. Raw Ingested Packet (Scapy Layer)
              </span>
              <div className="space-y-1 text-slate-700 font-mono text-[11px]">
                <div>Source IP: <strong className="text-slate-900">{event.sourceIp}:{event.rawPacket.sourcePort}</strong></div>
                <div>Destination IP: <strong className="text-slate-900">{event.destinationIp}:{event.rawPacket.destinationPort}</strong></div>
                <div>Protocol: <strong className="text-slate-900">{event.protocol}</strong></div>
                <div>Packet Size: <strong className="text-slate-900">{event.rawPacket.packetSize} bytes</strong></div>
                <div>Payload Summary: <span className="text-slate-600 block truncate">{event.rawPacket.payloadSummary}</span></div>
              </div>
            </div>

            <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-2">
              <span className="font-bold text-slate-900 flex items-center gap-1.5 text-xs">
                <Layers className="w-3.5 h-3.5 text-slate-800" />
                3. Extracted Flow Features
              </span>
              <div className="space-y-1 text-slate-700 font-mono text-[11px]">
                <div>Packets Per Second: <strong className="text-slate-900">{event.flowFeatures.packetsPerSecond} pps</strong></div>
                <div>Unique Ports Hit: <strong className="text-slate-900">{event.flowFeatures.uniquePortsAccessed} ports</strong></div>
                <div>Failed / RST Conns: <strong className="text-slate-900">{event.flowFeatures.failedConnectionsCount}</strong></div>
                <div>SYN-to-ACK Ratio: <strong className="text-slate-900">{event.flowFeatures.synToAckRatio}:1</strong></div>
                <div>Duration: <strong className="text-slate-900">{event.flowFeatures.connectionDurationMs} ms</strong></div>
              </div>
            </div>
          </div>

          {/* Section 2: ML (Random Forest) + DL (LSTM) + Risk Fusion */}
          <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-3">
            <span className="font-bold text-slate-900 flex items-center gap-1.5 text-xs">
              <Cpu className="w-3.5 h-3.5 text-slate-800" />
              4, 5 & 6. Hybrid Detection & Unified Risk Score
            </span>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="bg-white p-3 rounded-lg border border-slate-200">
                <span className="text-slate-500 block mb-0.5 text-[11px]">Random Forest (Static):</span>
                <div className="text-lg font-bold font-mono text-slate-900">
                  {(event.mlResult.attackProbability * 100).toFixed(1)}%
                </div>
                <span className="text-[10px] text-slate-500">{event.mlResult.predictedClass}</span>
              </div>

              <div className="bg-white p-3 rounded-lg border border-slate-200">
                <span className="text-slate-500 block mb-0.5 text-[11px]">LSTM Temporal (Sequential):</span>
                <div className="text-lg font-bold font-mono text-slate-900">
                  {(event.dlResult.temporalAnomalyScore * 100).toFixed(1)}%
                </div>
                <span className="text-[10px] text-slate-500">Trend: {event.dlResult.temporalTrend}</span>
              </div>

              <div className="bg-white p-3 rounded-lg border border-slate-200">
                <span className="text-slate-500 block mb-0.5 text-[11px]">Unified Risk Level:</span>
                <div className="text-lg font-bold font-mono text-rose-600">
                  {(event.riskScore.finalScore * 100).toFixed(0)}%
                </div>
                <span className="text-[10px] font-bold text-rose-700 font-mono">{event.riskScore.level}</span>
              </div>
            </div>
          </div>

          {/* Section 3: Explainable AI (SHAP) */}
          <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-2">
            <span className="font-bold text-slate-900 flex items-center gap-1.5 text-xs">
              <BrainCircuit className="w-3.5 h-3.5 text-slate-800" />
              7. Explainable AI (SHAP Attribution)
            </span>
            <p className="text-slate-800 bg-white p-3 rounded-lg border border-slate-200 text-xs leading-relaxed">
              {event.xaiExplanation.summaryNarrative}
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-1">
              {event.xaiExplanation.shapValues.map((s, idx) => (
                <div key={idx} className="bg-white p-2.5 rounded-lg border border-slate-200 text-[11px] font-mono">
                  <div className="text-slate-500 text-[10px] truncate">{s.displayName}</div>
                  <div className={s.shapValue >= 0 ? 'text-rose-700 font-bold' : 'text-emerald-700 font-bold'}>
                    {s.shapValue >= 0 ? `+${s.shapValue.toFixed(2)}` : s.shapValue.toFixed(2)} φ
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 4: RL (DQN) Decision & Action Execution */}
          <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-2">
            <span className="font-bold text-slate-900 flex items-center gap-1.5 text-xs">
              <Terminal className="w-3.5 h-3.5 text-slate-800" />
              8, 9 & 10. Autonomous DQN Decision & Action Enforcement
            </span>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 bg-white p-3.5 rounded-lg border border-slate-200">
              <div>
                <span className="text-slate-500 block text-[11px]">DQN Action Executed:</span>
                <span className={`text-base font-bold font-mono ${
                  event.actionExecuted === 'BLOCK' ? 'text-rose-600' :
                  event.actionExecuted === 'ALERT' ? 'text-amber-700' :
                  'text-emerald-700'
                }`}>
                  {event.actionExecuted} (Q-Allow: {event.rlDecision.qValues.allow.toFixed(1)}, Q-Alert: {event.rlDecision.qValues.alert.toFixed(1)}, Q-Block: {event.rlDecision.qValues.block.toFixed(1)})
                </span>
              </div>
              <div className="text-right">
                <span className="text-slate-500 block text-[11px]">Firewall Quarantine:</span>
                <span className={`font-mono font-bold ${event.isBlocked ? 'text-rose-700' : 'text-slate-700'}`}>
                  {event.isBlocked ? 'IP QUARANTINED' : 'ROUTING ALLOWED'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-md text-xs font-semibold transition shadow-2xs"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
