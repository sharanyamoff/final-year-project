import React, { useState } from 'react';
import { Cpu, Brain, Layers, Sliders, CheckCircle2, TrendingUp, Zap, Sparkles } from 'lucide-react';
import { mlInference } from '../services/mlModels';
import { packetEngine } from '../services/packetEngine';
import { FlowFeatures } from '../types';

export const ModelPipelineView: React.FC = () => {
  // Interactive sandbox flow state
  const [pps, setPps] = useState<number>(380);
  const [ports, setPorts] = useState<number>(14);
  const [failedConns, setFailedConns] = useState<number>(7);
  const [synAckRatio, setSynAckRatio] = useState<number>(6.5);
  const [packetSize, setPacketSize] = useState<number>(60);
  const [duration, setDuration] = useState<number>(1200);

  // Generate synthetic flow features based on sliders
  const testFlow: FlowFeatures = {
    flowId: 'sandbox_test_flow',
    sourceIp: '192.168.1.199',
    destinationIp: '192.168.1.10',
    windowStartTime: Date.now() - duration,
    windowEndTime: Date.now(),
    packetsPerSecond: pps,
    bytesPerSecond: pps * packetSize,
    uniquePortsAccessed: ports,
    avgPacketSize: packetSize,
    packetSizeStdDev: 12.4,
    connectionDurationMs: duration,
    failedConnectionsCount: failedConns,
    synToAckRatio: synAckRatio,
    distinctProtocolsCount: 2,
    flowEntropy: Math.min(1.0, (ports * 0.1) + 0.1)
  };

  const rfResult = mlInference.predictRandomForest(testFlow);
  const lstmResult = mlInference.predictLSTM(testFlow);
  const riskResult = mlInference.computeUnifiedRiskScore(rfResult, lstmResult, testFlow);

  return (
    <div className="space-y-6">
      {/* Top Architecture Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-2xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <span className="text-xs font-semibold px-2.5 py-1 rounded bg-slate-100 border border-slate-200 text-slate-800">
              Hybrid Machine Learning & Deep Learning Engine
            </span>
            <h2 className="text-xl font-bold text-slate-900 mt-2">
              Dual-Stream Hybrid AI Detection Architecture
            </h2>
            <p className="text-xs text-slate-500 mt-1 max-w-2xl">
              Combines <strong className="text-slate-800">Random Forest (ML)</strong> for static flow signature classification with <strong className="text-slate-800">LSTM Recurrent Neural Network (DL)</strong> for dynamic temporal sequence analysis, fused into a Unified Risk Score.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="bg-slate-50 border border-slate-200 px-4 py-2 rounded-lg text-center">
              <span className="text-[11px] text-slate-500 block">ML Benchmark (RF)</span>
              <span className="text-lg font-bold text-slate-900 font-mono">98.4% Acc</span>
            </div>
            <div className="bg-slate-50 border border-slate-200 px-4 py-2 rounded-lg text-center">
              <span className="text-[11px] text-slate-500 block">DL Benchmark (LSTM)</span>
              <span className="text-lg font-bold text-slate-900 font-mono">96.8% Acc</span>
            </div>
          </div>
        </div>
      </div>

      {/* Model Sandbox & Live Evaluator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Interactive Feature Parameter Controls */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-slate-900" />
              Flow Feature Sandbox
            </h3>
            <button
              onClick={() => {
                setPps(22);
                setPorts(1);
                setFailedConns(0);
                setSynAckRatio(1.0);
                setPacketSize(650);
                setDuration(3200);
              }}
              className="text-[11px] text-slate-600 hover:text-slate-900 transition font-medium"
            >
              Reset Normal
            </button>
          </div>

          {/* Slider 1: Packets Per Second */}
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">Packets Per Second (PPS)</span>
              <span className="font-mono text-slate-900 font-bold">{pps} pps</span>
            </div>
            <input
              type="range"
              min="1"
              max="800"
              value={pps}
              onChange={(e) => setPps(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
            <span className="text-[10px] text-slate-500">Normal LAN: 5-30 | Flooding: &gt; 250</span>
          </div>

          {/* Slider 2: Unique Ports Accessed */}
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">Unique Ports Accessed</span>
              <span className="font-mono text-slate-900 font-bold">{ports} ports</span>
            </div>
            <input
              type="range"
              min="1"
              max="40"
              value={ports}
              onChange={(e) => setPorts(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
            <span className="text-[10px] text-slate-500">Normal: 1-2 | Port Scanning: &gt; 8</span>
          </div>

          {/* Slider 3: Failed Connections */}
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">Failed Connections / RSTs</span>
              <span className="font-mono text-rose-600 font-bold">{failedConns} failed</span>
            </div>
            <input
              type="range"
              min="0"
              max="20"
              value={failedConns}
              onChange={(e) => setFailedConns(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
            <span className="text-[10px] text-slate-500">Normal: 0 | Brute Force: &gt; 5</span>
          </div>

          {/* Slider 4: SYN-to-ACK Ratio */}
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">SYN-to-ACK Ratio</span>
              <span className="font-mono text-slate-900 font-bold">{synAckRatio.toFixed(1)}:1</span>
            </div>
            <input
              type="range"
              min="0.5"
              max="15.0"
              step="0.5"
              value={synAckRatio}
              onChange={(e) => setSynAckRatio(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
            <span className="text-[10px] text-slate-500">Normal: ~1.0 | SYN Flood: &gt; 4.0</span>
          </div>

          {/* Slider 5: Average Packet Size */}
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">Avg Packet Size (Bytes)</span>
              <span className="font-mono text-slate-900 font-bold">{packetSize} B</span>
            </div>
            <input
              type="range"
              min="40"
              max="1500"
              value={packetSize}
              onChange={(e) => setPacketSize(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
          </div>

          {/* Quick Presets */}
          <div className="pt-2 border-t border-slate-100">
            <span className="text-[11px] text-slate-500 block mb-2 font-semibold">Preset Attack Scenarios:</span>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <button
                onClick={() => {
                  setPps(620);
                  setPorts(1);
                  setFailedConns(2);
                  setSynAckRatio(12.0);
                  setPacketSize(60);
                  setDuration(800);
                }}
                className="p-2 rounded bg-slate-50 hover:bg-slate-100 text-slate-900 border border-slate-200 text-left font-medium transition"
              >
                ⚡ DoS SYN Flood
              </button>
              <button
                onClick={() => {
                  setPps(140);
                  setPorts(28);
                  setFailedConns(4);
                  setSynAckRatio(3.5);
                  setPacketSize(44);
                  setDuration(1500);
                }}
                className="p-2 rounded bg-slate-50 hover:bg-slate-100 text-slate-900 border border-slate-200 text-left font-medium transition"
              >
                🔍 Nmap Port Scan
              </button>
              <button
                onClick={() => {
                  setPps(80);
                  setPorts(1);
                  setFailedConns(14);
                  setSynAckRatio(1.2);
                  setPacketSize(320);
                  setDuration(4000);
                }}
                className="p-2 rounded bg-slate-50 hover:bg-slate-100 text-slate-900 border border-slate-200 text-left font-medium transition"
              >
                🔑 SSH Brute Force
              </button>
              <button
                onClick={() => {
                  setPps(18);
                  setPorts(1);
                  setFailedConns(0);
                  setSynAckRatio(1.0);
                  setPacketSize(850);
                  setDuration(3500);
                }}
                className="p-2 rounded bg-slate-50 hover:bg-slate-100 text-slate-900 border border-slate-200 text-left font-medium transition"
              >
                🌐 Campus Browsing
              </button>
            </div>
          </div>
        </div>

        {/* Center & Right Cols: Real-Time Model Outputs & Fusion Calculation */}
        <div className="lg:col-span-2 space-y-6">
          {/* 1. ML Model (Random Forest) Output Card */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-slate-100 text-slate-900 border border-slate-200 flex items-center justify-center">
                  <Cpu className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-900">
                    6.3 Machine Learning Model (Random Forest Classifier)
                  </h3>
                  <span className="text-[11px] text-slate-500">
                    50 Estimators • Static Pattern Recognition • NSL-KDD / CIC-IDS Optimized
                  </span>
                </div>
              </div>
              <span className="font-mono text-xs text-slate-700 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                Latency: {rfResult.inferenceTimeMs} ms
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3 bg-slate-50 p-4 rounded-lg border border-slate-200">
              <div>
                <span className="text-xs text-slate-500 block mb-1">Attack Probability (P_RF)</span>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold font-mono text-slate-900">
                    {(rfResult.attackProbability * 100).toFixed(1)}%
                  </span>
                  <span className="text-xs text-slate-500">confidence</span>
                </div>
                <div className="mt-2 flex items-center gap-2 text-xs">
                  <span className="text-slate-500">Class:</span>
                  <span className="px-2 py-0.5 rounded bg-slate-900 text-white font-semibold font-mono">
                    {rfResult.predictedClass}
                  </span>
                </div>
              </div>

              {/* Class Probability Breakdown */}
              <div className="space-y-1.5 text-xs">
                <span className="text-slate-500 block font-semibold">Multiclass Ensemble Vote:</span>
                {Object.entries(rfResult.classProbabilities).map(([cls, prob]) => (
                  <div key={cls} className="flex items-center justify-between">
                    <span className="text-slate-600">{cls.replace(/_/g, ' ')}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-24 bg-slate-200 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-slate-900 h-full rounded-full"
                          style={{ width: `${prob * 100}%` }}
                        ></div>
                      </div>
                      <span className="font-mono text-[11px] text-slate-700 w-10 text-right font-medium">
                        {(prob * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* 2. Deep Learning Model (LSTM) Output Card */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-slate-100 text-slate-900 border border-slate-200 flex items-center justify-center">
                  <Brain className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-900">
                    6.4 Deep Learning Model (LSTM Temporal Sequence)
                  </h3>
                  <span className="text-[11px] text-slate-500">
                    Recurrent Gates (f_t, i_t, o_t) • Temporal Window T=5 • Behavioral Anomaly Score
                  </span>
                </div>
              </div>
              <span className="font-mono text-xs text-slate-700 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                Latency: {lstmResult.inferenceTimeMs} ms
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3 bg-slate-50 p-4 rounded-lg border border-slate-200">
              <div>
                <span className="text-xs text-slate-500 block mb-1">Temporal Behavior Score (P_LSTM)</span>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold font-mono text-slate-900">
                    {(lstmResult.temporalAnomalyScore * 100).toFixed(1)}%
                  </span>
                  <span className="text-xs text-slate-500">anomaly index</span>
                </div>
                <div className="mt-2 flex items-center gap-2 text-xs">
                  <span className="text-slate-500">Temporal Trend:</span>
                  <span className="px-2 py-0.5 rounded bg-slate-900 text-white font-semibold font-mono">
                    {lstmResult.temporalTrend}
                  </span>
                </div>
              </div>

              <div className="space-y-2 text-xs text-slate-700">
                <div className="flex justify-between py-1 border-b border-slate-200">
                  <span className="text-slate-500">Sequence Window Length (T):</span>
                  <span className="font-mono font-semibold text-slate-900">{lstmResult.sequenceLength} / 5 slices</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-200">
                  <span className="text-slate-500">Hidden State Norm ||h_t||:</span>
                  <span className="font-mono font-semibold text-slate-900">{lstmResult.hiddenStateNorm}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Abnormal Pattern Trigger:</span>
                  <span className={`font-mono font-bold ${lstmResult.abnormalPatternDetected ? 'text-rose-600' : 'text-emerald-600'}`}>
                    {lstmResult.abnormalPatternDetected ? 'DETECTED' : 'NORMAL'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* 3. Section 6.5: Combined Risk Scoring Layer */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Layers className="w-4 h-4 text-slate-900" />
                6.5 Unified Risk Scoring Fusion
              </h3>
              <span className={`text-xs font-bold px-2.5 py-0.5 rounded font-mono border ${
                riskResult.level === 'CRITICAL' ? 'bg-rose-50 text-rose-800 border-rose-200' :
                riskResult.level === 'HIGH' ? 'bg-amber-50 text-amber-800 border-amber-200' :
                riskResult.level === 'MODERATE' ? 'bg-yellow-50 text-yellow-800 border-yellow-200' :
                'bg-emerald-50 text-emerald-800 border-emerald-200'
              }`}>
                {riskResult.level} RISK
              </span>
            </div>

            {/* Formula display from synopsis */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 text-xs font-mono text-slate-700 mb-4 leading-relaxed">
              <span className="text-slate-900 font-bold">Risk</span> = ({riskResult.weights.mlWeight} × <span className="text-slate-900 font-semibold">P_ML ({rfResult.attackProbability.toFixed(2)})</span>) + ({riskResult.weights.dlWeight} × <span className="text-slate-900 font-semibold">P_DL ({lstmResult.temporalAnomalyScore.toFixed(2)})</span>) + <span className="text-slate-600">Heuristic ({riskResult.weights.heuristicBoost.toFixed(2)})</span> = <strong className="text-slate-900 text-sm">{(riskResult.finalScore * 100).toFixed(1)}% ({riskResult.finalScore.toFixed(2)})</strong>
            </div>

            {/* Progress bar */}
            <div className="space-y-1">
              <div className="w-full bg-slate-200 h-3 rounded-full overflow-hidden p-0.5">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${
                    riskResult.finalScore > 0.75 ? 'bg-rose-600' :
                    riskResult.finalScore > 0.50 ? 'bg-amber-600' :
                    riskResult.finalScore > 0.30 ? 'bg-yellow-500' :
                    'bg-slate-900'
                  }`}
                  style={{ width: `${riskResult.finalScore * 100}%` }}
                ></div>
              </div>
              <div className="flex justify-between text-[10px] text-slate-500">
                <span>0.0 (Safe)</span>
                <span>0.35 (Moderate)</span>
                <span>0.65 (High)</span>
                <span>1.0 (Critical Threat)</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
