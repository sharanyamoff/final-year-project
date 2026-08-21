import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Brain, 
  RotateCw, 
  Award, 
  Sliders, 
  CheckCircle2, 
  AlertOctagon, 
  ArrowRight,
  TrendingUp,
  Cpu
} from 'lucide-react';
import { dqnAgent } from '../services/rlAgent';
import { controlModule } from '../services/controlModule';
import { DQNState, ActionType } from '../types';

export const RlDqnView: React.FC = () => {
  const [stats, setStats] = useState(dqnAgent.getStats());
  const [simRisk, setSimRisk] = useState<number>(0.85);
  const [simShap, setSimShap] = useState<number>(0.35);
  const [simVelocity, setSimVelocity] = useState<number>(0.75);
  const [simHistory, setSimHistory] = useState<number>(3);
  const [simBlocked, setSimBlocked] = useState<boolean>(false);
  const [trainingMessage, setTrainingMessage] = useState<string>('');

  const testState: DQNState = {
    riskScore: simRisk,
    topShapImpact: simShap,
    flowVelocity: simVelocity,
    historicalIncidentCount: simHistory,
    currentIpStatus: simBlocked ? 1.0 : 0.0
  };

  const qValues = dqnAgent.getQValues(testState);
  const decision = dqnAgent.selectAction(testState);

  const handleTrainEpisodes = (count: number) => {
    let earned = 0;
    for (let i = 0; i < count; i++) {
      const randomThreat = Math.random() > 0.4;
      const r = randomThreat ? 0.7 + Math.random() * 0.3 : 0.05 + Math.random() * 0.25;
      const s: DQNState = {
        riskScore: r,
        topShapImpact: randomThreat ? 0.3 : 0.02,
        flowVelocity: randomThreat ? 0.8 : 0.1,
        historicalIncidentCount: randomThreat ? 2 : 0,
        currentIpStatus: 0
      };
      const dec = dqnAgent.selectAction(s);
      const nextS: DQNState = { ...s, currentIpStatus: dec.action === 'BLOCK' ? 1 : 0 };
      const reward = dqnAgent.updatePolicy(s, dec.action, r, nextS);
      earned += reward;
    }
    setStats(dqnAgent.getStats());
    setTrainingMessage(`Successfully executed ${count} reinforcement learning episodes! Cumulative reward updated.`);
    setTimeout(() => setTrainingMessage(''), 4000);
  };

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-2xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <span className="text-xs font-semibold px-2.5 py-1 rounded bg-slate-100 border border-slate-200 text-slate-800">
              Autonomous Reinforcement Learning Agent
            </span>
            <h2 className="text-xl font-bold text-slate-900 mt-2 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-slate-900" />
              Autonomous Deep Q-Network (DQ-IDS) Decision Engine
            </h2>
            <p className="text-xs text-slate-500 mt-1 max-w-2xl">
              Based on base paper <em>M. A. Hossain et al., Elsevier ICT Express (2025)</em>. The RL agent dynamically maps composite risk, SHAP feature impact, and flow history to autonomous actions: <strong>ALLOW (0)</strong>, <strong>ALERT (1)</strong>, or <strong>BLOCK (2)</strong>.
            </p>
          </div>

          {/* Quick RL Training Controls */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleTrainEpisodes(50)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium transition shadow-2xs"
            >
              <RotateCw className="w-3.5 h-3.5" />
              <span>Train +50 Episodes</span>
            </button>
            <button
              onClick={() => {
                dqnAgent.resetEpsilon(0.20);
                setStats(dqnAgent.getStats());
              }}
              className="px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-medium border border-slate-200 transition"
            >
              Reset Exploration (ε)
            </button>
          </div>
        </div>

        {trainingMessage && (
          <div className="mt-3 p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>{trainingMessage}</span>
          </div>
        )}
      </div>

      {/* RL Agent Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs">
          <span className="text-xs text-slate-500">Total Learning Episodes</span>
          <div className="text-2xl font-bold text-slate-900 mt-1 font-mono">{stats.totalEpisodes}</div>
          <span className="text-[11px] text-slate-400">Bellman TD updates</span>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs">
          <span className="text-xs text-slate-500">Cumulative Environmental Reward</span>
          <div className="text-2xl font-bold text-emerald-700 mt-1 font-mono">+{stats.cumulativeReward} pts</div>
          <span className="text-[11px] text-slate-400">Optimization metric</span>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs">
          <span className="text-xs text-slate-500">Current Exploration Rate (ε)</span>
          <div className="text-2xl font-bold text-slate-900 mt-1 font-mono">{stats.epsilon}</div>
          <span className="text-[11px] text-slate-400">ε-greedy policy decay</span>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs">
          <span className="text-xs text-slate-500">Action Distribution</span>
          <div className="flex items-center gap-2 text-xs font-mono mt-2">
            <span className="text-emerald-700 font-semibold">Allow: {stats.totalActionsTaken.ALLOW}</span>
            <span className="text-amber-700 font-semibold">Alert: {stats.totalActionsTaken.ALERT}</span>
            <span className="text-rose-700 font-semibold">Block: {stats.totalActionsTaken.BLOCK}</span>
          </div>
        </div>
      </div>

      {/* Interactive RL Decision Studio */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: State Vector Inputs */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 border-b border-slate-100 pb-3">
            <Sliders className="w-4 h-4 text-slate-900" />
            DQN Environment State Vector (s)
          </h3>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700">Unified Risk Score</span>
              <span className="font-mono text-slate-900 font-bold">{(simRisk * 100).toFixed(0)}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="1"
              step="0.01"
              value={simRisk}
              onChange={(e) => setSimRisk(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700">Top SHAP Anomaly Impact</span>
              <span className="font-mono text-slate-900 font-bold">+{simShap.toFixed(2)} φ</span>
            </div>
            <input
              type="range"
              min="0"
              max="0.5"
              step="0.01"
              value={simShap}
              onChange={(e) => setSimShap(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700">Flow Velocity (Normalized PPS)</span>
              <span className="font-mono text-slate-900 font-bold">{simVelocity.toFixed(2)}</span>
            </div>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={simVelocity}
              onChange={(e) => setSimVelocity(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700">Historical IP Incidents</span>
              <span className="font-mono text-slate-900 font-bold">{simHistory} incidents</span>
            </div>
            <input
              type="range"
              min="0"
              max="10"
              value={simHistory}
              onChange={(e) => setSimHistory(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <span className="text-xs text-slate-700">Current IP Block Status</span>
            <button
              onClick={() => setSimBlocked(!simBlocked)}
              className={`px-3 py-1 rounded text-xs font-mono transition border ${
                simBlocked ? 'bg-rose-50 text-rose-800 border-rose-200 font-bold' : 'bg-slate-50 text-slate-700 border-slate-200'
              }`}
            >
              {simBlocked ? 'QUARANTINED' : 'NORMAL'}
            </button>
          </div>
        </div>

        {/* Center & Right Cols: Q-Values & Action Output */}
        <div className="lg:col-span-2 space-y-6">
          {/* Q-Value Action Comparison */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
            <h3 className="text-sm font-bold text-slate-900 mb-1">
              State-Action Value Evaluation Matrix Q(s, a)
            </h3>
            <p className="text-xs text-slate-500 mb-4">
              Agent evaluates expected cumulative reward for each available autonomous action.
            </p>

            <div className="grid grid-cols-3 gap-4">
              {/* Action 0: ALLOW */}
              <div className={`p-4 rounded-xl border transition ${
                decision.action === 'ALLOW' 
                  ? 'bg-emerald-50 border-emerald-500 ring-2 ring-emerald-500/20' 
                  : 'bg-slate-50 border-slate-200 opacity-60'
              }`}>
                <span className="text-xs font-mono text-slate-500 block">Action 0</span>
                <span className="text-base font-bold text-emerald-800">ALLOW (Forward)</span>
                <div className="text-2xl font-mono font-bold text-slate-900 mt-2">
                  {qValues.allow.toFixed(2)}
                </div>
                <span className="text-[10px] text-slate-500 block mt-1">Expected Q-Value</span>
              </div>

              {/* Action 1: ALERT */}
              <div className={`p-4 rounded-xl border transition ${
                decision.action === 'ALERT' 
                  ? 'bg-amber-50 border-amber-500 ring-2 ring-amber-500/20' 
                  : 'bg-slate-50 border-slate-200 opacity-60'
              }`}>
                <span className="text-xs font-mono text-slate-500 block">Action 1</span>
                <span className="text-base font-bold text-amber-800">ALERT (SOC Notify)</span>
                <div className="text-2xl font-mono font-bold text-slate-900 mt-2">
                  {qValues.alert.toFixed(2)}
                </div>
                <span className="text-[10px] text-slate-500 block mt-1">Expected Q-Value</span>
              </div>

              {/* Action 2: BLOCK */}
              <div className={`p-4 rounded-xl border transition ${
                decision.action === 'BLOCK' 
                  ? 'bg-rose-50 border-rose-500 ring-2 ring-rose-500/20' 
                  : 'bg-slate-50 border-slate-200 opacity-60'
              }`}>
                <span className="text-xs font-mono text-slate-500 block">Action 2</span>
                <span className="text-base font-bold text-rose-800">BLOCK (Firewall Drop)</span>
                <div className="text-2xl font-mono font-bold text-slate-900 mt-2">
                  {qValues.block.toFixed(2)}
                </div>
                <span className="text-[10px] text-slate-500 block mt-1">Expected Q-Value</span>
              </div>
            </div>

            {/* Decision Rationale */}
            <div className="mt-4 p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs">
              <span className="font-semibold text-slate-900 block mb-1">Autonomous Policy Decision:</span>
              <p className="text-slate-700 leading-relaxed">{decision.decisionReason}</p>
            </div>
          </div>

          {/* Reward Function Schema (from Section 6.7) */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 mb-3">
              <Award className="w-4 h-4 text-slate-900" />
              Environmental Reward Matrix & Penalty Architecture
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
                <span className="text-emerald-700 font-bold block mb-1">+10 pts: True Positive Block</span>
                <span className="text-slate-600">Accurately blocks malicious IP when risk &gt; 0.65.</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
                <span className="text-rose-700 font-bold block mb-1">-18 pts: False Positive Penalty</span>
                <span className="text-slate-600">Heavy penalty for blocking legitimate benign traffic.</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
                <span className="text-rose-700 font-bold block mb-1">-25 pts: False Negative Breach</span>
                <span className="text-slate-600">Critical penalty for allowing high-risk attack through.</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
