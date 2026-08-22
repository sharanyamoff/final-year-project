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
import { controlModule } from '../services/controlModule';
import { DQNState, ActionType, ProcessedSecurityEvent } from '../types';

interface RlDqnViewProps {
  events: ProcessedSecurityEvent[];
}

export const RlDqnView: React.FC<RlDqnViewProps> = ({ events }) => {
  
  const latestEvent = events.length > 0 ? events[0] : null;
  const dqnData = latestEvent?.realPrediction?.dqn;



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
              <span className="text-slate-700">Latest Event IP</span>
              <span className="font-mono text-slate-900 font-bold">{latestEvent?.sourceIp || 'N/A'}</span>
            </div>
          </div>
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700">Unified Risk Score</span>
              <span className="font-mono text-slate-900 font-bold">
                {latestEvent ? (latestEvent.realPrediction?.risk_score * 100).toFixed(0) + '%' : 'N/A'}
              </span>
            </div>
          </div>
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700">Top SHAP Feature</span>
              <span className="font-mono text-slate-900 font-bold">
                {latestEvent?.realPrediction?.shap?.features?.[0]?.feature || 'N/A'}
              </span>
            </div>
          </div>
          <div className="flex items-center justify-between pt-2">
            <span className="text-xs text-slate-700">Current Action Executed</span>
            <span className="px-3 py-1 rounded text-xs font-mono transition border bg-slate-50 text-slate-700 border-slate-200">
              {latestEvent?.actionExecuted || 'N/A'}
            </span>
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
                dqnData?.action === 'ALLOW' 
                  ? 'bg-emerald-50 border-emerald-500 ring-2 ring-emerald-500/20' 
                  : 'bg-slate-50 border-slate-200 opacity-60'
              }`}>
                <span className="text-xs font-mono text-slate-500 block">Action 0</span>
                <span className="text-base font-bold text-emerald-800">ALLOW (Forward)</span>
                <div className="text-2xl font-mono font-bold text-slate-900 mt-2">
                  {dqnData?.q_values.ALLOW.toFixed(2) || '0.00'}
                </div>
                <span className="text-[10px] text-slate-500 block mt-1">Expected Q-Value</span>
              </div>

              {/* Action 1: ALERT */}
              <div className={`p-4 rounded-xl border transition ${
                dqnData?.action === 'ALERT' 
                  ? 'bg-amber-50 border-amber-500 ring-2 ring-amber-500/20' 
                  : 'bg-slate-50 border-slate-200 opacity-60'
              }`}>
                <span className="text-xs font-mono text-slate-500 block">Action 1</span>
                <span className="text-base font-bold text-amber-800">ALERT (SOC Notify)</span>
                <div className="text-2xl font-mono font-bold text-slate-900 mt-2">
                  {dqnData?.q_values.ALERT.toFixed(2) || '0.00'}
                </div>
                <span className="text-[10px] text-slate-500 block mt-1">Expected Q-Value</span>
              </div>

              {/* Action 2: BLOCK */}
              <div className={`p-4 rounded-xl border transition ${
                dqnData?.action === 'BLOCK' 
                  ? 'bg-rose-50 border-rose-500 ring-2 ring-rose-500/20' 
                  : 'bg-slate-50 border-slate-200 opacity-60'
              }`}>
                <span className="text-xs font-mono text-slate-500 block">Action 2</span>
                <span className="text-base font-bold text-rose-800">BLOCK (Firewall Drop)</span>
                <div className="text-2xl font-mono font-bold text-slate-900 mt-2">
                  {dqnData?.q_values.BLOCK.toFixed(2) || '0.00'}
                </div>
                <span className="text-[10px] text-slate-500 block mt-1">Expected Q-Value</span>
              </div>
            </div>

            {/* Decision Rationale */}
            <div className="mt-4 p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs">
              <span className="font-semibold text-slate-900 block mb-1">Autonomous Policy Decision:</span>
              <p className="text-slate-700 leading-relaxed">Agent has selected to {dqnData?.action} based on python backend predictions.</p>
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
