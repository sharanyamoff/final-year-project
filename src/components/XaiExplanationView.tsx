import React, { useState } from 'react';
import { BrainCircuit, Info, CheckCircle2, AlertTriangle, ArrowRight, Sparkles, HelpCircle } from 'lucide-react';
import { ProcessedSecurityEvent, ShapValue } from '../types';

interface XaiExplanationViewProps {
  events: ProcessedSecurityEvent[];
  selectedEvent: ProcessedSecurityEvent | null;
  onSelectEvent: (event: ProcessedSecurityEvent) => void;
}

export const XaiExplanationView: React.FC<XaiExplanationViewProps> = ({
  events,
  selectedEvent,
  onSelectEvent
}) => {
  const currentEvent = selectedEvent || events[0];

  if (!currentEvent) {
    return (
      <div className="p-12 text-center text-slate-500 bg-white rounded-xl border border-slate-200">
        No security events recorded yet. Generate or stream traffic to inspect SHAP values.
      </div>
    );
  }

  const { xaiExplanation, mlResult, flowFeatures, riskScore, attackType } = currentEvent;
  const isAttack = attackType !== 'BENIGN';

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-2xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <span className="text-xs font-semibold px-2.5 py-1 rounded bg-slate-100 border border-slate-200 text-slate-800">
              Explainable AI (XAI) Attribution Engine
            </span>
            <h2 className="text-xl font-bold text-slate-900 mt-2 flex items-center gap-2">
              <BrainCircuit className="w-5 h-5 text-slate-900" />
              SHAP Interpretability & Feature Attribution Engine
            </h2>
            <p className="text-xs text-slate-500 mt-1 max-w-2xl">
              Deconstructs complex neural & ensemble model decisions into transparent Shapley additive values ($\phi_i$), pinpointing the exact network metrics that triggered the intrusion detection.
            </p>
          </div>

          {/* Event Quick Picker */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-medium">Inspect Event:</span>
            <select
              value={currentEvent.id}
              onChange={(e) => {
                const found = events.find(ev => ev.id === e.target.value);
                if (found) onSelectEvent(found);
              }}
              className="bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-md px-3 py-1.5 focus:outline-none focus:border-slate-400"
            >
              {events.slice(0, 15).map(ev => (
                <option key={ev.id} value={ev.id}>
                  {new Date(ev.timestamp).toLocaleTimeString()} - {ev.attackType} ({ev.sourceIp})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Selected Event Context Ribbon */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-2xs">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg border ${isAttack ? 'bg-rose-50 text-rose-700 border-rose-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200'}`}>
            {isAttack ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-slate-900 font-mono">{currentEvent.sourceIp}</span>
              <span className="text-xs text-slate-400">→</span>
              <span className="text-sm font-medium text-slate-700 font-mono">{currentEvent.destinationIp}:{currentEvent.rawPacket.destinationPort}</span>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-800 font-mono">
                {currentEvent.protocol}
              </span>
            </div>
            <span className="text-xs text-slate-500">
              Classification: <strong className="text-slate-900">{attackType.replace(/_/g, ' ')}</strong> | Combined Risk: <strong className="text-slate-900 font-mono">{(riskScore.finalScore * 100).toFixed(0)}%</strong>
            </span>
          </div>
        </div>

        {/* Narrative Summary Pill */}
        <div className="bg-slate-50 border border-slate-200 px-4 py-2.5 rounded-lg max-w-xl text-xs text-slate-800">
          <div className="flex items-center gap-1.5 text-slate-900 font-bold mb-0.5">
            <Sparkles className="w-3.5 h-3.5 text-slate-800" />
            <span>Root-Cause Explanation (XAI Synthesis)</span>
          </div>
          <p className="text-slate-700 leading-relaxed">{xaiExplanation.summaryNarrative}</p>
        </div>
      </div>

      {/* SHAP Mathematical Waterfall & Force Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: SHAP Feature Attribution Waterfall */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-5 shadow-2xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                SHAP Feature Attribution Waterfall (φ_i)
              </h3>
              <p className="text-xs text-slate-500">
                Positive values (red) push the model towards ATTACK; negative values (green) push towards BENIGN.
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1 text-rose-700 font-medium">
                <span className="w-2.5 h-2.5 rounded bg-rose-600"></span> Attack Force (+)
              </span>
              <span className="flex items-center gap-1 text-emerald-700 font-medium">
                <span className="w-2.5 h-2.5 rounded bg-emerald-600"></span> Benign Force (-)
              </span>
            </div>
          </div>

          {/* Waterfall Bars */}
          <div className="space-y-3.5 pt-2">
            {xaiExplanation.shapValues.map((shap, index) => {
              const isPositive = shap.shapValue >= 0;
              const absVal = Math.abs(shap.shapValue);
              const percentage = Math.min(100, Math.round(absVal * 200)); // normalized visual scale

              return (
                <div key={index} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-900">{shap.displayName}</span>
                      <span className="text-slate-500 font-mono text-[11px]">
                        (Actual: <strong className="text-slate-800">{shap.actualValue}</strong>, Baseline: {shap.baselineValue} {shap.unit})
                      </span>
                    </div>
                    <span className={`font-mono font-bold ${isPositive ? 'text-rose-700' : 'text-emerald-700'}`}>
                      {isPositive ? `+${shap.shapValue.toFixed(2)}` : shap.shapValue.toFixed(2)} φ
                    </span>
                  </div>

                  {/* Dual-Direction Center Aligned Bar */}
                  <div className="grid grid-cols-2 gap-1 bg-slate-100 p-1 rounded-md border border-slate-200 h-6">
                    {/* Left half: Negative (Benign) */}
                    <div className="flex justify-end items-center">
                      {!isPositive && (
                        <div
                          className="h-full bg-emerald-600 rounded transition-all duration-500"
                          style={{ width: `${percentage}%` }}
                        ></div>
                      )}
                    </div>
                    {/* Right half: Positive (Attack) */}
                    <div className="flex justify-start items-center">
                      {isPositive && (
                        <div
                          className="h-full bg-rose-600 rounded transition-all duration-500"
                          style={{ width: `${percentage}%` }}
                        ></div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Shapley Equation Reference */}
          <div className="mt-4 bg-slate-50 p-3 rounded-lg border border-slate-200 text-xs font-mono text-slate-600 flex items-center justify-between">
            <span>
              Baseline E[f(x)] = <strong className="text-slate-900">{(xaiExplanation.baseValue * 100).toFixed(1)}%</strong> → Σ φ_i = <strong className={isAttack ? 'text-rose-700' : 'text-emerald-700'}>{xaiExplanation.shapValues.reduce((a, b) => a + b.shapValue, 0) > 0 ? '+' : ''}{xaiExplanation.shapValues.reduce((a, b) => a + b.shapValue, 0).toFixed(2)}</strong> → Final Prediction f(x) = <strong className="text-slate-900">{(xaiExplanation.predictedValue * 100).toFixed(1)}%</strong>
            </span>
          </div>
        </div>

        {/* Right 1 Col: Why Explainability Matters in XRL-IDARS */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Info className="w-4 h-4 text-slate-900" />
            XAI Role in Decision Automation
          </h3>

          <div className="space-y-3 text-xs text-slate-700">
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="font-semibold text-slate-900 block mb-1">1. Transparent Auditing</span>
              <p className="text-slate-600">
                Prevents "black-box" decisions. Security analysts can verify exactly why an IP was blocked without guesswork.
              </p>
            </div>

            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="font-semibold text-slate-900 block mb-1">2. Input to Reinforcement Learning (DQN)</span>
              <p className="text-slate-600">
                Top SHAP magnitude is directly fed into the DQN state vector ($s$), allowing the RL agent to weigh feature confidence before executing quarantine.
              </p>
            </div>

            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="font-semibold text-slate-900 block mb-1">3. False-Positive Mitigation</span>
              <p className="text-slate-600">
                Distinguishes legitimate sudden spikes (e.g. video conferencing or large legitimate file downloads) from coordinated SYN floods or port scans.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
