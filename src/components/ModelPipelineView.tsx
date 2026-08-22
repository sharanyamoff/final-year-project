import React, { useState } from 'react';
import { Cpu, Brain, Layers, Sliders, CheckCircle2, TrendingUp, Zap, Sparkles } from 'lucide-react';
import { mlInference } from '../services/mlModels';
import { packetEngine } from '../services/packetEngine';
import { ProcessedSecurityEvent } from '../types';

interface ModelPipelineViewProps {
  events: ProcessedSecurityEvent[];
}

export const ModelPipelineView: React.FC<ModelPipelineViewProps> = ({ events }) => {
  const latestEvent = events.length > 0 ? events[0] : null;
  const realFeatures = latestEvent?.realFeatures;
  const rfProb = latestEvent?.realPrediction?.probabilities ? Math.max(...latestEvent.realPrediction.probabilities) : 0;
  const lstmProb = latestEvent?.realPrediction?.lstm?.anomaly_score || 0;
  const riskScore = latestEvent?.realPrediction?.risk_score || 0;
  const classProbabilities = latestEvent?.realPrediction?.probabilities || [0, 0, 0, 0];
  
  // Assuming probabilities array maps to: ['BENIGN', 'DOS_SYN_FLOOD', 'PORT_SCAN', 'BRUTE_FORCE'] based on standard mapping
  const classNames = ['BENIGN', 'DOS_SYN_FLOOD', 'PORT_SCAN', 'BRUTE_FORCE'];
  const probMap: Record<string, number> = {};
  classProbabilities.forEach((p, idx) => {
    probMap[classNames[idx] || `Class_${idx}`] = p;
  });

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
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-slate-900" />
              Latest Flow Features
            </h3>
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">Packets Per Second (PPS)</span>
              <span className="font-mono text-slate-900 font-bold">{realFeatures?.flow_packets_per_s.toFixed(2) || 0} pps</span>
            </div>
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">Bytes Per Second (BPS)</span>
              <span className="font-mono text-slate-900 font-bold">{realFeatures?.flow_bytes_per_s.toFixed(2) || 0} bps</span>
            </div>
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">SYN/ACK Count</span>
              <span className="font-mono text-slate-900 font-bold">{realFeatures?.syn_count || 0} / {realFeatures?.ack_count || 0}</span>
            </div>
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">SYN-to-ACK Ratio</span>
              <span className="font-mono text-slate-900 font-bold">{(realFeatures?.syn_ack_ratio || 0).toFixed(1)}:1</span>
            </div>
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">Avg Packet Size (Bytes)</span>
              <span className="font-mono text-slate-900 font-bold">{realFeatures?.packet_length_mean.toFixed(2) || 0} B</span>
            </div>
          </div>
          
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-700 font-medium">Duration (ms)</span>
              <span className="font-mono text-slate-900 font-bold">{realFeatures?.flow_duration_ms.toFixed(2) || 0} ms</span>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-100">
            <span className="text-[11px] text-slate-500 block font-semibold">
              Currently analyzing live traffic from network interface. Make sure the ML Backend is running and producing packets.
            </span>
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
                    {(rfProb * 100).toFixed(1)}%
                  </span>
                  <span className="text-xs text-slate-500">confidence</span>
                </div>
                <div className="mt-2 flex items-center gap-2 text-xs">
                  <span className="text-slate-500">Class:</span>
                  <span className="px-2 py-0.5 rounded bg-slate-900 text-white font-semibold font-mono">
                    {latestEvent?.realPrediction?.prediction || 'BENIGN'}
                  </span>
                </div>
              </div>

              <div className="space-y-1.5 text-xs">
                <span className="text-slate-500 block font-semibold">Multiclass Ensemble Vote:</span>
                {Object.entries(probMap).map(([cls, prob]) => (
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
                    {(lstmProb * 100).toFixed(1)}%
                  </span>
                  <span className="text-xs text-slate-500">anomaly index</span>
                </div>
                <div className="mt-2 flex items-center gap-2 text-xs">
                  <span className="text-slate-500">Status:</span>
                  <span className="px-2 py-0.5 rounded bg-slate-900 text-white font-semibold font-mono">
                    {latestEvent?.realPrediction?.lstm?.status || 'N/A'}
                  </span>
                </div>
              </div>

              <div className="space-y-2 text-xs text-slate-700">
                <div className="flex justify-between py-1 border-b border-slate-200">
                  <span className="text-slate-500">Sequence Window Length (T):</span>
                  <span className="font-mono font-semibold text-slate-900">5 slices</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-200">
                  <span className="text-slate-500">Abnormal Pattern Trigger:</span>
                  <span className={`font-mono font-bold ${lstmProb > 0.5 ? 'text-rose-600' : 'text-emerald-600'}`}>
                    {lstmProb > 0.5 ? 'DETECTED' : 'NORMAL'}
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
                riskScore >= 0.8 ? 'bg-rose-50 text-rose-800 border-rose-200' :
                riskScore >= 0.6 ? 'bg-amber-50 text-amber-800 border-amber-200' :
                riskScore >= 0.35 ? 'bg-yellow-50 text-yellow-800 border-yellow-200' :
                'bg-emerald-50 text-emerald-800 border-emerald-200'
              }`}>
                {riskScore >= 0.8 ? 'CRITICAL' : riskScore >= 0.6 ? 'HIGH' : riskScore >= 0.35 ? 'MODERATE' : 'LOW'} RISK
              </span>
            </div>

            {/* Formula display from synopsis */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 text-xs font-mono text-slate-700 mb-4 leading-relaxed">
              <span className="text-slate-900 font-bold">Risk Score directly from python inference backend</span> = <strong className="text-slate-900 text-sm">{(riskScore * 100).toFixed(1)}% ({riskScore.toFixed(2)})</strong>
            </div>

            {/* Progress bar */}
            <div className="space-y-1">
              <div className="w-full bg-slate-200 h-3 rounded-full overflow-hidden p-0.5">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${
                    riskScore > 0.75 ? 'bg-rose-600' :
                    riskScore > 0.50 ? 'bg-amber-600' :
                    riskScore > 0.30 ? 'bg-yellow-500' :
                    'bg-slate-900'
                  }`}
                  style={{ width: `${riskScore * 100}%` }}
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
