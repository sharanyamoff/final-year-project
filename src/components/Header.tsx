import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Cpu, 
  BrainCircuit, 
  Play, 
  Pause, 
  Flame, 
  Terminal
} from 'lucide-react';
import { controlModule } from '../services/controlModule';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isRunning: boolean;
  onToggleRunning: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  isRunning,
  onToggleRunning
}) => {
  const tabs = [
    { id: 'overview', label: 'SOC Live Monitor', icon: Activity },
    { id: 'models', label: 'ML (RF) & DL (LSTM)', icon: Cpu },
    { id: 'xai', label: 'XAI (SHAP Attribution)', icon: BrainCircuit },
    { id: 'rl', label: 'RL Decision (DQN)', icon: ShieldAlert },
    { id: 'firewall', label: 'Action & Firewall', icon: Terminal },
    { id: 'simulator', label: 'Attack Simulator', icon: Flame }
  ];

  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-40 shadow-xs">
      {/* Main Header Row */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-xs">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-slate-900 tracking-tight">
                XRL-IDARS
              </h1>
            </div>
            <p className="text-xs text-slate-500">
              Explainable Reinforcement Learning-Based Intrusion Detection & Autonomous Response System
            </p>
          </div>
        </div>

        {/* Global Pipeline Live Controls */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={onToggleRunning}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium text-xs transition border ${
              isRunning
                ? 'bg-emerald-50 text-emerald-800 border-emerald-300 hover:bg-emerald-100'
                : 'bg-amber-50 text-amber-800 border-amber-300 hover:bg-amber-100'
            }`}
          >
            {isRunning ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Streaming Live</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Engine Paused</span>
              </>
            )}
          </button>

          {/* Quick Simulation Injector */}
          <div className="flex items-center gap-1 bg-slate-100 border border-slate-200 rounded-md p-0.5">
            <button
              onClick={() => controlModule.injectCustomAttack('DOS_SYN_FLOOD')}
              className="px-2 py-1 text-xs font-medium text-rose-700 hover:bg-white rounded transition shadow-2xs"
              title="Inject DoS SYN Flood Attack"
            >
              +SYN Flood
            </button>
            <button
              onClick={() => controlModule.injectCustomAttack('PORT_SCAN')}
              className="px-2 py-1 text-xs font-medium text-amber-700 hover:bg-white rounded transition shadow-2xs"
              title="Inject Nmap Port Scan"
            >
              +Port Scan
            </button>
            <button
              onClick={() => controlModule.injectCustomAttack('BENIGN')}
              className="px-2 py-1 text-xs font-medium text-slate-700 hover:bg-white rounded transition shadow-2xs"
              title="Inject Normal Benign Packet"
            >
              +Normal LAN
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Bar */}
      <div className="border-t border-slate-200 bg-white px-4 sm:px-6 lg:px-8">
        <nav className="flex space-x-1 overflow-x-auto py-1.5 scrollbar-none">
          {tabs.map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition ${
                  isActive
                    ? 'bg-slate-900 text-white shadow-xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
