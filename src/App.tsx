import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { OverviewDashboard } from './components/OverviewDashboard';
import { ModelPipelineView } from './components/ModelPipelineView';
import { XaiExplanationView } from './components/XaiExplanationView';
import { RlDqnView } from './components/RlDqnView';
import { FirewallActionView } from './components/FirewallActionView';
import { AttackSimulator } from './components/AttackSimulator';
import { EventDetailModal } from './components/EventDetailModal';
import { controlModule } from './services/controlModule';
import { ProcessedSecurityEvent, SystemMetrics, TimeSeriesPoint, FirewallRule } from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isRunning, setIsRunning] = useState<boolean>(controlModule.isRunning());
  const [metrics, setMetrics] = useState<SystemMetrics>(controlModule.getSystemMetrics());
  const [events, setEvents] = useState<ProcessedSecurityEvent[]>(controlModule.getEventsLog());
  const [timeSeries, setTimeSeries] = useState<TimeSeriesPoint[]>(controlModule.getTimeSeriesData());
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>(controlModule.getFirewallRules());
  const [selectedEvent, setSelectedEvent] = useState<ProcessedSecurityEvent | null>(null);

  // Subscribe to real-time updates from controlModule
  useEffect(() => {
    const unsubscribe = controlModule.subscribe(() => {
      setMetrics(controlModule.getSystemMetrics());
      setEvents([...controlModule.getEventsLog()]);
      setTimeSeries([...controlModule.getTimeSeriesData()]);
      setFirewallRules([...controlModule.getFirewallRules()]);
      setIsRunning(controlModule.isRunning());
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const handleToggleRunning = () => {
    const newState = controlModule.toggleTrafficEngine();
    setIsRunning(newState);
  };

  const handleRefresh = () => {
    setMetrics(controlModule.getSystemMetrics());
    setEvents([...controlModule.getEventsLog()]);
    setTimeSeries([...controlModule.getTimeSeriesData()]);
    setFirewallRules([...controlModule.getFirewallRules()]);
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans selection:bg-slate-900 selection:text-white">
      {/* Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isRunning={isRunning}
        onToggleRunning={handleToggleRunning}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && (
          <OverviewDashboard
            metrics={metrics}
            events={events}
            timeSeries={timeSeries}
            onSelectEvent={(ev) => setSelectedEvent(ev)}
          />
        )}

        {activeTab === 'models' && <ModelPipelineView />}

        {activeTab === 'xai' && (
          <XaiExplanationView
            events={events}
            selectedEvent={selectedEvent}
            onSelectEvent={(ev) => setSelectedEvent(ev)}
          />
        )}

        {activeTab === 'rl' && <RlDqnView />}

        {activeTab === 'firewall' && (
          <FirewallActionView
            firewallRules={firewallRules}
            onRefresh={handleRefresh}
          />
        )}

        {activeTab === 'simulator' && <AttackSimulator />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex items-center justify-center">
          <span className="font-medium text-slate-700">
            XRL-IDARS • Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System
          </span>
        </div>
      </footer>

      {/* Modals */}
      <EventDetailModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
}
