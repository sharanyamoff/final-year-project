import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  Lock, 
  Unlock, 
  Send, 
  Bell, 
  Mail, 
  MessageSquare, 
  CheckCircle2, 
  AlertTriangle,
  RefreshCw,
  Plus
} from 'lucide-react';
import { controlModule } from '../services/controlModule';
import { FirewallRule } from '../types';

interface FirewallActionViewProps {
  firewallRules: FirewallRule[];
  onRefresh: () => void;
}

export const FirewallActionView: React.FC<FirewallActionViewProps> = ({
  firewallRules,
  onRefresh
}) => {
  const [manualIp, setManualIp] = useState<string>('');
  const [manualReason, setManualReason] = useState<string>('Suspicious high-frequency probe');
  const [webhookUrl, setWebhookUrl] = useState<string>('https://soc-incident-webhook.internal/lan-alerts');
  const [testAlertMessage, setTestAlertMessage] = useState<string>('');
  const [feedback, setFeedback] = useState<string>('');

  const handleManualBlock = (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualIp.trim()) return;
    controlModule.blockIpAddress(manualIp.trim(), manualReason, 'MANUAL_ADMIN');
    setFeedback(`IP address ${manualIp.trim()} successfully quarantined.`);
    setManualIp('');
    setTimeout(() => setFeedback(''), 4000);
    onRefresh();
  };

  const handleUnblock = (ip: string) => {
    controlModule.unblockIpAddress(ip);
    setFeedback(`IP address ${ip} unblocked and restored to normal routing.`);
    setTimeout(() => setFeedback(''), 4000);
    onRefresh();
  };

  const handleTestWebhook = () => {
    setTestAlertMessage(`Dispatched test incident payload to ${webhookUrl} [HTTP 200 OK]`);
    setTimeout(() => setTestAlertMessage(''), 4000);
  };

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-2xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <span className="text-xs font-semibold px-2.5 py-1 rounded bg-slate-100 border border-slate-200 text-slate-800">
              Active Network Defense & Firewall Control
            </span>
            <h2 className="text-xl font-bold text-slate-900 mt-2 flex items-center gap-2">
              <Terminal className="w-5 h-5 text-slate-900" />
              Autonomous Firewall Enforcement & Alert Dispatcher
            </h2>
            <p className="text-xs text-slate-500 mt-1 max-w-2xl">
              Executes autonomous DQN decisions by injecting IP drop rules into the firewall table, dispatching real-time webhooks, SMS, and Email security alerts to network administrators.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onRefresh}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 text-slate-800 text-xs font-medium border border-slate-200 transition shadow-2xs"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh Tables</span>
            </button>
          </div>
        </div>

        {feedback && (
          <div className="mt-3 p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>{feedback}</span>
          </div>
        )}
      </div>

      {/* Grid: Manual Quarantine & Webhook Testing */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Manual Admin Block Console */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 mb-3">
            <Lock className="w-4 h-4 text-rose-600" />
            Manual IP Quarantine Override
          </h3>
          <p className="text-xs text-slate-500 mb-4">
            Security administrators can manually insert high-priority drop rules bypassing automated RL.
          </p>

          <form onSubmit={handleManualBlock} className="space-y-3">
            <div>
              <label className="text-xs text-slate-700 font-medium block mb-1">Target IPv4 Address</label>
              <input
                type="text"
                value={manualIp}
                onChange={(e) => setManualIp(e.target.value)}
                placeholder="e.g. 192.168.1.250"
                className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 focus:outline-none focus:border-slate-400 font-mono"
              />
            </div>
            <div>
              <label className="text-xs text-slate-700 font-medium block mb-1">Quarantine Reason</label>
              <input
                type="text"
                value={manualReason}
                onChange={(e) => setManualReason(e.target.value)}
                placeholder="e.g. Unauthorized lateral probe"
                className="w-full bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 focus:outline-none focus:border-slate-400"
              />
            </div>
            <button
              type="submit"
              className="w-full flex items-center justify-center gap-2 bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold py-2 px-4 rounded-lg transition shadow-2xs"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Apply Firewall Drop Rule</span>
            </button>
          </form>
        </div>

        {/* Multi-Channel Alert Dispatcher Simulator */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 mb-3">
            <Bell className="w-4 h-4 text-slate-900" />
            Alert Notification Channels (Email / SMS / Webhook)
          </h3>
          <p className="text-xs text-slate-500 mb-4">
            Automated alerts are published in real time whenever an attack is quarantined or high risk detected.
          </p>

          <div className="space-y-3">
            <div>
              <label className="text-xs text-slate-700 font-medium block mb-1">Incident Webhook Endpoint</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  className="flex-1 bg-slate-50 border border-slate-200 text-xs text-slate-900 rounded-lg px-3 py-2 focus:outline-none focus:border-slate-400 font-mono text-[11px]"
                />
                <button
                  type="button"
                  onClick={handleTestWebhook}
                  className="px-3 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium rounded-lg transition flex items-center gap-1 shadow-2xs"
                >
                  <Send className="w-3 h-3" />
                  <span>Test</span>
                </button>
              </div>
            </div>

            {testAlertMessage && (
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800">
                {testAlertMessage}
              </div>
            )}

            {/* Active Channels Badge List */}
            <div className="grid grid-cols-3 gap-2 pt-2">
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 text-center">
                <Mail className="w-4 h-4 text-slate-900 mx-auto mb-1" />
                <span className="text-[11px] font-semibold text-slate-800 block">Email Dispatch</span>
                <span className="text-[10px] text-emerald-600 font-bold">READY</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 text-center">
                <MessageSquare className="w-4 h-4 text-slate-900 mx-auto mb-1" />
                <span className="text-[11px] font-semibold text-slate-800 block">SMS Gateway</span>
                <span className="text-[10px] text-emerald-600 font-bold">READY</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 text-center">
                <Bell className="w-4 h-4 text-slate-900 mx-auto mb-1" />
                <span className="text-[11px] font-semibold text-slate-800 block">SOC Webhook</span>
                <span className="text-[10px] text-emerald-600 font-bold">ONLINE</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Active Blocked IPs Table */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-600" />
              Active Firewall Blocked IP Quarantine Table ({firewallRules.length} Active Rules)
            </h3>
            <p className="text-xs text-slate-500">
              Live dropped packets and prevented bytes through automated RL mitigation
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
              <tr>
                <th className="p-3">Quarantined IP</th>
                <th className="p-3">Trigger / Reason</th>
                <th className="p-3">Rule Type</th>
                <th className="p-3">Blocked At</th>
                <th className="p-3">Packets Dropped</th>
                <th className="p-3">Status</th>
                <th className="p-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {firewallRules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-slate-400">
                    No IP addresses currently quarantined. Network is clean.
                  </td>
                </tr>
              ) : (
                firewallRules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-slate-50 transition">
                    <td className="p-3 font-mono font-bold text-rose-600">
                      {rule.ipAddress}
                    </td>
                    <td className="p-3 text-slate-800 max-w-sm truncate">
                      {rule.reason}
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-slate-100 text-slate-800 border border-slate-200 font-semibold">
                        {rule.ruleType}
                      </span>
                    </td>
                    <td className="p-3 font-mono text-slate-500">
                      {new Date(rule.blockedAt).toLocaleTimeString()}
                    </td>
                    <td className="p-3 font-mono text-slate-800 font-medium">
                      {rule.packetsDropped} dropped
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-bold font-mono text-[10px]">
                        ACTIVE DROP
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleUnblock(rule.ipAddress)}
                        className="px-2.5 py-1 rounded bg-slate-50 hover:bg-slate-100 text-slate-800 text-xs font-medium border border-slate-200 transition flex items-center gap-1 ml-auto"
                      >
                        <Unlock className="w-3 h-3 text-emerald-600" />
                        <span>Unblock</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
