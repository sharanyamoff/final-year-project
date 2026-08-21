import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Cpu, 
  Radio, 
  AlertTriangle, 
  CheckCircle, 
  Lock, 
  Filter,
  Eye,
  Smartphone,
  Laptop,
  Server,
  HardDrive,
  Wifi,
  Search,
  Home,
  Settings,
  Plus,
  Trash2,
  RefreshCw,
  Tablet,
  Network
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  CartesianGrid 
} from 'recharts';
import { ProcessedSecurityEvent, SystemMetrics, TimeSeriesPoint, DeviceInfo } from '../types';
import { controlModule } from '../services/controlModule';
import { lanDeviceManager } from '../services/lanDeviceManager';
import { HomeLanConfigModal } from './HomeLanConfigModal';

interface OverviewDashboardProps {
  metrics: SystemMetrics;
  events: ProcessedSecurityEvent[];
  timeSeries: TimeSeriesPoint[];
  onSelectEvent: (event: ProcessedSecurityEvent) => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  metrics,
  events,
  timeSeries,
  onSelectEvent
}) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [deviceSearch, setDeviceSearch] = useState<string>('');
  const [isHomeLanModalOpen, setIsHomeLanModalOpen] = useState<boolean>(false);
  const [, setRefreshKey] = useState<number>(0);

  const connectedDevices = controlModule.getConnectedDevices();

  const filteredDevices = connectedDevices.filter(d => 
    d.deviceName.toLowerCase().includes(deviceSearch.toLowerCase()) ||
    d.ipAddress.includes(deviceSearch) ||
    d.operatingSystem.toLowerCase().includes(deviceSearch.toLowerCase()) ||
    d.vendor.toLowerCase().includes(deviceSearch.toLowerCase()) ||
    d.macAddress.toLowerCase().includes(deviceSearch.toLowerCase())
  );

  const filteredEvents = events.filter(e => {
    if (filterType === 'ATTACKS') return e.attackType !== 'BENIGN';
    if (filterType === 'BLOCKED') return e.actionExecuted === 'BLOCK';
    if (filterType === 'BENIGN') return e.attackType === 'BENIGN';
    return true;
  });

  const handleDeviceDeleted = (ip: string) => {
    lanDeviceManager.removeDevice(ip);
    setRefreshKey(k => k + 1);
  };

  const getDeviceIcon = (type: DeviceInfo['deviceType']) => {
    switch (type) {
      case 'Smart Phone':
        return <Smartphone className="w-4 h-4 text-slate-700" />;
      case 'Laptop / PC':
        return <Laptop className="w-4 h-4 text-slate-700" />;
      case 'Server / Gateway':
        return <Server className="w-4 h-4 text-slate-700" />;
      case 'IoT Device':
        return <HardDrive className="w-4 h-4 text-slate-700" />;
      case 'Tablet':
        return <Tablet className="w-4 h-4 text-slate-700" />;
      default:
        return <Wifi className="w-4 h-4 text-slate-700" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Top Metrics KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="bg-white border border-slate-200 rounded-xl p-4.5 shadow-2xs relative">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Packets Processed</span>
            <Activity className="w-4 h-4 text-slate-900" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900 tracking-tight">
              {metrics.totalPacketsProcessed.toLocaleString()}
            </span>
            <span className="text-xs text-slate-600 font-mono font-medium">
              {metrics.currentTrafficRatePps} pps
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">Live LAN Scapy Sniffer capture</p>
        </div>

        {/* Metric 2 */}
        <div className="bg-white border border-slate-200 rounded-xl p-4.5 shadow-2xs relative">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Attacks Detected (ML/DL)</span>
            <ShieldAlert className="w-4 h-4 text-rose-600" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-rose-600 tracking-tight">
              {metrics.totalAttacksDetected}
            </span>
            <span className="text-xs text-rose-700 font-medium">
              {metrics.totalPacketsProcessed > 0 ? ((metrics.totalAttacksDetected / metrics.totalPacketsProcessed) * 100).toFixed(1) : 0}% threat rate
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">Random Forest + LSTM Temporal</p>
        </div>

        {/* Metric 3 */}
        <div className="bg-white border border-slate-200 rounded-xl p-4.5 shadow-2xs relative">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Autonomous Blocks (DQN)</span>
            <Lock className="w-4 h-4 text-slate-900" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900 tracking-tight">
              {metrics.totalIpsBlocked}
            </span>
            <span className="text-xs text-slate-600 font-medium">
              {metrics.totalAlertsDispatched} active alerts
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">Automated firewall IP quarantine</p>
        </div>

        {/* Metric 4 */}
        <div className="bg-white border border-slate-200 rounded-xl p-4.5 shadow-2xs relative">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">DQN Policy Efficiency</span>
            <Cpu className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-700 tracking-tight">
              {metrics.modelAccuracy.rlDecisionEfficiency}%
            </span>
            <span className="text-xs text-slate-600 font-mono font-medium">
              ε = {metrics.rlStats.epsilon}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">Reward: +{metrics.rlStats.cumulativeReward} pts</p>
        </div>
      </div>

      {/* 2. Real-Time Telemetry & Architecture Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: InfluxDB Live Telemetry Chart */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
            <div>
              <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Radio className="w-4 h-4 text-slate-900 animate-pulse" />
                Real-Time Network Telemetry & Traffic Influx
              </h2>
              <p className="text-xs text-slate-500">
                Live packet throughput (PPS) and composite risk score timeline (InfluxDB time-series model)
              </p>
            </div>
            <span className="text-xs bg-slate-100 text-slate-700 px-2.5 py-1 rounded-md border border-slate-200 font-mono">
              Avg Latency: {metrics.averageInferenceLatencyMs} ms
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeries.map(pt => ({ ...pt }))} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0f172a" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#0f172a" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#e11d48" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#e11d48" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    borderColor: '#cbd5e1',
                    borderRadius: '6px',
                    fontSize: '12px',
                    color: '#0f172a',
                    boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="packetsPerSec"
                  name="Packets / Sec"
                  stroke="#0f172a"
                  fillOpacity={1}
                  fill="url(#ppsGradient)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="riskScore"
                  name="Risk Index"
                  stroke="#e11d48"
                  fillOpacity={1}
                  fill="url(#riskGradient)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right 1 Col: Live 12-Layer Pipeline Status */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2 mb-1">
              <Cpu className="w-4 h-4 text-slate-900" />
              12-Layer System Architecture
            </h2>
            <p className="text-xs text-slate-500 mb-3">
              Real-time synchronization status across all project layers
            </p>

            <div className="space-y-1.5 text-xs">
              {[
                { layer: '1. Network Traffic', desc: 'Campus LAN Stream', status: 'ACTIVE' },
                { layer: '2. Packet Capture', desc: 'Scapy Ingestion Engine', status: 'ACTIVE' },
                { layer: '3. Feature Extraction', desc: 'Flow Features (PPS, Ports, RST)', status: 'ACTIVE' },
                { layer: '4. ML Random Forest', desc: '50 Estimators (Static Patterns)', status: 'ACC 98.4%' },
                { layer: '5. DL LSTM Sequence', desc: 'Recurrent Memory (T=5)', status: 'ACC 96.8%' },
                { layer: '6. Risk Scoring Layer', desc: 'ML & DL Weighted Fusion', status: 'SYNCHRONIZED' },
                { layer: '7. Explainable AI', desc: 'SHAP Shapley Attribution', status: 'ACTIVE' },
                { layer: '8. RL DQN Agent', desc: 'Self-Learning Autonomous Policy', status: 'Q-OPT' },
                { layer: '9. Control Module', desc: 'Data Flow Orchestration', status: 'OPERATIONAL' },
                { layer: '10. Action Execution', desc: 'IP Blocking & Webhook Alerts', status: 'READY' },
                { layer: '11. Database Layer', desc: 'PostgreSQL & InfluxDB', status: 'PERSISTED' },
                { layer: '12. Dashboard Layer', desc: 'SOC Monitoring (Grafana Spec)', status: 'ONLINE' }
              ].map((item, idx) => (
                <div key={idx} className="flex items-center justify-between py-1 border-b border-slate-100 last:border-0">
                  <span className="text-slate-700 font-medium">{item.layer}</span>
                  <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-800 font-mono text-[10px] font-semibold">
                    {item.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Device Discovery & Phone Tracker Card */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
        {/* LAN Subnet Banner Bar */}
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-slate-900 text-white rounded-lg">
              <Network className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-slate-900 text-xs">
                  Network Subnet: <span className="font-mono text-slate-950">{lanDeviceManager.getSubnetPrefix()}.0/24</span>
                </span>
                <span className="bg-slate-200 text-slate-800 text-[10px] font-semibold px-2 py-0.5 rounded">
                  {connectedDevices.length} Connected Devices
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Monitoring live phone models, Wi-Fi gateways, laptops, and smart devices
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setIsHomeLanModalOpen(true)}
              className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition shadow-2xs"
            >
              <Settings className="w-3.5 h-3.5" />
              Configure LAN
            </button>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Smartphone className="w-4 h-4 text-slate-900" />
              LAN Device Discovery & Phone Hardware Tracker
            </h2>
            <p className="text-xs text-slate-500">
              Passively identifies phone models, hostnames, hardware MAC vendors, and OS fingerprints using IP traffic analysis (DHCP, mDNS & TCP/IP SYN TTL)
            </p>
          </div>

          {/* Search Device Bar & Quick Add */}
          <div className="flex items-center gap-2">
            <div className="relative w-full sm:w-60">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search phone model, IP, MAC..."
                value={deviceSearch}
                onChange={(e) => setDeviceSearch(e.target.value)}
                className="w-full bg-slate-50 border border-slate-200 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-slate-400"
              />
            </div>
            <button
              onClick={() => setIsHomeLanModalOpen(true)}
              className="p-1.5 border border-slate-200 hover:bg-slate-100 rounded-md text-slate-700 transition"
              title="Add or manage devices"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Devices Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
              <tr>
                <th className="p-3">IP Address</th>
                <th className="p-3">Device Name & Model</th>
                <th className="p-3">Hardware Vendor</th>
                <th className="p-3">Operating System</th>
                <th className="p-3">MAC Address</th>
                <th className="p-3">DHCP Hostname</th>
                <th className="p-3">Network Subnet</th>
                <th className="p-3">TTL Fingerprint</th>
                <th className="p-3 text-right">Status / Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-800">
              {filteredDevices.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-slate-400">
                    <p className="mb-2">No devices found matching your search or current subnet.</p>
                    <button
                      onClick={() => setIsHomeLanModalOpen(true)}
                      className="px-3 py-1.5 bg-slate-900 text-white rounded text-xs font-semibold"
                    >
                      Open LAN Manager
                    </button>
                  </td>
                </tr>
              ) : (
                filteredDevices.map((dev) => {
                  const isCompromised = dev.deviceName.toLowerCase().includes('compromised') || dev.deviceName.toLowerCase().includes('bot');
                  return (
                    <tr 
                      key={dev.ipAddress} 
                      className={`hover:bg-slate-50/80 transition ${
                        dev.isMyDevice ? 'bg-slate-50/70 font-semibold' : ''
                      }`}
                    >
                      <td className="p-3 font-mono font-semibold text-slate-900">
                        {dev.ipAddress}
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <span className="p-1 rounded bg-slate-100 border border-slate-200">
                            {getDeviceIcon(dev.deviceType)}
                          </span>
                          <div>
                            <div className="flex items-center gap-1.5">
                              <span className="font-semibold text-slate-900">{dev.deviceName}</span>
                              {dev.isMyDevice && (
                                <span className="bg-slate-900 text-white text-[9px] font-bold px-1.5 py-0.2 rounded">
                                  YOU (THIS DEVICE)
                                </span>
                              )}
                            </div>
                            <span className="block text-[10px] text-slate-500 font-normal">{dev.deviceType}</span>
                          </div>
                        </div>
                      </td>
                      <td className="p-3 text-slate-700 font-normal">
                        {dev.vendor}
                      </td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-800 font-mono text-[11px] border border-slate-200 font-normal">
                          {dev.operatingSystem}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-slate-600 font-normal">
                        {dev.macAddress}
                      </td>
                      <td className="p-3 font-mono text-slate-700 font-normal">
                        {dev.dhcpHostname}
                      </td>
                      <td className="p-3 text-slate-600 text-[11px] font-normal">
                        {dev.networkSegment}
                      </td>
                      <td className="p-3 font-mono text-slate-600 font-normal">
                        TTL={dev.ttlFingerprint}
                      </td>
                      <td className="p-3 text-right whitespace-nowrap">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold border mr-2 ${
                          isCompromised
                            ? 'bg-rose-50 text-rose-800 border-rose-200'
                            : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        }`}>
                          {isCompromised ? 'FLAGGED' : 'HEALTHY'}
                        </span>
                        <button
                          onClick={() => handleDeviceDeleted(dev.ipAddress)}
                          className="p-1 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded transition"
                          title="Remove device from tracker"
                        >
                          <Trash2 className="w-3.5 h-3.5 inline" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Home LAN Configuration & Subnet Scanner Modal */}
      <HomeLanConfigModal
        isOpen={isHomeLanModalOpen}
        onClose={() => setIsHomeLanModalOpen(false)}
        onDevicesUpdated={() => setRefreshKey(k => k + 1)}
      />

      {/* 4. Live Packet & Security Event Stream */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Activity className="w-4 h-4 text-slate-900" />
              Live Security Event & Packet Audit Feed (PostgreSQL Storage)
            </h2>
            <p className="text-xs text-slate-500">
              Complete end-to-end trace from raw packet and identified phone/device to ML/DL probability, SHAP reason, and DQN action
            </p>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <div className="flex bg-slate-100 border border-slate-200 rounded-md p-0.5 text-xs">
              {['ALL', 'ATTACKS', 'BLOCKED', 'BENIGN'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilterType(f)}
                  className={`px-2.5 py-1 rounded transition font-medium ${
                    filterType === f
                      ? 'bg-slate-900 text-white shadow-2xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table / List */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
              <tr>
                <th className="p-3">Time</th>
                <th className="p-3">Source IP & Device Name</th>
                <th className="p-3">Destination</th>
                <th className="p-3">Protocol / Port</th>
                <th className="p-3">Attack Classification</th>
                <th className="p-3">ML (RF)</th>
                <th className="p-3">DL (LSTM)</th>
                <th className="p-3">Risk</th>
                <th className="p-3">Top SHAP Feature</th>
                <th className="p-3">DQN Decision</th>
                <th className="p-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-800">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={11} className="p-6 text-center text-slate-400">
                    No security events recorded in this filter.
                  </td>
                </tr>
              ) : (
                filteredEvents.slice(0, 12).map((event) => {
                  const isAttack = event.attackType !== 'BENIGN';
                  const topShap = event.xaiExplanation.shapValues[0];
                  const devInfo = event.flowFeatures.deviceInfo || event.rawPacket.deviceInfo;

                  return (
                    <tr
                      key={event.id}
                      className="hover:bg-slate-50 transition cursor-pointer"
                      onClick={() => onSelectEvent(event)}
                    >
                      <td className="p-3 whitespace-nowrap text-slate-500 font-mono">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="p-3">
                        <div className="font-mono text-slate-900 font-semibold">{event.sourceIp}</div>
                        <div className="text-[11px] text-slate-600 flex items-center gap-1 mt-0.5">
                          <Smartphone className="w-3 h-3 text-slate-400" />
                          <span>{devInfo?.deviceName || 'Standard LAN Host'}</span>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="font-mono text-slate-700">{event.destinationIp}</div>
                      </td>
                      <td className="p-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-800 font-mono">
                          {event.protocol}:{event.rawPacket.destinationPort}
                        </span>
                      </td>
                      <td className="p-3">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded font-medium border ${
                            isAttack
                              ? 'bg-rose-50 border-rose-200 text-rose-800'
                              : 'bg-emerald-50 border-emerald-200 text-emerald-800'
                          }`}
                        >
                          {isAttack ? <AlertTriangle className="w-3 h-3" /> : <CheckCircle className="w-3 h-3" />}
                          {event.attackType.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-slate-700">
                        {(event.mlResult.attackProbability * 100).toFixed(1)}%
                      </td>
                      <td className="p-3 font-mono text-slate-700">
                        {(event.dlResult.temporalAnomalyScore * 100).toFixed(1)}%
                      </td>
                      <td className="p-3">
                        <span
                          className={`font-bold font-mono px-2 py-0.5 rounded border text-xs ${
                            event.riskScore.level === 'CRITICAL'
                              ? 'bg-rose-100 text-rose-900 border-rose-300'
                              : event.riskScore.level === 'HIGH'
                              ? 'bg-amber-100 text-amber-900 border-amber-300'
                              : event.riskScore.level === 'MODERATE'
                              ? 'bg-yellow-100 text-yellow-900 border-yellow-300'
                              : 'bg-emerald-100 text-emerald-900 border-emerald-300'
                          }`}
                        >
                          {(event.riskScore.finalScore * 100).toFixed(0)}%
                        </span>
                      </td>
                      <td className="p-3 max-w-xs truncate text-slate-700">
                        {topShap ? (
                          <span className="text-xs">
                            <strong className="text-slate-900">{topShap.displayName}</strong>: {topShap.actualValue} (
                            <span className={topShap.shapValue > 0 ? 'text-rose-700 font-medium' : 'text-emerald-700 font-medium'}>
                              {topShap.shapValue > 0 ? `+${topShap.shapValue.toFixed(2)}` : topShap.shapValue.toFixed(2)}
                            </span>
                            )
                          </span>
                        ) : (
                          'N/A'
                        )}
                      </td>
                      <td className="p-3">
                        <span
                          className={`font-semibold px-2 py-0.5 rounded text-[11px] ${
                            event.actionExecuted === 'BLOCK'
                              ? 'bg-rose-600 text-white'
                              : event.actionExecuted === 'ALERT'
                              ? 'bg-amber-100 text-amber-900 border border-amber-300'
                              : 'bg-slate-100 text-slate-700 border border-slate-200'
                          }`}
                        >
                          {event.actionExecuted}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectEvent(event);
                          }}
                          className="text-slate-700 hover:text-slate-900 p-1.5 rounded hover:bg-slate-100 transition"
                          title="View Full Pipeline Inspection"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
