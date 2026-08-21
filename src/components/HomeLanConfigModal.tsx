import React, { useState, useEffect } from 'react';
import { 
  X, 
  Home, 
  Search, 
  Plus, 
  Trash2, 
  Edit3, 
  Check, 
  Smartphone, 
  Laptop, 
  Server, 
  HardDrive, 
  Tablet, 
  Radio, 
  RefreshCw, 
  CheckCircle2, 
  AlertCircle,
  Network
} from 'lucide-react';
import { DeviceInfo } from '../types';
import { 
  lanDeviceManager, 
  LocalClientInfo 
} from '../services/lanDeviceManager';

const COMMON_VENDORS = ['Unknown'];

interface HomeLanConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDevicesUpdated: () => void;
}

export const HomeLanConfigModal: React.FC<HomeLanConfigModalProps> = ({
  isOpen,
  onClose,
  onDevicesUpdated
}) => {
  const [subnetInput, setSubnetInput] = useState<string>(lanDeviceManager.getSubnetPrefix());
  const [devices, setDevices] = useState<DeviceInfo[]>(lanDeviceManager.getAllDevices());
  const [detectedClient, setDetectedClient] = useState<LocalClientInfo | null>(null);
  const [isDetecting, setIsDetecting] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanStatusText, setScanStatusText] = useState<string>('');

  // Editing / Adding Form State
  const [isFormOpen, setIsFormOpen] = useState<boolean>(false);
  const [editingIp, setEditingIp] = useState<string | null>(null);
  const [formIp, setFormIp] = useState<string>('');
  const [formName, setFormName] = useState<string>('');
  const [formVendor, setFormVendor] = useState<string>('Unknown');
  const [formType, setFormType] = useState<DeviceInfo['deviceType']>('Smart Phone');
  const [formOs, setFormOs] = useState<string>('iOS 17.5');
  const [formMac, setFormMac] = useState<string>('');
  const [formIsMyDevice, setFormIsMyDevice] = useState<boolean>(false);
  const [formError, setFormError] = useState<string>('');

  useEffect(() => {
    if (isOpen) {
      setSubnetInput(lanDeviceManager.getSubnetPrefix());
      setDevices(lanDeviceManager.getAllDevices());
      detectClientInfo();
    }
  }, [isOpen]);

  const detectClientInfo = async () => {
    setIsDetecting(true);
    try {
      const info = await lanDeviceManager.detectLocalBrowserClient();
      setDetectedClient(info);
    } catch {
      // ignore
    } finally {
      setIsDetecting(false);
    }
  };

  if (!isOpen) return null;

  const handleSubnetChange = (newPrefix: string) => {
    setSubnetInput(newPrefix);
    lanDeviceManager.setSubnetPrefix(newPrefix);
    setDevices(lanDeviceManager.getAllDevices());
    onDevicesUpdated();
  };

  const handleOpenAddForm = () => {
    const prefix = lanDeviceManager.getSubnetPrefix();
    const existingLastOctets = devices.map(d => parseInt(d.ipAddress.split('.').pop() || '0', 10));
    let nextOctet = 101;
    while (existingLastOctets.includes(nextOctet) && nextOctet < 250) {
      nextOctet++;
    }

    setEditingIp(null);
    setFormIp(`${prefix}.${nextOctet}`);
    setFormName('My Home Device');
    setFormVendor('Unknown');
    setFormType('Smart Phone');
    setFormOs('iOS 17.5');
    setFormMac('00:00:00:00:00:00');
    setFormIsMyDevice(false);
    setFormError('');
    setIsFormOpen(true);
  };

  const handleOpenEditForm = (device: DeviceInfo) => {
    setEditingIp(device.ipAddress);
    setFormIp(device.ipAddress);
    setFormName(device.deviceName);
    setFormVendor(device.vendor);
    setFormType(device.deviceType);
    setFormOs(device.operatingSystem);
    setFormMac(device.macAddress);
    setFormIsMyDevice(device.isMyDevice || false);
    setFormError('');
    setIsFormOpen(true);
  };

  const handleSaveDevice = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formIp.trim()) {
      setFormError('IP Address is required');
      return;
    }
    if (!formName.trim()) {
      setFormError('Device Name is required');
      return;
    }

    const lastOctet = formIp.split('.').pop() || '100';
    const updatedDevice: DeviceInfo = {
      ipAddress: formIp.trim(),
      macAddress: formMac.trim() || '00:00:00:00:00:00',
      vendor: formVendor,
      deviceName: formName.trim(),
      deviceType: formType,
      operatingSystem: formOs.trim() || 'Custom OS',
      dhcpHostname: `${formName.toLowerCase().replace(/[^a-z0-9]/g, '-')}.lan`,
      networkSegment: 'Home LAN Subnet',
      ttlFingerprint: formType === 'Laptop / PC' && formOs.includes('Windows') ? 128 : 64,
      lastSeen: Date.now(),
      isMyDevice: formIsMyDevice,
      isCustomHomeDevice: true
    };

    // If editing and IP changed, remove old IP entry
    if (editingIp && editingIp !== formIp) {
      lanDeviceManager.removeDevice(editingIp);
    }

    lanDeviceManager.addOrUpdateDevice(updatedDevice);
    setDevices(lanDeviceManager.getAllDevices());
    setIsFormOpen(false);
    onDevicesUpdated();
  };

  const handleDeleteDevice = (ip: string) => {
    lanDeviceManager.removeDevice(ip);
    setDevices(lanDeviceManager.getAllDevices());
    onDevicesUpdated();
  };

  const handleClearAll = () => {
    if (confirm('Clear all devices? You can add your own home devices or restore the standard home preset.')) {
      lanDeviceManager.clearAllDevices();
      setDevices(lanDeviceManager.getAllDevices());
      onDevicesUpdated();
    }
  };

  const handleResetPreset = () => {
    lanDeviceManager.initDefaultHomePreset();
    setDevices(lanDeviceManager.getAllDevices());
    onDevicesUpdated();
  };

  const handleQuickAddDetectedClient = () => {
    if (!detectedClient) return;
    const prefix = lanDeviceManager.getSubnetPrefix();
    const targetIp = detectedClient.ip || `${prefix}.102`;

    const clientDevice: DeviceInfo = {
      ipAddress: targetIp,
      macAddress: '00:00:00:00:00:00',
      vendor: detectedClient.vendor,
      deviceName: `${detectedClient.deviceName} (This Device)`,
      deviceType: detectedClient.deviceType,
      operatingSystem: `${detectedClient.os} (${detectedClient.browser})`,
      dhcpHostname: 'my-current-client.lan',
      networkSegment: '5GHz Main Wi-Fi',
      ttlFingerprint: detectedClient.os.includes('Windows') ? 128 : 64,
      lastSeen: Date.now(),
      isMyDevice: true,
      isCustomHomeDevice: true
    };

    lanDeviceManager.addOrUpdateDevice(clientDevice);
    setDevices(lanDeviceManager.getAllDevices());
    onDevicesUpdated();
  };

  const handleRunSubnetScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    setScanStatusText('Initializing local subnet probe sweep...');

    await lanDeviceManager.scanSubnet((currentIp, percent, found) => {
      setScanProgress(percent);
      setScanStatusText(`Pinging ${currentIp} (${found.length} responsive endpoints)...`);
      setDevices(lanDeviceManager.getAllDevices());
    });

    setIsScanning(false);
    setScanStatusText('Subnet scan complete! All discovered devices loaded.');
    setDevices(lanDeviceManager.getAllDevices());
    onDevicesUpdated();
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
        return <Radio className="w-4 h-4 text-slate-700" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-4xl max-h-[92vh] shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/70">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-slate-900 text-white rounded-lg">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                LAN Network & Device Manager
              </h2>
              <p className="text-xs text-slate-500">
                Configure network subnet, discover connected phones & PCs, and manage devices
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1.5 rounded-lg hover:bg-slate-100 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          
          {/* Section 1: Detected Browser Client */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-full bg-slate-200 text-slate-800">
                  <Smartphone className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-900 text-sm">
                      {detectedClient?.deviceName || 'Current Browser Client'}
                    </span>
                    <span className="bg-slate-900 text-white text-[10px] font-semibold px-2 py-0.5 rounded-full">
                      THIS DEVICE
                    </span>
                  </div>
                  <p className="text-slate-600 mt-0.5">
                    OS: <strong className="text-slate-800">{detectedClient?.os}</strong> • Vendor: <strong className="text-slate-800">{detectedClient?.vendor}</strong>
                    {detectedClient?.ip ? ` • Detected IP: ${detectedClient.ip}` : ''}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={detectClientInfo}
                  disabled={isDetecting}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-100 transition flex items-center gap-1.5 font-medium"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isDetecting ? 'animate-spin' : ''}`} />
                  Re-Detect
                </button>
                <button
                  onClick={handleQuickAddDetectedClient}
                  className="px-3.5 py-1.5 rounded-lg bg-slate-900 text-white hover:bg-slate-800 transition font-medium flex items-center gap-1.5 shadow-2xs"
                >
                  <Check className="w-3.5 h-3.5" />
                  Add / Sync As My Device
                </button>
              </div>
            </div>
          </div>

          {/* Section 2: LAN Subnet Configuration & Discovery Sweep */}
          <div className="border border-slate-200 rounded-xl p-4 bg-white space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
                  <Network className="w-4 h-4 text-slate-900" />
                  LAN Subnet & Gateway Prefix
                </h3>
                <p className="text-slate-500 text-xs">
                  Set the IP subnet matching your network router (e.g. 192.168.1.x or 192.168.0.x)
                </p>
              </div>

              {/* Subnet Quick Preset Chips */}
              <div className="flex flex-wrap items-center gap-1.5">
                {[
                  { label: '192.168.1.x', val: '192.168.1' },
                  { label: '192.168.0.x', val: '192.168.0' },
                  { label: '10.0.0.x', val: '10.0.0' },
                  { label: '172.16.0.x', val: '172.16.0' }
                ].map(sub => (
                  <button
                    key={sub.val}
                    onClick={() => handleSubnetChange(sub.val)}
                    className={`px-2.5 py-1 rounded-md text-xs font-mono font-medium transition ${
                      subnetInput === sub.val
                        ? 'bg-slate-900 text-white shadow-2xs'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200 border border-slate-200'
                    }`}
                  >
                    {sub.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Custom Subnet Input + Scan Button */}
            <div className="flex flex-col sm:flex-row items-center gap-2 pt-1">
              <div className="relative flex-1 w-full">
                <input
                  type="text"
                  value={subnetInput}
                  onChange={(e) => handleSubnetChange(e.target.value)}
                  placeholder="e.g. 192.168.1"
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono font-semibold text-slate-900 focus:outline-none focus:border-slate-500"
                />
                <span className="absolute right-3 top-2 text-slate-400 font-mono text-xs">.0/24</span>
              </div>

              <button
                onClick={handleRunSubnetScan}
                disabled={isScanning}
                className="w-full sm:w-auto px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg transition font-medium flex items-center justify-center gap-2 shadow-2xs whitespace-nowrap"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Scanning Subnet ({scanProgress}%)...
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5" />
                    Scan Subnet for Devices
                  </>
                )}
              </button>
            </div>

            {/* Scan Progress Bar & Status Text */}
            {isScanning && (
              <div className="space-y-1.5 pt-2">
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden border border-slate-200">
                  <div 
                    className="bg-slate-900 h-full rounded-full transition-all duration-150"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
                <p className="text-[11px] text-slate-600 font-mono">{scanStatusText}</p>
              </div>
            )}
            {!isScanning && scanStatusText && (
              <div className="flex items-center gap-1.5 text-emerald-700 text-xs bg-emerald-50 border border-emerald-200 p-2 rounded-lg">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{scanStatusText}</span>
              </div>
            )}
          </div>

          {/* Section 3: Device List & Custom Addition */}
          <div className="border border-slate-200 rounded-xl p-4 bg-white space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h3 className="font-bold text-slate-900 text-sm">
                  Active Connected LAN Devices ({devices.length})
                </h3>
                <p className="text-slate-500 text-xs">
                  These devices are monitored in real time by the XRL-IDARS pipeline
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={handleClearAll}
                  className="px-2.5 py-1.5 rounded-lg border border-slate-300 text-slate-700 hover:bg-rose-50 hover:text-rose-700 hover:border-rose-300 transition flex items-center gap-1 font-medium"
                  title="Remove all current devices to start clean"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Clear All
                </button>
                <button
                  onClick={handleResetPreset}
                  className="px-2.5 py-1.5 rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-100 transition flex items-center gap-1 font-medium"
                  title="Restore standard router + phones preset"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Restore Default Preset
                </button>
                <button
                  onClick={handleOpenAddForm}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white transition font-medium flex items-center gap-1.5 shadow-2xs"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add Device
                </button>
              </div>
            </div>

            {/* Device Table */}
            <div className="overflow-x-auto border border-slate-200 rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
                  <tr>
                    <th className="p-2.5">Device Name & Role</th>
                    <th className="p-2.5">IP Address</th>
                    <th className="p-2.5">Vendor / Brand</th>
                    <th className="p-2.5">Operating System</th>
                    <th className="p-2.5">MAC Address</th>
                    <th className="p-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-slate-800">
                  {devices.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-8 text-center text-slate-400">
                        <div className="max-w-xs mx-auto space-y-2">
                          <p>No devices currently configured.</p>
                          <button
                            onClick={handleResetPreset}
                            className="px-3 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-medium"
                          >
                            Load Default Presets
                          </button>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    devices.map((dev) => (
                      <tr 
                        key={dev.ipAddress}
                        className={`hover:bg-slate-50/80 transition ${
                          dev.isMyDevice ? 'bg-slate-50/60 font-semibold' : ''
                        }`}
                      >
                        <td className="p-2.5">
                          <div className="flex items-center gap-2">
                            <span className="p-1 rounded bg-slate-100 border border-slate-200">
                              {getDeviceIcon(dev.deviceType)}
                            </span>
                            <div>
                              <div className="flex items-center gap-1.5">
                                <span className="font-semibold text-slate-900">{dev.deviceName}</span>
                                {dev.isMyDevice && (
                                  <span className="bg-slate-900 text-white text-[9px] font-bold px-1.5 py-0.2 rounded">
                                    YOU
                                  </span>
                                )}
                              </div>
                              <span className="text-[10px] text-slate-500 font-normal">{dev.deviceType}</span>
                            </div>
                          </div>
                        </td>
                        <td className="p-2.5 font-mono text-slate-900 font-semibold">
                          {dev.ipAddress}
                        </td>
                        <td className="p-2.5 text-slate-700">
                          {dev.vendor}
                        </td>
                        <td className="p-2.5">
                          <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px] text-slate-800">
                            {dev.operatingSystem}
                          </span>
                        </td>
                        <td className="p-2.5 font-mono text-slate-600 text-[11px]">
                          {dev.macAddress}
                        </td>
                        <td className="p-2.5 text-right whitespace-nowrap">
                          <button
                            onClick={() => handleOpenEditForm(dev)}
                            className="p-1 text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded mr-1 transition"
                            title="Edit Device"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleDeleteDevice(dev.ipAddress)}
                            className="p-1 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded transition"
                            title="Remove Device"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 4: Add / Edit Form Drawer/Modal */}
          {isFormOpen && (
            <form onSubmit={handleSaveDevice} className="border-2 border-slate-900 bg-slate-50 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                <h4 className="font-bold text-slate-900 text-sm">
                  {editingIp ? `Edit Device (${editingIp})` : 'Add New Device / Phone'}
                </h4>
                <button
                  type="button"
                  onClick={() => setIsFormOpen(false)}
                  className="text-slate-400 hover:text-slate-700"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {formError && (
                <div className="bg-rose-50 border border-rose-200 text-rose-800 p-2 rounded text-xs flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>{formError}</span>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-slate-700 font-semibold mb-1">Device Name</label>
                  <input
                    type="text"
                    value={formName}
                    onChange={(e) => setFormName(e.target.value)}
                    placeholder="e.g. My iPhone 15, Samsung TV, Router"
                    className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 text-slate-900 focus:outline-none focus:border-slate-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-700 font-semibold mb-1">IP Address</label>
                  <input
                    type="text"
                    value={formIp}
                    onChange={(e) => setFormIp(e.target.value)}
                    placeholder="e.g. 192.168.1.105"
                    className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 font-mono text-slate-900 focus:outline-none focus:border-slate-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-700 font-semibold mb-1">Hardware Vendor</label>
                  <select
                    value={formVendor}
                    onChange={(e) => {
                      setFormVendor(e.target.value);
                      setFormMac('00:00:00:00:00:00');
                    }}
                    className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 text-slate-900 focus:outline-none focus:border-slate-500"
                  >
                    {COMMON_VENDORS.map(v => (
                      <option key={v} value={v}>{v}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-slate-700 font-semibold mb-1">Device Type</label>
                  <select
                    value={formType}
                    onChange={(e) => setFormType(e.target.value as DeviceInfo['deviceType'])}
                    className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 text-slate-900 focus:outline-none focus:border-slate-500"
                  >
                    <option value="Smart Phone">Smart Phone</option>
                    <option value="Laptop / PC">Laptop / PC</option>
                    <option value="Server / Gateway">Server / Gateway</option>
                    <option value="IoT Device">IoT Device</option>
                    <option value="Tablet">Tablet</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-700 font-semibold mb-1">Operating System</label>
                  <input
                    type="text"
                    value={formOs}
                    onChange={(e) => setFormOs(e.target.value)}
                    placeholder="e.g. iOS 17.5, Android 14, Windows 11"
                    className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 text-slate-900 focus:outline-none focus:border-slate-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-700 font-semibold mb-1">MAC Address</label>
                  <div className="flex items-center gap-1.5">
                    <input
                      type="text"
                      value={formMac}
                      onChange={(e) => setFormMac(e.target.value)}
                      placeholder="e.g. A4:83:E7:11:22:33"
                      className="w-full bg-white border border-slate-300 rounded px-2.5 py-1.5 font-mono text-slate-900 focus:outline-none focus:border-slate-500"
                    />
                    <button
                      type="button"
                      onClick={() => setFormMac('00:00:00:00:00:00')}
                      className="px-2 py-1.5 bg-slate-200 hover:bg-slate-300 rounded text-[11px] font-medium whitespace-nowrap"
                      title="Generate random MAC for vendor"
                    >
                      Gen MAC
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formIsMyDevice}
                    onChange={(e) => setFormIsMyDevice(e.target.checked)}
                    className="rounded border-slate-300 text-slate-900 focus:ring-0"
                  />
                  <span className="text-slate-800 font-medium">Mark as My Device (Current Client)</span>
                </label>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setIsFormOpen(false)}
                    className="px-3 py-1.5 rounded border border-slate-300 text-slate-700 hover:bg-slate-100 font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-white font-semibold shadow-2xs"
                  >
                    {editingIp ? 'Save Changes' : 'Add Device'}
                  </button>
                </div>
              </div>
            </form>
          )}

        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <span className="text-xs text-slate-500">
            Current Subnet: <strong className="font-mono text-slate-800">{lanDeviceManager.getSubnetPrefix()}.0/24</strong>
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-2xs transition"
          >
            Done & Apply
          </button>
        </div>

      </div>
    </div>
  );
};
