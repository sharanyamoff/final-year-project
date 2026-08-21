/**
 * LAN Device Discovery & Home Network Management Service
 * Detects the user's current client device (via WebRTC & User-Agent heuristics),
 * allows custom home subnet configuration (192.168.1.x, 192.168.0.x, 10.0.0.x),
 * performs browser HTTP/ping timing sweeps, and manages the user's real home LAN devices.
 */

import { DeviceInfo } from '../types';

const STORAGE_KEY_DEVICES = 'xrl_idars_home_devices';
const STORAGE_KEY_SUBNET = 'xrl_idars_home_subnet';
const STORAGE_KEY_MY_DEVICE = 'xrl_idars_my_device_ip';

export interface LocalClientInfo {
  ip?: string;
  os: string;
  deviceName: string;
  vendor: string;
  deviceType: DeviceInfo['deviceType'];
  browser: string;
  isMobile: boolean;
}

// Removed mock vendor registries

export class LanDeviceManager {
  private devices: Map<string, DeviceInfo> = new Map();
  private subnetPrefix: string = '';
  private myDeviceIp: string | null = null;
  private subscribers: (() => void)[] = [];

  constructor() {
    this.loadFromStorage();
  }

  public subscribe(callback: () => void): () => void {
    this.subscribers.push(callback);
    return () => {
      this.subscribers = this.subscribers.filter(cb => cb !== callback);
    };
  }

  private notify(): void {
    this.saveToStorage();
    this.subscribers.forEach(cb => cb());
  }

  private loadFromStorage(): void {
    // We intentionally ignore localStorage for devices and subnet now.
    // The backend is the single source of truth for the active network.
    localStorage.removeItem(STORAGE_KEY_DEVICES);
    localStorage.removeItem(STORAGE_KEY_SUBNET);
    
    // We can still preserve myDeviceIp if we want, but it's safer to clear it 
    // if the network changes. Let's just clear it.
    localStorage.removeItem(STORAGE_KEY_MY_DEVICE);

    this.initDefaultHomePreset();
  }

  public initDefaultHomePreset(): void {
    this.devices.clear();
    this.notify();
    
    // Auto-trigger a scan on boot to populate from the real backend
    setTimeout(() => {
      this.scanSubnet(() => {});
    }, 1000);
  }

  public saveToStorage(): void {
    try {
      localStorage.setItem(STORAGE_KEY_SUBNET, this.subnetPrefix);
      if (this.myDeviceIp) {
        localStorage.setItem(STORAGE_KEY_MY_DEVICE, this.myDeviceIp);
      } else {
        localStorage.removeItem(STORAGE_KEY_MY_DEVICE);
      }
      const deviceList = Array.from(this.devices.values());
      localStorage.setItem(STORAGE_KEY_DEVICES, JSON.stringify(deviceList));
    } catch (e) {
      console.warn('Error saving LAN devices to storage:', e);
    }
  }

  public getSubnetPrefix(): string {
    return this.subnetPrefix;
  }

  public setSubnetPrefix(prefix: string): void {
    const cleanPrefix = prefix.replace(/\.\d+$/, '').replace(/\/24$/, '').trim();
    if (!cleanPrefix) return;
    this.subnetPrefix = cleanPrefix;

    // Adjust IPs of existing devices to match new subnet prefix
    const oldDevices = Array.from(this.devices.values());
    this.devices.clear();
    oldDevices.forEach(dev => {
      const lastOctet = dev.ipAddress.split('.').pop() || '100';
      const newIp = `${cleanPrefix}.${lastOctet}`;
      const updated: DeviceInfo = {
        ...dev,
        ipAddress: newIp,
        dhcpHostname: dev.dhcpHostname.replace(/^host-\d+/, `host-${lastOctet}`)
      };
      if (dev.isMyDevice) {
        this.myDeviceIp = newIp;
      }
      this.devices.set(newIp, updated);
    });

    this.notify();
  }

  public getAllDevices(): DeviceInfo[] {
    const list = Array.from(this.devices.values());
    // Ensure isMyDevice flag is marked
    return list.map(d => ({
      ...d,
      isMyDevice: d.ipAddress === this.myDeviceIp || d.isMyDevice === true
    })).sort((a, b) => {
      if (a.isMyDevice) return -1;
      if (b.isMyDevice) return 1;
      return a.ipAddress.localeCompare(b.ipAddress, undefined, { numeric: true });
    });
  }

  public getDeviceByIp(ip: string): DeviceInfo | undefined {
    return this.devices.get(ip);
  }

  public addOrUpdateDevice(device: DeviceInfo): void {
    if (device.isMyDevice) {
      this.myDeviceIp = device.ipAddress;
    }
    this.devices.set(device.ipAddress, {
      ...device,
      lastSeen: Date.now(),
      isCustomHomeDevice: true
    });
    this.notify();
  }

  public removeDevice(ipAddress: string): boolean {
    if (this.devices.has(ipAddress)) {
      if (this.myDeviceIp === ipAddress) {
        this.myDeviceIp = null;
      }
      this.devices.delete(ipAddress);
      this.notify();
      return true;
    }
    return false;
  }

  public clearAllDevices(): void {
    this.devices.clear();
    this.myDeviceIp = null;
    this.notify();
  }

  public setMyDeviceIp(ip: string): void {
    this.myDeviceIp = ip;
    const dev = this.devices.get(ip);
    if (dev) {
      this.devices.set(ip, { ...dev, isMyDevice: true });
    }
    this.notify();
  }

  public getMyDeviceIp(): string | null {
    return this.myDeviceIp;
  }

  /**
   * Detects the user's browser client device information
   */
  public async detectLocalBrowserClient(): Promise<LocalClientInfo> {
    const ua = navigator.userAgent;
    let os = 'Unknown OS';
    let deviceName = 'My Device';
    let vendor = 'Unknown';
    let deviceType: DeviceInfo['deviceType'] = 'Laptop / PC';
    const isMobile = /iPhone|iPad|iPod|Android/i.test(ua);

    if (isMobile) {
      deviceType = 'Smart Phone';
    }

    // Try WebRTC candidate local IP discovery
    let detectedIp: string | undefined;
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel('');
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          try { pc.close(); } catch { /* ignore */ }
          resolve();
        }, 1000);

        pc.onicecandidate = (event) => {
          if (!event || !event.candidate) {
            clearTimeout(timer);
            try { pc.close(); } catch { /* ignore */ }
            resolve();
            return;
          }
          const candidate = event.candidate.candidate;
          const ipMatch = candidate.match(/(\b192\.168\.\d+\.\d+|\b10\.\d+\.\d+\.\d+|\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/);
          if (ipMatch && ipMatch[1]) {
            detectedIp = ipMatch[1];
            clearTimeout(timer);
            try { pc.close(); } catch { /* ignore */ }
            resolve();
          }
        };
      });
    } catch {
      // Browser sandboxed WebRTC ICE candidate
    }

    return {
      ip: detectedIp,
      os,
      deviceName,
      vendor,
      deviceType,
      browser: ua.includes('Chrome') ? 'Google Chrome' : ua.includes('Safari') ? 'Apple Safari' : 'Web Browser',
      isMobile
    };
  }

  /**
   * Generates a random realistic MAC address (Removed as it is fake data)
   */
  public generateMacForVendor(vendor: string): string {
    return '00:00:00:00:00:00'; // Should not be called
  }

  /**
   * Real Subnet Scanner that queries the backend API for actual ARP table devices.
   */
  public async scanSubnet(
    onProgress: (currentIp: string, percent: number, found: DeviceInfo[]) => void
  ): Promise<DeviceInfo[]> {
    const discovered: DeviceInfo[] = [];

    try {
      onProgress('Scanning ARP Table...', 10, []);
      
      const response = await fetch('/api/lan-devices');
      if (!response.ok) throw new Error('API failed');
      const data = await response.json();
      const realDevices: {ip: string, mac: string, vendor?: string, isHost?: boolean, isGateway?: boolean}[] = data.devices || [];
      const realPrefix: string = data.prefix;
      
      if (realPrefix) {
        this.subnetPrefix = realPrefix.replace(/\.$/, '');
      }

      onProgress('Parsing Real Devices...', 50, []);

      // Remove stale devices not present in the new realDevices array
      const realIps = new Set(realDevices.map(d => d.ip));
      for (const ip of Array.from(this.devices.keys())) {
        if (!realIps.has(ip)) {
          this.devices.delete(ip);
        }
      }

      realDevices.forEach((dev, index) => {
        const existing = this.devices.get(dev.ip);
        if (existing) {
          existing.isMyDevice = !!dev.isHost;
          if (dev.isHost) this.myDeviceIp = dev.ip;
          if (dev.isGateway) existing.deviceType = 'Server / Gateway';
          existing.deviceName = dev.isHost ? 'My Device (This Host)' : (dev.isGateway ? 'Gateway / Router' : existing.deviceName);
          discovered.push(existing);
        } else {
          const newDev: DeviceInfo = {
            ipAddress: dev.ip,
            macAddress: dev.mac.toUpperCase(),
            vendor: dev.vendor || 'Unknown',
            deviceName: dev.isHost ? 'My Device (This Host)' : (dev.isGateway ? 'Gateway / Router' : (dev.vendor && dev.vendor !== 'Unknown' ? dev.vendor + ' Device' : 'Unknown Device')),
            deviceType: dev.isHost ? 'Laptop / PC' : (dev.isGateway ? 'Server / Gateway' : 'IoT Device'),
            operatingSystem: 'Unknown OS',
            dhcpHostname: `Unknown`,
            networkSegment: 'Real LAN Subnet',
            ttlFingerprint: 64,
            lastSeen: Date.now(),
            isCustomHomeDevice: true,
            isMyDevice: !!dev.isHost
          };
          if (dev.isHost) this.myDeviceIp = dev.ip;
          this.devices.set(dev.ip, newDev);
          discovered.push(newDev);
        }
        onProgress(dev.ip, 50 + Math.round((index / realDevices.length) * 50), [...discovered]);
      });
      
      onProgress('Scan Complete', 100, discovered);
    } catch (err) {
      console.error('Failed to run real LAN scan:', err);
      // Fallback or error state
    }

    this.notify();
    return discovered;
  }
}

export const lanDeviceManager = new LanDeviceManager();
