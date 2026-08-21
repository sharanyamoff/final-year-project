/**
 * Packet Capture & Feature Extraction Layer (Scapy-equivalent engine)
 * Converts raw LAN packet stream into structured flow-based features.
 * Performs passive OS fingerprinting, DHCP Hostname resolution, and MAC OUI tracking.
 */

import { FlowFeatures, ProtocolType, RawPacket, AttackType, DeviceInfo } from '../types';
import { lanDeviceManager } from './lanDeviceManager';

// Removed fake KNOWN_DEVICES registry

export function getDeviceFingerprint(ip: string): DeviceInfo {
  // Check user's actual LAN registry first
  const homeDevice = lanDeviceManager.getDeviceByIp(ip);
  if (homeDevice) {
    return { ...homeDevice, lastSeen: Date.now() };
  }

  // If not found, return an Unknown generic profile
  return {
    ipAddress: ip,
    macAddress: 'Unknown',
    vendor: 'Unknown',
    deviceName: 'Unknown Device',
    deviceType: 'Laptop / PC',
    operatingSystem: 'Unknown',
    dhcpHostname: 'Unknown',
    networkSegment: 'Network',
    ttlFingerprint: 64,
    lastSeen: Date.now()
  };
}

export class PacketCaptureEngine {
  private flowHistory: Map<string, RawPacket[]> = new Map();
  private windowSizeMs = 3000; // 3 second rolling window

  // Removed mock packet generator completely

  /**
   * Ingests a raw packet, maintains window history, and extracts structured flow features per IP.
   */
  public extractFlowFeatures(packet: RawPacket): FlowFeatures {
    const now = packet.timestamp;
    const ipKey = packet.sourceIp;

    if (!this.flowHistory.has(ipKey)) {
      this.flowHistory.set(ipKey, []);
    }

    const history = this.flowHistory.get(ipKey)!;
    history.push(packet);

    // Prune packets older than window size
    const cutoff = now - this.windowSizeMs;
    const windowPackets = history.filter(p => p.timestamp >= cutoff);
    this.flowHistory.set(ipKey, windowPackets);

    const totalPackets = windowPackets.length;
    const durationSeconds = Math.max(0.5, (now - windowPackets[0].timestamp) / 1000);
    const durationMs = Math.max(50, now - windowPackets[0].timestamp);

    const totalBytes = windowPackets.reduce((acc, p) => acc + p.packetSize, 0);
    const packetsPerSecond = Math.round((totalPackets / durationSeconds) * 10) / 10;
    const bytesPerSecond = Math.round(totalBytes / durationSeconds);

    const uniquePorts = new Set(windowPackets.map(p => p.destinationPort)).size;
    const avgPacketSize = Math.round(totalBytes / Math.max(1, totalPackets));

    // Calculate packet size variance / std dev
    const variance = windowPackets.reduce((acc, p) => acc + Math.pow(p.packetSize - avgPacketSize, 2), 0) / Math.max(1, totalPackets);
    const packetSizeStdDev = Math.round(Math.sqrt(variance) * 10) / 10;

    // Count failed connections (SYNs with no ACK, or RST flag occurrences)
    let synCount = 0;
    let ackCount = 0;
    let rstCount = 0;

    windowPackets.forEach(p => {
      if (p.tcpFlags?.syn) synCount++;
      if (p.tcpFlags?.ack) ackCount++;
      if (p.tcpFlags?.rst) rstCount++;
    });

    const failedConnectionsCount = rstCount + (synCount > ackCount ? synCount - ackCount : 0);
    const synToAckRatio = ackCount === 0 ? synCount : Math.round((synCount / ackCount) * 100) / 100;

    const distinctProtocolsCount = new Set(windowPackets.map(p => p.protocol)).size;

    // Entropy estimation (higher entropy = varied distribution, low entropy = repetitive flood)
    const entropy = Math.min(1.0, Math.max(0.1, (uniquePorts * 0.15) + (distinctProtocolsCount * 0.1)));

    return {
      flowId: `flow_${packet.sourceIp}_${packet.destinationIp}`,
      sourceIp: packet.sourceIp,
      destinationIp: packet.destinationIp,
      deviceInfo: packet.deviceInfo || getDeviceFingerprint(packet.sourceIp),
      windowStartTime: windowPackets[0].timestamp,
      windowEndTime: now,
      packetsPerSecond,
      bytesPerSecond,
      uniquePortsAccessed: uniquePorts,
      avgPacketSize,
      packetSizeStdDev,
      connectionDurationMs: durationMs,
      failedConnectionsCount,
      synToAckRatio,
      distinctProtocolsCount,
      flowEntropy: Math.round(entropy * 100) / 100
    };
  }

  public clearHistory(): void {
    this.flowHistory.clear();
  }
}

export const packetEngine = new PacketCaptureEngine();
