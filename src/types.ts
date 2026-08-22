/**
 * Core Data Architecture & Database Schema
 * Project: Explainable RL-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)
 * Institution: VTU - JSS Academy of Technical Education
 */

export type ProtocolType = 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'SSH' | 'DNS';

export type AttackType = 
  | 'BENIGN'
  | 'DOS_SYN_FLOOD'
  | 'PORT_SCAN'
  | 'SSH_BRUTE_FORCE'
  | 'ICMP_FLOOD'
  | 'MALWARE_C2_PROBE';

export type ActionType = 'ALLOW' | 'ALERT' | 'BLOCK';

export type RiskLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export interface DeviceInfo {
  ipAddress: string;
  macAddress: string;
  vendor: string; // e.g. Apple, Samsung, Google, Intel
  deviceName: string; // e.g. "iPhone 15 Pro", "Galaxy S24 Ultra", "MacBook Pro M2"
  deviceType: 'Smart Phone' | 'Laptop / PC' | 'Server / Gateway' | 'IoT Device' | 'Tablet';
  operatingSystem: string; // e.g. "iOS 17.5", "Android 14", "macOS Sonoma", "Windows 11"
  dhcpHostname: string; // e.g. "iPhone-15-Pro.lan"
  networkSegment: string; // e.g. "Mobile Wi-Fi Subnet (VLAN 20)"
  ttlFingerprint: number; // e.g. 64 (Linux/Android/iOS) or 128 (Windows)
  lastSeen: number;
  isMyDevice?: boolean;
  isCustomHomeDevice?: boolean;
  rssiSignalDbm?: number;
}

export interface RawPacket {
  id: string;
  timestamp: number;
  sourceIp: string;
  destinationIp: string;
  protocol: ProtocolType;
  sourcePort: number;
  destinationPort: number;
  packetSize: number; // bytes
  deviceInfo?: DeviceInfo;
  tcpFlags?: {
    syn: boolean;
    ack: boolean;
    fin: boolean;
    rst: boolean;
    psh: boolean;
  };
  payloadSummary?: string;
  simulatedLabel?: AttackType;
}

export interface FlowFeatures {
  flowId: string;
  sourceIp: string;
  destinationIp: string;
  deviceInfo?: DeviceInfo;
  windowStartTime: number;
  windowEndTime: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  uniquePortsAccessed: number;
  avgPacketSize: number;
  packetSizeStdDev: number;
  connectionDurationMs: number;
  failedConnectionsCount: number; // Failed SYN or RST without ACK
  synToAckRatio: number;
  distinctProtocolsCount: number;
  flowEntropy: number;
}

export interface MLPrediction {
  modelName: 'Random Forest Classifier';
  attackProbability: number; // 0.0 to 1.0
  predictedClass: AttackType;
  classProbabilities: Record<AttackType, number>;
  featureImportances: Record<string, number>;
  inferenceTimeMs: number;
}

export interface DLPrediction {
  modelName: 'LSTM Temporal Sequence Model';
  temporalAnomalyScore: number; // 0.0 to 1.0
  sequenceLength: number;
  hiddenStateNorm: number;
  abnormalPatternDetected: boolean;
  temporalTrend: 'STABLE' | 'ESCALATING' | 'BURSTY' | 'DORMANT';
  inferenceTimeMs: number;
}

export interface UnifiedRiskScore {
  finalScore: number; // 0.0 to 1.0 (e.g. 0.90)
  level: RiskLevel;
  mlContribution: number; // e.g. 0.85
  dlContribution: number; // e.g. 0.95
  weights: {
    mlWeight: number; // default 0.50
    dlWeight: number; // default 0.50
    heuristicBoost: number;
  };
  computedAt: number;
}

export interface ShapValue {
  featureName: string;
  displayName: string;
  actualValue: number | string;
  shapValue: number; // Positive = pushes toward Attack, Negative = pushes toward Normal
  baselineValue: number;
  unit: string;
  impactSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface XAIExplanation {
  baseValue: number; // Expected baseline model output
  predictedValue: number;
  shapValues: ShapValue[];
  topContributors: string[];
  summaryNarrative: string; // Clear human-readable reason
  confidence: number;
}

export interface DQNState {
  riskScore: number;
  topShapImpact: number;
  flowVelocity: number; // normalized pps
  historicalIncidentCount: number;
  currentIpStatus: number; // 0: Normal, 1: Monitored, 2: Blocked
}

export interface DQNDecision {
  action: ActionType;
  actionCode: number; // 0: Allow, 1: Alert, 2: Block
  qValues: {
    allow: number;
    alert: number;
    block: number;
  };
  explorationRate: number; // Epsilon
  rewardExpected: number;
  decisionReason: string;
  autonomousConfidence: number;
}

export interface RealLSTMResult {
  status: string;
  anomaly_score: number;
}

export interface RealSHAPResult {
  features: {
    feature: string;
    shap_value: number;
    importance: number;
  }[];
  top_features: string[];
}

export interface RealDQNResult {
  action: ActionType;
  q_values: {
    ALLOW: number;
    ALERT: number;
    BLOCK: number;
  };
}

export interface RealPredictionResponse {
  status: string;
  flow_id: string;
  prediction: AttackType;
  probabilities: number[];
  lstm?: RealLSTMResult;
  risk_score: number;
  shap?: RealSHAPResult;
  dqn?: RealDQNResult;
}

export interface CombinedSecurityEvent {
  type: string;
  flow: {
    source_ip: string;
    destination_ip: string;
    source_port: number;
    destination_port: number;
    protocol: string;
  };
  features: {
    flow_duration_ms: number;
    flow_packets_per_s: number;
    flow_bytes_per_s: number;
    packet_length_mean: number;
    packet_length_std: number;
    syn_count: number;
    ack_count: number;
    rst_count: number;
    fin_count: number;
    syn_ack_ratio: number;
  };
  prediction: RealPredictionResponse;
}

export interface ProcessedSecurityEvent {
  id: string;
  timestamp: number;
  sourceIp: string;
  destinationIp: string;
  protocol: ProtocolType;
  attackType: AttackType;
  rawPacket?: RawPacket;
  flowFeatures?: FlowFeatures; // Legacy frontend features
  mlResult?: MLPrediction; // Legacy
  dlResult?: DLPrediction; // Legacy
  riskScore?: UnifiedRiskScore; // Legacy
  xaiExplanation?: XAIExplanation; // Legacy
  rlDecision?: DQNDecision; // Legacy
  realPrediction?: RealPredictionResponse; // Real Python API
  realFeatures?: CombinedSecurityEvent['features']; // Real features
  actionExecuted: ActionType;
  isBlocked: boolean;
  alertDispatched: boolean;
  alertChannels?: ('EMAIL' | 'SMS' | 'WEBHOOK' | 'SOC_DASHBOARD')[];
}

export interface FirewallRule {
  id: string;
  ipAddress: string;
  reason: string;
  blockedAt: number;
  expiresAt: number | null; // null = permanent until manual release
  ruleType: 'AUTOMATIC_RL' | 'MANUAL_ADMIN';
  packetsDropped: number;
  bytesPrevented: number;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
}

export interface SystemMetrics {
  totalPacketsProcessed: number;
  totalAttacksDetected: number;
  totalIpsBlocked: number;
  totalAlertsDispatched: number;
  currentTrafficRatePps: number;
  currentBandwidthKbps: number;
  averageInferenceLatencyMs: number;
  modelAccuracy: {
    randomForestAccuracy: number;
    lstmAccuracy: number;
    rlDecisionEfficiency: number;
    falsePositiveRate: number;
  };
  rlStats: {
    totalEpisodes: number | string;
    cumulativeReward: number | string;
    epsilon: number | string;
    averageQValue: number | string;
  };
}

export interface TimeSeriesPoint {
  time: string;
  timestamp: number;
  packetsPerSec: number;
  riskScore: number;
  attacksCount: number;
  blockedCount: number;
  normalCount: number;
}
