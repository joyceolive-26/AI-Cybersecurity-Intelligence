export type EntityId = 'PC-07' | 'PC-12' | 'SERVER-02' | 'BACKUP-01' | 'DATABASE-01';

export type ThreatCategory =
  | 'Normal'
  | 'Port Scan'
  | 'Brute Force'
  | 'Lateral Movement'
  | 'Data Exfiltration'
  | 'Unknown Suspicious Behavior';

export type RiskBand = 'NORMAL' | 'SUSPICIOUS' | 'MALICIOUS';

export type ScenarioId =
  | 'Data Exfiltration'
  | 'Normal'
  | 'Port Scan'
  | 'Brute Force'
  | 'Lateral Movement'
  | 'Unknown Attack'
  | 'Backup Server False Positive'
  | 'Slow Baseline Poisoning';

export type EvidenceState = 'TRUE' | 'FALSE' | 'UNKNOWN';

export interface BehavioralFeatures {
  connections: number;
  uniqueDestinations: number;
  uniquePorts: number;
  failedLogins: number;
  outboundTrafficMB: number;
  activeHours: string;
  commonPeers: string[];
  newDestination: boolean;
}

export interface ThreeLayerBaseline {
  longTerm: BehavioralFeatures & { description: string };
  shortTerm: BehavioralFeatures & { description: string };
  peerGroup: BehavioralFeatures & { description: string; peerRole: string };
  coldStartStatus: 'ESTABLISHED' | 'LEARNING';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface MutationMetric {
  feature: string;
  normalValue: string | number;
  currentValue: string | number;
  multiplier: number;
  unit: string;
}

export interface DriftPoint {
  day: string;
  driftPct: number;
  naiveBaselinePct: number;
  protectedBaselinePct: number;
}

export interface TreeVote {
  treeId: string;
  vote: ThreatCategory | 'Unknown';
}

export interface EvidenceItem {
  id: string;
  label: string;
  state: EvidenceState;
  supportsThreat: boolean; // Whether TRUE supports threat or FALSE mitigates threat
  explanation: string;
  investigationType?: 'Destination Trust' | 'Historical Contact' | 'Backup Activity' | 'User Authentication' | 'Peer Relationship';
}

export interface TimelineEvent {
  id: string;
  time: string;
  stage: ThreatCategory;
  title: string;
  mitreTactic: string;
  rawTelemetry: {
    timestamp: string;
    source_ip: string;
    dest_ip: string;
    src_port: number;
    dest_port: number;
    protocol: string;
    bytes: string;
    packets: number;
    auth_status: string;
    event_type: string;
  };
  featureValues: {
    destination_count: number;
    port_count: number;
    failed_login_count: number;
    outbound_bytes: string;
    connection_duration: string;
    peer_relationship: string;
  };
  evidenceNote: string;
  riskContribution: number;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: 'workstation' | 'server' | 'database' | 'external';
  risk: number;
  stage: string;
  x: number;
  y: number;
}

export interface AttackGraphEdge {
  from: string;
  to: string;
  label: string;
  stage: string;
  active: boolean;
}

export interface HistoricalPatternMatch {
  incidentId: string;
  title: string;
  date: string;
  stages: string[];
  similarityPct: number;
  isNovel: boolean;
  notes: string;
}

export interface InvestigationAction {
  id: 'Destination Trust' | 'Historical Contact' | 'Backup Activity' | 'User Authentication' | 'Peer Relationship';
  label: string;
  question: string;
  reason: string;
  potentialImpactPts: number;
  resolvedOutcome?: 'TRUSTED_SAFE' | 'CONFIRMED_THREAT';
}

export interface CounterfactualItem {
  id: string;
  label: string;
  changedFactor: string;
  currentStateText: string;
  counterfactualStateText: string;
  description: string;
  modifiedInputs: {
    anomaly?: number;
    mutation?: number;
    classifier?: number;
    progression?: number;
    evidence?: number;
    contextAdjustment?: number;
  };
}

export interface AttackPathPrediction {
  currentEntity: string;
  nextTarget: string;
  secondaryTarget: string;
  finalAsset: string;
  confidencePct: number;
  reasons: string[];
  nodes: { id: string; label: string; role: string; probability: number }[];
}

export interface UnknownCluster {
  id: string;
  name: string;
  entityCount: number;
  patternSummary: string;
  avgAnomaly: number;
  avgMutation: number;
  sampleEntities: string[];
  analystLabel: ThreatCategory | 'Benign' | 'Keep Unknown';
  promoted: boolean;
}

export interface AuditRecord {
  alert_id: string;
  timestamp: string;
  entity: string;
  source_ip: string;
  dest_ip: string;
  classification: ThreatCategory;
  risk_score: number;
  mutation_score: number;
  attack_fingerprint: string;
  evidence: string;
  decision: RiskBand;
  status: string;
  previous_hash: string;
  current_hash: string;
}

export interface IncidentGroup {
  id: string;
  title: string;
  rawAlertCount: number;
  entities: EntityId[];
  timelineSpan: string;
  stages: string[];
  evidenceAgreement: number;
  riskScore: number;
  status: RiskBand;
  primaryEntity: EntityId;
}

export interface RiskCalculationResult {
  anomaly: number;
  mutation: number;
  classifier: number;
  progression: number;
  evidence: number;
  anomalyWeighted: number;
  mutationWeighted: number;
  classifierWeighted: number;
  progressionWeighted: number;
  evidenceWeighted: number;
  baseRisk: number;
  contextAdjustment: number;
  unknownGateTriggered: boolean;
  finalRisk: number;
  riskBand: RiskBand;
  classification: ThreatCategory;
}
