import React, { useState } from 'react';
import {
  ArrowRight,
  Filter,
  ShieldAlert,
  ShieldCheck,
  TrendingDown,
} from 'lucide-react';
import {
  EntityId,
  IncidentGroup,
  RiskCalculationResult,
  ScenarioId,
} from '../types/cyberpulse';
import {
  ABLATION_METRICS,
  ENTITY_BASELINES,
  INCIDENT_GROUPS,
  NOISE_SHIELD_STATS,
  SCENARIOS,
  ScenarioDataset,
} from '../data/syntheticData';
import {
  calculateDeterministicRisk,
  calculateEvidenceAgreement,
} from '../logic/riskEngine';

interface CommandCenterProps {
  scenario: ScenarioDataset;
  riskResult: RiskCalculationResult;
  evidenceAgreementPct: number;
  policyThreshold: number;
  unknownClusterCount: number;
  onInvestigateEntity: (entity: EntityId) => void;
  onNavigatePage: (
    page: 'command' | 'identity' | 'investigation' | 'governance'
  ) => void;
  onSelectScenario: (scenarioId: ScenarioId) => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({
  scenario,
  riskResult,
  evidenceAgreementPct,
  policyThreshold,
  unknownClusterCount,
  onInvestigateEntity,
  onNavigatePage,
  onSelectScenario,
}) => {
  const [showNoiseModal, setShowNoiseModal] = useState(false);
  const [selectedIncidentId, setSelectedIncidentId] =
    useState<string>('INC-2026-041');

  // Compute deterministic scores for other scenarios so nothing is loosely hardcoded
  const backupScenario = SCENARIOS['Backup Server False Positive'];
  const backupRisk = calculateDeterministicRisk({
    anomaly: backupScenario.anomalyScore,
    mutation: backupScenario.mutationScore,
    classifier: backupScenario.classifierScore,
    classifierCertainty: backupScenario.classifierCertainty,
    progression: backupScenario.progressionScore,
    evidence: calculateEvidenceAgreement(backupScenario.evidenceItems)
      .agreementPct,
    contextAdjustment: backupScenario.contextAdjustment,
    primaryClass: backupScenario.primaryClass,
  }).finalRisk;

  const unknownScenario = SCENARIOS['Unknown Attack'];
  const unknownRisk = calculateDeterministicRisk({
    anomaly: unknownScenario.anomalyScore,
    mutation: unknownScenario.mutationScore,
    classifier: unknownScenario.classifierScore,
    classifierCertainty: unknownScenario.classifierCertainty,
    progression: unknownScenario.progressionScore,
    evidence: calculateEvidenceAgreement(unknownScenario.evidenceItems)
      .agreementPct,
    contextAdjustment: unknownScenario.contextAdjustment,
    primaryClass: unknownScenario.primaryClass,
  }).finalRisk;

  const isCalmNormalState = scenario.id === 'Normal';

  const entityRanking = [
    {
      id: 'PC-07' as EntityId,
      role: 'Finance Workstation',
      risk:
        scenario.primaryEntity === 'PC-07'
          ? riskResult.finalRisk
          : isCalmNormalState
          ? 7
          : 94,
      threat:
        scenario.primaryEntity === 'PC-07'
          ? riskResult.classification
          : 'Data Exfiltration',
      mutation:
        scenario.primaryEntity === 'PC-07' ? riskResult.mutation : 96,
    },
    {
      id: 'DATABASE-01' as EntityId,
      role: 'Customer Ledger DB',
      risk: isCalmNormalState
        ? 9
        : scenario.id === 'Port Scan'
        ? 22
        : scenario.id === 'Brute Force'
        ? 38
        : 86,
      threat:
        isCalmNormalState ||
        scenario.id === 'Port Scan' ||
        scenario.id === 'Brute Force'
          ? 'Normal'
          : 'Lateral Movement',
      mutation: isCalmNormalState ? 8 : 78,
    },
    {
      id: 'SERVER-02' as EntityId,
      role: 'Middleware Gateway',
      risk: isCalmNormalState
        ? 8
        : scenario.id === 'Port Scan'
        ? 48
        : 78,
      threat: isCalmNormalState
        ? 'Normal'
        : scenario.id === 'Port Scan'
        ? 'Port Scan'
        : 'Brute Force',
      mutation: isCalmNormalState ? 7 : 74,
    },
    {
      id: 'PC-12' as EntityId,
      role: 'Contractor Laptop',
      risk:
        scenario.primaryEntity === 'PC-12'
          ? riskResult.finalRisk
          : isCalmNormalState
          ? 18
          : unknownRisk,
      threat: isCalmNormalState
        ? 'Normal'
        : 'Unknown Suspicious Behavior',
      mutation: isCalmNormalState ? 15 : 88,
    },
    {
      id: 'BACKUP-01' as EntityId,
      role: 'Nightly Vault Node',
      risk:
        scenario.primaryEntity === 'BACKUP-01'
          ? riskResult.finalRisk
          : isCalmNormalState
          ? 12
          : backupRisk,
      threat: 'Normal (Context Mitigated)',
      mutation: isCalmNormalState ? 10 : 80,
    },
  ].sort((a, b) => b.risk - a.risk);

  // Policy evaluation always agrees with active scenario riskResult.finalRisk
  const policyBreached = riskResult.finalRisk > policyThreshold;
  const breachCount = entityRanking.filter(
    (e) => e.risk > policyThreshold
  ).length;
  const avgRisk = Math.round(
    entityRanking.reduce((acc, e) => acc + e.risk, 0) / entityRanking.length
  );

  // Sync INC-2026-041 dynamically with current PC-07 scenario state
  const dynamicIncidents: (IncidentGroup & {
    sampleEvents: { time: string; desc: string; src: string; dst: string }[];
  })[] = INCIDENT_GROUPS.map((inc) => {
    if (inc.id === 'INC-2026-041') {
      const pc07Risk =
        scenario.primaryEntity === 'PC-07' ? riskResult.finalRisk : 94;
      const pc07Status =
        pc07Risk <= 30
          ? 'NORMAL'
          : pc07Risk <= 70
          ? 'SUSPICIOUS'
          : 'MALICIOUS';
      return {
        ...inc,
        riskScore: pc07Risk,
        status: pc07Status,
        evidenceAgreement:
          scenario.primaryEntity === 'PC-07' ? evidenceAgreementPct : 100,
        stages:
          scenario.primaryEntity === 'PC-07'
            ? Array.from(new Set(scenario.timeline.map((t) => t.stage)))
            : inc.stages,
        sampleEvents: SCENARIOS['Data Exfiltration'].timeline.map((t) => ({
          time: t.time,
          desc: `${t.stage}: ${t.title}`,
          src: t.rawTelemetry.source_ip,
          dst: `${t.rawTelemetry.dest_ip}:${t.rawTelemetry.dest_port}`,
        })),
      };
    }
    if (inc.id === 'INC-2026-042') {
      return {
        ...inc,
        riskScore:
          scenario.primaryEntity === 'PC-12'
            ? riskResult.finalRisk
            : unknownRisk,
        sampleEvents: SCENARIOS['Unknown Attack'].timeline.map((t) => ({
          time: t.time,
          desc: `${t.stage}: ${t.title}`,
          src: t.rawTelemetry.source_ip,
          dst: `${t.rawTelemetry.dest_ip}:${t.rawTelemetry.dest_port}`,
        })),
      };
    }
    if (inc.id === 'INC-2026-043') {
      return {
        ...inc,
        riskScore:
          scenario.primaryEntity === 'BACKUP-01'
            ? riskResult.finalRisk
            : backupRisk,
        sampleEvents: SCENARIOS['Backup Server False Positive'].timeline.map(
          (t) => ({
            time: t.time,
            desc: `${t.stage}: ${t.title}`,
            src: t.rawTelemetry.source_ip,
            dst: `${t.rawTelemetry.dest_ip}:${t.rawTelemetry.dest_port}`,
          })
        ),
      };
    }
    return {
      ...inc,
      sampleEvents: SCENARIOS['Normal'].timeline.map((t) => ({
        time: t.time,
        desc: `${t.stage}: ${t.title}`,
        src: t.rawTelemetry.source_ip,
        dst: `${t.rawTelemetry.dest_ip}:${t.rawTelemetry.dest_port}`,
      })),
    };
  });

  const activeIncident =
    dynamicIncidents.find((i) => i.id === selectedIncidentId) ||
    dynamicIncidents[0];

  // Dynamic 5-stage risk trajectory driven by actual riskEngine calculations
  const stageTrajectory = (
    [
      { id: 'Normal' as ScenarioId, time: '09:04', label: '0. Normal DNA' },
      { id: 'Port Scan' as ScenarioId, time: '10:42', label: '1. Port Scan (47p)' },
      { id: 'Brute Force' as ScenarioId, time: '10:43', label: '2. Brute Force (35x)' },
      { id: 'Lateral Movement' as ScenarioId, time: '10:45', label: '3. Lateral Pivot' },
      { id: 'Data Exfiltration' as ScenarioId, time: '10:48', label: '4. Exfiltration (850MB)' },
    ] as const
  ).map((st) => {
    const sc = SCENARIOS[st.id];
    const calc =
      scenario.id === st.id
        ? riskResult
        : calculateDeterministicRisk({
            anomaly: sc.anomalyScore,
            mutation: sc.mutationScore,
            classifier: sc.classifierScore,
            classifierCertainty: sc.classifierCertainty,
            progression: sc.progressionScore,
            evidence: calculateEvidenceAgreement(sc.evidenceItems).agreementPct,
            contextAdjustment: sc.contextAdjustment,
            primaryClass: sc.primaryClass,
          });
    return {
      ...st,
      score: calc.finalRisk,
      isCurrent: scenario.id === st.id,
    };
  });

  // Dynamic fleet risk band counts
  const normalCount = entityRanking.filter((e) => e.risk <= 30).length;
  const suspiciousCount = entityRanking.filter(
    (e) => e.risk > 30 && e.risk <= 70
  ).length;
  const maliciousCount = entityRanking.filter((e) => e.risk > 70).length;
  const normalPct = Math.round((normalCount / entityRanking.length) * 100);
  const suspiciousPct = Math.round(
    (suspiciousCount / entityRanking.length) * 100
  );
  const maliciousPct = 100 - normalPct - suspiciousPct;

  // Semicircle gauge angle (-90 deg to +90 deg)
  const gaugeRadius = 56;
  const gaugeCircumference = Math.PI * gaugeRadius;
  const gaugeProgress = (riskResult.finalRisk / 100) * gaugeCircumference;
  const gaugeColor =
    riskResult.finalRisk > 70
      ? '#EF4444'
      : riskResult.finalRisk > 30
      ? '#F59E0B'
      : '#10B981';

  return (
    <div className="space-y-6">
      {/* Top Executive Banner & Architecture Positioning */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1 max-w-3xl">
          <div className="text-xs text-sky-400 font-medium tracking-wide">
            Behavioral Identity · Attack Intent · Evidence Verification
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Don't just detect anomalies. Understand the attack.
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            CYBERPULSE is a distinctive cybersecurity investigation architecture combining behavioral identity, behavior mutation, attack progression, evidence verification, uncertainty-aware classification, behavioral memory, next-best investigation, and attack-path reasoning.
          </p>
        </div>

        {/* Policy Status Indicator */}
        <div className="flex items-center gap-4 border-t lg:border-t-0 lg:border-l border-slate-800 pt-4 lg:pt-0 lg:pl-6 shrink-0">
          <div>
            <div className="text-xs text-slate-400">
              Active Scenario Policy Evaluation (Max {policyThreshold})
            </div>
            <div className="flex items-center gap-2 mt-1">
              {policyBreached ? (
                <>
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                  <span className="text-base font-bold text-red-400 font-mono tabular-nums">
                    POLICY BREACH ({riskResult.finalRisk} &gt; {policyThreshold})
                  </span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <span className="text-base font-bold text-emerald-400 font-mono tabular-nums">
                    POLICY PASS ({riskResult.finalRisk} ≤ {policyThreshold})
                  </span>
                </>
              )}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              312 raw anomalies correlated into 4 actionable incidents
            </div>
          </div>
        </div>
      </div>

      {/* 6 KPI Stat Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="border border-slate-800 bg-[#111827] rounded-lg p-4">
          <div className="text-xs text-slate-400">Active Incidents</div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums mt-1">
            {isCalmNormalState ? 0 : 4}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            From 312 raw alerts · 98.7% reduction
          </div>
        </div>

        <div className="border border-slate-800 bg-[#111827] rounded-lg p-4">
          <div className="text-xs text-slate-400">Critical Alerts</div>
          <div
            className={`text-2xl font-bold font-mono tabular-nums mt-1 ${
              maliciousCount > 0 ? 'text-red-400' : 'text-emerald-400'
            }`}
          >
            {maliciousCount}
          </div>
          <div className="text-xs text-slate-500 mt-1">Band 71–100 · Malicious</div>
        </div>

        <div className="border border-slate-800 bg-[#111827] rounded-lg p-4">
          <div className="text-xs text-slate-400">Average Risk</div>
          <div
            className={`text-2xl font-bold font-mono tabular-nums mt-1 ${
              avgRisk > 70
                ? 'text-red-400'
                : avgRisk > 30
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}
          >
            {avgRisk}
            <span className="text-sm text-slate-500 font-normal">/100</span>
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Across 5 monitored entities
          </div>
        </div>

        <div className="border border-slate-800 bg-[#111827] rounded-lg p-4">
          <div className="text-xs text-slate-400">Unknown Behaviors</div>
          <div className="text-2xl font-bold text-sky-400 font-mono tabular-nums mt-1">
            19
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Grouped in {unknownClusterCount} active clusters
          </div>
        </div>

        <div className="border border-slate-800 bg-[#111827] rounded-lg p-4">
          <div className="text-xs text-slate-400">Entities Monitored</div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums mt-1">
            {Object.keys(ENTITY_BASELINES).length}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            4 Established · 1 Learning
          </div>
        </div>

        <div className="border border-slate-800 bg-[#111827] rounded-lg p-4">
          <div className="text-xs text-slate-400">Policy Breaches</div>
          <div
            className={`text-2xl font-bold font-mono tabular-nums mt-1 ${
              breachCount > 0 ? 'text-red-400' : 'text-emerald-400'
            }`}
          >
            {breachCount}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Threshold &gt; {policyThreshold} risk score
          </div>
        </div>
      </div>

      {/* Primary Focal Anchor: Main Incident Card with SVG Risk Gauge + Risk Trajectory */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Main Incident Spotlight Card */}
        <div
          className={`lg:col-span-5 border bg-[#111827] rounded-lg p-5 flex flex-col justify-between ${
            riskResult.finalRisk > 70
              ? 'border-red-500/40'
              : riskResult.finalRisk > 30
              ? 'border-amber-500/40'
              : 'border-emerald-500/40'
          }`}
        >
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="text-xs text-sky-400 font-medium">
                  Active Investigation Spotlight
                </div>
                <h2 className="text-xl font-bold text-white mt-0.5 font-mono">
                  {scenario.primaryEntity} ·{' '}
                  {ENTITY_BASELINES[scenario.primaryEntity].role}
                </h2>
              </div>

              {/* SVG Risk Gauge */}
              <div className="flex flex-col items-center">
                <svg width="136" height="76" viewBox="0 0 136 76">
                  <path
                    d="M 12 68 A 56 56 0 0 1 124 68"
                    fill="none"
                    stroke="#1E293B"
                    strokeWidth="10"
                    strokeLinecap="round"
                  />
                  <path
                    d="M 12 68 A 56 56 0 0 1 124 68"
                    fill="none"
                    stroke={gaugeColor}
                    strokeWidth="10"
                    strokeLinecap="round"
                    strokeDasharray={`${gaugeProgress} ${gaugeCircumference}`}
                  />
                  <text
                    x="68"
                    y="54"
                    textAnchor="middle"
                    className="fill-white text-xl font-mono font-bold"
                  >
                    {riskResult.finalRisk}/100
                  </text>
                  <text
                    x="68"
                    y="70"
                    textAnchor="middle"
                    className="fill-slate-400 text-[10px] font-mono"
                  >
                    {riskResult.riskBand}
                  </text>
                </svg>
              </div>
            </div>

            {/* Key Metrics Table inside Spotlight */}
            <div className="grid grid-cols-2 gap-y-3 gap-x-4 py-4 text-sm border-b border-slate-800">
              <div>
                <div className="text-xs text-slate-400">Threat Classification</div>
                <div className="font-semibold text-white mt-0.5">
                  {riskResult.classification}
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-400">Policy Status</div>
                <div
                  className={`font-mono font-semibold mt-0.5 ${
                    policyBreached ? 'text-red-400' : 'text-emerald-400'
                  }`}
                >
                  {policyBreached
                    ? `POLICY BREACH (>${policyThreshold})`
                    : `POLICY PASS (≤${policyThreshold})`}
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-400">Evidence Agreement</div>
                <div className="font-mono font-semibold text-sky-400 tabular-nums mt-0.5">
                  {riskResult.evidence}% Verified
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-400">Attack Progression</div>
                <div className="font-mono font-semibold text-white tabular-nums mt-0.5">
                  {riskResult.progression}% ({scenario.timeline.length} Events)
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-400">Behavior Mutation</div>
                <div className="font-mono font-semibold text-amber-400 tabular-nums mt-0.5">
                  {riskResult.mutation}/100
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-400">Historical Memory Match</div>
                <div className="font-mono font-semibold text-slate-200 tabular-nums mt-0.5">
                  {scenario.historicalMemory.similarityPct}% (
                  {scenario.historicalMemory.isNovel
                    ? 'Novel'
                    : scenario.historicalMemory.incidentId.split(' ')[0]}
                  )
                </div>
              </div>
            </div>

            <div className="py-3 text-xs text-slate-300 space-y-1">
              <div className="font-medium text-slate-400">
                Concrete Behavioral Delta ({scenario.primaryEntity}):
              </div>
              <p className="leading-relaxed font-mono text-[11px]">
                Ports: 3 → {scenario.currentBehavior.uniquePorts} · Failed logins:
                1 → {scenario.currentBehavior.failedLogins} · Peers: 3 →{' '}
                {scenario.currentBehavior.uniqueDestinations} · Outbound: 12 MB →{' '}
                {scenario.currentBehavior.outboundTrafficMB} MB
              </p>
            </div>
          </div>

          <div className="pt-3 flex flex-wrap items-center gap-3">
            <button
              onClick={() => onInvestigateEntity(scenario.primaryEntity)}
              className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-sm rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <span>Investigate {scenario.primaryEntity}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => onNavigatePage('identity')}
              className="px-4 py-2.5 border border-slate-700 hover:border-slate-500 text-slate-200 text-sm font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              Inspect Behavioral DNA
            </button>
          </div>
        </div>

        {/* Right 7 Columns: Interactive 5-Stage Attack Trajectory & Risk + Threat Category Distributions */}
        <div className="lg:col-span-7 grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Interactive Risk Trajectory Over Attack Stages */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white">
                  1. Attack Progression Risk Trajectory
                </h3>
                <span className="text-xs font-mono text-slate-400 tabular-nums">
                  Threshold: {policyThreshold}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Click any stage below to step through the evolving PC-07 attack sequence
              </p>

              {/* Interactive Stage Bars */}
              <div className="mt-4 space-y-2.5">
                {stageTrajectory.map((pt) => {
                  const isBreach = pt.score > policyThreshold;
                  return (
                    <button
                      key={pt.id}
                      onClick={() => onSelectScenario(pt.id)}
                      className={`w-full text-left p-2 rounded border transition-colors cursor-pointer ${
                        pt.isCurrent
                          ? 'border-sky-400 bg-slate-800/80'
                          : 'border-slate-800/80 bg-slate-900/40 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono text-slate-300 tabular-nums">
                          {pt.time} ·{' '}
                          <strong className="text-white">{pt.label}</strong>
                        </span>
                        <span
                          className={`font-mono font-bold tabular-nums ${
                            isBreach
                              ? 'text-red-400'
                              : pt.score > 30
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {pt.score}/100
                        </span>
                      </div>
                      <div className="w-full h-2 bg-slate-800 rounded-sm overflow-hidden mt-1.5">
                        <div
                          className={`h-full transition-all duration-200 ${
                            isBreach
                              ? 'bg-red-500'
                              : pt.score > 30
                              ? 'bg-amber-500'
                              : 'bg-emerald-500'
                          }`}
                          style={{ width: `${pt.score}%` }}
                        />
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
              <span>0–30 Normal · 31–70 Suspicious · 71–100 Malicious</span>
              <span className="font-mono text-sky-400">Click stage to replay</span>
            </div>
          </div>

          {/* Threat Category & Risk Band Distribution */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between">
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-white">
                  2. Threat Category & Fleet Risk Distribution
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Live fleet risk bands & Random Forest ensemble probabilities
                </p>
              </div>

              {/* Risk Band Distribution Bar */}
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs text-slate-300 font-mono tabular-nums">
                  <span className="text-emerald-400">Normal ({normalPct}%)</span>
                  <span className="text-amber-400">
                    Suspicious ({suspiciousPct}%)
                  </span>
                  <span className="text-red-400">Malicious ({maliciousPct}%)</span>
                </div>
                <div className="w-full h-3 bg-slate-800 rounded-sm overflow-hidden flex">
                  <div
                    className="bg-emerald-500 h-full transition-all"
                    style={{ width: `${normalPct}%` }}
                  />
                  <div
                    className="bg-amber-500 h-full transition-all"
                    style={{ width: `${suspiciousPct}%` }}
                  />
                  <div
                    className="bg-red-500 h-full transition-all"
                    style={{ width: `${maliciousPct}%` }}
                  />
                </div>
              </div>

              {/* Threat Class Distribution */}
              <div className="space-y-2.5 pt-2">
                {scenario.classProbabilities.map((item) => (
                  <div key={item.category} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-300">{item.category}</span>
                      <span className="font-mono text-slate-200 tabular-nums">
                        {item.pct}%
                      </span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-sm overflow-hidden">
                      <div
                        className="h-full bg-sky-400"
                        style={{ width: `${Math.max(item.pct, 3)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
              <span>Random Forest — Prototype Simulation</span>
              <span className="font-mono text-slate-300 tabular-nums">
                Certainty: {scenario.classifierCertainty}%
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Second Row: Top Risky Entities Table + Alert Compression (312 -> 4 Incidents) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Top Risky Entities */}
        <div className="lg:col-span-5 border border-slate-800 bg-[#111827] rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">
                3. Monitored Entities Ranked by Risk
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Click any entity to inspect its Behavioral DNA or launch investigation
              </p>
            </div>
            <span className="text-xs text-slate-400 font-mono">
              5 Active Endpoints
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400">
                  <th className="py-2.5 pr-3 font-medium">Entity</th>
                  <th className="py-2.5 px-2 font-medium">Classification</th>
                  <th className="py-2.5 px-2 font-medium text-right">Mutation</th>
                  <th className="py-2.5 px-2 font-medium text-right">Risk</th>
                  <th className="py-2.5 pl-2 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {entityRanking.map((ent) => {
                  const isMalicious = ent.risk > 70;
                  const isSuspicious = ent.risk > 30 && ent.risk <= 70;
                  return (
                    <tr
                      key={ent.id}
                      className="hover:bg-slate-800/40 transition-colors"
                    >
                      <td className="py-2.5 pr-3">
                        <div className="font-mono font-semibold text-white">
                          {ent.id}
                        </div>
                        <div className="text-xs text-slate-400">{ent.role}</div>
                      </td>
                      <td className="py-2.5 px-2 text-slate-300 text-xs">
                        {ent.threat}
                      </td>
                      <td className="py-2.5 px-2 text-right font-mono tabular-nums text-slate-300">
                        {ent.mutation}/100
                      </td>
                      <td className="py-2.5 px-2 text-right font-mono font-bold tabular-nums">
                        <span
                          className={
                            isMalicious
                              ? 'text-red-400'
                              : isSuspicious
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }
                        >
                          {ent.risk}/100
                        </span>
                      </td>
                      <td className="py-2.5 pl-2 text-right">
                        <button
                          onClick={() => onInvestigateEntity(ent.id)}
                          className="text-xs text-sky-400 hover:text-sky-300 font-medium cursor-pointer whitespace-nowrap"
                        >
                          Investigate →
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Incident Grouping & Alert Compression (312 Raw Alerts -> 4 Incidents) with Expandable Events */}
        <div className="lg:col-span-7 border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-white">
                  4. Behavior Correlation & Incident Grouping
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Click any correlated incident below to inspect its underlying raw alerts & telemetry sequence
                </p>
              </div>
              <div className="text-right font-mono text-xs text-sky-400 tabular-nums">
                312 RAW ALERTS → 4 INCIDENTS
              </div>
            </div>

            {/* Visual Compression Funnel Bar */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-md p-3 mb-4 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div>
                <span className="text-slate-400">Raw Telemetry Anomalies:</span>{' '}
                <span className="font-mono font-bold text-white tabular-nums">
                  312
                </span>
              </div>
              <span className="text-slate-500">↓</span>
              <div>
                <span className="text-slate-400">
                  Correlation / Temporal / Entity Grouping:
                </span>{' '}
                <span className="font-mono font-bold text-sky-400 tabular-nums">
                  98.7% Reduction
                </span>
              </div>
              <span className="text-slate-500">↓</span>
              <div>
                <span className="text-slate-400">Actionable Incidents:</span>{' '}
                <span className="font-mono font-bold text-emerald-400 tabular-nums">
                  4
                </span>
              </div>
            </div>

            {/* 4 Correlated Incidents List */}
            <div className="space-y-2">
              {dynamicIncidents.map((inc) => {
                const isSelected = activeIncident.id === inc.id;
                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncidentId(inc.id)}
                    className={`p-3 rounded-md border transition-colors cursor-pointer ${
                      isSelected
                        ? 'border-sky-500/60 bg-slate-800/70'
                        : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs font-mono text-slate-400">
                        {inc.id} ·{' '}
                        <strong className="text-slate-200">
                          {inc.rawAlertCount} raw alerts correlated
                        </strong>{' '}
                        · Entities: {inc.entities.join(', ')}
                      </div>
                      <div
                        className={`text-xs font-mono font-bold tabular-nums ${
                          inc.riskScore > 70
                            ? 'text-red-400'
                            : inc.riskScore > 30
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        Risk {inc.riskScore}/100 ({inc.status})
                      </div>
                    </div>
                    <div className="text-sm font-medium text-white mt-1">
                      {inc.title}
                    </div>
                    <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
                      <span>Stages: {inc.stages.join(' → ')}</span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (inc.id === 'INC-2026-042') {
                            onSelectScenario('Unknown Attack');
                          } else if (inc.id === 'INC-2026-043') {
                            onSelectScenario('Backup Server False Positive');
                          } else if (inc.id === 'INC-2026-044') {
                            onSelectScenario('Normal');
                          } else {
                            onSelectScenario('Data Exfiltration');
                          }
                          onInvestigateEntity(inc.primaryEntity);
                        }}
                        className="text-sky-400 hover:underline font-medium cursor-pointer"
                      >
                        Open in Investigation →
                      </button>
                    </div>

                    {/* Expanded Correlated Alert Stream for the selected incident */}
                    {isSelected && (
                      <div className="mt-3 pt-2.5 border-t border-slate-700/80 space-y-1.5 text-xs">
                        <div className="font-mono text-[11px] text-sky-400">
                          Correlated Event Sequence inside {inc.id} ({inc.rawAlertCount} raw alerts grouped):
                        </div>
                        {inc.sampleEvents.map((ev, i) => (
                          <div
                            key={i}
                            className="flex flex-wrap items-center justify-between gap-2 bg-slate-950/70 px-2.5 py-1.5 rounded border border-slate-800 font-mono text-[11px]"
                          >
                            <span className="text-slate-300">
                              [{ev.time}] {ev.desc}
                            </span>
                            <span className="text-slate-500">
                              {ev.src} → {ev.dst}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Third Row: Data Quality / Noise Shield Monitor + Synthetic Prototype Ablation Evaluation */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Noise Shield & Data Quality Monitor */}
        <div className="lg:col-span-5 border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-sky-400" />
                <h3 className="text-sm font-semibold text-white">
                  5. Noise Shield & Data Quality Monitor
                </h3>
              </div>
              <button
                onClick={() => setShowNoiseModal(!showNoiseModal)}
                className="text-xs text-sky-400 hover:text-sky-300 font-medium cursor-pointer"
              >
                {showNoiseModal ? 'Hide Breakdown' : 'Inspect Filtered Records'}
              </button>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Gracefully filters routine broadcast noise (DHCP, ARP, multicast, DNS) and quarantines malformed packets before feature extraction.
            </p>

            <div className="grid grid-cols-4 gap-2 mt-4 text-center">
              <div className="border border-slate-800 bg-slate-900/60 p-2.5 rounded">
                <div className="text-xs text-slate-400">Received</div>
                <div className="text-lg font-bold text-white font-mono tabular-nums mt-0.5">
                  {NOISE_SHIELD_STATS.received}
                </div>
              </div>
              <div className="border border-slate-800 bg-slate-900/60 p-2.5 rounded">
                <div className="text-xs text-slate-400">Valid</div>
                <div className="text-lg font-bold text-emerald-400 font-mono tabular-nums mt-0.5">
                  {NOISE_SHIELD_STATS.valid}
                </div>
              </div>
              <div className="border border-slate-800 bg-slate-900/60 p-2.5 rounded">
                <div className="text-xs text-slate-400">Filtered Noise</div>
                <div className="text-lg font-bold text-sky-400 font-mono tabular-nums mt-0.5">
                  {NOISE_SHIELD_STATS.filteredNoise}
                </div>
              </div>
              <div className="border border-slate-800 bg-slate-900/60 p-2.5 rounded">
                <div className="text-xs text-slate-400">Malformed</div>
                <div className="text-lg font-bold text-amber-400 font-mono tabular-nums mt-0.5">
                  {NOISE_SHIELD_STATS.malformed}
                </div>
              </div>
            </div>

            {showNoiseModal && (
              <div className="mt-4 pt-3 border-t border-slate-800 space-y-2 text-xs">
                <div className="font-semibold text-slate-300">
                  Suppressed Noise (28 records):
                </div>
                {NOISE_SHIELD_STATS.noiseBreakdown.map((n, i) => (
                  <div key={i} className="flex justify-between text-slate-400">
                    <span>{n.type}</span>
                    <span className="font-mono text-slate-200 tabular-nums">
                      {n.count} pkts
                    </span>
                  </div>
                ))}
                <div className="font-semibold text-amber-400 pt-2">
                  Quarantined Malformed Input (8 records — Zero Crashes):
                </div>
                {NOISE_SHIELD_STATS.malformedBreakdown.map((m, i) => (
                  <div key={i} className="flex justify-between text-slate-400">
                    <span>{m.type}</span>
                    <span className="font-mono text-amber-300 tabular-nums">
                      {m.count} records
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs text-slate-400 flex items-center justify-between">
            <span>Schema Normalizer: Active</span>
            <span className="text-emerald-400 font-mono">
              0 Parser Exceptions
            </span>
          </div>
        </div>

        {/* Ablation / Proof Section */}
        <div className="lg:col-span-7 border border-slate-800 bg-[#111827] rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <TrendingDown className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">
                6. Architecture Ablation Evaluation — False Positive Reduction
              </h3>
            </div>
            <span className="text-xs font-mono text-amber-400">
              Synthetic Prototype Evaluation
            </span>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Demonstrates why each layer of the CYBERPULSE architecture exists by measuring false-positive rate as behavioral identity, context, and progression are added.
          </p>

          <div className="space-y-2.5">
            {ABLATION_METRICS.map((row, index) => (
              <div key={index} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-slate-200">{row.config}</span>
                  <span className="font-mono tabular-nums text-slate-300">
                    False Positives:{' '}
                    <strong
                      className={
                        row.falsePositives <= 5
                          ? 'text-emerald-400'
                          : row.falsePositives <= 10
                          ? 'text-sky-400'
                          : 'text-amber-400'
                      }
                    >
                      {row.falsePositives}%
                    </strong>{' '}
                    · Precision: {row.precision}%
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-sm overflow-hidden">
                  <div
                    className={`h-full ${
                      row.falsePositives <= 5
                        ? 'bg-emerald-500'
                        : row.falsePositives <= 10
                        ? 'bg-sky-500'
                        : 'bg-amber-500'
                    }`}
                    style={{ width: `${row.falsePositives * 4}%` }}
                  />
                </div>
                <div className="text-[11px] text-slate-500">{row.note}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
