import React from 'react';
import {
  Activity,
  AlertCircle,
  ArrowRight,
  Cpu,
  Layers,
  Shield,
  TrendingUp,
} from 'lucide-react';
import {
  EntityId,
  RiskCalculationResult,
} from '../types/cyberpulse';
import {
  ENTITY_BASELINES,
  ScenarioDataset,
} from '../data/syntheticData';

interface EntityIdentityProps {
  selectedEntity: EntityId;
  onSelectEntity: (entity: EntityId) => void;
  scenario: ScenarioDataset;
  riskResult: RiskCalculationResult;
  onLaunchInvestigation: () => void;
}

export const EntityIdentity: React.FC<EntityIdentityProps> = ({
  selectedEntity,
  onSelectEntity,
  scenario,
  riskResult,
  onLaunchInvestigation,
}) => {
  const entityProfile = ENTITY_BASELINES[selectedEntity];
  const baseline = entityProfile.baseline;

  // Use scenario's currentBehavior if selectedEntity matches scenario.primaryEntity, otherwise derive from entity shortTerm
  const isScenarioPrimary = selectedEntity === scenario.primaryEntity;
  const current = isScenarioPrimary
    ? scenario.currentBehavior
    : baseline.shortTerm;

  const normalPorts = baseline.longTerm.uniquePorts;
  const currentPorts = current.uniquePorts;
  const portMult = Number((currentPorts / Math.max(1, normalPorts)).toFixed(1));

  const normalLogins = baseline.longTerm.failedLogins;
  const currentLogins = current.failedLogins;
  const loginMult =
    normalLogins === 0
      ? currentLogins > 0
        ? currentLogins
        : 1.0
      : Number((currentLogins / normalLogins).toFixed(1));

  const normalMB = baseline.longTerm.outboundTrafficMB;
  const currentMB = current.outboundTrafficMB;
  const mbMult = Number((currentMB / Math.max(1, normalMB)).toFixed(1));

  const normalDest = baseline.longTerm.uniqueDestinations;
  const currentDest = current.uniqueDestinations;
  const destMult = Number((currentDest / Math.max(1, normalDest)).toFixed(1));

  const entityMutationScore = isScenarioPrimary
    ? scenario.mutationScore
    : selectedEntity === 'PC-12'
    ? 88
    : selectedEntity === 'BACKUP-01'
    ? 80
    : selectedEntity === 'DATABASE-01'
    ? 78
    : 74;

  // Radar Chart 5 axes normalized (0..100)
  const radarAxes = [
    {
      label: 'Unique Ports',
      baselineNorm: Math.min(100, (normalPorts / 50) * 100 + 12),
      currentNorm: Math.min(100, (currentPorts / 50) * 100 + 12),
    },
    {
      label: 'Failed Logins',
      baselineNorm: Math.min(100, (normalLogins / 40) * 100 + 10),
      currentNorm: Math.min(100, (currentLogins / 40) * 100 + 10),
    },
    {
      label: 'Outbound Volume',
      baselineNorm: Math.min(100, (normalMB / 900) * 100 + 12),
      currentNorm: Math.min(100, (currentMB / 900) * 100 + 12),
    },
    {
      label: 'Destinations',
      baselineNorm: Math.min(100, (normalDest / 15) * 100 + 12),
      currentNorm: Math.min(100, (currentDest / 15) * 100 + 12),
    },
    {
      label: 'Connections',
      baselineNorm: Math.min(100, (baseline.longTerm.connections / 180) * 100 + 12),
      currentNorm: Math.min(100, (current.connections / 180) * 100 + 12),
    },
  ];

  const computeRadarPolygon = (key: 'baselineNorm' | 'currentNorm') => {
    const cx = 130;
    const cy = 130;
    const maxR = 90;
    return radarAxes
      .map((axis, i) => {
        const angle = (Math.PI * 2 * i) / radarAxes.length - Math.PI / 2;
        const r = (axis[key] / 100) * maxR;
        const x = cx + r * Math.cos(angle);
        const y = cy + r * Math.sin(angle);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  };

  return (
    <div className="space-y-6">
      {/* Header & Entity Selector */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="text-xs text-sky-400 font-medium">
            Entity-Specific Behavioral Profiling · 3-Layer Baseline Engine
          </div>
          <h1 className="text-2xl font-bold text-white mt-0.5">
            Behavioral Identity & Mutation Engine
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Every network entity maintains its own protected Behavioral DNA across Long-Term, Short-Term, and Peer-Group baselines.
          </p>
        </div>

        {/* Interactive Entity Selector Tabs */}
        <div className="flex flex-wrap items-center gap-1.5 bg-slate-900 p-1.5 rounded-lg border border-slate-800">
          {(Object.keys(ENTITY_BASELINES) as EntityId[]).map((id) => {
            const active = selectedEntity === id;
            return (
              <button
                key={id}
                onClick={() => onSelectEntity(id)}
                className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition-colors cursor-pointer whitespace-nowrap ${
                  active
                    ? 'bg-sky-500 text-slate-950'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800'
                }`}
              >
                {id}
              </button>
            );
          })}
        </div>
      </div>

      {/* Cold Start Warning Banner if PC-12 is selected */}
      {baseline.coldStartStatus === 'LEARNING' && (
        <div className="border border-amber-500/50 bg-amber-950/20 rounded-lg p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-amber-400 shrink-0" />
            <div>
              <div className="text-sm font-semibold text-amber-300 font-mono">
                Baseline Status: LEARNING · Confidence: LOW (Cold Start Mode)
              </div>
              <div className="text-xs text-slate-300 mt-0.5">
                {selectedEntity} has only 36 hours of observed telemetry. CYBERPULSE does not pretend a reliable long-term individual baseline exists; it relies more heavily on Layer 3 (Peer-Group Baseline) and Evidence Verification.
              </div>
            </div>
          </div>
          <span className="text-xs font-mono text-amber-400 shrink-0">
            Cold Start Safeguard Active
          </span>
        </div>
      )}

      {/* Side-by-Side: NORMAL DNA vs CURRENT BEHAVIOR + BEHAVIOR MUTATION SCORE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Normal DNA Column */}
        <div className="lg:col-span-4 border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="text-xs text-emerald-400 font-medium">
                  Protected Historical Identity
                </div>
                <h2 className="text-lg font-bold text-white font-mono mt-0.5">
                  {selectedEntity} NORMAL DNA
                </h2>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Status: {baseline.coldStartStatus}
              </span>
            </div>

            <dl className="divide-y divide-slate-800/80 text-sm mt-2">
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Average connections</dt>
                <dd className="font-mono font-semibold text-white tabular-nums">
                  {baseline.longTerm.connections} / hr
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Unique destinations</dt>
                <dd className="font-mono font-semibold text-white tabular-nums">
                  {baseline.longTerm.uniqueDestinations}
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Unique ports</dt>
                <dd className="font-mono font-semibold text-white tabular-nums">
                  {baseline.longTerm.uniquePorts}
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Failed logins</dt>
                <dd className="font-mono font-semibold text-white tabular-nums">
                  {baseline.longTerm.failedLogins}
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Outbound traffic</dt>
                <dd className="font-mono font-semibold text-white tabular-nums">
                  {baseline.longTerm.outboundTrafficMB} MB
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Typical active hours</dt>
                <dd className="font-mono font-semibold text-emerald-400 tabular-nums">
                  {baseline.longTerm.activeHours}
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Common peers</dt>
                <dd className="font-mono text-xs text-slate-200 text-right">
                  {baseline.longTerm.commonPeers.join(', ')}
                </dd>
              </div>
            </dl>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400">
            IP: <span className="font-mono text-slate-300">{entityProfile.ip}</span> ·{' '}
            {entityProfile.subnet}
          </div>
        </div>

        {/* Current Observed Behavior Column */}
        <div className="lg:col-span-4 border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="text-xs text-amber-400 font-medium">
                  Active Telemetry Window
                </div>
                <h2 className="text-lg font-bold text-white font-mono mt-0.5">
                  CURRENT BEHAVIOR
                </h2>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Confidence: {baseline.confidence}
              </span>
            </div>

            <dl className="divide-y divide-slate-800/80 text-sm mt-2">
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Connections</dt>
                <dd className="font-mono font-semibold text-white tabular-nums">
                  {current.connections} / hr
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Unique destinations</dt>
                <dd className="font-mono font-semibold text-amber-400 tabular-nums">
                  {current.uniqueDestinations} ({destMult}×)
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Unique ports</dt>
                <dd className="font-mono font-semibold text-red-400 tabular-nums">
                  {current.uniquePorts} ({portMult}×)
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Failed logins</dt>
                <dd className="font-mono font-semibold text-red-400 tabular-nums">
                  {current.failedLogins} ({loginMult}×)
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Outbound traffic</dt>
                <dd className="font-mono font-semibold text-red-400 tabular-nums">
                  {current.outboundTrafficMB} MB ({mbMult}×)
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">Active hour</dt>
                <dd className="font-mono font-semibold text-amber-400 tabular-nums">
                  {current.activeHours}
                </dd>
              </div>
              <div className="py-2.5 flex justify-between">
                <dt className="text-slate-400">New destination</dt>
                <dd
                  className={`font-mono font-bold ${
                    current.newDestination ? 'text-red-400' : 'text-emerald-400'
                  }`}
                >
                  {current.newDestination ? 'YES' : 'NO'}
                </dd>
              </div>
            </dl>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-400">Active Peers: {current.commonPeers.join(', ')}</span>
          </div>
        </div>

        {/* Radar Chart + Behavior Mutation Score Card */}
        <div className="lg:col-span-4 border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="text-xs text-sky-400 font-medium">
                  Signature Feature · Mutation Quantification
                </div>
                <h2 className="text-lg font-bold text-white mt-0.5">
                  Behavior Mutation Score
                </h2>
              </div>
              <div className="text-2xl font-bold font-mono text-amber-400 tabular-nums">
                {entityMutationScore}/100
              </div>
            </div>
            <div className="mt-2 flex items-center justify-between text-xs font-mono bg-slate-900/80 border border-slate-800 rounded px-3 py-1.5">
              <span className="text-slate-400">Authoritative Stage Risk:</span>
              <span
                className={`font-bold tabular-nums ${
                  riskResult.finalRisk > 70
                    ? 'text-red-400'
                    : riskResult.finalRisk > 30
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {riskResult.finalRisk}/100 ({riskResult.riskBand})
              </span>
            </div>

            {/* SVG Multi-Axis Behavioral DNA Radar */}
            <div className="flex flex-col items-center my-2">
              <svg width="260" height="250" viewBox="0 0 260 260" className="overflow-visible">
                {/* Concentric Pentagon Rings */}
                {[0.25, 0.5, 0.75, 1].map((scale, idx) => {
                  const pts = radarAxes
                    .map((_, i) => {
                      const angle = (Math.PI * 2 * i) / radarAxes.length - Math.PI / 2;
                      const r = 90 * scale;
                      return `${(130 + r * Math.cos(angle)).toFixed(1)},${(
                        130 +
                        r * Math.sin(angle)
                      ).toFixed(1)}`;
                    })
                    .join(' ');
                  return (
                    <polygon
                      key={idx}
                      points={pts}
                      fill="none"
                      stroke="#1E293B"
                      strokeWidth="1"
                    />
                  );
                })}

                {/* Axis Spokes & Labels */}
                {radarAxes.map((axis, i) => {
                  const angle = (Math.PI * 2 * i) / radarAxes.length - Math.PI / 2;
                  const x2 = 130 + 90 * Math.cos(angle);
                  const y2 = 130 + 90 * Math.sin(angle);
                  const lx = 130 + 112 * Math.cos(angle);
                  const ly = 130 + 112 * Math.sin(angle);
                  return (
                    <g key={axis.label}>
                      <line
                        x1="130"
                        y1="130"
                        x2={x2}
                        y2={y2}
                        stroke="#334155"
                        strokeWidth="1"
                      />
                      <text
                        x={lx}
                        y={ly}
                        textAnchor="middle"
                        dominantBaseline="middle"
                        className="fill-slate-400 text-[10px] font-mono"
                      >
                        {axis.label}
                      </text>
                    </g>
                  );
                })}

                {/* Baseline Polygon (Emerald) */}
                <polygon
                  points={computeRadarPolygon('baselineNorm')}
                  fill="rgba(16, 185, 129, 0.2)"
                  stroke="#10B981"
                  strokeWidth="2"
                />

                {/* Current Behavior Polygon (Red/Amber) */}
                <polygon
                  points={computeRadarPolygon('currentNorm')}
                  fill="rgba(239, 68, 68, 0.25)"
                  stroke="#EF4444"
                  strokeWidth="2"
                />
              </svg>

              <div className="flex items-center gap-6 text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-3 h-0.5 bg-emerald-400 inline-block" />
                  <span className="text-slate-300">Normal DNA Baseline</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-0.5 bg-red-400 inline-block" />
                  <span className="text-slate-300">Current Mutated State</span>
                </div>
              </div>
            </div>
          </div>

          <button
            onClick={onLaunchInvestigation}
            className="w-full mt-3 inline-flex items-center justify-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded transition-colors cursor-pointer"
          >
            <span>Open Full Investigation Workspace for {selectedEntity}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Visual Comparison: NORMAL ────── CURRENT (Horizontal Bars & Multipliers) */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 mb-4">
          <div>
            <h3 className="text-base font-semibold text-white">
              Baseline vs. Current Behavior Mutation Breakdown
            </h3>
            <p className="text-xs text-slate-400">
              Quantifies exact feature multipliers driving the {entityMutationScore}/100 Behavior Mutation Score
            </p>
          </div>
          <div className="text-xs font-mono text-slate-300">
            NORMAL ─────────────── CURRENT
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            {
              title: 'Unique Ports',
              normal: `${normalPorts} ports`,
              current: `${currentPorts} ports`,
              mult: `${portMult}×`,
              pct: Math.min(100, (currentPorts / 50) * 100),
            },
            {
              title: 'Failed Logins',
              normal: `${normalLogins} failure`,
              current: `${currentLogins} failures`,
              mult: `${loginMult}×`,
              pct: Math.min(100, (currentLogins / 35) * 100),
            },
            {
              title: 'Outbound Data',
              normal: `${normalMB} MB`,
              current: `${currentMB} MB`,
              mult: `${mbMult}×`,
              pct: Math.min(100, (currentMB / 850) * 100),
            },
            {
              title: 'Unique Destinations',
              normal: `${normalDest} peers`,
              current: `${currentDest} peers`,
              mult: `${destMult}×`,
              pct: Math.min(100, (currentDest / 14) * 100),
            },
          ].map((item) => (
            <div
              key={item.title}
              className="border border-slate-800 bg-slate-900/60 rounded-md p-4 space-y-2.5"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300">{item.title}</span>
                <span className="text-xs font-mono font-bold text-amber-400 tabular-nums">
                  Change: {item.mult}
                </span>
              </div>
              <div className="flex items-center justify-between text-xs font-mono tabular-nums">
                <span className="text-emerald-400">Normal: {item.normal}</span>
                <span className="text-slate-500">→</span>
                <span className="text-red-400 font-semibold">Current: {item.current}</span>
              </div>
              <div className="w-full h-2 bg-slate-800 rounded-sm overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-emerald-500 via-amber-500 to-red-500"
                  style={{ width: `${Math.max(item.pct, 8)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Three-Layer Baseline Engine + Behavioral Drift Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Three-Layer Baseline Engine */}
        <div className="lg:col-span-7 border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-sky-400" />
              <h3 className="text-base font-semibold text-white">
                Three-Layer Baseline Engine ({selectedEntity})
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Multi-Horizon Reference
            </span>
          </div>

          <div className="space-y-3">
            <div className="border border-slate-800 bg-slate-900/50 rounded-md p-3.5">
              <div className="flex items-center justify-between text-xs font-semibold text-emerald-400">
                <span>Layer 1 — Long-Term Baseline (30-Day Historical DNA)</span>
                <span className="font-mono tabular-nums">
                  {baseline.longTerm.uniqueDestinations} dests · {baseline.longTerm.uniquePorts} ports · {baseline.longTerm.outboundTrafficMB} MB
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">{baseline.longTerm.description}</p>
            </div>

            <div className="border border-slate-800 bg-slate-900/50 rounded-md p-3.5">
              <div className="flex items-center justify-between text-xs font-semibold text-sky-400">
                <span>Layer 2 — Short-Term Baseline (Recent 30-Minute Rolling Window)</span>
                <span className="font-mono tabular-nums">
                  {baseline.shortTerm.uniqueDestinations} dests · {baseline.shortTerm.uniquePorts} ports · {baseline.shortTerm.outboundTrafficMB} MB
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">{baseline.shortTerm.description}</p>
            </div>

            <div className="border border-slate-800 bg-slate-900/50 rounded-md p-3.5">
              <div className="flex items-center justify-between text-xs font-semibold text-amber-400">
                <span>Layer 3 — Peer-Group Baseline ({baseline.peerGroup.peerRole})</span>
                <span className="font-mono tabular-nums">
                  Peer Avg: {baseline.peerGroup.uniqueDestinations} dests · {baseline.peerGroup.outboundTrafficMB} MB
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">{baseline.peerGroup.description}</p>
            </div>
          </div>
        </div>

        {/* Behavioral Drift Over Time (Day 1 -> Day 5) */}
        <div className="lg:col-span-5 border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-amber-400" />
                <h3 className="text-base font-semibold text-white">
                  5-Day Behavioral Drift Tracker
                </h3>
              </div>
              <span className="text-xs font-mono text-amber-400 tabular-nums">
                Day 5 Drift: {scenario.driftSeries[scenario.driftSeries.length - 1].driftPct}%
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Behavioral drift indicates gradual deviation from the protected behavioral identity.
            </p>

            <div className="mt-4 space-y-3">
              {scenario.driftSeries.map((pt) => (
                <div key={pt.day} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono tabular-nums">
                    <span className="text-slate-300">{pt.day}</span>
                    <span
                      className={
                        pt.driftPct > 50
                          ? 'text-red-400 font-bold'
                          : pt.driftPct > 20
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }
                    >
                      {pt.driftPct}% Deviation
                    </span>
                  </div>
                  <div className="w-full h-2.5 bg-slate-800 rounded-sm overflow-hidden">
                    <div
                      className={`h-full ${
                        pt.driftPct > 50
                          ? 'bg-red-500'
                          : pt.driftPct > 20
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                      style={{ width: `${pt.driftPct}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400">
            Safe Baseline Learning Rule: <strong className="text-white">SUSPICIOUS</strong> and{' '}
            <strong className="text-white">MALICIOUS</strong> windows are blocked from updating Layer-1 DNA.
          </div>
        </div>
      </div>
    </div>
  );
};
