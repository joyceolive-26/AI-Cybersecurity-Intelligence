import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  EvidenceItem,
  InvestigationAction,
  RiskCalculationResult,
  TimelineEvent,
} from '../types/cyberpulse';
import { ENTITY_BASELINES, ScenarioDataset } from '../data/syntheticData';
import { calculateDeterministicRisk } from '../logic/riskEngine';

interface InvestigationProps {
  scenario: ScenarioDataset;
  riskResult: RiskCalculationResult;
  policyThreshold: number;
  evidenceItems: EvidenceItem[];
  evidenceStats: {
    supportingCount: number;
    evaluatedCount: number;
    unknownCount: number;
    contradictingCount: number;
    agreementPct: number;
  };
  investigatedMap: Record<string, 'TRUSTED_SAFE' | 'CONFIRMED_THREAT'>;
  onRunInvestigationAction: (
    actionId: InvestigationAction['id'],
    outcome: 'TRUSTED_SAFE' | 'CONFIRMED_THREAT'
  ) => void;
  onResetInvestigation: () => void;
  activeCounterfactualId: string | null;
  onSelectCounterfactual: (cfId: string | null) => void;
}

export const Investigation: React.FC<InvestigationProps> = ({
  scenario,
  riskResult,
  policyThreshold,
  evidenceItems,
  evidenceStats,
  investigatedMap,
  onRunInvestigationAction,
  onResetInvestigation,
  activeCounterfactualId,
  onSelectCounterfactual,
}) => {
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent>(
    scenario.timeline[scenario.timeline.length - 1] || scenario.timeline[0]
  );
  const [showExpandableMath, setShowExpandableMath] = useState<boolean>(true);

  // Ensure selectedEvent stays valid when scenario changes
  const activeEvent =
    scenario.timeline.find((e) => e.id === selectedEvent?.id) ||
    scenario.timeline[scenario.timeline.length - 1];

  const primaryNextAction = scenario.nextBestActions[0];

  // Baseline reference for concrete delta comparison
  const baseFeatures =
    ENTITY_BASELINES[scenario.primaryEntity].baseline.longTerm;
  const currFeatures = scenario.currentBehavior;

  // Baseline scenario risk BEFORE any active counterfactual selection (for Risk Before -> Risk After comparison)
  const preCounterfactualRisk = calculateDeterministicRisk({
    anomaly: scenario.anomalyScore,
    mutation: scenario.mutationScore,
    classifier: scenario.classifierScore,
    classifierCertainty: scenario.classifierCertainty,
    progression: scenario.progressionScore,
    evidence: evidenceStats.agreementPct,
    contextAdjustment: riskResult.contextAdjustment,
    primaryClass: scenario.primaryClass,
  });

  // Pre-compute counterfactual sensitivity risks using the exact same formula
  const counterfactualEvaluations = scenario.counterfactuals.map((cf) => {
    const cfCalc = calculateDeterministicRisk({
      anomaly: cf.modifiedInputs.anomaly ?? preCounterfactualRisk.anomaly,
      mutation: cf.modifiedInputs.mutation ?? preCounterfactualRisk.mutation,
      classifier:
        cf.modifiedInputs.classifier ?? preCounterfactualRisk.classifier,
      classifierCertainty: scenario.classifierCertainty,
      progression:
        cf.modifiedInputs.progression ?? preCounterfactualRisk.progression,
      evidence: cf.modifiedInputs.evidence ?? preCounterfactualRisk.evidence,
      contextAdjustment:
        cf.modifiedInputs.contextAdjustment ??
        preCounterfactualRisk.contextAdjustment,
      primaryClass: scenario.primaryClass,
    });
    const delta = cfCalc.finalRisk - preCounterfactualRisk.finalRisk;
    return {
      ...cf,
      riskBefore: preCounterfactualRisk.finalRisk,
      cfRisk: cfCalc.finalRisk,
      cfBand: cfCalc.riskBand,
      delta,
    };
  });

  const isPolicyBreached = riskResult.finalRisk > policyThreshold;

  return (
    <div className="space-y-6">
      {/* Top Investigation Context Header */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="text-xs text-sky-400 font-medium">
            Analyst Investigation Workspace · End-to-End Evidence & Attack Intent Verification
          </div>
          <h1 className="text-xl font-bold text-white mt-0.5">
            Investigating {scenario.primaryEntity} — {scenario.label}
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">{scenario.subtitle}</p>
        </div>

        <div className="flex flex-wrap items-center gap-4">
          {(Object.keys(investigatedMap).length > 0 ||
            activeCounterfactualId) && (
            <button
              onClick={onResetInvestigation}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 rounded border border-slate-700 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Simulated Checks</span>
            </button>
          )}

          <div className="text-right border-l border-slate-800 pl-4">
            <div className="text-[11px] text-slate-400">
              Policy Guardrail (Max {policyThreshold})
            </div>
            <div
              className={`text-sm font-mono font-bold flex items-center justify-end gap-1 ${
                isPolicyBreached ? 'text-red-400' : 'text-emerald-400'
              }`}
            >
              {isPolicyBreached ? (
                <>
                  <ShieldAlert className="w-4 h-4" />
                  <span>POLICY BREACH</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>POLICY PASS</span>
                </>
              )}
            </div>
          </div>

          <div className="text-right border-l border-slate-800 pl-4">
            <div className="text-[11px] text-slate-400">Unified Final Risk</div>
            <div
              className={`text-2xl font-bold font-mono tabular-nums ${
                riskResult.finalRisk > 70
                  ? 'text-red-400'
                  : riskResult.finalRisk > 30
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {riskResult.finalRisk}/100 ({riskResult.riskBand})
            </div>
          </div>
        </div>
      </div>

      {/* Structured 7-Question Explainability Strip */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-white">
              Structured Analyst Explainability Report ({scenario.primaryEntity})
            </h2>
            <p className="text-xs text-slate-400">
              Every alert answers 7 concrete investigative questions using measured behavioral deltas
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3 font-mono text-xs bg-slate-900 px-3 py-1.5 rounded border border-slate-800 tabular-nums">
            <span>
              ports: <strong className="text-white">{baseFeatures.uniquePorts} → {currFeatures.uniquePorts}</strong>
            </span>
            <span>·</span>
            <span>
              failed logins: <strong className="text-white">{baseFeatures.failedLogins} → {currFeatures.failedLogins}</strong>
            </span>
            <span>·</span>
            <span>
              new peers: <strong className="text-white">{baseFeatures.uniqueDestinations} → {currFeatures.uniqueDestinations}</strong>
            </span>
            <span>·</span>
            <span>
              outbound: <strong className="text-white">{baseFeatures.outboundTrafficMB} MB → {currFeatures.outboundTrafficMB} MB</strong>
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded border border-slate-800 bg-slate-900/50 space-y-1">
            <div className="font-mono font-bold text-sky-400">
              1. WHAT HAPPENED?
            </div>
            <p className="text-slate-300 leading-relaxed">
              {scenario.primaryEntity} executed {currFeatures.connections} connections across {currFeatures.uniquePorts} ports, generated {currFeatures.failedLogins} failed logins, contacted {currFeatures.uniqueDestinations} peers, and transferred {currFeatures.outboundTrafficMB} MB at {currFeatures.activeHours}.
            </p>
          </div>

          <div className="p-3 rounded border border-slate-800 bg-slate-900/50 space-y-1">
            <div className="font-mono font-bold text-amber-400">
              2. WHY IS IT UNUSUAL?
            </div>
            <p className="text-slate-300 leading-relaxed">
              Behavior Mutation Score is {riskResult.mutation}/100 and Isolation Forest Anomaly is {riskResult.anomaly}/100 compared to {scenario.primaryEntity}'s baseline ({baseFeatures.uniquePorts} ports, {baseFeatures.failedLogins} failed login, {baseFeatures.outboundTrafficMB} MB during {baseFeatures.activeHours}).
            </p>
          </div>

          <div className="p-3 rounded border border-slate-800 bg-slate-900/50 space-y-1">
            <div className="font-mono font-bold text-red-400">
              3. WHAT THREAT IS SUSPECTED?
            </div>
            <p className="text-slate-300 leading-relaxed">
              Classified as <strong className="text-white">{riskResult.classification}</strong> with Attack Progression at {riskResult.progression}% ({scenario.timeline.map((t) => t.stage).join(' → ')}).
            </p>
          </div>

          <div className="p-3 rounded border border-slate-800 bg-slate-900/50 space-y-1">
            <div className="font-mono font-bold text-emerald-400">
              4. WHAT EVIDENCE SUPPORTS IT?
            </div>
            <p className="text-slate-300 leading-relaxed">
              {evidenceStats.supportingCount} of {evidenceStats.evaluatedCount} evaluated evidence checks support the finding ({evidenceStats.agreementPct}% Evidence Agreement).
            </p>
          </div>

          <div className="p-3 rounded border border-slate-800 bg-slate-900/50 space-y-1">
            <div className="font-mono font-bold text-sky-400">
              5. HOW CONFIDENT ARE WE?
            </div>
            <p className="text-slate-300 leading-relaxed">
              Ensemble Classifier Certainty is {scenario.classifierCertainty}% across 7 decision trees; Evidence Agreement is {evidenceStats.agreementPct}% ({evidenceStats.unknownCount} checks still UNKNOWN).
            </p>
          </div>

          <div className="p-3 rounded border border-slate-800 bg-slate-900/50 space-y-1">
            <div className="font-mono font-bold text-white">
              6. WHY DID FINAL RISK BECOME {riskResult.finalRisk}?
            </div>
            <p className="text-slate-300 leading-relaxed font-mono text-[11px]">
              BaseRisk ({riskResult.baseRisk.toFixed(2)}) = Anom({riskResult.anomalyWeighted}) + Mut({riskResult.mutationWeighted}) + Class({riskResult.classifierWeighted}) + Prog({riskResult.progressionWeighted}) + Evid({riskResult.evidenceWeighted}), plus Context ({riskResult.contextAdjustment >= 0 ? `+${riskResult.contextAdjustment}` : riskResult.contextAdjustment}) → {riskResult.finalRisk}/100.
            </p>
          </div>

          <div className="p-3 rounded border border-slate-800 bg-slate-900/50 space-y-1 md:col-span-2">
            <div className="font-mono font-bold text-emerald-400">
              7. WHY WAS IT NOT ESCALATED FURTHER (OR WHY NOT 100/100)?
            </div>
            <p className="text-slate-300 leading-relaxed">
              {scenario.whyNotMalicious.join(' · ')}
            </p>
          </div>
        </div>
      </div>

      {/* 3-Column Analyst Workspace Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* LEFT COLUMN (3 cols): Attack Progression + Interactive Timeline + Telemetry Inspector + ML Ensemble */}
        <div className="lg:col-span-3 space-y-5">
          {/* Attack Transition & Progression Score */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">
                Attack Transition Engine
              </h2>
              <span className="text-sm font-mono font-bold text-red-400 tabular-nums">
                {riskResult.progression}/100
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Tracks sequential kill-chain state transitions: SCAN → BRUTE FORCE → LATERAL MOVEMENT → EXFILTRATION.
            </p>

            {/* Kill Chain Sequence Steps */}
            <div className="space-y-1.5 pt-1">
              {[
                { stage: 'Normal', tactic: 'Baseline DNA' },
                { stage: 'Port Scan', tactic: 'Discovery' },
                { stage: 'Brute Force', tactic: 'Credential Access' },
                { stage: 'Lateral Movement', tactic: 'Lateral Movement' },
                { stage: 'Data Exfiltration', tactic: 'Exfiltration' },
              ].map((step, i) => {
                const reached =
                  scenario.timeline.some((t) => t.stage === step.stage) ||
                  step.stage === 'Normal';
                return (
                  <div
                    key={step.stage}
                    className={`flex items-center justify-between px-2.5 py-1.5 rounded text-xs border ${
                      reached
                        ? 'border-sky-500/40 bg-sky-950/30 text-white'
                        : 'border-slate-800/80 bg-slate-900/40 text-slate-500'
                    }`}
                  >
                    <span className="font-medium">
                      {i}. {step.stage}
                    </span>
                    <span className="font-mono text-[11px]">{step.tactic}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Interactive Event Timeline */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">
                Interactive Attack Timeline
              </h2>
              <span className="text-xs text-slate-400 font-mono">
                Click event
              </span>
            </div>

            <div className="space-y-2">
              {scenario.timeline.map((evt) => {
                const isSelected = activeEvent?.id === evt.id;
                return (
                  <button
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className={`w-full text-left p-2.5 rounded border transition-colors cursor-pointer ${
                      isSelected
                        ? 'border-sky-400 bg-slate-800/90'
                        : 'border-slate-800 bg-slate-900/50 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-sky-400 font-semibold">
                        {evt.time}
                      </span>
                      <span className="text-slate-400">{evt.mitreTactic}</span>
                    </div>
                    <div className="text-xs font-semibold text-white mt-1">
                      {evt.title}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5 flex justify-between">
                      <span>Stage: {evt.stage}</span>
                      <span className="font-mono text-amber-400">
                        +{evt.riskContribution} pts
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Selected Event Raw Telemetry & Derived Features */}
            {activeEvent && (
              <div className="mt-3 pt-3 border-t border-slate-800 space-y-2 text-xs">
                <div className="font-semibold text-sky-400">
                  Selected Event Telemetry ({activeEvent.time}):
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded p-2.5 font-mono text-[11px] space-y-1 text-slate-300">
                  <div>
                    src: {activeEvent.rawTelemetry.source_ip}:
                    {activeEvent.rawTelemetry.src_port}
                  </div>
                  <div>
                    dst: {activeEvent.rawTelemetry.dest_ip}:
                    {activeEvent.rawTelemetry.dest_port}
                  </div>
                  <div>
                    proto: {activeEvent.rawTelemetry.protocol} · bytes:{' '}
                    {activeEvent.rawTelemetry.bytes}
                  </div>
                  <div>auth: {activeEvent.rawTelemetry.auth_status}</div>
                  <div>type: {activeEvent.rawTelemetry.event_type}</div>
                </div>
                <div className="text-[11px] text-slate-300 leading-relaxed">
                  <strong className="text-white">Engineered Features:</strong>{' '}
                  ports={activeEvent.featureValues.port_count}, failed_logins=
                  {activeEvent.featureValues.failed_login_count}, outbound=
                  {activeEvent.featureValues.outbound_bytes}
                </div>
                <div className="text-[11px] text-slate-400">
                  {activeEvent.evidenceNote}
                </div>
              </div>
            )}
          </div>

          {/* Anomaly Detection (Isolation Forest) & Classifier Tree Uncertainty */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">
                ML Detection & Tree Uncertainty
              </h2>
              <span className="text-[11px] font-mono text-sky-400">
                Prototype Simulation
              </span>
            </div>

            {/* Isolation Forest Visual Cluster */}
            <div className="border border-slate-800 bg-slate-900/60 rounded p-3 space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300 font-medium">
                  Isolation Forest Anomaly
                </span>
                <span className="font-mono font-bold text-amber-400 tabular-nums">
                  {riskResult.anomaly}/100
                </span>
              </div>
              <svg
                width="100%"
                height="64"
                viewBox="0 0 240 64"
                className="bg-slate-950 rounded border border-slate-800/80"
              >
                <circle
                  cx="42"
                  cy="32"
                  r="18"
                  fill="rgba(16, 185, 129, 0.12)"
                  stroke="#10B981"
                  strokeDasharray="2 2"
                />
                <circle cx="36" cy="28" r="3" fill="#10B981" />
                <circle cx="45" cy="36" r="3" fill="#10B981" />
                <circle cx="48" cy="26" r="3" fill="#10B981" />
                <circle cx="39" cy="38" r="3" fill="#10B981" />
                <text
                  x="42"
                  y="58"
                  textAnchor="middle"
                  className="fill-slate-400 text-[9px] font-mono"
                >
                  Normal Cluster
                </text>

                <line
                  x1="65"
                  y1="32"
                  x2="185"
                  y2="24"
                  stroke="#64748B"
                  strokeDasharray="3 3"
                />

                <circle
                  cx={42 + (riskResult.anomaly / 100) * 165}
                  cy="24"
                  r="5"
                  fill={riskResult.anomaly > 70 ? '#EF4444' : '#F59E0B'}
                />
                <text
                  x={42 + (riskResult.anomaly / 100) * 165}
                  y="44"
                  textAnchor="middle"
                  className="fill-red-400 text-[9px] font-mono"
                >
                  {scenario.primaryEntity} ({riskResult.anomaly})
                </text>
              </svg>
            </div>

            {/* Random Forest Tree Votes & Certainty */}
            <div className="border border-slate-800 bg-slate-900/60 rounded p-3 space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300 font-medium">
                  Classifier Certainty (7 Trees)
                </span>
                <span
                  className={`font-mono font-bold tabular-nums ${
                    scenario.classifierCertainty <= 55
                      ? 'text-red-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {scenario.classifierCertainty}%
                </span>
              </div>
              {riskResult.unknownGateTriggered && (
                <div className="text-[11px] text-amber-300 bg-amber-950/40 border border-amber-500/40 p-2 rounded space-y-1">
                  <div className="font-mono font-bold">
                    UNKNOWN GATE TRIGGERED → UNKNOWN SUSPICIOUS BEHAVIOR
                  </div>
                  <div>
                    <strong>Why Known Classification Was Rejected:</strong> High Anomaly ({riskResult.anomaly}) & High Mutation ({riskResult.mutation}), but low Classifier Confidence ({scenario.classifierCertainty}% ≤ 55%) and incomplete Evidence ({riskResult.evidence}% ≤ 60%).
                  </div>
                  <div>
                    <strong>Suggested Analyst Action:</strong> Inspect unlisted UDP peer 10.24.99.88 and assign cluster label in Audit & Policy tab.
                  </div>
                </div>
              )}
              <div className="grid grid-cols-1 gap-1 pt-1 text-[11px] font-mono">
                {scenario.treeVotes.map((t) => (
                  <div
                    key={t.treeId}
                    className="flex items-center justify-between text-slate-400"
                  >
                    <span>{t.treeId}</span>
                    <span
                      className={
                        t.vote === 'Unknown'
                          ? 'text-amber-400'
                          : t.vote === 'Normal'
                          ? 'text-emerald-400'
                          : 'text-slate-200'
                      }
                    >
                      → {t.vote}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* CENTER COLUMN (5 cols): Interactive Attack Intent Graph + Signature #2 Next-Best Investigation + Signature #1 Attack Memory + Signature #3 Attack Path Simulator */}
        <div className="lg:col-span-5 space-y-5">
          {/* Interactive Attack Intent Graph */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  Attack Intent & Lateral Movement Graph
                </h2>
                <p className="text-xs text-slate-400">
                  Visualizes entities, directional movement stages, and per-node risk
                </p>
              </div>
              <span className="text-xs font-mono text-sky-400">
                {scenario.attackGraphNodes.length} Active Nodes
              </span>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-md p-2 overflow-x-auto">
              <svg
                width="100%"
                height="260"
                viewBox="0 0 880 260"
                className="min-w-[540px]"
              >
                <defs>
                  <marker
                    id="arrow-active"
                    viewBox="0 0 10 10"
                    refX="9"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#EF4444" />
                  </marker>
                  <marker
                    id="arrow-normal"
                    viewBox="0 0 10 10"
                    refX="9"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#38BDF8" />
                  </marker>
                </defs>

                {/* Edges */}
                {scenario.attackGraphEdges.map((edge, idx) => {
                  const fromNode = scenario.attackGraphNodes.find(
                    (n) => n.id === edge.from
                  );
                  const toNode = scenario.attackGraphNodes.find(
                    (n) => n.id === edge.to
                  );
                  if (!fromNode || !toNode) return null;
                  const midX = (fromNode.x + toNode.x) / 2;
                  const midY = (fromNode.y + toNode.y) / 2 - 12;

                  return (
                    <g key={idx}>
                      <line
                        x1={fromNode.x + 55}
                        y1={fromNode.y}
                        x2={toNode.x - 60}
                        y2={toNode.y}
                        stroke={edge.active ? '#EF4444' : '#38BDF8'}
                        strokeWidth={edge.active ? '2.5' : '1.5'}
                        markerEnd={
                          edge.active
                            ? 'url(#arrow-active)'
                            : 'url(#arrow-normal)'
                        }
                      />
                      <text
                        x={midX}
                        y={midY}
                        textAnchor="middle"
                        className="fill-slate-300 text-[11px] font-mono"
                      >
                        {edge.label}
                      </text>
                    </g>
                  );
                })}

                {/* Nodes */}
                {scenario.attackGraphNodes.map((node) => {
                  const nodeRisk =
                    node.id === scenario.primaryEntity
                      ? riskResult.finalRisk
                      : node.risk;
                  const isHigh = nodeRisk > 70;
                  const isMed = nodeRisk > 30 && nodeRisk <= 70;
                  const strokeColor = isHigh
                    ? '#EF4444'
                    : isMed
                    ? '#F59E0B'
                    : '#10B981';

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${node.x}, ${node.y})`}
                    >
                      <rect
                        x="-58"
                        y="-30"
                        width="116"
                        height="60"
                        rx="6"
                        fill="#0F172A"
                        stroke={strokeColor}
                        strokeWidth="2"
                      />
                      <text
                        x="0"
                        y="-8"
                        textAnchor="middle"
                        className="fill-white text-[12px] font-mono font-bold"
                      >
                        {node.label.split(' ')[0]}
                      </text>
                      <text
                        x="0"
                        y="8"
                        textAnchor="middle"
                        className="fill-slate-400 text-[10px]"
                      >
                        {node.stage}
                      </text>
                      <text
                        x="0"
                        y="22"
                        textAnchor="middle"
                        className="fill-amber-400 text-[10px] font-mono font-semibold"
                      >
                        Risk: {nodeRisk}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
          </div>

          {/* SIGNATURE FEATURE #2: NEXT-BEST INVESTIGATION */}
          <div className="border border-sky-500/40 bg-[#111827] rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="text-xs text-sky-400 font-semibold">
                  Signature Feature #2 · Active Analyst Guidance
                </div>
                <h2 className="text-base font-bold text-white mt-0.5">
                  Next-Best Investigation Recommendation
                </h2>
              </div>
              <span className="text-xs font-mono text-sky-400">
                Same Risk Formula
              </span>
            </div>

            {primaryNextAction && (
              <div className="bg-slate-900/90 border border-slate-800 rounded-md p-3.5 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-amber-400">
                    Recommended Next Check: {primaryNextAction.label}
                  </span>
                  <span className="text-xs font-mono text-slate-300 tabular-nums">
                    Max Potential Impact: ±{primaryNextAction.potentialImpactPts} pts
                  </span>
                </div>
                <div className="text-sm font-medium text-white">
                  {primaryNextAction.question}
                </div>
                <p className="text-xs text-slate-400">
                  Reason: "{primaryNextAction.reason}"
                </p>
              </div>
            )}

            {/* Interactive Investigation Simulation Buttons */}
            <div className="space-y-2.5">
              <div className="text-xs font-medium text-slate-300">
                Simulate Investigation Outcome (Updates Evidence & Recomputes Risk Live):
              </div>
              <div className="space-y-2">
                {(
                  [
                    'Destination Trust',
                    'Historical Contact',
                    'Backup Activity',
                    'User Authentication',
                    'Peer Relationship',
                  ] as const
                ).map((actionType) => {
                  const currentStatus = investigatedMap[actionType];
                  return (
                    <div
                      key={actionType}
                      className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded border border-slate-800 bg-slate-900/50 text-xs"
                    >
                      <span className="font-medium text-slate-200">
                        {actionType}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() =>
                            onRunInvestigationAction(actionType, 'TRUSTED_SAFE')
                          }
                          className={`px-2.5 py-1 rounded font-mono text-[11px] transition-colors cursor-pointer ${
                            currentStatus === 'TRUSTED_SAFE'
                              ? 'bg-emerald-500 text-slate-950 font-bold'
                              : 'bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700'
                          }`}
                        >
                          Verify Benign / Trusted
                        </button>
                        <button
                          onClick={() =>
                            onRunInvestigationAction(
                              actionType,
                              'CONFIRMED_THREAT'
                            )
                          }
                          className={`px-2.5 py-1 rounded font-mono text-[11px] transition-colors cursor-pointer ${
                            currentStatus === 'CONFIRMED_THREAT'
                              ? 'bg-red-500 text-white font-bold'
                              : 'bg-slate-800 hover:bg-slate-700 text-red-400 border border-slate-700'
                          }`}
                        >
                          Confirm Hostile / Untrusted
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* SIGNATURE FEATURE #1: ATTACK MEMORY GRAPH */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="text-xs text-sky-400 font-semibold">
                  Signature Feature #1 · Behavioral Memory
                </div>
                <h2 className="text-base font-bold text-white mt-0.5">
                  Attack Memory Graph — "Have we seen this pattern before?"
                </h2>
              </div>
              <div className="text-right">
                <div className="text-[11px] text-slate-400">
                  Pattern Similarity
                </div>
                <div className="text-lg font-bold font-mono text-sky-400 tabular-nums">
                  {scenario.historicalMemory.similarityPct}%
                </div>
              </div>
            </div>

            {scenario.historicalMemory.isNovel ? (
              <div className="p-3 rounded border border-amber-500/40 bg-amber-950/20 text-xs text-amber-300 font-mono">
                Novel Attack Progression — No prior incident matches this sequence ({scenario.historicalMemory.similarityPct}% similarity).
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="border border-slate-800 bg-slate-900/60 p-3 rounded space-y-1.5">
                  <div className="font-semibold text-white">
                    Current Incident Sequence
                  </div>
                  {scenario.timeline.map((t, i) => (
                    <div key={t.id} className="font-mono text-slate-300">
                      {i + 1}. {t.stage} ({t.title.split('(')[0]})
                    </div>
                  ))}
                </div>
                <div className="border border-slate-800 bg-slate-900/60 p-3 rounded space-y-1.5">
                  <div className="font-semibold text-sky-400">
                    Historical Match: {scenario.historicalMemory.incidentId}
                  </div>
                  {scenario.historicalMemory.stages.map((st, i) => (
                    <div key={i} className="font-mono text-slate-300">
                      {i + 1}. {st}
                    </div>
                  ))}
                </div>
              </div>
            )}
            <p className="text-xs text-slate-400">
              {scenario.historicalMemory.notes}
            </p>
          </div>

          {/* SIGNATURE FEATURE #3: ATTACK PATH SIMULATOR */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="text-xs text-amber-400 font-semibold">
                  Signature Feature #3 · Lateral Trajectory Reasoning
                </div>
                <h2 className="text-base font-bold text-white mt-0.5">
                  Attack Path Simulator — "Where could this behavior move next?"
                </h2>
              </div>
              <div className="text-right">
                <div className="text-[11px] text-slate-400">Path Confidence</div>
                <div className="text-lg font-bold font-mono text-amber-400 tabular-nums">
                  {scenario.attackPath.confidencePct}%
                </div>
              </div>
            </div>

            <div className="text-[11px] font-mono text-amber-300/90 bg-amber-950/30 border border-amber-500/30 px-2.5 py-1.5 rounded">
              Predicted attack path — not confirmed attacker activity.
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1">
              {scenario.attackPath.nodes.map((n) => (
                <div
                  key={n.id}
                  className="border border-slate-800 bg-slate-900/70 p-2.5 rounded text-xs"
                >
                  <div className="font-mono font-bold text-white truncate">
                    {n.label}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5 truncate">
                    {n.role}
                  </div>
                  <div className="font-mono text-sky-400 text-[11px] mt-1 tabular-nums">
                    Prob: {n.probability}%
                  </div>
                </div>
              ))}
            </div>

            <div className="space-y-1 pt-1">
              <div className="text-xs font-semibold text-white">
                Potential Next Target:{' '}
                <span className="font-mono text-amber-400">
                  {scenario.attackPath.nextTarget}
                </span>
              </div>
              <ul className="text-xs text-slate-400 space-y-1 list-disc pl-4">
                {scenario.attackPath.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN (4 cols): Risk Fusion Breakdown + Expandable Risk Calculation + Evidence Agreement + Counterfactual Analysis */}
        <div className="lg:col-span-4 space-y-5">
          {/* Deterministic Risk Fusion Breakdown + Expandable "Risk Calculation" Ledger */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  Confidence Matrix & Risk Breakdown
                </h2>
                <p className="text-[11px] text-slate-400">
                  Base = 0.22·Anom + 0.18·Mut + 0.15·Class + 0.20·Prog + 0.25·Evid
                </p>
              </div>
              <span className="text-lg font-bold font-mono text-white tabular-nums">
                {riskResult.finalRisk}/100
              </span>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              {[
                {
                  label: 'ANOMALY (0.22×)',
                  raw: riskResult.anomaly,
                  weighted: riskResult.anomalyWeighted,
                  maxW: 22,
                },
                {
                  label: 'MUTATION (0.18×)',
                  raw: riskResult.mutation,
                  weighted: riskResult.mutationWeighted,
                  maxW: 18,
                },
                {
                  label: 'CLASSIFIER (0.15×)',
                  raw: riskResult.classifier,
                  weighted: riskResult.classifierWeighted,
                  maxW: 15,
                },
                {
                  label: 'PROGRESSION (0.20×)',
                  raw: riskResult.progression,
                  weighted: riskResult.progressionWeighted,
                  maxW: 20,
                },
                {
                  label: 'EVIDENCE (0.25×)',
                  raw: riskResult.evidence,
                  weighted: riskResult.evidenceWeighted,
                  maxW: 25,
                },
              ].map((row) => (
                <div key={row.label} className="space-y-1">
                  <div className="flex justify-between tabular-nums">
                    <span className="text-slate-300">
                      {row.label} [{row.raw}]
                    </span>
                    <span className="text-white font-semibold">
                      +{row.weighted.toFixed(2)}
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-800 rounded-sm overflow-hidden">
                    <div
                      className="h-full bg-sky-400"
                      style={{ width: `${(row.weighted / row.maxW) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            {/* Expandable "Risk Calculation" Verification Section */}
            <div className="pt-2 border-t border-slate-800">
              <button
                onClick={() => setShowExpandableMath(!showExpandableMath)}
                className="w-full flex items-center justify-between text-xs font-semibold text-sky-400 hover:text-sky-300 py-1 cursor-pointer"
              >
                <span>Risk Calculation (Mathematical Proof)</span>
                {showExpandableMath ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>

              {showExpandableMath && (
                <div className="mt-2 bg-slate-950 border border-slate-800 rounded p-3 font-mono text-xs space-y-1.5 tabular-nums">
                  <div className="flex justify-between text-slate-300">
                    <span>Anomaly contribution (0.22 × {riskResult.anomaly})</span>
                    <span>{riskResult.anomalyWeighted.toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span>Mutation contribution (0.18 × {riskResult.mutation})</span>
                    <span>{riskResult.mutationWeighted.toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span>Classifier contribution (0.15 × {riskResult.classifier})</span>
                    <span>{riskResult.classifierWeighted.toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span>Progression contribution (0.20 × {riskResult.progression})</span>
                    <span>{riskResult.progressionWeighted.toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span>Evidence contribution (0.25 × {riskResult.evidence})</span>
                    <span>{riskResult.evidenceWeighted.toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between text-slate-200 border-t border-slate-800 pt-1 font-semibold">
                    <span>BaseRisk Exact Sum</span>
                    <span>{riskResult.baseRisk.toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between text-amber-400">
                    <span>Context adjustment</span>
                    <span>
                      {riskResult.contextAdjustment >= 0
                        ? `+${riskResult.contextAdjustment.toFixed(2)}`
                        : riskResult.contextAdjustment.toFixed(2)}
                    </span>
                  </div>
                  {riskResult.unknownGateTriggered && (
                    <div className="flex justify-between text-sky-400">
                      <span>Unknown Gate Floor</span>
                      <span>min 55.00</span>
                    </div>
                  )}
                  <div className="flex justify-between text-white font-bold border-t border-slate-800 pt-1 text-sm">
                    <span>Final risk (clamped 0–100)</span>
                    <span>
                      {(riskResult.baseRisk + riskResult.contextAdjustment).toFixed(2)} → {riskResult.finalRisk}
                    </span>
                  </div>
                </div>
              )}
            </div>

            <div className="text-[11px] text-slate-400 bg-slate-900/70 p-2.5 rounded border border-slate-800">
              <strong className="text-slate-200">Context Engine:</strong>{' '}
              {scenario.contextReason}
            </div>
          </div>

          {/* Counterfactual Analysis: "WHAT WOULD MAKE THIS SAFE?" */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  What Would Make This Safe? (Counterfactuals)
                </h2>
                <p className="text-xs text-slate-400">
                  Changes ONE factor at a time and reruns the exact same risk formula
                </p>
              </div>
              {activeCounterfactualId && (
                <button
                  onClick={() => onSelectCounterfactual(null)}
                  className="text-xs text-sky-400 hover:underline cursor-pointer"
                >
                  Restore Current State
                </button>
              )}
            </div>

            <div className="space-y-3">
              {counterfactualEvaluations.map((cf) => {
                const isSelected = activeCounterfactualId === cf.id;
                return (
                  <div
                    key={cf.id}
                    onClick={() =>
                      onSelectCounterfactual(isSelected ? null : cf.id)
                    }
                    className={`p-3 rounded border transition-colors cursor-pointer text-xs space-y-1.5 ${
                      isSelected
                        ? 'border-emerald-400 bg-emerald-950/25'
                        : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-white">
                        {cf.label}
                      </span>
                      <span className="font-mono font-bold text-emerald-400 tabular-nums shrink-0">
                        {cf.riskBefore} → {cf.cfRisk} ({cf.delta} pts)
                      </span>
                    </div>

                    <div className="grid grid-cols-1 gap-1 text-[11px] font-mono bg-slate-950/70 p-2 rounded border border-slate-800/80">
                      <div className="text-sky-400">
                        Changed factor: <span className="text-slate-200">{cf.changedFactor}</span>
                      </div>
                      <div className="text-slate-400">
                        Current state: <span className="text-slate-300">{cf.currentStateText}</span>
                      </div>
                      <div className="text-emerald-400">
                        Counterfactual: <span className="text-slate-200">{cf.counterfactualStateText}</span>
                      </div>
                      <div className="flex justify-between pt-1 border-t border-slate-800 text-slate-300">
                        <span>Risk before: {cf.riskBefore}/100</span>
                        <span className="text-emerald-400 font-bold">
                          Risk after: {cf.cfRisk}/100 ({cf.cfBand})
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Evidence Verification & Agreement Score */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  Evidence Verification Engine
                </h2>
                <p className="text-xs text-slate-400">
                  Supporting ({evidenceStats.supportingCount}) / Evaluated ({evidenceStats.evaluatedCount})
                </p>
              </div>
              <div className="text-right">
                <div className="text-[11px] text-slate-400">Agreement</div>
                <div className="text-lg font-bold font-mono text-sky-400 tabular-nums">
                  {evidenceStats.agreementPct}%
                </div>
              </div>
            </div>

            <div className="space-y-2">
              {evidenceItems.map((item) => (
                <div
                  key={item.id}
                  className="p-2.5 rounded border border-slate-800 bg-slate-900/50 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-200">
                      {item.label}
                    </span>
                    <span
                      className={`font-mono font-bold text-[11px] shrink-0 ${
                        item.state === 'TRUE'
                          ? 'text-emerald-400'
                          : item.state === 'FALSE'
                          ? 'text-red-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {item.state}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {item.explanation}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* "WHY SUSPICIOUS?" & "WHY NOT MALICIOUS?" Dual Explainability Panel */}
          <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-4">
            <div>
              <h3 className="text-xs font-bold text-red-400 tracking-wide">
                WHY SUSPICIOUS? (Supporting Threat Indicators)
              </h3>
              <ul className="mt-2 space-y-1.5 text-xs text-slate-300 list-disc pl-4">
                {scenario.whySuspicious.map((line, i) => (
                  <li key={i}>{line}</li>
                ))}
              </ul>
            </div>

            <div className="pt-3 border-t border-slate-800">
              <h3 className="text-xs font-bold text-emerald-400 tracking-wide">
                WHY NOT MALICIOUS? (Mitigating / Ambiguous Factors)
              </h3>
              <ul className="mt-2 space-y-1.5 text-xs text-slate-300 list-disc pl-4">
                {scenario.whyNotMalicious.map((line, i) => (
                  <li key={i}>{line}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
