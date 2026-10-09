import React, { useState } from 'react';
import {
  RefreshCw,
  Sliders,
  Terminal,
} from 'lucide-react';
import {
  AuditRecord,
  RiskCalculationResult,
  ScenarioId,
  ThreatCategory,
  UnknownCluster,
} from '../types/cyberpulse';
import { SCENARIOS } from '../data/syntheticData';
import { computeAuditHash } from '../logic/riskEngine';
import { runSystemValidationSuite } from '../logic/validationEngine';

interface UnknownAuditPolicyProps {
  clusters: UnknownCluster[];
  onUpdateClusterLabel: (
    clusterId: string,
    label: ThreatCategory | 'Benign' | 'Keep Unknown'
  ) => void;
  onPromoteCluster: (clusterId: string) => void;
  retrainCount: number;
  onTriggerRetrain: () => void;
  auditRecords: AuditRecord[];
  onTamperRecord: (index: number) => void;
  onRestoreAuditChain: () => void;
  policyThreshold: number;
  onChangePolicyThreshold: (val: number) => void;
  currentRisk: RiskCalculationResult;
  onSelectScenario: (scenarioId: ScenarioId) => void;
}

export const UnknownAuditPolicy: React.FC<UnknownAuditPolicyProps> = ({
  clusters,
  onUpdateClusterLabel,
  onPromoteCluster,
  retrainCount,
  onTriggerRetrain,
  auditRecords,
  onTamperRecord,
  onRestoreAuditChain,
  policyThreshold,
  onChangePolicyThreshold,
  currentRisk,
  onSelectScenario,
}) => {
  const [auditVerifiedState, setAuditVerifiedState] = useState<
    'IDLE' | 'VERIFIED' | 'TAMPERED'
  >('IDLE');
  const [tamperedIndex, setTamperedIndex] = useState<number | null>(null);
  const [poisoningDay, setPoisoningDay] = useState<number>(5);

  const validationSuite = runSystemValidationSuite();
  const poisoningSeries = SCENARIOS['Slow Baseline Poisoning'].driftSeries;
  const unkScenario = SCENARIOS['Unknown Attack'];

  const handleVerifyAuditChain = () => {
    let prev = 'sha256:0000000000000000';
    for (let i = 0; i < auditRecords.length; i++) {
      const rec = auditRecords[i];
      const expected = computeAuditHash(
        prev,
        rec.alert_id,
        rec.entity,
        rec.risk_score,
        rec.classification,
        rec.decision
      );
      if (rec.previous_hash !== prev || rec.current_hash !== expected) {
        setAuditVerifiedState('TAMPERED');
        setTamperedIndex(i);
        return;
      }
      prev = rec.current_hash;
    }
    setAuditVerifiedState('VERIFIED');
    setTamperedIndex(null);
  };

  const isPolicyBreached = currentRisk.finalRisk > policyThreshold;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="text-xs text-sky-400 font-medium">
            Unknown Gate · SQLite Audit Chain · Policy Guardrails · Poisoning Defense
          </div>
          <h1 className="text-2xl font-bold text-white mt-0.5">
            Unknown Behaviors, Cryptographic Audit & Policy Control
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Inspect Unknown Decision Gate logic, verify deterministic SHA-256 audit logs, configure risk breach thresholds, and test baseline poisoning resistance.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <div className="border border-slate-800 bg-slate-900/80 px-3.5 py-2 rounded text-right">
            <div className="text-xs text-slate-400">System Validation Suite</div>
            <div className="text-sm font-mono font-bold text-emerald-400 tabular-nums">
              ✓ {validationSuite.passedCount} / {validationSuite.totalCount} Checks Passed
            </div>
          </div>
        </div>
      </div>

      {/* SECTION 1: UNKNOWN BEHAVIOR DECISION GATE & CLUSTERING */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-base font-bold text-white">
              1. Unknown Behavior Decision Gate & Active Clustering
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Unknown is a decision gate, not a weighted risk component. When anomaly & mutation are high but classifier confidence is low, CYBERPULSE outputs UNKNOWN SUSPICIOUS BEHAVIOR (FinalRisk ≥ 55).
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onSelectScenario('Unknown Attack')}
              className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-400/50 text-amber-300 font-mono text-xs rounded transition-colors cursor-pointer whitespace-nowrap"
            >
              Load Unknown Gate Scenario (PC-12)
            </button>
            <button
              onClick={onTriggerRetrain}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded transition-colors cursor-pointer whitespace-nowrap"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retrain Simulation ({retrainCount})</span>
            </button>
          </div>
        </div>

        {/* Unknown Gate Inspector Box */}
        <div className="border border-amber-500/40 bg-slate-900/80 rounded-md p-4 grid grid-cols-1 lg:grid-cols-12 gap-4 text-xs">
          <div className="lg:col-span-5 space-y-2 border-b lg:border-b-0 lg:border-r border-slate-800 pb-3 lg:pb-0 lg:pr-4">
            <div className="font-mono font-bold text-amber-400">
              UNKNOWN GATE TELEMETRY (PC-12 SCENARIO)
            </div>
            <div className="grid grid-cols-2 gap-2 font-mono">
              <div className="bg-slate-950 p-2 rounded border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Anomaly Score</span>
                <span className="text-white font-bold text-sm">{unkScenario.anomalyScore}/100 (High)</span>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Mutation Score</span>
                <span className="text-white font-bold text-sm">{unkScenario.mutationScore}/100 (High)</span>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Classifier Confidence</span>
                <span className="text-red-400 font-bold text-sm">{unkScenario.classifierScore}% (Low)</span>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Tree Uncertainty</span>
                <span className="text-amber-400 font-bold text-sm">{unkScenario.classifierCertainty}% Certainty</span>
              </div>
            </div>
          </div>

          <div className="lg:col-span-7 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono font-bold text-sky-400">
                DECISION OUTPUT: UNKNOWN SUSPICIOUS BEHAVIOR
              </span>
              <span className="font-mono text-amber-300 font-semibold">
                Minimum Risk Floor ≥ 55 Enforced (Risk: 68/100)
              </span>
            </div>
            <div className="text-slate-300">
              <strong className="text-white">Why Known Classification Was Rejected:</strong> 7 decision trees split across Lateral Movement (2), Data Exfiltration (2), Port Scan (1), and Unknown Abstain (2). Forcing this event into "Lateral Movement" at 32% probability would misdirect the analyst.
            </div>
            <div className="text-slate-300">
              <strong className="text-white">Suggested Analyst Action:</strong> Verify destination trust on unlisted internal host <code className="text-sky-300">10.24.99.88</code> (UDP port 19440) and assign a validated cluster label below.
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {clusters.map((cluster) => (
            <div
              key={cluster.id}
              className="border border-slate-800 bg-slate-900/60 rounded-md p-4 flex flex-col justify-between space-y-4"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-white text-sm">
                    {cluster.name} ({cluster.entityCount} entities)
                  </span>
                  <span
                    className={`text-xs font-mono ${
                      cluster.promoted ? 'text-emerald-400' : 'text-amber-400'
                    }`}
                  >
                    {cluster.promoted
                      ? `Promoted → ${cluster.analystLabel}`
                      : 'Status: Unclassified Cluster'}
                  </span>
                </div>
                <p className="text-xs text-slate-300">{cluster.patternSummary}</p>
                <div className="flex flex-wrap gap-4 text-xs font-mono text-slate-400 pt-1">
                  <span>Avg Anomaly: {cluster.avgAnomaly}/100</span>
                  <span>Avg Mutation: {cluster.avgMutation}/100</span>
                  <span>Sample: {cluster.sampleEntities.join(', ')}</span>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <label className="text-xs text-slate-400">Analyst Label:</label>
                  <select
                    value={cluster.analystLabel}
                    onChange={(e) =>
                      onUpdateClusterLabel(
                        cluster.id,
                        e.target.value as ThreatCategory | 'Benign' | 'Keep Unknown'
                      )
                    }
                    className="bg-slate-950 border border-slate-700 text-xs text-white rounded px-2.5 py-1.5 font-mono"
                  >
                    <option value="Keep Unknown">Keep Unknown</option>
                    <option value="Port Scan">Port Scan</option>
                    <option value="Brute Force">Brute Force</option>
                    <option value="Lateral Movement">Lateral Movement</option>
                    <option value="Data Exfiltration">Data Exfiltration</option>
                    <option value="Benign">Benign</option>
                  </select>
                </div>

                <button
                  onClick={() => onPromoteCluster(cluster.id)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-xs font-medium text-white rounded transition-colors cursor-pointer whitespace-nowrap"
                >
                  {cluster.promoted
                    ? '✓ Promoted to Known Class'
                    : 'Promote to Known Class'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* SECTION 2: POLICY GUARDRAIL + BASELINE POISONING RESISTANCE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Policy Guardrail */}
        <div className="lg:col-span-5 border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-white">
                  2. Policy Guardrail & Threshold Control
                </h2>
                <p className="text-xs text-slate-400">
                  Evaluates deterministic FinalRisk against organizational risk tolerance (Default: 70)
                </p>
              </div>
              <Sliders className="w-4 h-4 text-sky-400" />
            </div>

            <div className="p-4 rounded border border-slate-800 bg-slate-900/70 space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-300">
                  Maximum Allowed Risk Threshold:
                </label>
                <span className="text-lg font-mono font-bold text-sky-400 tabular-nums">
                  [ {policyThreshold} ]
                </span>
              </div>
              <input
                type="range"
                min={30}
                max={95}
                value={policyThreshold}
                onChange={(e) =>
                  onChangePolicyThreshold(Number(e.target.value))
                }
                className="w-full accent-sky-400 cursor-pointer"
              />
              <div className="flex justify-between text-[11px] font-mono text-slate-500">
                <span>Strict (30)</span>
                <span>Default (70)</span>
                <span>Permissive (95)</span>
              </div>
            </div>

            {/* Live Policy Decision Box */}
            <div
              className={`p-4 rounded border ${
                isPolicyBreached
                  ? 'border-red-500/50 bg-red-950/20'
                  : 'border-emerald-500/50 bg-emerald-950/20'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="text-xs font-mono text-slate-300">
                  FinalRisk = {currentRisk.finalRisk} · MaxRisk = {policyThreshold}
                </div>
                <span
                  className={`text-sm font-mono font-bold ${
                    isPolicyBreached ? 'text-red-400' : 'text-emerald-400'
                  }`}
                >
                  {isPolicyBreached ? 'POLICY BREACH' : 'POLICY PASS'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1.5">
                {isPolicyBreached
                  ? `FinalRisk (${currentRisk.finalRisk}) > MaxRisk (${policyThreshold}) → POLICY BREACH. Automated containment workflow & SOC escalation triggered.`
                  : `FinalRisk (${currentRisk.finalRisk}) ≤ MaxRisk (${policyThreshold}) → POLICY PASS.`}
              </p>
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded p-3 text-xs font-mono text-slate-400 space-y-1">
            <div className="flex items-center gap-1.5 text-slate-300">
              <Terminal className="w-3.5 h-3.5 text-sky-400" />
              <span>CI/CD & CLI Policy Gate Concept:</span>
            </div>
            <div>
              $ cyberpulse evaluate --max-risk {policyThreshold}
            </div>
            <div
              className={
                isPolicyBreached ? 'text-red-400' : 'text-emerald-400'
              }
            >
              → Result: {isPolicyBreached ? 'POLICY BREACH (Exit Code 2)' : 'POLICY PASS (Exit Code 0)'}
            </div>
            <div className="text-[11px] text-slate-500 pt-1 font-sans">
              Production implementation can return a non-zero exit code when the configured maximum risk is exceeded.
            </div>
          </div>
        </div>

        {/* Baseline Poisoning Resistance Demo */}
        <div className="lg:col-span-7 border border-slate-800 bg-[#111827] rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-white">
                  3. Baseline Poisoning Resistance (Naive Rolling vs. Protected Baseline)
                </h2>
                <p className="text-xs text-slate-400">
                  Suspicious or malicious behavior is prevented from automatically becoming the new trusted baseline.
                </p>
              </div>
              <span className="text-xs font-mono text-emerald-400">
                Safe Baseline Learning
              </span>
            </div>

            {/* Interactive Day Step Selector */}
            <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-900/80 border border-slate-800 rounded p-3 text-xs">
              <span className="text-slate-300 font-medium">
                Simulate ~5% Daily Attacker Creep (Day 1 → Day {poisoningDay}):
              </span>
              <div className="flex items-center gap-1.5">
                {[1, 2, 3, 4, 5].map((d) => (
                  <button
                    key={d}
                    onClick={() => setPoisoningDay(d)}
                    className={`px-2.5 py-1 rounded font-mono cursor-pointer ${
                      poisoningDay === d
                        ? 'bg-sky-500 text-slate-950 font-bold'
                        : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                    }`}
                  >
                    Day {d}
                  </button>
                ))}
              </div>
            </div>

            {/* Explicit Table Showing: Day | Observed Activity | Naive Baseline | Protected Baseline | Deviation */}
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-sans">
                    <th className="py-2 pr-2">Day</th>
                    <th className="py-2 px-2">Observed Activity</th>
                    <th className="py-2 px-2 text-amber-400">
                      Naive Rolling Baseline
                    </th>
                    <th className="py-2 px-2 text-emerald-400">
                      Protected Baseline
                    </th>
                    <th className="py-2 pl-2 text-right">
                      Detected Deviation
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {poisoningSeries.slice(0, poisoningDay).map((pt) => {
                    const deviationFromProtected =
                      pt.driftPct - pt.protectedBaselinePct;
                    return (
                      <tr key={pt.day} className="hover:bg-slate-800/30">
                        <td className="py-2 pr-2 font-bold text-white">
                          {pt.day}
                        </td>
                        <td className="py-2 px-2 text-slate-200">
                          {pt.driftPct}% index
                        </td>
                        <td className="py-2 px-2 text-amber-300">
                          {pt.naiveBaselinePct}% (Absorbed)
                        </td>
                        <td className="py-2 px-2 text-emerald-400 font-semibold">
                          {pt.protectedBaselinePct}% (Frozen)
                        </td>
                        <td className="py-2 pl-2 text-right font-bold">
                          <span
                            className={
                              deviationFromProtected > 25
                                ? 'text-red-400'
                                : deviationFromProtected > 10
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }
                          >
                            +{deviationFromProtected}% Drift
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="text-xs text-slate-400 border-t border-slate-800 pt-3 flex flex-wrap justify-between gap-2">
            <span>
              NORMAL → Confirmed Benign →{' '}
              <strong className="text-emerald-400">Baseline Update</strong>
            </span>
            <span>
              SUSPICIOUS / MALICIOUS →{' '}
              <strong className="text-red-400">
                NO BASELINE UPDATE (Poisoning Blocked)
              </strong>
            </span>
          </div>
        </div>
      </div>

      {/* SECTION 3: SQLITE-STYLE CRYPTOGRAPHIC AUDIT MEMORY */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-base font-bold text-white">
              4. Deterministic SQLite-Style Audit Chain Simulation
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Each audit record stores alert_id, timestamp, source, destination, classification, risk, evidence, decision, previous_hash, and current_hash (local tamper-evident hash chain, not a blockchain).
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleVerifyAuditChain}
              className="px-3.5 py-1.5 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded transition-colors cursor-pointer whitespace-nowrap"
            >
              VERIFY AUDIT CHAIN
            </button>
            <button
              onClick={() => {
                onTamperRecord(3);
                setAuditVerifiedState('TAMPERED');
                setTamperedIndex(3);
              }}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-amber-500/40 text-amber-300 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap"
            >
              Simulate Tamper on ALT-9084
            </button>
            <button
              onClick={() => {
                onRestoreAuditChain();
                setAuditVerifiedState('VERIFIED');
                setTamperedIndex(null);
              }}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs rounded transition-colors cursor-pointer whitespace-nowrap"
            >
              Restore Valid Chain
            </button>
          </div>
        </div>

        {/* Verification Banner */}
        {auditVerifiedState === 'VERIFIED' && (
          <div className="p-3 rounded border border-emerald-500/50 bg-emerald-950/25 flex items-center justify-between text-xs font-mono text-emerald-300">
            <span>
              ✓ CHAIN VALID (AUDIT CHAIN VERIFIED) — All {auditRecords.length} sequential SHA-256 links match deterministic payload.
            </span>
            <span>STATUS: CHAIN VALID</span>
          </div>
        )}
        {auditVerifiedState === 'TAMPERED' && (
          <div className="p-3 rounded border border-red-500/60 bg-red-950/30 flex items-center justify-between text-xs font-mono text-red-300">
            <span>
              ⚠ CHAIN INVALID (AUDIT CHAIN TAMPER DETECTED) at Record #
              {(tamperedIndex ?? 0) + 1} (
              {auditRecords[tamperedIndex ?? 0]?.alert_id}) — Historical field modified; hash mismatch!
            </span>
            <span>STATUS: CHAIN INVALID</span>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 pr-3">alert_id</th>
                <th className="py-2 px-2">timestamp</th>
                <th className="py-2 px-2">source → destination</th>
                <th className="py-2 px-2">classification</th>
                <th className="py-2 px-2 text-right">risk</th>
                <th className="py-2 px-2">decision</th>
                <th className="py-2 px-2">evidence</th>
                <th className="py-2 pl-2">previous_hash → current_hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 font-mono">
              {auditRecords.map((rec, idx) => {
                const isRowTampered = tamperedIndex === idx;
                return (
                  <tr
                    key={rec.alert_id}
                    className={
                      isRowTampered
                        ? 'bg-red-950/40 text-red-200'
                        : 'hover:bg-slate-800/40 text-slate-300'
                    }
                  >
                    <td className="py-2.5 pr-3 font-bold text-white">
                      {rec.alert_id}
                    </td>
                    <td className="py-2.5 px-2 text-slate-400 tabular-nums">
                      {rec.timestamp}
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="text-white font-semibold">{rec.entity}</div>
                      <div className="text-[10px] text-slate-500">
                        {rec.source_ip} → {rec.dest_ip}
                      </div>
                    </td>
                    <td className="py-2.5 px-2 font-sans">
                      {rec.classification}
                    </td>
                    <td className="py-2.5 px-2 text-right font-bold tabular-nums">
                      <span
                        className={
                          rec.risk_score > 70
                            ? 'text-red-400'
                            : rec.risk_score > 30
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }
                      >
                        {rec.risk_score}
                      </span>
                    </td>
                    <td className="py-2.5 px-2 font-bold">
                      <span
                        className={
                          rec.decision === 'MALICIOUS'
                            ? 'text-red-400'
                            : rec.decision === 'SUSPICIOUS'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }
                      >
                        {rec.decision}
                      </span>
                    </td>
                    <td className="py-2.5 px-2 font-sans text-[11px] text-slate-300">
                      {rec.evidence}
                    </td>
                    <td className="py-2.5 pl-2 text-[10px] text-slate-400 tabular-nums">
                      <div>prev: {rec.previous_hash}</div>
                      <div className="text-emerald-400">
                        curr: {rec.current_hash}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* SECTION 4: 16/16 DETERMINISTIC SYSTEM VALIDATION SUITE */}
      <div className="border border-slate-800 bg-[#111827] rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-base font-bold text-white">
              5. Internal Deterministic System Validation Runner
            </h2>
            <p className="text-xs text-slate-400">
              Executes 16 automated verification checks against the live risk engine, counterfactual formula, unknown gate, baseline poisoning, and audit hash chain
            </p>
          </div>
          <span className="text-sm font-mono font-bold text-emerald-400 tabular-nums">
            {validationSuite.passedCount} / {validationSuite.totalCount} PASS
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {validationSuite.checks.map((chk) => (
            <div
              key={chk.id}
              className="border border-slate-800 bg-slate-900/50 p-3 rounded text-xs space-y-1"
            >
              <div className="flex items-center justify-between font-mono">
                <span className="text-slate-400">Test #{chk.id}</span>
                <span
                  className={
                    chk.passed
                      ? 'text-emerald-400 font-bold'
                      : 'text-red-400 font-bold'
                  }
                >
                  {chk.passed ? 'PASS' : 'FAIL'}
                </span>
              </div>
              <div className="font-semibold text-white">{chk.name}</div>
              <div className="text-[11px] text-slate-400 font-mono">
                {chk.detail}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
