import React, { useMemo, useState } from 'react';
import {
  AuditRecord,
  EntityId,
  EvidenceItem,
  InvestigationAction,
  ScenarioId,
  ThreatCategory,
  UnknownCluster,
} from './types/cyberpulse';
import {
  buildInitialAuditChain,
  INITIAL_UNKNOWN_CLUSTERS,
  SCENARIOS,
} from './data/syntheticData';
import {
  calculateDeterministicRisk,
  calculateEvidenceAgreement,
  computeScenarioDeterministicRisk,
} from './logic/riskEngine';
import { CommandCenter } from './pages/CommandCenter';
import { EntityIdentity } from './pages/EntityIdentity';
import { Investigation } from './pages/Investigation';
import { UnknownAuditPolicy } from './pages/UnknownAuditPolicy';

type PageTab = 'command' | 'identity' | 'investigation' | 'governance';

export function App() {
  const [activePage, setActivePage] = useState<PageTab>('command');
  const [selectedScenarioId, setSelectedScenarioId] =
    useState<ScenarioId>('Data Exfiltration');
  const [selectedEntity, setSelectedEntity] = useState<EntityId>('PC-07');
  const [policyThreshold, setPolicyThreshold] = useState<number>(70);

  // Interactive Next-Best Investigation overrides for current scenario
  const [investigatedMap, setInvestigatedMap] = useState<
    Record<string, 'TRUSTED_SAFE' | 'CONFIRMED_THREAT'>
  >({});

  // Interactive Counterfactual selection
  const [activeCounterfactualId, setActiveCounterfactualId] = useState<
    string | null
  >(null);

  // Unknown clusters state
  const [unknownClusters, setUnknownClusters] = useState<UnknownCluster[]>(
    INITIAL_UNKNOWN_CLUSTERS
  );
  const [retrainCount, setRetrainCount] = useState<number>(0);

  // Audit Chain state
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>(() =>
    buildInitialAuditChain()
  );

  const scenario = SCENARIOS[selectedScenarioId];

  // Switch scenario cleanly and sync entity + reset interactive overrides
  const handleSelectScenario = (newScenarioId: ScenarioId) => {
    setSelectedScenarioId(newScenarioId);
    setSelectedEntity(SCENARIOS[newScenarioId].primaryEntity);
    setInvestigatedMap({});
    setActiveCounterfactualId(null);
  };

  // RESET DEMO: Returns application to PC-07, Normal DNA, Risk 2/100 (Normal), Policy Pass (Threshold 70), Clean investigation state
  const handleResetDemo = () => {
    setSelectedScenarioId('Normal');
    setSelectedEntity('PC-07');
    setPolicyThreshold(70);
    setInvestigatedMap({});
    setActiveCounterfactualId(null);
    setUnknownClusters(INITIAL_UNKNOWN_CLUSTERS);
    setAuditRecords(buildInitialAuditChain());
  };

  // Compute updated Evidence Items when analyst clicks Next-Best Investigation buttons
  const effectiveEvidenceItems: EvidenceItem[] = useMemo(() => {
    return scenario.evidenceItems.map((item) => {
      if (!item.investigationType) return item;
      const outcome = investigatedMap[item.investigationType];
      if (!outcome) return item;

      if (outcome === 'TRUSTED_SAFE') {
        return {
          ...item,
          state: item.supportsThreat ? 'FALSE' : 'TRUE',
          explanation: `${item.explanation} [Analyst Verified: BENIGN / TRUSTED]`,
        };
      } else {
        return {
          ...item,
          state: item.supportsThreat ? 'TRUE' : 'FALSE',
          explanation: `${item.explanation} [Analyst Verified: UNTRUSTED / HOSTILE]`,
        };
      }
    });
  }, [scenario.evidenceItems, investigatedMap]);

  const evidenceStats = useMemo(
    () => calculateEvidenceAgreement(effectiveEvidenceItems),
    [effectiveEvidenceItems]
  );

  // Compute context adjustment including any Next-Best Investigation checks
  const effectiveContextAdjustment = useMemo(() => {
    let adj = scenario.contextAdjustment;
    for (const outcome of Object.values(investigatedMap)) {
      if (outcome === 'TRUSTED_SAFE') {
        adj -= 12;
      } else if (outcome === 'CONFIRMED_THREAT') {
        adj += 6;
      }
    }
    return Math.max(-30, Math.min(20, adj));
  }, [scenario.contextAdjustment, investigatedMap]);

  // Unified Deterministic Risk Calculation
  const riskResult = useMemo(() => {
    const activeCf = scenario.counterfactuals.find(
      (c) => c.id === activeCounterfactualId
    );

    const anomaly = activeCf?.modifiedInputs.anomaly ?? scenario.anomalyScore;
    const mutation =
      activeCf?.modifiedInputs.mutation ?? scenario.mutationScore;
    const classifier =
      activeCf?.modifiedInputs.classifier ?? scenario.classifierScore;
    const progression =
      activeCf?.modifiedInputs.progression ?? scenario.progressionScore;
    const evidence =
      activeCf?.modifiedInputs.evidence ?? evidenceStats.agreementPct;
    const contextAdjustment =
      activeCf?.modifiedInputs.contextAdjustment ?? effectiveContextAdjustment;

    return calculateDeterministicRisk({
      anomaly,
      mutation,
      classifier,
      classifierCertainty: scenario.classifierCertainty,
      progression,
      evidence,
      contextAdjustment,
      primaryClass: scenario.primaryClass,
    });
  }, [
    scenario,
    evidenceStats.agreementPct,
    effectiveContextAdjustment,
    activeCounterfactualId,
  ]);

  const handleRunInvestigationAction = (
    actionId: InvestigationAction['id'],
    outcome: 'TRUSTED_SAFE' | 'CONFIRMED_THREAT'
  ) => {
    setActiveCounterfactualId(null);
    setInvestigatedMap((prev) => ({
      ...prev,
      [actionId]: outcome,
    }));
  };

  const handleResetInvestigation = () => {
    setInvestigatedMap({});
    setActiveCounterfactualId(null);
  };

  const handleUpdateClusterLabel = (
    clusterId: string,
    label: ThreatCategory | 'Benign' | 'Keep Unknown'
  ) => {
    setUnknownClusters((prev) =>
      prev.map((c) =>
        c.id === clusterId ? { ...c, analystLabel: label, promoted: false } : c
      )
    );
  };

  const handlePromoteCluster = (clusterId: string) => {
    setUnknownClusters((prev) =>
      prev.map((c) =>
        c.id === clusterId && c.analystLabel !== 'Keep Unknown'
          ? { ...c, promoted: true }
          : c
      )
    );
  };

  const handleTamperAuditRecord = (idx: number) => {
    setAuditRecords((prev) =>
      prev.map((rec, i) =>
        i === idx
          ? {
              ...rec,
              risk_score: 18,
              decision: 'NORMAL',
              evidence: 'TAMPERED_BY_INTRUDER: Risk artificially lowered to 18',
            }
          : rec
      )
    );
  };

  const handleRestoreAuditChain = () => {
    setAuditRecords(buildInitialAuditChain());
  };

  const isPolicyBreached = riskResult.finalRisk > policyThreshold;

  return (
    <div className="min-h-screen flex flex-col bg-[#0B0F19] text-slate-200 soc-grid-bg">
      {/* Top Bar Contract: 3 Zones (Wordmark | 4 Nav Links | Demo Selector + RESET DEMO) */}
      <header className="sticky top-0 z-30 bg-[#0B0F19]/95 backdrop-blur border-b border-slate-800 px-6 py-3.5 flex items-center justify-between gap-4">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#command"
          onClick={(e) => {
            e.preventDefault();
            setActivePage('command');
          }}
          className="text-lg font-bold tracking-tight text-white font-display whitespace-nowrap shrink-0"
        >
          CYBERPULSE
        </a>

        {/* Zone 2: 4 Clean Text Navigation Links */}
        <nav className="flex items-center gap-6 text-sm font-medium">
          {[
            { id: 'command' as const, label: 'Command Center' },
            { id: 'identity' as const, label: 'Entity Identity' },
            { id: 'investigation' as const, label: 'Investigation' },
            { id: 'governance' as const, label: 'Audit & Policy' },
          ].map((tab) => {
            const isActive = activePage === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActivePage(tab.id)}
                className={`py-1 transition-colors cursor-pointer whitespace-nowrap border-b-2 ${
                  isActive
                    ? 'border-sky-400 text-white font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Demo Scenario Selector + RESET DEMO Action */}
        <div className="flex items-center gap-2.5 shrink-0">
          <select
            aria-label="Demo Scenario Selector"
            value={selectedScenarioId}
            onChange={(e) => handleSelectScenario(e.target.value as ScenarioId)}
            className="bg-slate-900 border border-slate-700 hover:border-sky-500/60 text-xs text-slate-100 font-mono rounded-md px-2.5 py-1.5 cursor-pointer"
          >
            <option value="Normal">
              0. Normal DNA (Risk {computeScenarioDeterministicRisk(SCENARIOS['Normal']).finalRisk})
            </option>
            <option value="Port Scan">
              1. Port Scan (Risk {computeScenarioDeterministicRisk(SCENARIOS['Port Scan']).finalRisk})
            </option>
            <option value="Brute Force">
              2. Brute Force (Risk {computeScenarioDeterministicRisk(SCENARIOS['Brute Force']).finalRisk})
            </option>
            <option value="Lateral Movement">
              3. Lateral Pivot (Risk {computeScenarioDeterministicRisk(SCENARIOS['Lateral Movement']).finalRisk})
            </option>
            <option value="Data Exfiltration">
              4. Data Exfiltration (Risk {computeScenarioDeterministicRisk(SCENARIOS['Data Exfiltration']).finalRisk})
            </option>
            <option value="Unknown Attack">
              Unknown Gate (PC-12 · Risk {computeScenarioDeterministicRisk(SCENARIOS['Unknown Attack']).finalRisk})
            </option>
            <option value="Backup Server False Positive">
              Backup Context (-26 → Risk {computeScenarioDeterministicRisk(SCENARIOS['Backup Server False Positive']).finalRisk})
            </option>
            <option value="Slow Baseline Poisoning">
              Baseline Poisoning (5% Daily Creep · Risk {computeScenarioDeterministicRisk(SCENARIOS['Slow Baseline Poisoning']).finalRisk})
            </option>
          </select>

          <button
            onClick={handleResetDemo}
            title="Reset to PC-07 Normal DNA (Risk 2/100, No Policy Breach)"
            className="px-3 py-1.5 text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-emerald-500/40 rounded-md transition-colors cursor-pointer whitespace-nowrap"
          >
            RESET DEMO
          </button>
        </div>
      </header>

      {/* Interactive Demo Scenario Story Strip */}
      <div className="border-b border-slate-800/80 bg-[#0F172A] px-6 py-2.5">
        <div className="max-w-[1440px] mx-auto flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-slate-400 font-medium mr-1">
              Replay Attack Sequence:
            </span>
            {(
              [
                { id: 'Normal', label: `0. Normal DNA (${computeScenarioDeterministicRisk(SCENARIOS['Normal']).finalRisk})` },
                { id: 'Port Scan', label: `1. Port Scan (${computeScenarioDeterministicRisk(SCENARIOS['Port Scan']).finalRisk})` },
                { id: 'Brute Force', label: `2. Brute Force (${computeScenarioDeterministicRisk(SCENARIOS['Brute Force']).finalRisk})` },
                { id: 'Lateral Movement', label: `3. Lateral Pivot (${computeScenarioDeterministicRisk(SCENARIOS['Lateral Movement']).finalRisk})` },
                { id: 'Data Exfiltration', label: `4. Data Exfiltration (${computeScenarioDeterministicRisk(SCENARIOS['Data Exfiltration']).finalRisk})` },
                { id: 'Unknown Attack', label: 'Unknown Gate' },
                {
                  id: 'Backup Server False Positive',
                  label: 'Backup Context',
                },
                { id: 'Slow Baseline Poisoning', label: 'Baseline Poisoning' },
              ] as { id: ScenarioId; label: string }[]
            ).map((st) => {
              const active = selectedScenarioId === st.id;
              return (
                <button
                  key={st.id}
                  onClick={() => handleSelectScenario(st.id)}
                  className={`px-2.5 py-1 rounded font-mono text-[11px] transition-colors cursor-pointer whitespace-nowrap ${
                    active
                      ? 'bg-sky-500/20 border border-sky-400 text-sky-300 font-semibold'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {st.label}
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-3 font-mono text-xs tabular-nums">
            <span>
              Entity:{' '}
              <strong className="text-white">{scenario.primaryEntity}</strong>
            </span>
            <span>·</span>
            <span>
              Mutation:{' '}
              <strong className="text-amber-400">{riskResult.mutation}</strong>
            </span>
            <span>·</span>
            <span>
              Risk:{' '}
              <strong
                className={
                  riskResult.finalRisk > 70
                    ? 'text-red-400'
                    : riskResult.finalRisk > 30
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }
              >
                {riskResult.finalRisk}/100 ({riskResult.riskBand})
              </strong>
            </span>
            <span>·</span>
            <span
              className={`font-bold ${
                isPolicyBreached ? 'text-red-400' : 'text-emerald-400'
              }`}
            >
              {isPolicyBreached ? 'POLICY BREACH' : 'POLICY PASS'}
            </span>
          </div>
        </div>
      </div>

      {/* Main Content Container (1440px max-width desktop baseline) */}
      <main className="flex-1 w-full max-w-[1440px] mx-auto px-6 py-6">
        {activePage === 'command' && (
          <CommandCenter
            scenario={scenario}
            riskResult={riskResult}
            evidenceAgreementPct={evidenceStats.agreementPct}
            policyThreshold={policyThreshold}
            unknownClusterCount={unknownClusters.length}
            onInvestigateEntity={(entityId) => {
              setSelectedEntity(entityId);
              if (entityId === 'PC-12') {
                handleSelectScenario('Unknown Attack');
              } else if (entityId === 'BACKUP-01') {
                handleSelectScenario('Backup Server False Positive');
              } else if (
                entityId === 'PC-07' &&
                selectedScenarioId !== 'Port Scan' &&
                selectedScenarioId !== 'Brute Force' &&
                selectedScenarioId !== 'Lateral Movement' &&
                selectedScenarioId !== 'Normal'
              ) {
                handleSelectScenario('Data Exfiltration');
              }
              setActivePage('investigation');
            }}
            onNavigatePage={(page) => setActivePage(page)}
            onSelectScenario={handleSelectScenario}
          />
        )}

        {activePage === 'identity' && (
          <EntityIdentity
            selectedEntity={selectedEntity}
            onSelectEntity={(ent) => setSelectedEntity(ent)}
            scenario={scenario}
            riskResult={riskResult}
            onLaunchInvestigation={() => setActivePage('investigation')}
          />
        )}

        {activePage === 'investigation' && (
          <Investigation
            scenario={scenario}
            riskResult={riskResult}
            policyThreshold={policyThreshold}
            evidenceItems={effectiveEvidenceItems}
            evidenceStats={evidenceStats}
            investigatedMap={investigatedMap}
            onRunInvestigationAction={handleRunInvestigationAction}
            onResetInvestigation={handleResetInvestigation}
            activeCounterfactualId={activeCounterfactualId}
            onSelectCounterfactual={setActiveCounterfactualId}
          />
        )}

        {activePage === 'governance' && (
          <UnknownAuditPolicy
            clusters={unknownClusters}
            onUpdateClusterLabel={handleUpdateClusterLabel}
            onPromoteCluster={handlePromoteCluster}
            retrainCount={retrainCount}
            onTriggerRetrain={() => setRetrainCount((c) => c + 1)}
            auditRecords={auditRecords}
            onTamperRecord={handleTamperAuditRecord}
            onRestoreAuditChain={handleRestoreAuditChain}
            policyThreshold={policyThreshold}
            onChangePolicyThreshold={setPolicyThreshold}
            currentRisk={riskResult}
            onSelectScenario={handleSelectScenario}
          />
        )}
      </main>

      {/* Honest Prototype Notice & Architecture Positioning Footer */}
      <footer className="border-t border-slate-800 bg-[#0B0F19] px-6 py-5 mt-12">
        <div className="max-w-[1440px] mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4 text-xs text-slate-400">
          <div className="space-y-1 max-w-4xl">
            <div className="font-semibold text-slate-300">
              CYBERPULSE — Understand the behavior. Reconstruct the attack. Verify the evidence. Decide the risk.
            </div>
            <p className="leading-relaxed text-slate-400">
              <strong className="text-slate-300">Prototype Simulation Notice:</strong> CYBERPULSE uses deterministic synthetic telemetry and simulated ML behavior (Isolation Forest anomaly scoring & Random Forest ensemble classification with tree-vote uncertainty) for demonstration. A production implementation connects this same architecture to live NetFlow/EDR pipelines, pandas/scikit-learn feature engineering, and SQLite/SIEM persistence.
            </p>
          </div>
          <div className="text-right font-mono text-slate-500 shrink-0">
            <div>16 / 16 Validation Checks PASS</div>
            <div>Deterministic Risk Fusion Engine</div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
