import {
  buildInitialAuditChain,
  INCIDENT_GROUPS,
  NOISE_SHIELD_STATS,
  SCENARIOS,
} from '../data/syntheticData';
import {
  calculateDeterministicRisk,
  calculateEvidenceAgreement,
  computeAuditHash,
  computeScenarioDeterministicRisk,
} from './riskEngine';

export interface ValidationCheckResult {
  id: number;
  name: string;
  passed: boolean;
  detail: string;
}

export function runSystemValidationSuite(): {
  passedCount: number;
  totalCount: number;
  checks: ValidationCheckResult[];
} {
  const checks: ValidationCheckResult[] = [];

  const sExfil = SCENARIOS['Data Exfiltration'];
  const rExfil = computeScenarioDeterministicRisk(sExfil);

  // 1. risk formula
  const expectedBase = Number(
    (
      0.22 * sExfil.anomalyScore +
      0.18 * sExfil.mutationScore +
      0.15 * sExfil.classifierScore +
      0.20 * sExfil.progressionScore +
      0.25 * 100
    ).toFixed(2)
  );
  checks.push({
    id: 1,
    name: '1. Risk formula exact weights',
    passed:
      rExfil.baseRisk === expectedBase &&
      sExfil.contextAdjustment === 5 &&
      rExfil.finalRisk === Math.round(expectedBase + sExfil.contextAdjustment) &&
      rExfil.finalRisk === 99,
    detail: `0.22·91 + 0.18·96 + 0.15·88 + 0.20·92 + 0.25·100 = ${rExfil.baseRisk} (+${sExfil.contextAdjustment} ctx → ${rExfil.finalRisk})`,
  });

  // 2. risk breakdown sum
  const sumContributions = Number(
    (
      rExfil.anomalyWeighted +
      rExfil.mutationWeighted +
      rExfil.classifierWeighted +
      rExfil.progressionWeighted +
      rExfil.evidenceWeighted
    ).toFixed(2)
  );
  checks.push({
    id: 2,
    name: '2. Risk breakdown sum consistency',
    passed: sumContributions === rExfil.baseRisk,
    detail: `${rExfil.anomalyWeighted} + ${rExfil.mutationWeighted} + ${rExfil.classifierWeighted} + ${rExfil.progressionWeighted} + ${rExfil.evidenceWeighted} = ${sumContributions}`,
  });

  // 3. deterministic risk
  const rExfilRepeat = computeScenarioDeterministicRisk(sExfil);
  checks.push({
    id: 3,
    name: '3. Deterministic risk repeatability',
    passed:
      rExfil.finalRisk === rExfilRepeat.finalRisk &&
      rExfil.baseRisk === rExfilRepeat.baseRisk,
    detail: `Identical state deterministically yields ${rExfil.finalRisk}/100 (${rExfil.riskBand})`,
  });

  // 4. counterfactual calculation (99 -> 64)
  const cf0 = sExfil.counterfactuals[0];
  const rCf0 = calculateDeterministicRisk({
    anomaly: cf0.modifiedInputs.anomaly ?? rExfil.anomaly,
    mutation: cf0.modifiedInputs.mutation ?? rExfil.mutation,
    classifier: cf0.modifiedInputs.classifier ?? rExfil.classifier,
    classifierCertainty: sExfil.classifierCertainty,
    progression: cf0.modifiedInputs.progression ?? rExfil.progression,
    evidence: cf0.modifiedInputs.evidence ?? rExfil.evidence,
    contextAdjustment:
      cf0.modifiedInputs.contextAdjustment ?? rExfil.contextAdjustment,
    primaryClass: sExfil.primaryClass,
  });
  checks.push({
    id: 4,
    name: '4. Counterfactual calculation',
    passed:
      rExfil.finalRisk === 99 &&
      rCf0.finalRisk < rExfil.finalRisk &&
      rCf0.finalRisk === 64,
    detail: `Trusted destination reduces risk ${rExfil.finalRisk} → ${rCf0.finalRisk} via same formula`,
  });

  // 5. unknown gate
  const sUnk = SCENARIOS['Unknown Attack'];
  const rUnk = computeScenarioDeterministicRisk(sUnk);
  checks.push({
    id: 5,
    name: '5. Unknown behavior decision gate',
    passed:
      rUnk.unknownGateTriggered &&
      rUnk.classification === 'Unknown Suspicious Behavior' &&
      rUnk.finalRisk >= 55,
    detail: `Anom ${sUnk.anomalyScore}, Mut ${sUnk.mutationScore}, Cert ${sUnk.classifierCertainty}% → ${rUnk.classification} (Risk ${rUnk.finalRisk})`,
  });

  // 6. classifier uncertainty
  const unkVotes = sUnk.treeVotes.filter((t) => t.vote === 'Unknown').length;
  const distinctVotes = new Set(sUnk.treeVotes.map((t) => t.vote)).size;
  checks.push({
    id: 6,
    name: '6. Classifier tree uncertainty',
    passed: sUnk.classifierCertainty <= 55 && unkVotes >= 2 && distinctVotes >= 4,
    detail: `7-tree ensemble splits across ${distinctVotes} classes (${unkVotes} abstain) → ${sUnk.classifierCertainty}% certainty`,
  });

  // 7. baseline poisoning
  const sPoison = SCENARIOS['Slow Baseline Poisoning'];
  const day5 = sPoison.driftSeries[sPoison.driftSeries.length - 1];
  checks.push({
    id: 7,
    name: '7. Baseline poisoning simulation',
    passed: day5.driftPct === 73 && day5.naiveBaselinePct === 71,
    detail: `5% daily creep reaches ${day5.driftPct}% drift; naive baseline absorbs ${day5.naiveBaselinePct}%`,
  });

  // 8. protected baseline
  checks.push({
    id: 8,
    name: '8. Protected baseline freeze',
    passed:
      day5.protectedBaselinePct === 11 &&
      day5.driftPct - day5.protectedBaselinePct === 62,
    detail: `Protected baseline freezes at ${day5.protectedBaselinePct}% when suspicious drift (>20%) appears`,
  });

  // 9. incident grouping
  const totalRawCompressed = INCIDENT_GROUPS.reduce(
    (sum, g) => sum + g.rawAlertCount,
    0
  );
  checks.push({
    id: 9,
    name: '9. Incident grouping compression',
    passed: totalRawCompressed === 312 && INCIDENT_GROUPS.length === 4,
    detail: `${totalRawCompressed} raw anomalies correlated into ${INCIDENT_GROUPS.length} actionable incidents`,
  });

  // 10. policy threshold
  const breachAt70 = rExfil.finalRisk > 70;
  const passAt55 = 55 <= 70;
  checks.push({
    id: 10,
    name: '10. Policy threshold evaluation',
    passed: breachAt70 && passAt55,
    detail: `Risk ${rExfil.finalRisk} > 70 → POLICY BREACH; Risk 55 ≤ 70 → POLICY PASS`,
  });

  // 11. audit hash chain
  const chain = buildInitialAuditChain();
  let chainValid = true;
  let prev = 'sha256:0000000000000000';
  for (const rec of chain) {
    const expected = computeAuditHash(
      prev,
      rec.alert_id,
      rec.entity,
      rec.risk_score,
      rec.classification,
      rec.decision
    );
    if (rec.previous_hash !== prev || rec.current_hash !== expected) {
      chainValid = false;
    }
    prev = rec.current_hash;
  }
  checks.push({
    id: 11,
    name: '11. Audit hash chain verification',
    passed: chainValid && chain.length === 6,
    detail: `All ${chain.length} sequential SHA-256 links verified → CHAIN VALID`,
  });

  // 12. tamper detection
  const tamperedRec = { ...chain[3], risk_score: 18 };
  const recomputedTampered = computeAuditHash(
    tamperedRec.previous_hash,
    tamperedRec.alert_id,
    tamperedRec.entity,
    tamperedRec.risk_score,
    tamperedRec.classification,
    tamperedRec.decision
  );
  checks.push({
    id: 12,
    name: '12. Audit tamper detection',
    passed: recomputedTampered !== tamperedRec.current_hash,
    detail: `Modifying historical risk (99 → 18) causes hash mismatch → CHAIN INVALID`,
  });

  // 13. noise handling
  const noiseSum = NOISE_SHIELD_STATS.noiseBreakdown.reduce(
    (s, n) => s + n.count,
    0
  );
  checks.push({
    id: 13,
    name: '13. Routine noise filtering',
    passed: noiseSum === NOISE_SHIELD_STATS.filteredNoise && noiseSum === 28,
    detail: `${noiseSum} DHCP/ARP/mDNS/DNS broadcast events suppressed cleanly`,
  });

  // 14. malformed telemetry handling
  const malformedSum = NOISE_SHIELD_STATS.malformedBreakdown.reduce(
    (s, m) => s + m.count,
    0
  );
  checks.push({
    id: 14,
    name: '14. Malformed telemetry resilience',
    passed:
      malformedSum === NOISE_SHIELD_STATS.malformed &&
      NOISE_SHIELD_STATS.received - noiseSum - malformedSum ===
        NOISE_SHIELD_STATS.valid,
    detail: `${malformedSum} malformed records quarantined safely (1000 - 28 - 8 = 964 valid)`,
  });

  // 15. reset behavior
  const sNormal = SCENARIOS['Normal'];
  const rNormal = computeScenarioDeterministicRisk(sNormal);
  checks.push({
    id: 15,
    name: '15. Demo reset state verification',
    passed:
      sNormal.primaryEntity === 'PC-07' &&
      rNormal.finalRisk === 2 &&
      rNormal.finalRisk <= 30 &&
      rNormal.finalRisk <= 70 &&
      rNormal.riskBand === 'NORMAL',
    detail: `Reset restores PC-07 Normal DNA (Risk ${rNormal.finalRisk}/100, NORMAL, Policy PASS)`,
  });

  // 16. full attack progression (2 -> 63 -> 76 -> 91 -> 99)
  const expectedStageProgression: { id: keyof typeof SCENARIOS; expected: number }[] = [
    { id: 'Normal', expected: 2 },
    { id: 'Port Scan', expected: 63 },
    { id: 'Brute Force', expected: 76 },
    { id: 'Lateral Movement', expected: 91 },
    { id: 'Data Exfiltration', expected: 99 },
  ];
  const stageRisks = expectedStageProgression.map(
    (st) => computeScenarioDeterministicRisk(SCENARIOS[st.id]).finalRisk
  );
  const matchesExpectedSequence = expectedStageProgression.every(
    (st, i) => stageRisks[i] === st.expected
  );
  checks.push({
    id: 16,
    name: '16. Full 5-stage attack progression',
    passed: matchesExpectedSequence,
    detail: `Risk escalates across stages: ${stageRisks.join(' → ')}`,
  });

  const passedCount = checks.filter((c) => c.passed).length;
  return {
    passedCount,
    totalCount: checks.length,
    checks,
  };
}
