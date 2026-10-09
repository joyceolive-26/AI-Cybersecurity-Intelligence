import {
  EvidenceItem,
  RiskBand,
  RiskCalculationResult,
  ThreatCategory,
} from '../types/cyberpulse';

/**
 * Deterministic Risk Fusion Formula:
 * BaseRisk = 0.22 * Anomaly + 0.18 * Mutation + 0.15 * Classifier + 0.20 * Progression + 0.25 * Evidence
 * FinalRisk = clamp(BaseRisk + ContextAdjustment, 0, 100)
 *
 * Unknown Decision Gate:
 * If Anomaly >= 75, Mutation >= 70, ClassifierConfidence <= 55, and Evidence <= 60:
 * Classification = 'Unknown Suspicious Behavior'
 * FinalRisk = max(FinalRisk, 55)
 */
export function calculateDeterministicRisk(params: {
  anomaly: number;
  mutation: number;
  classifier: number;
  classifierCertainty: number;
  progression: number;
  evidence: number;
  contextAdjustment: number;
  primaryClass: ThreatCategory;
}): RiskCalculationResult {
  const anomaly = Math.max(0, Math.min(100, params.anomaly));
  const mutation = Math.max(0, Math.min(100, params.mutation));
  const classifier = Math.max(0, Math.min(100, params.classifier));
  const progression = Math.max(0, Math.min(100, params.progression));
  const evidence = Math.max(0, Math.min(100, params.evidence));
  const contextAdjustment = Math.max(-35, Math.min(25, params.contextAdjustment));

  const anomalyWeighted = Number((0.22 * anomaly).toFixed(2));
  const mutationWeighted = Number((0.18 * mutation).toFixed(2));
  const classifierWeighted = Number((0.15 * classifier).toFixed(2));
  const progressionWeighted = Number((0.20 * progression).toFixed(2));
  const evidenceWeighted = Number((0.25 * evidence).toFixed(2));

  const baseRisk = Number(
    (
      anomalyWeighted +
      mutationWeighted +
      classifierWeighted +
      progressionWeighted +
      evidenceWeighted
    ).toFixed(2)
  );

  const unknownGateTriggered =
    anomaly >= 75 &&
    mutation >= 70 &&
    params.classifierCertainty <= 55 &&
    evidence <= 60;

  let rawFinal = Math.max(
    0,
    Math.min(100, Number((baseRisk + contextAdjustment).toFixed(2)))
  );
  if (unknownGateTriggered) {
    rawFinal = Math.max(rawFinal, 55);
  }

  const finalRisk = Math.round(rawFinal);

  const classification: ThreatCategory = unknownGateTriggered
    ? 'Unknown Suspicious Behavior'
    : params.primaryClass;

  const riskBand: RiskBand =
    finalRisk <= 30 ? 'NORMAL' : finalRisk <= 70 ? 'SUSPICIOUS' : 'MALICIOUS';

  return {
    anomaly,
    mutation,
    classifier,
    progression,
    evidence,
    anomalyWeighted,
    mutationWeighted,
    classifierWeighted,
    progressionWeighted,
    evidenceWeighted,
    baseRisk,
    contextAdjustment,
    unknownGateTriggered,
    finalRisk,
    riskBand,
    classification,
  };
}

/**
 * Calculate Evidence Agreement Score:
 * Supporting evidence / Evaluated evidence
 */
export function calculateEvidenceAgreement(items: EvidenceItem[]): {
  supportingCount: number;
  evaluatedCount: number;
  unknownCount: number;
  contradictingCount: number;
  agreementPct: number;
} {
  let supportingCount = 0;
  let evaluatedCount = 0;
  let unknownCount = 0;
  let contradictingCount = 0;

  for (const item of items) {
    if (item.state === 'UNKNOWN') {
      unknownCount += 1;
    } else {
      evaluatedCount += 1;
      const isSupporting =
        (item.supportsThreat && item.state === 'TRUE') ||
        (!item.supportsThreat && item.state === 'FALSE');
      if (isSupporting) {
        supportingCount += 1;
      } else {
        contradictingCount += 1;
      }
    }
  }

  const agreementPct =
    evaluatedCount === 0
      ? 50
      : Math.round((supportingCount / evaluatedCount) * 100);

  return {
    supportingCount,
    evaluatedCount,
    unknownCount,
    contradictingCount,
    agreementPct,
  };
}

/**
 * Authoritative deterministic risk calculation for any scenario dataset
 */
export function computeScenarioDeterministicRisk(scenario: {
  anomalyScore: number;
  mutationScore: number;
  classifierScore: number;
  classifierCertainty: number;
  progressionScore: number;
  contextAdjustment: number;
  primaryClass: ThreatCategory;
  evidenceItems: EvidenceItem[];
}): RiskCalculationResult {
  const evidence = calculateEvidenceAgreement(scenario.evidenceItems).agreementPct;
  return calculateDeterministicRisk({
    anomaly: scenario.anomalyScore,
    mutation: scenario.mutationScore,
    classifier: scenario.classifierScore,
    classifierCertainty: scenario.classifierCertainty,
    progression: scenario.progressionScore,
    evidence,
    contextAdjustment: scenario.contextAdjustment,
    primaryClass: scenario.primaryClass,
  });
}

/**
 * Deterministic lightweight hash generator for SQLite-style audit chain verification
 */
export function computeAuditHash(
  prevHash: string,
  alertId: string,
  entity: string,
  riskScore: number,
  classification: string,
  decision: string
): string {
  const payload = `${prevHash}|${alertId}|${entity}|${riskScore}|${classification}|${decision}`;
  let h1 = 0xdeadbeef ^ payload.length;
  let h2 = 0x41c6ce57 ^ payload.length;
  for (let i = 0, ch; i < payload.length; i++) {
    ch = payload.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 =
    Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^
    Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 =
    Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^
    Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const hex1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const hex2 = (h2 >>> 0).toString(16).padStart(8, '0');
  return `sha256:${hex1}${hex2}`;
}
