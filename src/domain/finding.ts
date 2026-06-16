import { nanoid } from "nanoid";
import { ok, err, type Result } from "neverthrow";
import type {
  Finding,
  FindingId,
  FindingType,
  ConfidenceLevel,
  LedgerEntryId,
  HypothesisId,
  IOC,
  MitreTactic,
  ArtifactCategory,
} from "./types.js";
import { findingError, type FindingError } from "./errors.js";

// ─── Finding Registration ────────────────────────────────────────────────────

export interface RegisterFindingInput {
  readonly type: FindingType;
  readonly description: string;
  readonly evidence: readonly LedgerEntryId[];
  readonly temporalRange?: { readonly start: string; readonly end: string };
  readonly mitreTechnique?: string;
  readonly mitreTactic?: MitreTactic;
  readonly affectedHosts?: readonly string[];
  readonly iocs?: readonly IOC[];
  readonly supportsHypotheses?: readonly HypothesisId[];
  readonly contradictsHypotheses?: readonly HypothesisId[];
}

/**
 * Compute confidence level based on evidence diversity.
 * This is DETERMINISTIC — no LLM involved.
 */
export function computeConfidence(
  evidence: readonly LedgerEntryId[],
  getCategoryForEntry: (id: LedgerEntryId) => ArtifactCategory | undefined,
): ConfidenceLevel {
  if (evidence.length === 0) return "HYPOTHESIZED";
  if (evidence.length === 1) return "INFERRED";

  // Check if evidence comes from different artifact categories
  const categories = new Set<ArtifactCategory>();
  for (const id of evidence) {
    const cat = getCategoryForEntry(id);
    if (cat) categories.add(cat);
  }

  if (categories.size >= 2) return "CONFIRMED";
  return "SUPPORTED";
}

/**
 * Register a finding with validation.
 * Rejects findings with zero evidence (hallucination prevention).
 */
export function createFinding(
  input: RegisterFindingInput,
  existingLedgerIds: ReadonlySet<string>,
  getCategoryForEntry: (id: LedgerEntryId) => ArtifactCategory | undefined,
): Result<Finding, FindingError> {
  // CRITICAL INVARIANT: No finding without evidence
  if (input.evidence.length === 0) {
    return err(
      findingError(
        "register",
        "Cannot register a finding with zero evidence. Every finding MUST link to at least one ledger entry.",
        "Run forensic tools first, then reference their ledger entry IDs in the evidence array.",
      ),
    );
  }

  // Validate evidence links exist
  const missingEvidence = input.evidence.filter(
    (id) => !existingLedgerIds.has(id as string),
  );
  if (missingEvidence.length > 0) {
    return err(
      findingError(
        "register",
        `Evidence IDs not found in ledger: ${missingEvidence.join(", ")}`,
        "Ensure all evidence IDs reference existing ledger entries from prior tool executions.",
      ),
    );
  }

  // Compute confidence — deduplicate evidence first to prevent inflation
  const uniqueEvidence = [...new Set(input.evidence.map((id) => id as string))] as unknown as readonly LedgerEntryId[];
  const confidence = computeConfidence(uniqueEvidence, getCategoryForEntry);

  // Note: HYPOTHESIZED findings are allowed as investigation markers
  // but cannot appear in the final report (enforced by generate_report)

  const finding: Finding = {
    id: nanoid() as unknown as FindingId,
    type: input.type,
    description: input.description,
    evidence: input.evidence,
    confidence,
    temporalRange: input.temporalRange,
    mitreTechnique: input.mitreTechnique,
    mitreTactic: input.mitreTactic,
    affectedHosts: input.affectedHosts ?? [],
    iocs: input.iocs ?? [],
    supportsHypotheses: input.supportsHypotheses ?? [],
    contradictsHypotheses: input.contradictsHypotheses ?? [],
    registeredAt: new Date().toISOString(),
    lastReassessed: undefined,
  };

  return ok(finding);
}

/**
 * Reassess a finding's confidence based on new evidence.
 * Returns updated finding or error if finding not found.
 */
export function reassessFinding(
  finding: Finding,
  additionalEvidence: readonly LedgerEntryId[],
  existingLedgerIds: ReadonlySet<string>,
  getCategoryForEntry: (id: LedgerEntryId) => ArtifactCategory | undefined,
): Result<Finding, FindingError> {
  // Validate new evidence
  const missingEvidence = additionalEvidence.filter(
    (id) => !existingLedgerIds.has(id as string),
  );
  if (missingEvidence.length > 0) {
    return err(
      findingError(
        "reassess",
        `Additional evidence IDs not found: ${missingEvidence.join(", ")}`,
        "Provide valid ledger entry IDs.",
        finding.id,
      ),
    );
  }

  const allEvidence = [...finding.evidence, ...additionalEvidence];
  const newConfidence = computeConfidence(allEvidence, getCategoryForEntry);

  return ok({
    ...finding,
    evidence: allEvidence,
    confidence: newConfidence,
    lastReassessed: new Date().toISOString(),
  });
}

/**
 * Check if two findings conflict (describe contradictory conclusions).
 * This is a helper — actual conflict detection uses finding metadata.
 */
export function findingsConflict(a: Finding, b: Finding): boolean {
  // Same temporal range, same hosts, but different conclusions about same technique
  if (a.mitreTechnique && b.mitreTechnique && a.mitreTechnique === b.mitreTechnique) {
    // Same technique but one supports and one contradicts the same hypothesis
    const aSupports = new Set(a.supportsHypotheses.map(String));
    const bContradicts = new Set(b.contradictsHypotheses.map(String));
    for (const h of aSupports) {
      if (bContradicts.has(h)) return true;
    }
    const bSupports = new Set(b.supportsHypotheses.map(String));
    const aContradicts = new Set(a.contradictsHypotheses.map(String));
    for (const h of bSupports) {
      if (aContradicts.has(h)) return true;
    }
  }
  return false;
}
