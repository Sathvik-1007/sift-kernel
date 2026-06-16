import { nanoid } from "nanoid";
import type { Hypothesis, HypothesisId, HypothesisStatus, FindingId } from "./types.js";

// ─── Hypothesis Management ───────────────────────────────────────────────────

export interface RegisterHypothesisInput {
  readonly description: string;
}

export function createHypothesis(input: RegisterHypothesisInput): Hypothesis {
  return {
    id: nanoid() as unknown as HypothesisId,
    description: input.description,
    status: "OPEN",
    supportingFindings: [],
    contradictingFindings: [],
    registeredAt: new Date().toISOString(),
    resolvedAt: undefined,
  };
}

/** Compute hypothesis status based on supporting/contradicting evidence */
export function computeHypothesisStatus(
  supporting: readonly FindingId[],
  contradicting: readonly FindingId[],
): HypothesisStatus {
  if (supporting.length === 0 && contradicting.length === 0) return "OPEN";
  if (contradicting.length > supporting.length) return "REFUTED";
  if (supporting.length >= 2 && contradicting.length === 0) return "SUPPORTED";
  if (supporting.length > 0 && contradicting.length === 0) return "OPEN"; // Not enough to confirm
  return "OPEN"; // Mixed evidence — still investigating
}

/** Update hypothesis with new supporting/contradicting finding */
export function updateHypothesis(
  hypothesis: Hypothesis,
  action: { type: "support" | "contradict"; findingId: FindingId },
): Hypothesis {
  const supporting = action.type === "support"
    ? [...hypothesis.supportingFindings, action.findingId]
    : hypothesis.supportingFindings;
  const contradicting = action.type === "contradict"
    ? [...hypothesis.contradictingFindings, action.findingId]
    : hypothesis.contradictingFindings;

  const status = computeHypothesisStatus(supporting, contradicting);
  const resolvedAt = (status === "SUPPORTED" || status === "REFUTED")
    ? new Date().toISOString()
    : undefined;

  return {
    ...hypothesis,
    supportingFindings: supporting,
    contradictingFindings: contradicting,
    status,
    resolvedAt,
  };
}
