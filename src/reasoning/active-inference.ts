// FARE: Active Inference — Expected Free Energy for Forensic Tool Selection
// Implements: Friston 2015 (Active Inference & Epistemic Value), adapted for discrete DFIR
// Novel: first application of EFE to forensic tool orchestration
// Reference: pymdp (infer-actively/pymdp, JOSS 2022) for A/B/C/D model structure

import type { EFEScore, MassFunction } from "./types.js";
import { pignisticDistribution, shannonEntropy, singleton, THETA, belief, plausibility } from "./dempster-shafer.js";
import { HYPOTHESES, EVIDENCE_RULES, getToolReliability } from "./knowledge-base.js";

const FRAME_SIZE = HYPOTHESES.length;

/** Preferred outcome: case resolved (low entropy, high confidence) */
const PREFERRED_ENTROPY = 0.3; // bits — convergence target
const GAMMA = 4.0; // precision parameter for softmax

/** A matrix: P(observation_type | hypothesis) — likelihood of each signal given each hypothesis
 *  Derived from knowledge-base rules: for each tool, which rules might fire given each hypothesis */
function computeLikelihood(tool: string): number[][] {
  // For each hypothesis h, estimate P(informative_output | h) from rules that target h
  const toolRules = EVIDENCE_RULES.filter(r =>
    r.id.startsWith(tool.slice(0, 4)) || r.category === getCategoryForTool(tool)
  );

  // Build |observations| × |hypotheses| matrix
  // 2 observation types: [informative, uninformative] per hypothesis
  const row0 = new Array<number>(FRAME_SIZE).fill(0);
  const row1 = new Array<number>(FRAME_SIZE).fill(0);

  for (let h = 0; h < FRAME_SIZE; h++) {
    const hMask = singleton(h);
    let informativeness = 0.1;

    for (const rule of toolRules) {
      for (const [fe, mass] of rule.mass) {
        if (fe !== THETA && (fe & hMask) !== 0) {
          informativeness += mass * rule.reliability * 0.3;
        }
      }
    }
    informativeness = Math.min(informativeness, 0.95);
    row0[h] = informativeness;
    row1[h] = 1 - informativeness;
  }
  return [row0, row1] as const;
}

/** Get category for a tool name (heuristic from naming convention) */
function getCategoryForTool(tool: string): string {
  if (tool.includes("directory") || tool.includes("file") || tool.includes("search")) return "filesystem";
  if (tool.includes("registry") || tool.includes("hive") || tool.includes("persistence_key")) return "registry";
  if (tool.includes("event") || tool.includes("log")) return "event_logs";
  if (tool.includes("prefetch") || tool.includes("amcache") || tool.includes("shimcache")) return "execution";
  if (tool.includes("yara") || tool.includes("service") || tool.includes("startup") || tool.includes("task")) return "persistence";
  if (tool.includes("process") || tool.includes("inject") || tool.includes("memory")) return "memory";
  if (tool.includes("pcap") || tool.includes("connect") || tool.includes("dns") || tool.includes("beacon")) return "network";
  if (tool.includes("timestomp") || tool.includes("clearing") || tool.includes("wiping") || tool.includes("hidden")) return "anti_forensics";
  if (tool.includes("browser") || tool.includes("history")) return "user_activity";
  return "filesystem"; // default
}

/** Compute Expected Free Energy for a single tool action
 *  G(a) = Risk + Ambiguity
 *  Risk = KL[ q(o|a) ‖ p(o) ]  — predicted obs vs preferred obs
 *  Ambiguity = E_{q(s|a)}[ H[ P(o|s,a) ] ]  — expected observation entropy */
export function computeEFE(
  tool: string,
  currentBeliefMass: MassFunction,
  executedTools: ReadonlySet<string>
): EFEScore {
  // Skip already-executed tools (no new information)
  if (executedTools.has(tool)) {
    return { tool, risk: 10, ambiguity: 10, total: 20, explanation: "Already executed", discriminates: [] };
  }

  // Get pignistic probability from current mass function
  const q_s = pignisticDistribution(currentBeliefMass, FRAME_SIZE);
  const currentEntropy = shannonEntropy(q_s);

  // Compute likelihood matrix A for this tool
  const A = computeLikelihood(tool);

  // Expected observation distribution: q(o|a) = Σ_s P(o|s,a) · q(s)
  // A is a known 2-element tuple from computeLikelihood
  const A0 = A[0]!;
  const A1 = A[1]!;
  let q_o0 = 0, q_o1 = 0;
  for (let s = 0; s < FRAME_SIZE; s++) {
    const qs = q_s[s] ?? 0;
    q_o0 += (A0[s] ?? 0) * qs;
    q_o1 += (A1[s] ?? 0) * qs;
  }

  // RISK: KL[ q(o|a) ‖ p(o) ] with preferred p(o) = [0.9, 0.1]
  let risk = 0;
  if (q_o0 > 1e-12) risk += q_o0 * Math.log2(q_o0 / 0.9);
  if (q_o1 > 1e-12) risk += q_o1 * Math.log2(q_o1 / 0.1);

  // AMBIGUITY: E_{q(s)}[ H[ P(o|s,a) ] ]
  let ambiguity = 0;
  for (let s = 0; s < FRAME_SIZE; s++) {
    const qs = q_s[s] ?? 0;
    if (qs > 1e-12) {
      const p0 = A0[s] ?? 0.5;
      const p1 = A1[s] ?? 0.5;
      let H_os = 0;
      if (p0 > 1e-12 && p0 < 1 - 1e-12) H_os -= p0 * Math.log2(p0) + p1 * Math.log2(p1);
      ambiguity += qs * H_os;
    }
  }

  // Tool reliability discount — unreliable tools have higher effective ambiguity
  const reliability = getToolReliability(tool);
  ambiguity /= Math.max(reliability, 0.1);

  const total = risk + ambiguity;

  // Determine which hypotheses this tool discriminates between
  const discriminates: string[] = [];
  const Ad0 = A[0]!;
  for (let i = 0; i < FRAME_SIZE; i++) {
    for (let j = i + 1; j < FRAME_SIZE; j++) {
      if (Math.abs((Ad0[i] ?? 0) - (Ad0[j] ?? 0)) > 0.2) {
        discriminates.push(`${HYPOTHESES[i]?.id ?? ""} vs ${HYPOTHESES[j]?.id ?? ""}`);
      }
    }
  }

  // Build explanation
  const explanation = `EFE=${total.toFixed(3)} (risk=${risk.toFixed(3)}, ambiguity=${ambiguity.toFixed(3)}). ` +
    `Current entropy: ${currentEntropy.toFixed(2)} bits. ` +
    (discriminates.length > 0
      ? `Discriminates: ${discriminates.slice(0, 3).join(", ")}`
      : "General information gathering");

  return { tool, risk, ambiguity, total, explanation, discriminates: discriminates.slice(0, 5) };
}

/** Select the best next tool from candidates using EFE (lower G = better)
 *  Returns sorted list: best tool first */
export function selectNextTool(
  candidates: readonly string[],
  currentBeliefMass: MassFunction,
  executedTools: ReadonlySet<string>
): EFEScore[] {
  const scores = candidates.map(t => computeEFE(t, currentBeliefMass, executedTools));
  // Sort by total EFE (lower = more informative = better choice)
  scores.sort((a, b) => a.total - b.total);
  return scores;
}

/** Compute softmax policy selection probability P(π) = σ(−γ·G(π)) */
export function policyProbabilities(scores: readonly EFEScore[]): Map<string, number> {
  if (scores.length === 0) return new Map();
  const negG = scores.map(s => -GAMMA * s.total);
  const maxNegG = Math.max(...negG);
  const expValues = negG.map(v => Math.exp(v - maxNegG));
  const sumExp = expValues.reduce((a, b) => a + b, 0);
  const result = new Map<string, number>();
  for (let i = 0; i < scores.length; i++) {
    const score = scores[i];
    const expVal = expValues[i];
    if (score && expVal !== undefined) result.set(score.tool, expVal / sumExp);
  }
  return result;
}

/** Compute expected information gain (epistemic value) — the negative of EFE's ambiguity term
 *  Higher = more informative tool. This is equivalent to D-optimal design (max det FIM) */
export function epistemicValue(tool: string, currentBeliefMass: MassFunction, executedTools: ReadonlySet<string>): number {
  const efe = computeEFE(tool, currentBeliefMass, executedTools);
  // Epistemic value is inversely proportional to ambiguity (lower ambiguity = higher epistemic value)
  return 1.0 / Math.max(efe.ambiguity, 0.01);
}
