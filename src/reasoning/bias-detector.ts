// FARE: Cognitive Bias Detection (Meta-Reasoning)
// Implements: Kahneman & Tversky 1974, Heuer ACH, Sunde & Dror 2019
// Detects: confirmation bias, anchoring, tunnel vision in investigation patterns
// Novel: automated bias detection for forensic AI agents (SANS FOR508 discipline enforcement)

import type { BiasType, BiasWarning } from "./types.js";

/** Action record for bias analysis */
export interface ActionRecord {
  readonly tool: string;
  readonly category: string;
  readonly timestamp: number;
  readonly targetedHypothesis: string | null; // which hypothesis this action primarily tests
  readonly informationGain: number; // how much entropy it reduced
}

/** Configuration */
const CONFIRMATION_THRESHOLD = 0.75; // >75% actions targeting leading hypothesis = bias
const ANCHORING_THRESHOLD = 0.85;    // >85% actions driven by first finding = anchored
const TUNNEL_VISION_MIN_ACTIONS = 8; // check after N actions
const TUNNEL_VISION_UNTESTED = 3;    // >3 hypotheses with 0 tests = tunnel vision

/** Detect all biases from action history */
export function detectBiases(
  history: readonly ActionRecord[],
  leadingHypothesis: string | null,
  allHypotheses: readonly string[]
): readonly BiasWarning[] {
  const warnings: BiasWarning[] = [];

  if (history.length < 5) return warnings; // too early to detect

  const conf = checkConfirmationBias(history, leadingHypothesis);
  if (conf) warnings.push(conf);

  const anchor = checkAnchoring(history);
  if (anchor) warnings.push(anchor);

  const tunnel = checkTunnelVision(history, allHypotheses);
  if (tunnel) warnings.push(tunnel);

  return warnings;
}

/** Confirmation bias: >75% of actions target the leading hypothesis */
function checkConfirmationBias(
  history: readonly ActionRecord[],
  leadingHypothesis: string | null
): BiasWarning | null {
  if (!leadingHypothesis || history.length < 6) return null;

  const targetingLeading = history.filter(a => a.targetedHypothesis === leadingHypothesis).length;
  const ratio = targetingLeading / history.length;

  if (ratio > CONFIRMATION_THRESHOLD) {
    const severity = ratio > 0.9 ? "HIGH" as const : "MEDIUM" as const;
    return {
      type: "confirmation" as BiasType,
      severity,
      description: `${(ratio * 100).toFixed(0)}% of ${history.length} actions target the leading hypothesis "${leadingHypothesis}". ` +
        `Confirmation bias risk: investigating only what supports the current theory.`,
      suggestion: `Test alternative hypotheses. Run tools that could DISPROVE "${leadingHypothesis}" — ` +
        `e.g., if hypothesis is "insider threat", check for external C2 indicators that would suggest APT instead.`,
    };
  }
  return null;
}

/** Anchoring: first finding drives 85%+ of subsequent actions */
function checkAnchoring(history: readonly ActionRecord[]): BiasWarning | null {
  if (history.length < 8) return null;

  // Check if the category of the first finding dominates subsequent actions
  const firstCategory = history[0]?.category;
  if (!firstCategory) return null;

  const subsequent = history.slice(1);
  const sameCategoryCount = subsequent.filter(a => a.category === firstCategory).length;
  const ratio = sameCategoryCount / subsequent.length;

  if (ratio > ANCHORING_THRESHOLD) {
    return {
      type: "anchoring" as BiasType,
      severity: "MEDIUM",
      description: `${(ratio * 100).toFixed(0)}% of actions remain in the "${firstCategory}" category. ` +
        `Anchoring risk: first finding may be overly influencing investigation direction.`,
      suggestion: `Broaden investigation scope. Consider other artifact categories: ` +
        `registry, event logs, network, user activity. The first finding may not be the most significant.`,
    };
  }
  return null;
}

/** Tunnel vision: multiple hypotheses have zero predictions tested */
function checkTunnelVision(
  history: readonly ActionRecord[],
  allHypotheses: readonly string[]
): BiasWarning | null {
  if (history.length < TUNNEL_VISION_MIN_ACTIONS) return null;

  const testedHypotheses = new Set(history.map(a => a.targetedHypothesis).filter(Boolean));
  const untestedCount = allHypotheses.filter(h => !testedHypotheses.has(h)).length;

  if (untestedCount >= TUNNEL_VISION_UNTESTED) {
    const untested = allHypotheses.filter(h => !testedHypotheses.has(h)).slice(0, 4);
    const severity = untestedCount >= 6 ? "HIGH" as const : "MEDIUM" as const;
    return {
      type: "tunnel_vision" as BiasType,
      severity,
      description: `${untestedCount} of ${allHypotheses.length} hypotheses have zero predictions tested after ${history.length} actions. ` +
        `Tunnel vision risk: alternative explanations not considered.`,
      suggestion: `Consider testing: ${untested.join(", ")}. ` +
        `Run at least one tool that specifically targets each untested hypothesis.`,
    };
  }
  return null;
}

/** Determine which hypothesis a tool action primarily targets
 *  Used to populate ActionRecord.targetedHypothesis */
export function inferTargetedHypothesis(
  tool: string,
  category: string,
  activeHypotheses: readonly { id: string; belief: number }[]
): string | null {
  // Map tool categories to most-related hypothesis types
  const categoryHypothesisMap: Record<string, string[]> = {
    filesystem: ["apt_targeted", "apt_opportunistic", "insider_data_theft", "data_exfiltration"],
    registry: ["persistence_established", "apt_targeted", "credential_compromise"],
    event_logs: ["credential_compromise", "lateral_movement", "anti_forensics"],
    execution: ["apt_targeted", "apt_opportunistic", "persistence_established"],
    persistence: ["persistence_established", "apt_targeted", "supply_chain"],
    memory: ["apt_targeted", "apt_opportunistic"],
    network: ["apt_targeted", "data_exfiltration", "lateral_movement"],
    anti_forensics: ["anti_forensics", "apt_targeted"],
    user_activity: ["insider_data_theft", "insider_sabotage", "data_exfiltration"],
    browser: ["insider_data_theft", "credential_compromise"],
  };

  const candidates = categoryHypothesisMap[category] ?? [];
  if (candidates.length === 0) return null;

  // Return the highest-belief hypothesis from candidates
  const ranked = activeHypotheses
    .filter(h => candidates.includes(h.id))
    .sort((a, b) => b.belief - a.belief);

  return ranked[0]?.id ?? candidates[0] ?? null;
}
