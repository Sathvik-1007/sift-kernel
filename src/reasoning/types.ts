// FARE: Forensic Abductive Reasoning Engine — Core Types
// Implements Carrier 2006 hypothesis-based model computationally via
// DSmT/PCR5 fusion + Active Inference EFE + Rough Sets

/** Focal element: bitmask over hypothesis space (efficient ∩=&, ∪=|) */
export type FocalElement = number;

/** Mass function: sparse map from focal element (bitmask) → mass value ∈ [0,1] */
export type MassFunction = ReadonlyMap<FocalElement, number>;

/** Mutable mass function for construction */
export type MutableMassFunction = Map<FocalElement, number>;

/** Hypothesis definition in the frame of discernment */
export interface Hypothesis {
  readonly id: string;
  readonly index: number; // bit position in bitmask
  readonly description: string;
  readonly mitreTactics: readonly string[];
  readonly priorWeight: number; // relative prior probability
}

/** Belief interval [Bel, Pl] with uncertainty gap */
export interface BeliefInterval {
  readonly belief: number;      // lower bound (sum of mass on subsets of H)
  readonly plausibility: number; // upper bound (1 - Bel(¬H))
  readonly uncertainty: number;  // Pl - Bel
}

/** Evidence mass rule: maps tool output pattern → mass function */
export interface EvidenceMassRule {
  readonly id: string;
  readonly signal: string;
  readonly category: string;
  readonly condition: (output: string) => boolean;
  readonly mass: MassFunction;
  readonly reliability: number; // discount factor ∈ [0,1]
  readonly source: string; // citation (ATT&CK technique, SANS methodology)
}

/** Expected Free Energy score for a candidate tool */
export interface EFEScore {
  readonly tool: string;
  readonly risk: number;       // KL[q(o|π) ‖ p(o)] — distance from preferred state
  readonly ambiguity: number;  // E[H[p(o|s)]] — expected observation entropy
  readonly total: number;      // risk + ambiguity (lower = better)
  readonly explanation: string;
  readonly discriminates: readonly string[]; // hypothesis pairs this tool separates
}

/** Convergence state of the investigation */
export type ConvergenceState =
  | "EXPLORING"   // entropy high/flat — initial phase
  | "CONVERGING"  // entropy monotonically decreasing — learning
  | "CONVERGED"   // entropy below threshold — case resolved
  | "STUCK"       // entropy plateau >5 steps — need different approach
  | "DIVERGING";  // entropy increasing — contradictions/new info

/** Comeback trigger (from Jang et al. 2025 SAGE) */
export type ComebackTrigger =
  | "DIVERGENCE"          // entropy rising → beliefs becoming less certain
  | "STUCK"              // no progress for N steps
  | "COLLAPSE"           // dominant hypothesis suddenly loses support
  | "PREDICTION_FAILURE"; // expected evidence not found where it should be

/** Bias type detected in investigation pattern */
export type BiasType = "confirmation" | "anchoring" | "tunnel_vision";

/** Bias warning with severity */
export interface BiasWarning {
  readonly type: BiasType;
  readonly severity: "LOW" | "MEDIUM" | "HIGH";
  readonly description: string;
  readonly suggestion: string;
}

/** Rough-set approximation result */
export interface RoughApproximation {
  readonly lower: ReadonlySet<string>;    // B_*(X) — definitely in concept
  readonly upper: ReadonlySet<string>;    // B*(X) — possibly in concept
  readonly boundary: ReadonlySet<string>; // BND — undecidable (drives next tool)
  readonly accuracy: number;              // |lower|/|upper| ∈ [0,1]
}

/** Full reasoning state returned after each tool execution */
export interface ReasoningUpdate {
  readonly beliefState: ReadonlyMap<string, BeliefInterval>;
  readonly conflict: number;        // K coefficient from fusion (0=agreement, 1=total conflict)
  readonly entropy: number;         // Generalized Hartley entropy of current mass
  readonly convergenceState: ConvergenceState;
  readonly biasWarnings: readonly BiasWarning[];
  readonly triggeredRules: readonly string[];
  readonly comebackTriggered: ComebackTrigger | null;
  readonly dominantHypothesis: { readonly id: string; readonly belief: number; readonly plausibility: number } | null;
}

/** Action selection result from Active Inference EFE */
export interface ActionSelection {
  readonly tool: string;
  readonly efeScore: EFEScore;
  readonly alternatives: readonly EFEScore[];
  readonly reasoningExplanation: string;
}

/** Full reasoning report for generate_report */
export interface ReasoningReport {
  readonly hypothesisRanking: readonly { id: string; belief: number; plausibility: number }[];
  readonly entropyCurve: readonly number[];
  readonly conflictHistory: readonly number[];
  readonly convergenceState: ConvergenceState;
  readonly biasWarnings: readonly BiasWarning[];
  readonly comebacksTriggered: number;
  readonly rulesTriggered: readonly string[];
  readonly dominantHypothesis: { id: string; belief: number; plausibility: number } | null;
  readonly investigationQuality: "POOR" | "FAIR" | "GOOD" | "EXCELLENT";
}

/** Tool reliability record (adaptive) */
export interface ToolReliability {
  readonly tool: string;
  reliability: number;
  callCount: number;
  informativeCount: number; // times it triggered a significant belief update
}

/** The THETA element — total ignorance (all bits set) */
export const THETA_LABEL = "THETA";
