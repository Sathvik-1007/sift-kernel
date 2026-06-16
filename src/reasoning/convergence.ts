// FARE: Convergence Monitor + Comeback Mechanism
// Implements: entropy-based phase detection + backward FSM transitions
// Reference: Jang et al. 2025 SAGE ("return to abductive reasoning when hypothesis engenders doubt")
// Novel: formal comeback triggers with precision decay for forensic investigation

import type { ConvergenceState, ComebackTrigger } from "./types.js";

/** Configuration for convergence detection */
const CONVERGENCE_THRESHOLD = 0.5;  // entropy below this = CONVERGED
const STUCK_WINDOW = 5;             // consecutive similar-entropy steps = STUCK
const STUCK_TOLERANCE = 0.05;       // entropy change < this = "no movement"
const DIVERGENCE_THRESHOLD = 0.15;  // entropy increase > this = DIVERGING
const MAX_COMEBACKS = 2;            // prevent infinite revisitation
const COLLAPSE_THRESHOLD = 0.3;     // dominant hypothesis drops this much = COLLAPSE

/** Convergence tracker state */
export interface ConvergenceTracker {
  readonly entropyCurve: readonly number[];
  readonly conflictHistory: readonly number[];
  readonly dominantHistory: readonly { hypothesis: string; belief: number }[];
  readonly comebackCount: number;
  readonly state: ConvergenceState;
}

/** Create initial tracker */
export function createConvergenceTracker(): ConvergenceTracker {
  return { entropyCurve: [], conflictHistory: [], dominantHistory: [], comebackCount: 0, state: "EXPLORING" };
}

/** Record a new entropy measurement and detect state transitions */
export function updateConvergence(
  tracker: ConvergenceTracker,
  entropy: number,
  conflict: number,
  dominant: { hypothesis: string; belief: number } | null
): { tracker: ConvergenceTracker; state: ConvergenceState; comebackTriggered: ComebackTrigger | null } {
  const newEntropyCurve = [...tracker.entropyCurve, entropy];
  const newConflictHistory = [...tracker.conflictHistory, conflict];
  const newDominantHistory = dominant
    ? [...tracker.dominantHistory, dominant]
    : [...tracker.dominantHistory];

  let newState = detectState(newEntropyCurve);
  let comebackTriggered: ComebackTrigger | null = null;

  // Check comeback triggers (only if under max comeback limit)
  if (tracker.comebackCount < MAX_COMEBACKS) {
    comebackTriggered = checkComebackTriggers(newEntropyCurve, newConflictHistory, newDominantHistory);
  }

  // If comeback triggered, force state to EXPLORING (restart investigation path)
  let newComebackCount = tracker.comebackCount;
  if (comebackTriggered) {
    newState = "EXPLORING";
    newComebackCount++;
  }

  return {
    tracker: {
      entropyCurve: newEntropyCurve,
      conflictHistory: newConflictHistory,
      dominantHistory: newDominantHistory,
      comebackCount: newComebackCount,
      state: newState,
    },
    state: newState,
    comebackTriggered,
  };
}

/** Detect convergence state from entropy curve */
function detectState(curve: readonly number[]): ConvergenceState {
  if (curve.length < 3) return "EXPLORING";

  const latest = curve[curve.length - 1];

  // CONVERGED: entropy below threshold
  if (latest !== undefined && latest < CONVERGENCE_THRESHOLD) return "CONVERGED";

  // Check recent trend (last 5 steps)
  const window = curve.slice(-STUCK_WINDOW);
  if (window.length >= STUCK_WINDOW) {
    const first = window[0];
    const last = window[window.length - 1];
    if (first !== undefined && last !== undefined) {
      const delta = last - first;

      // STUCK: no meaningful change
      if (Math.abs(delta) < STUCK_TOLERANCE) return "STUCK";

      // DIVERGING: entropy increasing
      if (delta > DIVERGENCE_THRESHOLD) return "DIVERGING";
    }
  }

  // Check if monotonically decreasing (last 3 steps)
  const recent = curve.slice(-3);
  if (recent.length >= 3) {
    const r0 = recent[0];
    const r1 = recent[1];
    const r2 = recent[2];
    if (r0 !== undefined && r1 !== undefined && r2 !== undefined) {
      if (r0 > r1 && r1 > r2) return "CONVERGING";
    }
  }

  return "EXPLORING";
}

/** Check all comeback triggers (Jang et al. 2025 SAGE mechanism) */
function checkComebackTriggers(
  entropyCurve: readonly number[],
  conflictHistory: readonly number[],
  dominantHistory: readonly { hypothesis: string; belief: number }[]
): ComebackTrigger | null {
  // 1. DIVERGENCE: entropy rising significantly over 3+ steps
  if (entropyCurve.length >= 4) {
    const recent = entropyCurve.slice(-4);
    const r0 = recent[0];
    const r3 = recent[3];
    if (r0 !== undefined && r3 !== undefined && r3 - r0 > DIVERGENCE_THRESHOLD * 2) {
      return "DIVERGENCE";
    }
  }

  // 2. STUCK: no entropy change for STUCK_WINDOW steps
  if (entropyCurve.length >= STUCK_WINDOW + 2) {
    const window = entropyCurve.slice(-(STUCK_WINDOW + 2));
    const first = window[0];
    const last = window[window.length - 1];
    if (first !== undefined && last !== undefined && Math.abs(last - first) < STUCK_TOLERANCE) {
      return "STUCK";
    }
  }

  // 3. COLLAPSE: dominant hypothesis suddenly drops
  if (dominantHistory.length >= 3) {
    const prev = dominantHistory[dominantHistory.length - 2];
    const curr = dominantHistory[dominantHistory.length - 1];
    if (prev && curr && prev.hypothesis === curr.hypothesis) {
      if (prev.belief - curr.belief > COLLAPSE_THRESHOLD) {
        return "COLLAPSE";
      }
    }
  }

  // 4. PREDICTION_FAILURE: high conflict after expected-confirming tool
  if (conflictHistory.length >= 2) {
    const latestConflict = conflictHistory[conflictHistory.length - 1];
    const prevConflict = conflictHistory[conflictHistory.length - 2];
    if (latestConflict !== undefined && prevConflict !== undefined) {
      if (latestConflict > 0.5 && latestConflict - prevConflict > 0.2) {
        return "PREDICTION_FAILURE";
      }
    }
  }

  return null;
}

/** Get the learning rate (derivative of entropy curve) */
export function getLearningRate(tracker: ConvergenceTracker): number {
  const curve = tracker.entropyCurve;
  if (curve.length < 2) return 0;
  const last = curve[curve.length - 1];
  const prev = curve[curve.length - 2];
  if (last === undefined || prev === undefined) return 0;
  return prev - last; // positive = learning (entropy dropping), negative = diverging
}

/** Get investigation progress as percentage toward convergence */
export function getConvergenceProgress(tracker: ConvergenceTracker): number {
  if (tracker.entropyCurve.length === 0) return 0;
  const initial = tracker.entropyCurve[0] ?? Math.log2(12); // max entropy for 12 hypotheses
  const current = tracker.entropyCurve[tracker.entropyCurve.length - 1] ?? initial;
  const target = CONVERGENCE_THRESHOLD;
  if (initial <= target) return 100;
  const progress = ((initial - current) / (initial - target)) * 100;
  return Math.max(0, Math.min(100, progress));
}

/** Generate SVG entropy curve for HTML report visualization */
export function generateEntropySVG(tracker: ConvergenceTracker, width: number = 400, height: number = 120): string {
  const curve = tracker.entropyCurve;
  if (curve.length < 2) return `<svg width="${width}" height="${height}"><text x="50%" y="50%" text-anchor="middle" fill="#888">Insufficient data</text></svg>`;

  const maxEntropy = Math.max(...curve, Math.log2(12));
  const padding = 30;
  const plotW = width - padding * 2;
  const plotH = height - padding * 2;

  // Build path
  const points = curve.map((e, i) => {
    const x = padding + (i / (curve.length - 1)) * plotW;
    const y = padding + (1 - e / maxEntropy) * plotH;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const pathD = `M ${points.join(" L ")}`;

  // Convergence threshold line
  const thresholdY = padding + (1 - CONVERGENCE_THRESHOLD / maxEntropy) * plotH;

  // Color based on state
  const stateColor = tracker.state === "CONVERGED" ? "#4caf50"
    : tracker.state === "CONVERGING" ? "#2196f3"
    : tracker.state === "DIVERGING" ? "#f44336"
    : tracker.state === "STUCK" ? "#ff9800"
    : "#9e9e9e";

  return `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
  <defs><linearGradient id="eg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${stateColor}" stop-opacity="0.3"/><stop offset="100%" stop-color="${stateColor}" stop-opacity="0.05"/></linearGradient></defs>
  <rect width="${width}" height="${height}" fill="#1a1a2e" rx="8"/>
  <line x1="${padding}" y1="${thresholdY.toFixed(1)}" x2="${width - padding}" y2="${thresholdY.toFixed(1)}" stroke="#4caf50" stroke-dasharray="4" opacity="0.5"/>
  <text x="${width - padding + 4}" y="${thresholdY.toFixed(1)}" fill="#4caf50" font-size="9">converged</text>
  <path d="${pathD} L ${(padding + plotW).toFixed(1)},${(padding + plotH).toFixed(1)} L ${padding},${(padding + plotH).toFixed(1)} Z" fill="url(#eg)"/>
  <path d="${pathD}" fill="none" stroke="${stateColor}" stroke-width="2"/>
  <text x="${padding}" y="${height - 5}" fill="#aaa" font-size="10">Step 1</text>
  <text x="${width - padding - 30}" y="${height - 5}" fill="#aaa" font-size="10">Step ${curve.length}</text>
  <text x="${width / 2}" y="15" fill="#ddd" font-size="11" text-anchor="middle">Entropy: ${curve[curve.length - 1]?.toFixed(2) ?? "?"} bits (${tracker.state})</text>
</svg>`;
}
