// ─── Intelligence Layer: Anomaly Detectors ───────────────────────────────────
// Pure deterministic detectors. No LLM. No AI. Pattern matching + statistics.

export { detectTimestomping } from "./timestomping.js";
export { detectBurstActivity } from "./burst-detector.js";
export { detectLogGaps } from "./log-gap.js";
export { detectKnownBadPaths } from "./known-bad-paths.js";
export { detectBeaconing } from "./beaconing.js";
export { detectWipingTools, detectAntiAnalysis } from "./wiping-tools.js";

export interface DetectedAnomaly {
  readonly type: string;
  readonly severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  readonly description: string;
  readonly evidence: string;
  readonly confidence: number; // 0.0-1.0
  readonly falsePositiveRate: "LOW" | "MEDIUM" | "HIGH";
}
