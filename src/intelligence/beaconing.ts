import type { DetectedAnomaly } from "./index.js";

// ─── C2 Beaconing Detector ───────────────────────────────────────────────────
// Detects periodic callback patterns characteristic of C2 implants.
// Method: interval analysis + jitter measurement.

export interface NetworkCallback {
  readonly timestamp: number; // epoch ms
  readonly dstAddr: string;
  readonly dstPort: number;
  readonly bytes: number;
}

/**
 * Detect C2 beaconing by analyzing callback periodicity.
 * 
 * Algorithm:
 * 1. Group connections by destination (addr:port)
 * 2. For each destination with >5 connections, calculate inter-arrival times
 * 3. Compute mean interval and jitter (coefficient of variation)
 * 4. If CV < threshold (regular) and interval < max_beacon_interval → C2 candidate
 */
export function detectBeaconing(
  callbacks: readonly NetworkCallback[],
  maxJitterCV: number = 0.3,         // Coefficient of variation threshold
  minConnections: number = 5,         // Minimum connections to analyze
  maxBeaconIntervalMs: number = 3600_000, // 1 hour max beacon interval
): readonly DetectedAnomaly[] {
  const anomalies: DetectedAnomaly[] = [];

  // Group by destination
  const groups = new Map<string, NetworkCallback[]>();
  for (const cb of callbacks) {
    const key = `${cb.dstAddr}:${cb.dstPort}`;
    const existing = groups.get(key) ?? [];
    existing.push(cb);
    groups.set(key, existing);
  }

  for (const [dest, conns] of groups) {
    if (conns.length < minConnections) continue;

    // Sort by timestamp
    const sorted = conns.sort((a, b) => a.timestamp - b.timestamp);

    // Calculate inter-arrival times
    const intervals: number[] = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i]!.timestamp - sorted[i - 1]!.timestamp);
    }

    if (intervals.length < 3) continue;

    // Calculate statistics
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, i) => sum + (i - mean) ** 2, 0) / intervals.length;
    const stddev = Math.sqrt(variance);
    const cv = mean > 0 ? stddev / mean : Infinity; // Coefficient of variation

    // Beaconing criteria: regular intervals within threshold
    if (cv <= maxJitterCV && mean <= maxBeaconIntervalMs && mean > 1000) {
      const severity = cv < 0.1 ? "CRITICAL" as const : "HIGH" as const;
      const intervalStr = mean < 60_000
        ? `${(mean / 1000).toFixed(0)}s`
        : `${(mean / 60_000).toFixed(1)}min`;

      anomalies.push({
        type: "c2_beaconing",
        severity,
        description: `Periodic callbacks to ${dest} — interval: ${intervalStr} ± ${(cv * 100).toFixed(1)}% jitter (${conns.length} connections)`,
        evidence: `Mean interval: ${intervalStr}, CV: ${cv.toFixed(3)}, Count: ${conns.length}, Span: ${((sorted[sorted.length - 1]!.timestamp - sorted[0]!.timestamp) / 3600_000).toFixed(1)}h`,
        confidence: cv < 0.1 ? 0.9 : cv < 0.2 ? 0.75 : 0.6,
        falsePositiveRate: cv < 0.1 ? "LOW" : "MEDIUM",
      });
    }
  }

  return anomalies;
}
