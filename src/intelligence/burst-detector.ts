import type { DetectedAnomaly } from "./index.js";

// ─── Burst Activity Detector ─────────────────────────────────────────────────
// Detects statistical anomalies in event timing — sudden spikes of activity.

export interface TimedEvent {
  readonly timestamp: number; // epoch ms
  readonly label: string;
}

/**
 * Detect burst activity using a sliding window approach.
 * 
 * Method:
 * 1. Bucket events into windows (default: 1 minute)
 * 2. Calculate mean and std dev of events per window
 * 3. Flag windows > mean + (threshold * stddev)
 */
export function detectBurstActivity(
  events: readonly TimedEvent[],
  windowMs: number = 60_000,
  thresholdSigma: number = 3,
): readonly DetectedAnomaly[] {
  if (events.length < 10) return [];

  const anomalies: DetectedAnomaly[] = [];

  // Sort by timestamp
  const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);
  if (sorted.length === 0) return [];

  const start = sorted[0]!.timestamp;
  const end = sorted[sorted.length - 1]!.timestamp;
  const totalWindows = Math.ceil((end - start) / windowMs);

  if (totalWindows < 3) return [];

  // Count events per window
  const buckets = new Map<number, number>();
  for (const event of sorted) {
    const bucket = Math.floor((event.timestamp - start) / windowMs);
    buckets.set(bucket, (buckets.get(bucket) ?? 0) + 1);
  }

  // Fill empty buckets
  const counts: number[] = [];
  for (let i = 0; i <= totalWindows; i++) {
    counts.push(buckets.get(i) ?? 0);
  }

  // Calculate mean and stddev
  const mean = counts.reduce((a, b) => a + b, 0) / counts.length;
  const variance = counts.reduce((sum, c) => sum + (c - mean) ** 2, 0) / counts.length;
  const stddev = Math.sqrt(variance);

  if (stddev === 0) return [];

  const threshold = mean + thresholdSigma * stddev;

  // Find bursts
  for (let i = 0; i < counts.length; i++) {
    if (counts[i]! > threshold) {
      const windowStart = new Date(start + i * windowMs).toISOString();
      const sigma = ((counts[i]! - mean) / stddev).toFixed(1);
      anomalies.push({
        type: "activity_burst",
        severity: counts[i]! > mean + 5 * stddev ? "CRITICAL" : "HIGH",
        description: `${counts[i]} events in ${windowMs / 1000}s window at ${windowStart} (${sigma}σ above mean of ${mean.toFixed(1)})`,
        evidence: `Window: ${windowStart}, Count: ${counts[i]}, Mean: ${mean.toFixed(1)}, Threshold: ${threshold.toFixed(1)}`,
        confidence: Math.min(0.95, 0.5 + (counts[i]! - threshold) / (threshold * 2)),
        falsePositiveRate: "MEDIUM",
      });
    }
  }

  return anomalies;
}
