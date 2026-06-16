import type { DetectedAnomaly } from "./index.js";

// ─── Log Gap Detector ────────────────────────────────────────────────────────
// Detects gaps in sequential Event Record IDs that indicate log clearing/tampering.

export interface EventRecord {
  readonly recordId: number;
  readonly timestamp: string;
  readonly eventId: number;
  readonly channel: string;
}

/**
 * Detect log gaps by analyzing sequential record IDs.
 * 
 * Method:
 * 1. Sort by record ID
 * 2. Find gaps (missing sequential IDs)
 * 3. Score by gap size and context
 */
export function detectLogGaps(
  records: readonly EventRecord[],
  minGapSize: number = 5,
): readonly DetectedAnomaly[] {
  if (records.length < 2) return [];

  const anomalies: DetectedAnomaly[] = [];

  // Partition by channel — EVTX record IDs are per-channel sequences
  const byChannel = new Map<string, EventRecord[]>();
  for (const r of records) {
    const ch = r.channel || "unknown";
    const arr = byChannel.get(ch);
    if (arr) arr.push(r);
    else byChannel.set(ch, [r]);
  }

  for (const [channel, channelRecords] of byChannel) {
    if (channelRecords.length < 2) continue;

    // Sort by recordId within this channel
    const sorted = [...channelRecords].sort((a, b) => a.recordId - b.recordId);

  // Find gaps
  const gaps: Array<{ start: number; end: number; size: number; beforeTs: string; afterTs: string }> = [];
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1]!;
    const curr = sorted[i]!;
    const gap = curr.recordId - prev.recordId - 1;
    if (gap >= minGapSize) {
      gaps.push({
        start: prev.recordId + 1,
        end: curr.recordId - 1,
        size: gap,
        beforeTs: prev.timestamp,
        afterTs: curr.timestamp,
      });
    }
  }

  for (const gap of gaps) {
    const severity = gap.size > 1000 ? "CRITICAL" as const :
                     gap.size > 100 ? "HIGH" as const : "MEDIUM" as const;
    anomalies.push({
      type: "event_log_gap",
      severity,
      description: `[${channel}] Gap of ${gap.size} missing record(s) (IDs ${gap.start}-${gap.end}). Events between ${gap.beforeTs} and ${gap.afterTs} may have been cleared.`,
      evidence: `Channel: ${channel}. Missing: records ${gap.start} to ${gap.end} (${gap.size} events)`,
      confidence: gap.size > 100 ? 0.9 : 0.7,
      falsePositiveRate: gap.size > 100 ? "LOW" : "MEDIUM",
    });
  }
  } // end channel loop

  // Check for EID 1102 (audit log cleared) or EID 104 (System log cleared)
  const clearEvents = records.filter(r => r.eventId === 1102 || r.eventId === 104);
  if (clearEvents.length > 0) {
    anomalies.push({
      type: "log_cleared_event",
      severity: "CRITICAL",
      description: `${clearEvents.length} log-clearing event(s) found (EID 1102/104). Explicit evidence of log tampering.`,
      evidence: clearEvents.map(e => `EID ${e.eventId} at ${e.timestamp}`).join("; "),
      confidence: 0.99,
      falsePositiveRate: "LOW",
    });
  }

  return anomalies;
}
