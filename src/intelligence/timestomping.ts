import type { DetectedAnomaly } from "./index.js";

// ─── Timestomping Detector ───────────────────────────────────────────────────
// Detects manipulation of NTFS timestamps by comparing $STANDARD_INFORMATION
// and $FILE_NAME attributes. $FN timestamps can't be easily modified because
// they're stored in the directory entry, not the file itself.

export interface TimestampPair {
  readonly siCreated: number;  // $STANDARD_INFORMATION Created (epoch ms)
  readonly fnCreated: number;  // $FILE_NAME Created (epoch ms)
  readonly siModified: number;
  readonly fnModified: number;
  readonly filename: string;
  readonly inode: string;
}

/**
 * Detect timestomping by comparing $SI vs $FN timestamps.
 * 
 * Rules:
 * 1. $SI Created < $FN Created → CRITICAL (impossible without manipulation)
 * 2. $SI dates are all identical → HIGH (common timestomping tool behavior)
 * 3. $SI times are exact hours/minutes with :00 seconds → MEDIUM (suspicious precision)
 * 4. Large gap between $SI and $FN (>1 year) → MEDIUM (unusual)
 */
export function detectTimestomping(pairs: readonly TimestampPair[]): readonly DetectedAnomaly[] {
  const anomalies: DetectedAnomaly[] = [];

  for (const pair of pairs) {
    // Rule 1: $SI Created earlier than $FN Created (impossible without tampering)
    if (pair.siCreated > 0 && pair.fnCreated > 0 && pair.siCreated < pair.fnCreated) {
      anomalies.push({
        type: "timestomping_si_before_fn",
        severity: "CRITICAL",
        description: `$SI Created is BEFORE $FN Created for "${pair.filename}" (inode ${pair.inode}). This is physically impossible without timestamp manipulation.`,
        evidence: `$SI: ${new Date(pair.siCreated).toISOString()}, $FN: ${new Date(pair.fnCreated).toISOString()}`,
        confidence: 0.95,
        falsePositiveRate: "LOW",
      });
    }

    // Rule 2: All FOUR $SI timestamps identical AND they differ from $FN
    // (a simple copy makes Created=Modified, but fn should still differ from si)
    if (pair.siCreated === pair.siModified && pair.siCreated > 0 &&
        pair.fnCreated > 0 && pair.siCreated !== pair.fnCreated) {
      anomalies.push({
        type: "timestomping_identical_si",
        severity: "HIGH",
        description: `$SI Created === $SI Modified for "${pair.filename}" AND differs from $FN — common timestomping tool artifact`,
        evidence: `$SI: ${new Date(pair.siCreated).toISOString()}, $FN: ${new Date(pair.fnCreated).toISOString()}`,
        confidence: 0.7,
        falsePositiveRate: "MEDIUM",
      });
    }

    // Rule 3 removed — :00 seconds triggers on ALL second-precision timestamps (every NTFS file via istat)

    // Rule 4: Large gap between $SI and $FN (>1 year)
    if (pair.siCreated > 0 && pair.fnCreated > 0) {
      const gapMs = Math.abs(pair.siCreated - pair.fnCreated);
      const oneYear = 365.25 * 24 * 60 * 60 * 1000;
      if (gapMs > oneYear) {
        anomalies.push({
          type: "timestomping_large_gap",
          severity: "MEDIUM",
          description: `>1 year gap between $SI and $FN timestamps for "${pair.filename}"`,
          evidence: `Gap: ${(gapMs / oneYear).toFixed(1)} years. $SI: ${new Date(pair.siCreated).toISOString()}, $FN: ${new Date(pair.fnCreated).toISOString()}`,
          confidence: 0.5,
          falsePositiveRate: "MEDIUM",
        });
      }
    }
  }

  return anomalies;
}
