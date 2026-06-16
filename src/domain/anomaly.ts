import type { AnomalyId, AnomalySeverity, LedgerEntryId } from "./types.js";
import { nanoid } from "nanoid";

// ─── Anomaly Types ───────────────────────────────────────────────────────────

export interface AnomalyDetection {
  readonly type: string;
  readonly severity: AnomalySeverity;
  readonly description: string;
  readonly affectedEntries: readonly string[];
}

export function createAnomaly(
  detection: AnomalyDetection,
  sourceLedgerEntry: LedgerEntryId,
): {
  readonly id: AnomalyId;
  readonly type: string;
  readonly severity: AnomalySeverity;
  readonly description: string;
  readonly sourceLedgerEntry: LedgerEntryId;
  readonly affectedEntries: readonly string[];
  readonly detectedAt: string;
} {
  return {
    id: nanoid() as unknown as AnomalyId,
    type: detection.type,
    severity: detection.severity,
    description: detection.description,
    sourceLedgerEntry: sourceLedgerEntry,
    affectedEntries: detection.affectedEntries,
    detectedAt: new Date().toISOString(),
  };
}
