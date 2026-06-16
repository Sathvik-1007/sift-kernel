import type { Result } from "neverthrow";
import type { LedgerEntry, LedgerEntryId, FindingId } from "../domain/types.js";
import type { LedgerError } from "../domain/errors.js";

// ─── Ledger Store Port ───────────────────────────────────────────────────────

export interface LedgerStore {
  /** Append a new entry to the ledger */
  append(entry: LedgerEntry): Result<LedgerEntryId, LedgerError>;

  /** Get an entry by ID */
  getEntry(id: LedgerEntryId): Result<LedgerEntry, LedgerError>;

  /** Get all entries (ordered by timestamp) */
  getAllEntries(): readonly LedgerEntry[];

  /** Get the last entry (for hash chain linking) */
  getLastEntry(): LedgerEntry | null;

  /** Get entries by tool name */
  getEntriesByTool(tool: string): readonly LedgerEntry[];

  /** Verify the entire hash chain */
  verifyChain(): Result<{ valid: boolean; entryCount: number; message: string }, LedgerError>;

  /** Trace provenance: find all entries that led to a finding */
  traceProvenance(findingId: FindingId): readonly LedgerEntry[];

  /** Check if an entry ID exists */
  exists(id: LedgerEntryId): boolean;

  /** Get all entry IDs as a set (for validation) */
  getAllIds(): ReadonlySet<string>;

  /** Get entry count */
  count(): number;
}
