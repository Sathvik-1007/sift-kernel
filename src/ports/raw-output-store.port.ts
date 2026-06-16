import type { Result } from "neverthrow";
import type { LedgerEntryId } from "../domain/types.js";

// ─── Raw Output Store Port ───────────────────────────────────────────────────

export interface RawOutputStore {
  /** Store raw output and return the file path */
  store(entryId: LedgerEntryId, data: string): Result<string, { message: string }>;

  /** Retrieve raw output by ledger entry ID */
  retrieve(entryId: LedgerEntryId): Result<string, { message: string }>;

  /** Check if raw output exists for an entry */
  exists(entryId: LedgerEntryId): boolean;

  /** Get the storage path for an entry (without retrieving content) */
  getPath(entryId: LedgerEntryId): string;
}
