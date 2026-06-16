import { createHash } from "node:crypto";
import type { LedgerEntry, LedgerEntryId, FindingId, AnomalyId, Capability } from "./types.js";
import { nanoid } from "nanoid";

// ─── Hash Chain Logic ────────────────────────────────────────────────────────

const GENESIS_HASH = createHash("sha256").update("GENESIS").digest("hex");

/** Serialize a ledger entry deterministically for hashing */
export function serializeEntry(entry: LedgerEntry): string {
  return JSON.stringify({
    id: entry.id,
    tool: entry.tool,
    params: entry.params,
    outputHash: entry.outputHash,
    rawOutputPath: entry.rawOutputPath,
    timestamp: entry.timestamp,
    prevHash: entry.prevHash,
    capabilitiesHeld: [...entry.capabilitiesHeld].sort(),
    findingsProduced: [...entry.findingsProduced],
    anomaliesFlagged: [...entry.anomaliesFlagged],
    durationMs: entry.durationMs,
    success: entry.success,
    errorMessage: entry.errorMessage,
  });
}

/** Compute hash of a serialized entry */
export function hashEntry(entry: LedgerEntry): string {
  return createHash("sha256").update(serializeEntry(entry)).digest("hex");
}

/** Compute hash of arbitrary data (for output hashing) */
export function hashData(data: unknown): string {
  return createHash("sha256").update(JSON.stringify(data)).digest("hex");
}

/** Get the genesis hash (used as prevHash for the first entry) */
export function getGenesisHash(): string {
  return GENESIS_HASH;
}

/** Create a new ledger entry */
export function createLedgerEntry(params: {
  tool: string;
  toolParams: Record<string, unknown>;
  outputHash: string;
  rawOutputPath: string;
  prevHash: string;
  capabilitiesHeld: readonly Capability[];
  findingsProduced: readonly FindingId[];
  anomaliesFlagged: readonly AnomalyId[];
  durationMs: number;
  success: boolean;
  errorMessage?: string;
}): LedgerEntry {
  const id = nanoid() as unknown as LedgerEntryId;
  return {
    id,
    tool: params.tool,
    params: params.toolParams,
    outputHash: params.outputHash,
    rawOutputPath: params.rawOutputPath,
    timestamp: new Date().toISOString(),
    prevHash: params.prevHash,
    capabilitiesHeld: params.capabilitiesHeld,
    findingsProduced: params.findingsProduced,
    anomaliesFlagged: params.anomaliesFlagged,
    durationMs: params.durationMs,
    success: params.success,
    errorMessage: params.errorMessage,
  };
}

/** Verify a chain of entries is valid */
export function verifyChain(entries: readonly LedgerEntry[]): {
  valid: boolean;
  brokenAt?: number;
  message: string;
} {
  if (entries.length === 0) {
    return { valid: true, message: "Empty chain is valid" };
  }

  // First entry must reference genesis
  if (entries[0]!.prevHash !== GENESIS_HASH) {
    return {
      valid: false,
      brokenAt: 0,
      message: `First entry prevHash doesn't match GENESIS. Expected: ${GENESIS_HASH}, Got: ${entries[0]!.prevHash}`,
    };
  }

  // Each subsequent entry must reference the hash of the previous
  for (let i = 1; i < entries.length; i++) {
    const expectedPrevHash = hashEntry(entries[i - 1]!);
    if (entries[i]!.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        brokenAt: i,
        message: `Chain broken at entry ${i}. Expected prevHash: ${expectedPrevHash}, Got: ${entries[i]!.prevHash}`,
      };
    }
  }

  return { valid: true, message: `Chain valid: ${entries.length} entries verified` };
}
