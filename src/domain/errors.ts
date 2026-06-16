import type { Capability, LedgerEntryId, FindingId, HypothesisId } from "./types.js";

// Discriminated union error types — every error is actionable.

export type DomainError =
  | CapabilityError
  | LedgerError
  | FindingError
  | HypothesisError
  | ExecutionError
  | EvidenceError
  | PathError
  | ValidationError;

export interface CapabilityError {
  readonly kind: "CAPABILITY_ERROR";
  readonly tool: string;
  readonly missing: readonly Capability[];
  readonly held: readonly Capability[];
  readonly message: string;
  readonly guidance: string;
}

export interface LedgerError {
  readonly kind: "LEDGER_ERROR";
  readonly operation: "append" | "query" | "verify_chain" | "trace";
  readonly message: string;
  readonly entryId?: LedgerEntryId | undefined;
}

export interface FindingError {
  readonly kind: "FINDING_ERROR";
  readonly operation: "register" | "reassess" | "query";
  readonly message: string;
  readonly findingId?: FindingId | undefined;
  readonly guidance: string;
}

export interface HypothesisError {
  readonly kind: "HYPOTHESIS_ERROR";
  readonly operation: "register" | "update" | "query";
  readonly message: string;
  readonly hypothesisId?: HypothesisId | undefined;
}

export interface ExecutionError {
  readonly kind: "EXECUTION_ERROR";
  readonly tool: string;
  readonly exitCode: number | null;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly retriable: boolean;
  readonly message: string;
  readonly guidance: string;
}

export interface EvidenceError {
  readonly kind: "EVIDENCE_ERROR";
  readonly operation: "mount" | "verify" | "read" | "extract";
  readonly path: string;
  readonly message: string;
  readonly guidance: string;
}

export interface PathError {
  readonly kind: "PATH_ERROR";
  readonly requestedPath: string;
  readonly allowedPrefix: string;
  readonly message: string;
}

export interface ValidationError {
  readonly kind: "VALIDATION_ERROR";
  readonly field: string;
  readonly expected: string;
  readonly received: string;
  readonly message: string;
}

// ─── Error Constructors ──────────────────────────────────────────────────────

export function capabilityError(
  tool: string,
  missing: readonly Capability[],
  held: readonly Capability[],
): CapabilityError {
  const missingStr = missing.join(", ");
  const guidance = `Required capabilities not met. You need: [${missingStr}]. ` +
    `Run the tools that produce these capabilities first.`;
  return {
    kind: "CAPABILITY_ERROR",
    tool,
    missing,
    held,
    message: `Tool "${tool}" requires capabilities [${missingStr}] which are not held`,
    guidance,
  };
}

export function executionError(
  tool: string,
  exitCode: number | null,
  stderr: string,
  timedOut: boolean,
): ExecutionError {
  const message = timedOut
    ? `Tool "${tool}" timed out`
    : `Tool "${tool}" exited with code ${exitCode}`;
  const guidance = timedOut
    ? `The tool took too long. Try with a smaller scope or increase timeout.`
    : `Check stderr for details: ${stderr.slice(0, 200)}`;
  // Mark as retriable if timedOut or if stderr hints at transient resource issues
  const retriable = timedOut || /EAGAIN|EBUSY|EIO|EMFILE|resource temporarily/i.test(stderr);
  return { kind: "EXECUTION_ERROR", tool, exitCode, stderr, timedOut, retriable, message, guidance };
}

export function evidenceError(
  operation: EvidenceError["operation"],
  path: string,
  message: string,
): EvidenceError {
  const guidanceMap: Record<EvidenceError["operation"], string> = {
    mount: "Verify the image path exists and is a supported format (E01/raw/VMDK/AFF4).",
    verify: "The image may be corrupted. Check hash against known-good value.",
    read: "File may not exist at this path in the image. Use list_directory to verify.",
    extract: "Inode may be invalid or file is unrecoverable. Try carve_files instead.",
  };
  return { kind: "EVIDENCE_ERROR", operation, path, message, guidance: guidanceMap[operation] };
}

export function pathError(requestedPath: string, allowedPrefix: string): PathError {
  return {
    kind: "PATH_ERROR",
    requestedPath,
    allowedPrefix,
    message: `Path "${requestedPath}" is outside the allowed evidence mount "${allowedPrefix}"`,
  };
}

export function findingError(
  operation: FindingError["operation"],
  message: string,
  guidance: string,
  findingId?: FindingId,
): FindingError {
  return { kind: "FINDING_ERROR", operation, message, findingId, guidance };
}
