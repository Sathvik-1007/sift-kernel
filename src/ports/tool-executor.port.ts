import type { Result } from "neverthrow";
import type { ExecutionError } from "../domain/errors.js";

// ─── Tool Executor Port ──────────────────────────────────────────────────────

export interface ToolExecutionResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number;
  readonly durationMs: number;
}

export interface ExecutorOptions {
  readonly timeoutMs?: number;
  readonly maxLines?: number;
  readonly cwd?: string;
  readonly env?: Record<string, string>;
}

export interface ToolExecutor {
  /** Execute a SIFT tool binary with arguments. Shell is NEVER used. */
  execute(
    binary: string,
    args: readonly string[],
    options?: ExecutorOptions,
  ): Promise<Result<ToolExecutionResult, ExecutionError>>;

  /**
   * Stream a binary's stdout directly to a file with NO output-size cap.
   * Used to extract large evidence artifacts (event logs, registry hives) that
   * exceed the in-memory output limit. Shell is NEVER used.
   */
  extractToFile(
    binary: string,
    args: readonly string[],
    outPath: string,
    options?: ExecutorOptions,
  ): Promise<Result<{ readonly path: string; readonly bytes: number; readonly durationMs: number }, ExecutionError>>;

  /** Check if a binary is available on the system */
  isAvailable(binary: string): Promise<boolean>;

  /** Get list of all available SIFT binaries */
  getAvailableBinaries(): Promise<readonly string[]>;
}
