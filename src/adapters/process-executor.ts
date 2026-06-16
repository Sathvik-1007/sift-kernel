import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { createWriteStream } from "node:fs";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { ok, err, type Result } from "neverthrow";
import { backOff } from "exponential-backoff";
import { executionError, type ExecutionError } from "../domain/errors.js";
import type { ToolExecutor, ToolExecutionResult, ExecutorOptions } from "../ports/tool-executor.port.js";

// Transient error codes that warrant retry (I/O contention, resource limits)
const RETRIABLE_ERRORS = new Set(["EAGAIN", "EIO", "EPIPE", "EBUSY", "EMFILE", "ENFILE", "ENOMEM"]);

// ─── Process Executor (Security Boundary) ────────────────────────────────────

/** Binary allowlist — ONLY these can be executed. No exceptions.
 * Each binary verified against SIFT Workstation package list + Protocol SIFT skills.
 * Sources: github.com/teamdfir/sift, Protocol SIFT install.sh, libevtx/libesedb packages.
 */
const ALLOWED_BINARIES = new Set([
  // Sleuth Kit (verified: apt package sleuthkit)
  "fls", "icat", "istat", "ifind", "mmls", "img_stat", "fsstat",
  "tsk_recover", "blkls", "blkcalc", "blkstat", "blkcat", "ffind",
  "fiwalk", "ils", "mactime", "sorter", "sigfind", "hfind",
  // Plaso Timeline (verified: pip install plaso, binaries: log2timeline, psort)
  "log2timeline.py", "psort.py", "pinfo.py", "psteal.py", "image_export.py",
  "log2timeline", "psort", "pinfo", "psteal", "image_export",
  // Registry (verified: regripper package, binary is rip.pl)
  "rip.pl",
  // Event logs (verified: evtx_dump from cargo install evtx, OR libevtx-utils)
  "evtxexport", "evtxinfo", "evtx_dump",
  // Registry (verified: regipy via pip install regipy)
  "regipy-plugins-run",
  // Memory (verified: volatility3 package, binary is "vol" or "vol.py" on SIFT)
  "vol", "vol.py",
  // YARA (verified: yara package)
  "yara", "yarac",
  // Network (verified: tshark from wireshark-common)
  "tshark", "capinfos", "editcap",
  // Hashing (verified: hashdeep/md5deep packages)
  "hashdeep", "md5deep", "sha256deep", "sha1deep", "ssdeep",
  // Carving (verified: foremost, scalpel, bulk-extractor packages)
  "foremost", "scalpel", "bulk_extractor",
  // Utilities (verified: standard packages on SIFT)
  "strings", "file", "exiftool", "binwalk", "readelf", "objdump",
  // Mounting (verified: standard Linux + ewf-tools/afflib-tools)
  "mount", "umount", "losetup", "ewfmount", "ewfverify", "ewfinfo", "affuse", "qemu-nbd",
  // ESE databases (verified: libesedb-utils package)
  "esedbexport", "esedbinfo",
  // ClamAV (verified: clamav package on SIFT)
  "clamscan", "freshclam",
  // .NET runtime (for Zimmerman tools on SIFT: PECmd, AmcacheParser, etc.)
  "dotnet",
  // Zimmerman EZ Tools (.NET — on SIFT at /usr/local/bin or dotnet-based)
  "PECmd", "AmcacheParser", "AppCompatCacheParser", "SBECmd", "LECmd",
  "JLECmd", "MFTECmd", "RBCmd", "SrumECmd", "EvtxECmd", "RECmd",
  "WxTCmd", "bstrings", "iisGeoLocate", "TimelineExplorer",
  // Linux forensic tools
  "auditd", "journalctl", "last", "lastlog",
  // sudo — used when evidence requires root access (FUSE mounts)
  // "sudo" intentionally excluded from allowlist — it's used ONLY as a wrapper via useSudo flag, never as a direct binary call
]);

const DEFAULT_TIMEOUT_MS = 45_000;

// Fallback binary names: SIFT uses .py suffixes, non-SIFT doesn't
const BINARY_FALLBACKS = new Map<string, string>([
  ["log2timeline", "log2timeline.py"],
  ["log2timeline.py", "log2timeline"],
  ["psort", "psort.py"],
  ["psort.py", "psort"],
  ["pinfo", "pinfo.py"],
  ["pinfo.py", "pinfo"],
  ["vol", "vol.py"],
  ["vol.py", "vol"],
  ["evtx_dump", "evtxexport"],
  ["evtxexport", "evtx_dump"],
  ["regipy-plugins-run", "rip.pl"],
  ["rip.pl", "regipy-plugins-run"],
  ["ewfverify", "img_stat"],
  ["img_stat", "ewfverify"],
]); // 45s — MUST be under MCP client's 60s timeout
const MAX_OUTPUT_BYTES = 50 * 1024 * 1024; // 50MB
const MAX_OUTPUT_LINES = 500_000; // Kill process if output exceeds this many lines

export class ProcessExecutor implements ToolExecutor {
  private readonly outputPath: string;
  private readonly useSudo: boolean;
  // Concurrency control: only ONE forensic tool runs at a time.
  // Prevents I/O contention on the evidence image that causes timeouts.
  private queue: Promise<unknown> = Promise.resolve();

  constructor(outputPath: string, useSudo = false) {
    this.outputPath = outputPath;
    this.useSudo = useSudo;
  }

  private serialize<T>(fn: () => Promise<T>): Promise<T> {
    const task = this.queue.then(fn, fn);
    this.queue = task.then(() => {}, () => {});
    return task;
  }

  async execute(
    binary: string,
    args: readonly string[],
    options?: ExecutorOptions,
  ): Promise<Result<ToolExecutionResult, ExecutionError>> {
    // Security: validate binary is in allowlist
    if (!ALLOWED_BINARIES.has(binary)) {
      return err(executionError(
        binary,
        null,
        `Binary "${binary}" is not in the allowed list. Only approved SIFT forensic tools can be executed.`,
        false,
      ));
    }
    // Serialize all executions to prevent I/O contention on the evidence image
    // with exponential backoff retry for transient I/O errors
    return this.serialize(() => backOff(
      () => this._executeInner(binary, args, options).then(r => {
        if (r.isErr() && r.error.retriable) throw r.error; // trigger retry
        return r;
      }),
      {
        numOfAttempts: 3,
        startingDelay: 500,
        timeMultiple: 2,
        jitter: "full",
        retry: (e) => {
          // Only retry truly transient errors
          const code = (e as { code?: string }).code;
          return RETRIABLE_ERRORS.has(code ?? "") || (e as { retriable?: boolean }).retriable === true;
        },
      },
    ).catch((lastErr) => {
      // All retries exhausted — return the last error
      if (lastErr && typeof lastErr === "object" && "kind" in lastErr) {
        return err(lastErr as ExecutionError);
      }
      const msg = lastErr instanceof Error ? lastErr.message : String(lastErr);
      return err(executionError(binary, null, msg, false));
    }));
  }

  private _executeInner(
    binary: string,
    args: readonly string[],
    options?: ExecutorOptions,
  ): Promise<Result<ToolExecutionResult, ExecutionError>> {
    const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const cwd = options?.cwd ?? this.outputPath;

    const startTime = Date.now();

    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      const errChunks: Buffer[] = [];
      let totalBytes = 0;
      let killed = false;

      // CRITICAL: shell: false — no shell interpretation, no injection
      // PATH: prepend standard forensic tool locations (SIFT, cargo, local bin)
      // Ensures correct binary is found regardless of platform (SIFT Workstation, dev machine, Docker)
      const home = process.env["HOME"] ?? "/root";
      const envPath = [
        "/usr/local/bin",                    // Zimmerman tools on SIFT, bulk_extractor
        `${home}/.cargo/bin`,                // Rust evtx_dump
        `${home}/.local/bin`,                // pip-installed tools (regipy, plaso)
        "/opt/volatility3",                  // SIFT volatility location
        "/opt/CyberChef",                    // SIFT CyberChef
        process.env["PATH"] ?? "",
      ].join(":");
      // If sudo mode is enabled, prepend sudo to execute forensic tools on FUSE-mounted evidence
      const actualBinary = this.useSudo ? "sudo" : binary;
      const actualArgs = this.useSudo ? [binary, ...args] : [...args];

      const proc = spawn(actualBinary, actualArgs, {
        shell: false,
        cwd,
        env: { ...process.env, PATH: envPath, ...options?.env },
        stdio: ["ignore", "pipe", "pipe"],
      });

      let lineCount = 0;
      const maxLines = options?.maxLines ?? MAX_OUTPUT_LINES;

      const timer = setTimeout(() => {
        killed = true;
        proc.kill("SIGTERM");
        setTimeout(() => proc.kill("SIGKILL"), 5000);
      }, timeoutMs);

      proc.stdout.on("data", (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes <= MAX_OUTPUT_BYTES && lineCount < maxLines) {
          chunks.push(chunk);
          // Count newlines in this chunk
          for (let i = 0; i < chunk.length; i++) {
            if (chunk[i] === 10) lineCount++;
          }
          if (lineCount >= maxLines && !killed) {
            killed = true;
            proc.kill("SIGTERM");
            setTimeout(() => { try { proc.kill("SIGKILL"); } catch { /* already dead */ } }, 3000);
          }
        } else if (!killed) {
          killed = true;
          proc.kill("SIGTERM");
          setTimeout(() => { try { proc.kill("SIGKILL"); } catch { /* already dead */ } }, 3000);
        }
      });

      proc.stderr.on("data", (chunk: Buffer) => {
        errChunks.push(chunk);
      });

      proc.on("error", (e) => {
        clearTimeout(timer);
        // Binary not found — try fallback name (log2timeline vs log2timeline.py)
        if ((e as NodeJS.ErrnoException).code === "ENOENT" && BINARY_FALLBACKS.has(binary)) {
          const fallback = BINARY_FALLBACKS.get(binary)!;
          resolve(this._executeInner(fallback, args, options));
          return;
        }
        resolve(err(executionError(binary, null, e.message, false)));
      });

      proc.on("close", (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - startTime;
        const stdout = Buffer.concat(chunks).toString("utf-8");
        const stderr = Buffer.concat(errChunks).toString("utf-8");

        if (killed) {
          // If killed due to output limits but we have data, return partial output with non-zero exit code
          if (stdout.length > 0) {
            resolve(ok({ stdout, stderr, exitCode: -1, durationMs }));
          } else {
            resolve(err(executionError(binary, code, stderr || "Process killed (timeout or output limit)", true)));
          }
          return;
        }

        if (code !== 0 && code !== null) {
          resolve(err(executionError(binary, code, stderr, false)));
          return;
        }

        resolve(ok({ stdout, stderr, exitCode: code ?? 0, durationMs }));
      });
    });
  }

  /**
   * Stream a binary's stdout to a file with NO size cap. For extracting large
   * evidence artifacts (event logs, registry hives) before parsing them.
   */
  extractToFile(
    binary: string,
    args: readonly string[],
    outPath: string,
    options?: ExecutorOptions,
  ): Promise<Result<{ readonly path: string; readonly bytes: number; readonly durationMs: number }, ExecutionError>> {
    if (!ALLOWED_BINARIES.has(binary)) {
      return Promise.resolve(err(executionError(binary, null, `Binary "${binary}" is not in the allowed list.`, false)));
    }
    return this.serialize(() => new Promise((resolve) => {
      const startTime = Date.now();
      const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
      const home = process.env["HOME"] ?? "/root";
      const envPath = ["/usr/local/bin", `${home}/.cargo/bin`, `${home}/.local/bin`, "/opt/volatility3", process.env["PATH"] ?? ""].join(":");
      const actualBinary = this.useSudo ? "sudo" : binary;
      const actualArgs = this.useSudo ? [binary, ...args] : [...args];
      try { mkdirSync(dirname(outPath), { recursive: true }); } catch { /* exists */ }
      const out = createWriteStream(outPath);
      let settled = false;
      const errChunks: Buffer[] = [];
      let bytes = 0;
      let killed = false;
      out.on("error", (e) => {
        if (settled) return;
        settled = true;
        resolve(err(executionError(binary, null, `write failed: ${e.message}`, false)));
      });
      const proc = spawn(actualBinary, actualArgs, {
        shell: false,
        cwd: options?.cwd ?? this.outputPath,
        env: { ...process.env, PATH: envPath, ...options?.env },
        stdio: ["ignore", "pipe", "pipe"],
      });
      const timer = setTimeout(() => { killed = true; proc.kill("SIGTERM"); setTimeout(() => proc.kill("SIGKILL"), 5000); }, timeoutMs);
      proc.stdout.on("data", (c: Buffer) => { bytes += c.length; out.write(c); });
      proc.stderr.on("data", (c: Buffer) => { errChunks.push(c); });
      proc.on("error", (e) => {
        clearTimeout(timer);
        out.end();
        if (settled) return;
        if ((e as NodeJS.ErrnoException).code === "ENOENT" && BINARY_FALLBACKS.has(binary)) {
          settled = true;
          resolve(this.extractToFile(BINARY_FALLBACKS.get(binary)!, args, outPath, options));
          return;
        }
        settled = true;
        resolve(err(executionError(binary, null, e.message, false)));
      });
      proc.on("close", (code) => {
        clearTimeout(timer);
        out.end(() => {
          if (settled) return;
          settled = true;
          const durationMs = Date.now() - startTime;
          if (killed) { resolve(err(executionError(binary, code, "Process killed (timeout)", true))); return; }
          if (code !== 0 && code !== null && bytes === 0) { resolve(err(executionError(binary, code, Buffer.concat(errChunks).toString("utf-8"), false))); return; }
          if (bytes === 0) { resolve(err(executionError(binary, code, "No data extracted", false))); return; }
          resolve(ok({ path: outPath, bytes, durationMs }));
        });
      });
    }));
  }

  async isAvailable(binary: string): Promise<boolean> {
    if (!ALLOWED_BINARIES.has(binary)) return false;
    try {
      // Check if binary exists in PATH
      return new Promise((resolve) => {
        const proc = spawn("which", [binary], { shell: false, stdio: ["ignore", "pipe", "pipe"] });
        proc.on("close", (code) => resolve(code === 0));
        proc.on("error", () => resolve(false));
      });
    } catch {
      return false;
    }
  }

  async getAvailableBinaries(): Promise<readonly string[]> {
    const results: string[] = [];
    for (const binary of ALLOWED_BINARIES) {
      if (await this.isAvailable(binary)) {
        results.push(binary);
      }
    }
    return results;
  }
}
