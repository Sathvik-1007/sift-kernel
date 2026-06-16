import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── Volatility 3 Parser ─────────────────────────────────────────────────────
// Parses output from Volatility 3 (vol3) plugins.

export interface VolProcess {
  readonly pid: number;
  readonly ppid: number;
  readonly name: string;
  readonly offset: string;
  readonly threads: number;
  readonly handles: number;
  readonly createTime: string;
  readonly exitTime: string;
  readonly wow64: boolean;
  readonly sessionId: number;
}

export function parseVolPsList(raw: string): ParseResult<readonly VolProcess[]> {
  const lines = raw.split("\n").filter(Boolean);
  const processes: VolProcess[] = [];
  const anomalies: AnomalyFlag[] = [];

  // Skip header lines (Volatility 3 outputs a header row with column names)
  let dataStart = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.match(/^\s*PID\s/i) || lines[i]!.match(/^-+$/)) {
      dataStart = i + 1;
    }
  }

  for (let i = dataStart; i < lines.length; i++) {
    const line = lines[i]!;
    // Volatility 3 can output tab-separated or multi-space-separated
    const parts = line.includes("\t")
      ? line.split("\t").filter(Boolean)
      : line.split(/\s{2,}/).filter(Boolean);
    if (parts.length >= 4) {
      const pid = parseInt(parts[0] ?? "0", 10);
      const ppid = parseInt(parts[1] ?? "0", 10);
      const name = parts[2] ?? "";
      const offset = parts[3] ?? "";

      if (isNaN(pid)) continue;

      // Vol3 pslist columns: PID PPID ImageFileName Offset(V) Threads Handles SessionId Wow64 CreateTime ExitTime
      processes.push({
        pid,
        ppid,
        name,
        offset,
        threads: parseInt(parts[4] ?? "0", 10) || 0,
        handles: parseInt(parts[5] ?? "0", 10) || 0,
        sessionId: parseInt(parts[6] ?? "0", 10) || 0,
        wow64: (parts[7] ?? "").toLowerCase() === "true",
        createTime: parts[8] ?? "",
        exitTime: parts[9] ?? "",
      });
    }
  }

  // Anomaly: suspicious process names
  const suspiciousNames = new Set([
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "wmic.exe", "schtasks.exe",
  ]);
  const suspicious = processes.filter(p => suspiciousNames.has(p.name.toLowerCase()));
  if (suspicious.length > 0) {
    anomalies.push({
      type: "suspicious_processes",
      severity: "HIGH",
      description: `${suspicious.length} potentially suspicious process(es) — commonly abused by attackers (LOLBins)`,
      affectedItems: suspicious.map(p => `PID ${p.pid}: ${p.name} (PPID ${p.ppid})`),
    });
  }

  // Anomaly: orphan processes (PPID doesn't exist — may indicate parent injection)
  const pidSet = new Set(processes.map(p => p.pid));
  const orphans = processes.filter(p => p.ppid !== 0 && !pidSet.has(p.ppid));
  if (orphans.length > 3) {
    anomalies.push({
      type: "orphan_processes",
      severity: "MEDIUM",
      description: `${orphans.length} process(es) with missing parent — possible parent process injection or terminated parent`,
      affectedItems: orphans.slice(0, 10).map(p => `PID ${p.pid} (${p.name}): PPID ${p.ppid} not found`),
    });
  }

  // Anomaly: processes spawned by unusual parents
  const shellChildren = processes.filter(p => {
    const parent = processes.find(pp => pp.pid === p.ppid);
    return parent && (parent.name.toLowerCase() === "explorer.exe" || parent.name.toLowerCase() === "winlogon.exe") &&
           suspiciousNames.has(p.name.toLowerCase());
  });
  if (shellChildren.length > 0) {
    anomalies.push({
      type: "unusual_parent_child",
      severity: "HIGH",
      description: `Suspicious process(es) spawned directly from Explorer/Winlogon`,
      affectedItems: shellChildren.map(p => `${p.name} (PID ${p.pid}) <- PPID ${p.ppid}`),
    });
  }

  const summary = `${processes.length} process(es)`;

  return ok({
    summary,
    data: processes,
    recordCount: processes.length,
    anomalies,
    rawTruncated: false,
  });
}
