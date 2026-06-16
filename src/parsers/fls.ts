import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── fls Parser ──────────────────────────────────────────────────────────────
// Parses output from The Sleuth Kit's `fls` command.
// Format: type/inode\tname (with optional metadata flags)

export interface FlsEntry {
  readonly type: "file" | "directory" | "link" | "other";
  readonly inode: string;
  readonly name: string;
  readonly path: string;
  readonly deleted: boolean;
  readonly reallocated: boolean;
}

// Handles: d/d 33329-144-6:\tname  |  r/r * 1234-128-3:\tname (deleted)  |  r/- 5678:\tname
const FLS_LINE_RE = /^([rdvl*-])\/([rdvl*-])\s+(\*\s+)?(\S+?):\s+(.+)$/;
const FLS_SIMPLE_RE = /^([rdvl*-])\/([rdvl*-])\s+(\*\s+)?(\d+[-\d]*):\t(.+)$/;

export function parseFls(raw: string): ParseResult<readonly FlsEntry[]> {
  const lines = raw.split("\n").filter(Boolean);
  const entries: FlsEntry[] = [];
  const anomalies: AnomalyFlag[] = [];
  const suspiciousPaths: string[] = [];

  for (const line of lines) {
    const match = FLS_LINE_RE.exec(line) ?? FLS_SIMPLE_RE.exec(line);
    if (!match) {
      // Try simpler tab-delimited format
      const parts = line.split("\t");
      if (parts.length >= 2) {
        const typeChar = parts[0]?.charAt(0) ?? "?";
        const deleted = parts[0]?.includes("*") ?? false;
        entries.push({
          type: typeChar === "d" ? "directory" : typeChar === "r" ? "file" : "other",
          inode: parts[0]?.replace(/[^0-9-]/g, "") ?? "0",
          name: parts[1] ?? line,
          path: parts[1] ?? line,
          deleted,
          reallocated: false,
        });
      }
      continue;
    }

    const [, typeChar, allocFlag, deletedMarker, inode, name] = match;
    const deleted = deletedMarker !== undefined || allocFlag === "-" || allocFlag === "*";
    const reallocated = allocFlag === "-";
    const type = typeChar === "d" ? "directory" as const :
                 typeChar === "r" ? "file" as const :
                 typeChar === "l" ? "link" as const : "other" as const;

    const entry: FlsEntry = {
      type,
      inode: inode!,
      name: name!.replace(/\s*\(deleted\)\s*$/, ""),
      path: name!.replace(/\s*\(deleted\)\s*$/, ""),
      deleted,
      reallocated,
    };
    entries.push(entry);

    // Anomaly detection: suspicious paths
    const lowerName = entry.name.toLowerCase();
    if (lowerName.match(/\.(exe|dll|bat|ps1|vbs|js|hta|scr)$/) &&
        (lowerName.includes("temp") || lowerName.includes("tmp") || lowerName.includes("appdata"))) {
      suspiciousPaths.push(entry.name);
    }
    // Hidden executable in system directory
    if (entry.deleted && lowerName.match(/\.(exe|dll)$/)) {
      suspiciousPaths.push(`[DELETED] ${entry.name}`);
    }
  }

  if (suspiciousPaths.length > 0) {
    anomalies.push({
      type: "suspicious_executables",
      severity: "HIGH",
      description: `Found ${suspiciousPaths.length} executable(s) in suspicious locations or deleted state`,
      affectedItems: suspiciousPaths.slice(0, 20),
    });
  }

  const deletedCount = entries.filter(e => e.deleted).length;
  if (deletedCount > 0) {
    anomalies.push({
      type: "deleted_files",
      severity: "MEDIUM",
      description: `${deletedCount} deleted file(s) found — may contain evidence of removed artifacts`,
      affectedItems: entries.filter(e => e.deleted).map(e => e.name).slice(0, 10),
    });
  }

  const summary = `${entries.length} entries (${entries.filter(e => e.type === "file").length} files, ${entries.filter(e => e.type === "directory").length} dirs, ${deletedCount} deleted)`;

  return ok({
    summary,
    data: entries,
    recordCount: entries.length,
    anomalies,
    rawTruncated: false,
  });
}
