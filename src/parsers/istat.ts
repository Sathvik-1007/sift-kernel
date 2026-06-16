import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── istat Parser ────────────────────────────────────────────────────────────
// Parses inode metadata from The Sleuth Kit's `istat` command.

export interface IstatTimestamp {
  readonly label: string;
  readonly value: string;
  readonly epoch: number;
}

export interface IstatOutput {
  readonly entry: number;
  readonly inode: string;
  readonly type: string;
  readonly uid: number;
  readonly gid: number;
  readonly size: number;
  readonly timestamps: readonly IstatTimestamp[];
  readonly attributes: readonly string[];
  readonly allocated: boolean;
  readonly numLinks: number;
}

export function parseIstat(raw: string): ParseResult<IstatOutput> {
  const lines = raw.split("\n");
  const anomalies: AnomalyFlag[] = [];

  let inode = "0";
  let type = "unknown";
  let uid = 0;
  let gid = 0;
  let size = 0;
  let allocated = true;
  let numLinks = 0;
  let currentSection = "";
  const timestamps: IstatTimestamp[] = [];
  const attributes: string[] = [];

  for (const line of lines) {
    const lower = line.toLowerCase();

    if (lower.startsWith("inode:") || lower.match(/^inode \d+/i) || lower.startsWith("entry:") || lower.match(/^entry:\s*\d+/i)) {
      const m = line.match(/\d+/);
      if (m) inode = m[0]!;
    }

    // Track current section ($STANDARD_INFORMATION or $FILE_NAME)
    if (lower.includes("$standard_information")) currentSection = "STANDARD_INFORMATION";
    else if (lower.includes("$file_name")) currentSection = "FILE_NAME";
    else if (lower.includes("attributes:") && !lower.includes("$")) currentSection = "";

    if (lower.includes("type:")) {
      const m = line.match(/type:\s*(\S+)/i);
      if (m) type = m[1]!;
    }
    if (lower.includes("uid:")) {
      const m = line.match(/uid:\s*(\d+)/i);
      if (m) uid = parseInt(m[1]!, 10);
    }
    if (lower.includes("gid:")) {
      const m = line.match(/gid:\s*(\d+)/i);
      if (m) gid = parseInt(m[1]!, 10);
    }
    if (lower.includes("size:")) {
      const m = line.match(/size:\s*(\d+)/i);
      if (m) size = parseInt(m[1]!, 10);
    }
    if (lower.includes("num of links:") || lower.includes("link count:") || lower.match(/^links:\s*\d+/)) {
      const m = line.match(/(\d+)/);
      if (m) numLinks = parseInt(m[0]!, 10);
    }
    if (lower.includes("not allocated") || lower.includes("unallocated") || lower.includes("deleted")) {
      allocated = false;
    }
    if (lower.includes("allocated file")) {
      allocated = true;
    }
    // Timestamps: Created, Modified, Accessed, Changed
    const tsMatch = line.match(/(Created|File Modified|MFT Modified|Accessed|Changed|Written|Entry Modified):\s*(.+)/i);
    if (tsMatch) {
      const dateStr = tsMatch[2]!.trim();
      const epoch = Date.parse(dateStr.replace(/ \(UTC\)$/, " UTC"));
      const label = currentSection ? `${currentSection}.${tsMatch[1]}` : tsMatch[1]!;
      timestamps.push({
        label,
        value: dateStr,
        epoch: isNaN(epoch) ? 0 : epoch,
      });
    }
    // Attributes section lines
    if (line.match(/^Type:\s*\$/)) {
      attributes.push(line.trim());
    }
  }

  // Anomaly: timestomping detection ($SI vs $FN)
  const siCreated = timestamps.find(t => t.label.includes("STANDARD_INFORMATION") && t.label.includes("Created"));
  const fnCreated = timestamps.find(t => t.label.includes("FILE_NAME") && t.label.includes("Created"));
  if (siCreated && fnCreated && siCreated.epoch > 0 && fnCreated.epoch > 0) {
    if (siCreated.epoch < fnCreated.epoch) {
      anomalies.push({
        type: "timestomping",
        severity: "CRITICAL",
        description: `$SI Created (${siCreated.value}) is EARLIER than $FN Created (${fnCreated.value}) — strong timestomping indicator`,
        affectedItems: [`inode ${inode}`],
      });
    }
  }

  // Anomaly: future timestamps
  const now = Date.now();
  for (const ts of timestamps) {
    if (ts.epoch > now + 86400000) { // more than 1 day in future
      anomalies.push({
        type: "future_timestamp",
        severity: "HIGH",
        description: `Timestamp "${ts.label}" is in the future: ${ts.value}`,
        affectedItems: [`inode ${inode}`],
      });
    }
  }

  // Anomaly: epoch-0 (1970-01-01)
  for (const ts of timestamps) {
    if (ts.epoch === 0 && ts.value !== "0") {
      anomalies.push({
        type: "epoch_zero_timestamp",
        severity: "MEDIUM",
        description: `Timestamp "${ts.label}" is epoch-0 (1970-01-01) — may indicate manipulation or parse failure`,
        affectedItems: [`inode ${inode}`],
      });
    }
  }

  const summary = `Inode ${inode}: ${type}, ${size} bytes, ${allocated ? "allocated" : "NOT allocated"}, ${timestamps.length} timestamps`;

  return ok({
    summary,
    data: { entry: parseInt(inode, 10) || 0, inode, type, uid, gid, size, timestamps, attributes, allocated, numLinks },
    recordCount: 1,
    anomalies,
    rawTruncated: false,
  });
}
