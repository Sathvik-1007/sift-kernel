import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── mmls Parser ─────────────────────────────────────────────────────────────
// Parses partition table output from The Sleuth Kit's `mmls` command.

export interface MmlsPartition {
  readonly index: number;
  readonly slot: string;
  readonly start: number;
  readonly end: number;
  readonly length: number;
  readonly description: string;
  readonly type: "primary" | "extended" | "logical" | "unallocated" | "meta";
}

export function parseMmls(raw: string): ParseResult<readonly MmlsPartition[]> {
  const lines = raw.split("\n").filter(Boolean);
  const partitions: MmlsPartition[] = [];
  const anomalies: AnomalyFlag[] = [];

  // Skip header lines (usually 2-3 lines of table header)
  let dataStart = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.match(/^\s*\d+:/)) {
      dataStart = i;
      break;
    }
  }

  for (let i = dataStart; i < lines.length; i++) {
    const line = lines[i]!;
    // Format: "000:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)"
    const match = line.match(/^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/);
    if (!match) continue;

    const [, idx, slot, start, end, length, description] = match;
    const descLower = description!.toLowerCase();
    const type = descLower.includes("unallocated") ? "unallocated" as const :
                 descLower.includes("meta") || descLower.includes("table") ? "meta" as const :
                 descLower.includes("extended") ? "extended" as const :
                 descLower.includes("logical") ? "logical" as const : "primary" as const;

    partitions.push({
      index: parseInt(idx!, 10),
      slot: slot!,
      start: parseInt(start!, 10),
      end: parseInt(end!, 10),
      length: parseInt(length!, 10),
      description: description!.trim(),
      type,
    });
  }

  // Anomaly: gaps between partitions (hidden data)
  const allocated = partitions.filter(p => p.type !== "unallocated" && p.type !== "meta");
  const unallocated = partitions.filter(p => p.type === "unallocated");
  if (unallocated.length > 0) {
    const totalUnalloc = unallocated.reduce((sum, p) => sum + p.length, 0);
    const totalSize = partitions.reduce((max, p) => Math.max(max, p.end), 0);
    if (totalSize > 0 && totalUnalloc / totalSize > 0.1) {
      anomalies.push({
        type: "large_unallocated_space",
        severity: "MEDIUM",
        description: `${((totalUnalloc / totalSize) * 100).toFixed(1)}% of disk is unallocated — may contain hidden or deleted partitions`,
        affectedItems: unallocated.map(p => `sectors ${p.start}-${p.end}`),
      });
    }
  }

  const summary = `${allocated.length} partition(s) found (${unallocated.length} unallocated regions)`;

  return ok({
    summary,
    data: partitions,
    recordCount: partitions.length,
    anomalies,
    rawTruncated: false,
  });
}
