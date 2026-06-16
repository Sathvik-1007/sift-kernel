import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── hashdeep/sha256deep Parser ──────────────────────────────────────────────

export interface HashEntry {
  readonly hash: string;
  readonly sha256: string;
  readonly md5: string;
  readonly algorithm: string;
  readonly size: number;
  readonly path: string;
}

export function parseHashDeep(raw: string): ParseResult<readonly HashEntry[]> {
  const lines = raw.split("\n").filter(l => l && !l.startsWith("%") && !l.startsWith("#"));
  const entries: HashEntry[] = [];
  const anomalies: AnomalyFlag[] = [];

  for (const line of lines) {
    // hashdeep format variants:
    //   size,md5,sha256,filename  (multi-hash with -c md5,sha256)
    //   size,sha256,filename      (single hash with -csha256)
    //   size,md5,filename         (single hash with -cmd5)
    const parts = line.split(",");
    if (parts.length >= 3) {
      const size = parseInt(parts[0] ?? "0", 10);
      if (isNaN(size)) continue;
      const field1 = parts[1] ?? "";

      // 4+ fields: size,md5,sha256,filename
      if (parts.length >= 4 && field1.match(/^[0-9a-f]{32}$/i) && (parts[2] ?? "").match(/^[0-9a-f]{64}$/i)) {
        const md5 = field1;
        const sha256 = parts[2]!;
        const path = parts.slice(3).join(",");
        entries.push({ size, md5, sha256, hash: sha256, algorithm: "md5+sha256", path });
        continue;
      }

      // 3+ fields: size,hash,filename (single hash mode — the REAL format from hashdeep -csha256)
      if (field1.match(/^[0-9a-f]{32,128}$/i)) {
        const hash = field1;
        const algo = hash.length === 32 ? "md5" : hash.length === 40 ? "sha1" : "sha256";
        const path = parts.slice(2).join(",");
        entries.push({ size, md5: algo === "md5" ? hash : "", sha256: algo === "sha256" ? hash : "", hash, algorithm: algo, path });
        continue;
      }
    }
    // sha256deep format: hash  filename
    const simpleMatch = line.match(/^([0-9a-f]{32,128})\s+(.+)$/i);
    if (simpleMatch) {
      const hash = simpleMatch[1]!;
      const algo = hash.length === 32 ? "md5" : hash.length === 40 ? "sha1" : "sha256";
      entries.push({
        hash,
        md5: algo === "md5" ? hash : "",
        sha256: algo === "sha256" ? hash : "",
        algorithm: algo,
        size: 0,
        path: simpleMatch[2]!,
      });
    }
  }

  // Anomaly: duplicate hashes (same file in multiple locations)
  const hashCounts = new Map<string, string[]>();
  for (const entry of entries) {
    const existing = hashCounts.get(entry.hash) ?? [];
    existing.push(entry.path);
    hashCounts.set(entry.hash, existing);
  }
  const duplicates = [...hashCounts.entries()].filter(([, paths]) => paths.length > 1);
  if (duplicates.length > 0) {
    anomalies.push({
      type: "duplicate_files",
      severity: "MEDIUM",
      description: `${duplicates.length} file(s) exist in multiple locations (same hash)`,
      affectedItems: duplicates.slice(0, 5).map(([hash, paths]) => `${hash.slice(0, 16)}...: ${paths.join(", ")}`),
    });
  }

  const summary = `${entries.length} file(s) hashed`;

  return ok({
    summary,
    data: entries,
    recordCount: entries.length,
    anomalies,
    rawTruncated: false,
  });
}
