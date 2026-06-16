import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── YARA Parser ─────────────────────────────────────────────────────────────
// Parses YARA scan results.

export interface YaraMatch {
  readonly rule: string;
  readonly namespace: string;
  readonly file: string;
  readonly strings: readonly YaraString[];
  readonly tags: readonly string[];
  readonly meta: Record<string, string>;
}

export interface YaraString {
  readonly offset: number;
  readonly identifier: string;
  readonly data: string;
}

export function parseYara(raw: string): ParseResult<readonly YaraMatch[]> {
  const lines = raw.split("\n").filter(Boolean);
  const matches: YaraMatch[] = [];
  const anomalies: AnomalyFlag[] = [];

  let currentMatch: Partial<YaraMatch> | null = null;
  let currentStrings: YaraString[] = [];

  for (const line of lines) {
    // Match line: "rule_name [tag1,tag2] file_path"
    const matchLine = line.match(/^(\S+)\s+(?:\[([^\]]*)\]\s+)?(.+)$/);
    if (matchLine && !line.startsWith("0x")) {
      // Save previous match
      if (currentMatch?.rule) {
        matches.push({ ...currentMatch, strings: currentStrings } as YaraMatch);
      }
      currentStrings = [];
      currentMatch = {
        rule: matchLine[1]!,
        namespace: "",
        file: matchLine[3]!,
        tags: matchLine[2]?.split(",").map(t => t.trim()) ?? [],
        meta: {},
      };
    }
    // String match line: "0x1234:$string_id: data"
    const stringLine = line.match(/^(0x[0-9a-f]+):(\$\S+):\s*(.*)$/i);
    if (stringLine) {
      currentStrings.push({
        offset: parseInt(stringLine[1]!, 16),
        identifier: stringLine[2]!,
        data: stringLine[3]!,
      });
    }
  }
  // Save last match
  if (currentMatch?.rule) {
    matches.push({ ...currentMatch, strings: currentStrings } as YaraMatch);
  }

  // Anomalies from YARA results
  if (matches.length > 0) {
    anomalies.push({
      type: "yara_matches",
      severity: "CRITICAL",
      description: `${matches.length} YARA rule(s) matched — potential malware or IOC indicators`,
      affectedItems: matches.map(m => `${m.rule}: ${m.file}`).slice(0, 20),
    });
  }

  const summary = matches.length > 0
    ? `${matches.length} YARA match(es): ${[...new Set(matches.map(m => m.rule))].slice(0, 5).join(", ")}`
    : "No YARA matches";

  return ok({
    summary,
    data: matches,
    recordCount: matches.length,
    anomalies,
    rawTruncated: false,
  });
}
