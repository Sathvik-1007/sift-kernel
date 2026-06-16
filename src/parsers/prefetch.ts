import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

export interface PrefetchEntry {
  readonly executableName: string;
  readonly prefetchHash: string;
  readonly runCount: number;
  readonly lastRun: string;
  readonly previousRuns: readonly string[];
  readonly volumesAccessed: readonly string[];
  readonly directoriesAccessed: readonly string[];
  readonly filesReferenced: readonly string[];
}

export function parsePrefetch(raw: string): ParseResult<readonly PrefetchEntry[]> {
  const entries: PrefetchEntry[] = [];
  const anomalies: AnomalyFlag[] = [];

  // Parse prefetch analysis output (from PECmd or similar)
  const blocks = raw.split(/(?=Executable Name:)/i).filter(Boolean);

  for (const block of blocks) {
    const nameMatch = block.match(/Executable Name:\s*(.+)/i);
    const hashMatch = block.match(/Hash:\s*([A-Fa-f0-9]+)/i);
    const countMatch = block.match(/Run count:\s*(\d+)/i);
    const lastRunMatch = block.match(/Last run:\s*(.+)/i);
    const filesMatches = block.match(/Files Referenced[\s\S]*?(?=\n\n|$)/i);

    if (nameMatch) {
      const execName = nameMatch[1]!.trim();
      const entry: PrefetchEntry = {
        executableName: execName,
        prefetchHash: hashMatch?.[1] ?? "",
        runCount: countMatch ? parseInt(countMatch[1]!, 10) : 0,
        lastRun: lastRunMatch?.[1]?.trim() ?? "",
        previousRuns: [],
        volumesAccessed: [],
        directoriesAccessed: [],
        filesReferenced: filesMatches ? filesMatches[0]!.split("\n").filter(Boolean).slice(1) : [],
      };
      entries.push(entry);

      // Flag suspicious executables
      const lowerName = execName.toLowerCase();
      if (/powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil/.test(lowerName)) {
        anomalies.push({ type: "lolbin_execution", severity: "HIGH", description: `LOLBin executed: ${execName} (${entry.runCount} times)`, affectedItems: [execName] });
      }
      if (/psexec|mimikatz|lazagne|sharphound|rubeus|cobalt/.test(lowerName)) {
        anomalies.push({ type: "known_tool_execution", severity: "CRITICAL", description: `Known attack tool executed: ${execName}`, affectedItems: [execName] });
      }
    }
  }

  return ok({ summary: `${entries.length} prefetch entries. ${anomalies.length} suspicious executables flagged.`, data: entries, recordCount: entries.length, anomalies, rawTruncated: false });
}
