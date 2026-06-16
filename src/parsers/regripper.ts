import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── RegRipper Parser ────────────────────────────────────────────────────────
// Parses output from regripper (structured registry analysis).

export interface RegripperOutput {
  readonly plugin: string;
  readonly hive: string;
  readonly entries: readonly RegripperEntry[];
}

export interface RegripperEntry {
  readonly key: string;
  readonly value: string;
  readonly data: string;
  readonly timestamp: string;
  readonly type: string;
}

// Known persistence registry paths
const PERSISTENCE_KEYS = [
  "run", "runonce", "runonceex", "runservices", "policies\\explorer\\run",
  "currentversion\\winlogon", "userinit", "shell", "appinit_dlls",
  "image file execution options", "debugger", "silent_process_exit",
];

export function parseRegripper(raw: string): ParseResult<RegripperOutput> {
  const anomalies: AnomalyFlag[] = [];

  // Handle regipy-plugins-run JSON output format
  const trimmed = raw.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      const entries: RegripperEntry[] = [];
      let plugin = "regipy";
      let hive = "";

      // regipy output: { "plugin_name": [{...entries...}], ... }
      for (const [key, val] of Object.entries(parsed)) {
        plugin = key;
        if (Array.isArray(val)) {
          for (const item of val) {
            if (typeof item === "object" && item !== null) {
              const obj = item as Record<string, unknown>;
              entries.push({
                key: String(obj["path"] ?? obj["key"] ?? obj["name"] ?? key),
                value: String(obj["value"] ?? obj["value_name"] ?? ""),
                data: String(obj["data"] ?? obj["value_data"] ?? JSON.stringify(obj)),
                timestamp: String(obj["timestamp"] ?? obj["last_write"] ?? obj["modified"] ?? ""),
                type: String(obj["type"] ?? obj["value_type"] ?? "REG_SZ"),
              });
            }
          }
        }
      }

      // Check for persistence-related entries
      for (const entry of entries) {
        const lowerKey = entry.key.toLowerCase();
        if (PERSISTENCE_KEYS.some(p => lowerKey.includes(p))) {
          anomalies.push({
            type: "persistence_key",
            severity: "HIGH",
            description: `Persistence-related registry key: ${entry.key}`,
            affectedItems: [entry.data.slice(0, 200)],
          });
        }
      }

      return ok({
        summary: `${entries.length} registry entries from ${plugin}`,
        data: { plugin, hive, entries },
        recordCount: entries.length,
        anomalies,
        rawTruncated: false,
      });
    } catch {
      // Fall through to text parsing
    }
  }

  const lines = raw.split("\n");
  const entries: RegripperEntry[] = [];
  let plugin = "";
  let hive = "";
  let currentKey = "";
  let currentTimestamp = "";

  for (const line of lines) {
    // Plugin name header
    const pluginMatch = line.match(/^Launching\s+\S+\s+from\s+/i) ?? line.match(/^Plugin:\s*(\S+)/i);
    if (pluginMatch) {
      // "Launching run from plugin list" → next line is plugin name
      continue;
    }
    // Standalone plugin name (line after "Launching...")
    if (line.match(/^\w+$/) && !plugin) {
      plugin = line.trim();
      continue;
    }
    // Hive info
    const hiveMatch = line.match(/^Hive:\s*(.+)/i) ?? line.match(/hive\s+file:\s*(.+)/i);
    if (hiveMatch) {
      hive = hiveMatch[1]!.trim();
      continue;
    }
    // Registry key path (full paths with backslashes or section headers ending in :)
    if (line.match(/^[A-Z]:\\|^\\|^HKEY/i) || line.match(/^[A-Za-z]+\\[A-Za-z]/)) {
      currentKey = line.trim();
      continue;
    }
    // Section header like "Run key contents:" or "UserAssist entries:"
    const sectionMatch = line.match(/^([A-Za-z][\w\s]+)(?:contents|entries)?:\s*$/i);
    if (sectionMatch) {
      currentKey = sectionMatch[1]!.trim();
      continue;
    }
    // Timestamp line
    const tsMatch = line.match(/LastWrite(?:\s+Time)?:\s*(.+)/i) ?? line.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
    if (tsMatch) {
      currentTimestamp = tsMatch[1]!.trim();
      continue;
    }
    // Value entry: "  ValueName  REG_TYPE  Data"
    const valueMatch = line.match(/^\s+(\S+)\s+(REG_\w+)\s+(.+)$/i);
    if (valueMatch) {
      entries.push({
        key: currentKey,
        value: valueMatch[1]!,
        type: valueMatch[2]!,
        data: valueMatch[3]!.trim(),
        timestamp: currentTimestamp,
      });
      continue;
    }
    // Simple key=value format (regripper often uses this): "  Key  = Value" or "  Key: Value"
    const simpleMatch = line.match(/^\s+(.+?)\s*(?:->|=|:)\s*(.+)$/);
    if (simpleMatch && simpleMatch[1] && !simpleMatch[1].startsWith("-")) {
      entries.push({
        key: currentKey,
        value: simpleMatch[1].trim(),
        type: "REG_SZ",
        data: simpleMatch[2]!.trim(),
        timestamp: currentTimestamp,
      });
    }
  }

  // Anomaly: persistence mechanisms
  const persistenceEntries = entries.filter(e => {
    const keyLower = e.key.toLowerCase();
    return PERSISTENCE_KEYS.some(pk => keyLower.includes(pk));
  });
  if (persistenceEntries.length > 0) {
    anomalies.push({
      type: "persistence_registry",
      severity: "CRITICAL",
      description: `${persistenceEntries.length} registry persistence entries found`,
      affectedItems: persistenceEntries.slice(0, 10).map(e => `${e.key}: ${e.value} = ${e.data.slice(0, 80)}`),
    });
  }

  // Anomaly: suspicious executables in Run keys
  const suspiciousRuns = entries.filter(e => {
    const keyLower = e.key.toLowerCase();
    const dataLower = e.data.toLowerCase();
    return keyLower.includes("run") &&
           (dataLower.includes("powershell") || dataLower.includes("cmd.exe") ||
            dataLower.includes("wscript") || dataLower.includes("temp") ||
            dataLower.includes("appdata") || dataLower.includes(".vbs") ||
            dataLower.includes("encoded") || dataLower.includes("-enc"));
  });
  if (suspiciousRuns.length > 0) {
    anomalies.push({
      type: "suspicious_autorun",
      severity: "CRITICAL",
      description: `Suspicious autorun entries — scripting engines or encoded commands in Run keys`,
      affectedItems: suspiciousRuns.map(e => `${e.value} = ${e.data.slice(0, 100)}`),
    });
  }

  const summary = `Plugin: ${plugin || "unknown"}, Hive: ${hive || "unknown"}, ${entries.length} entries`;

  return ok({
    summary,
    data: { plugin, hive, entries },
    recordCount: entries.length,
    anomalies,
    rawTruncated: false,
  });
}
