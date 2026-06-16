import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

export interface BrowserEntry {
  readonly url: string;
  readonly title: string;
  readonly timestamp: string;
  readonly browser: "chrome" | "firefox" | "edge" | "unknown";
  readonly type: "history" | "download" | "cookie" | "cache";
  readonly extra?: Record<string, string>;
}

export function parseBrowserHistory(raw: string): ParseResult<readonly BrowserEntry[]> {
  const lines = raw.split("\n").filter(Boolean);
  const entries: BrowserEntry[] = [];
  const anomalies: AnomalyFlag[] = [];

  for (const line of lines) {
    // Common SQLite dump format: timestamp|url|title
    const parts = line.split("|");
    if (parts.length >= 2) {
      const url = parts[1] ?? "";
      entries.push({
        url,
        title: parts[2] ?? "",
        timestamp: parts[0] ?? "",
        browser: detectBrowser(url),
        type: "history",
      });

      // Flag suspicious downloads
      if (/\.(exe|ps1|bat|cmd|vbs|hta|scr|dll|msi)$/i.test(url)) {
        anomalies.push({ type: "suspicious_download", severity: "HIGH", description: `Executable download: ${url}`, affectedItems: [url] });
      }
      // Flag known malware distribution domains
      if (/paste(bin|\.ee)|anonfiles|transfer\.sh|temp\.sh/i.test(url)) {
        anomalies.push({ type: "suspicious_domain", severity: "CRITICAL", description: `Known file-sharing/paste site: ${url}`, affectedItems: [url] });
      }
    }
  }

  return ok({ summary: `${entries.length} browser history entries. ${anomalies.length} suspicious.`, data: entries, recordCount: entries.length, anomalies, rawTruncated: false });
}

function detectBrowser(url: string): BrowserEntry["browser"] {
  if (url.includes("chrome")) return "chrome";
  if (url.includes("firefox")) return "firefox";
  if (url.includes("edge")) return "edge";
  return "unknown";
}
