import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

export interface AuthLogEntry {
  readonly timestamp: string;
  readonly hostname: string;
  readonly service: string;
  readonly pid: number;
  readonly message: string;
  readonly user?: string;
  readonly sourceIp?: string;
  readonly success: boolean;
  readonly eventType: "login" | "logout" | "sudo" | "su" | "failed" | "session" | "other";
}

const AUTH_LINE_RE = /^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\w+)\[?(\d+)?\]?:\s*(.+)$/;

export function parseAuthLog(raw: string): ParseResult<readonly AuthLogEntry[]> {
  const lines = raw.split("\n").filter(Boolean);
  const entries: AuthLogEntry[] = [];
  const anomalies: AnomalyFlag[] = [];
  const failedByIp = new Map<string, number>();

  for (const line of lines) {
    const match = AUTH_LINE_RE.exec(line);
    if (!match) continue;

    const message = match[5] ?? "";
    const userMatch = message.match(/(?:for invalid user|for user|for|user)\s+(\S+)/i);
    const ipMatch = message.match(/from\s+([\d.]+|[a-f0-9:]+)/i);
    const success = !(/fail|invalid|error|denied/i.test(message));

    let eventType: AuthLogEntry["eventType"] = "other";
    if (/accepted|session opened/i.test(message)) eventType = "login";
    else if (/session closed/i.test(message)) eventType = "logout";
    else if (/sudo/i.test(match[3] ?? "")) eventType = "sudo";
    else if (/su/i.test(match[3] ?? "")) eventType = "su";
    else if (/fail|invalid/i.test(message)) eventType = "failed";
    else if (/session/i.test(message)) eventType = "session";

    const entry: AuthLogEntry = {
      timestamp: match[1] ?? "",
      hostname: match[2] ?? "",
      service: match[3] ?? "",
      pid: parseInt(match[4] ?? "0", 10),
      message,
      ...(userMatch?.[1] ? { user: userMatch[1] } : {}),
      ...(ipMatch?.[1] ? { sourceIp: ipMatch[1] } : {}),
      success,
      eventType,
    };
    entries.push(entry);

    // Track failed attempts by IP
    if (!success && entry.sourceIp) {
      failedByIp.set(entry.sourceIp, (failedByIp.get(entry.sourceIp) ?? 0) + 1);
    }
  }

  // Flag brute force attempts
  for (const [ip, count] of failedByIp) {
    if (count >= 5) {
      anomalies.push({ type: "brute_force", severity: count >= 20 ? "CRITICAL" : "HIGH", description: `${count} failed auth attempts from ${ip}`, affectedItems: [ip] });
    }
  }

  // Flag root logins
  const rootLogins = entries.filter((e) => e.user === "root" && e.eventType === "login");
  if (rootLogins.length > 0) {
    anomalies.push({ type: "root_login", severity: "MEDIUM", description: `${rootLogins.length} direct root logins detected`, affectedItems: rootLogins.map((e) => e.sourceIp ?? "local") });
  }

  return ok({ summary: `${entries.length} auth log entries. ${anomalies.length} anomalies detected.`, data: entries, recordCount: entries.length, anomalies, rawTruncated: false });
}
