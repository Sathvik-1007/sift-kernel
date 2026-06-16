import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── evtxexport Parser ───────────────────────────────────────────────────────
// Parses event log output from evtxexport or structured event data.

export interface EvtxEvent {
  readonly eventId: number;
  readonly timestamp: string;
  readonly source: string;
  readonly computer: string;
  readonly user: string;
  readonly level: string;
  readonly message: string;
  readonly recordId: number;
  readonly channel: string;
  readonly raw: string;
}

// Security Event IDs of forensic interest
const CRITICAL_EVENT_IDS = new Set([
  4624, 4625, 4648, // Logon events
  4672, // Special privileges
  4688, 4689, // Process creation/termination
  4697, // Service install
  4698, 4699, 4700, 4701, 4702, // Scheduled tasks
  4720, 4722, 4723, 4724, 4725, 4726, // Account management
  4732, 4733, // Group membership
  4768, 4769, 4771, // Kerberos
  1102, 104, // Log cleared
  7045, 7040, // Service changes
  4104, 4103, // PowerShell
]);

export function parseEvtx(raw: string): ParseResult<readonly EvtxEvent[]> {
  const events: EvtxEvent[] = [];
  const anomalies: AnomalyFlag[] = [];

  // Try JSONL format first (evtx_dump -o jsonl output)
  if (raw.trimStart().startsWith("{")) {
    const lines = raw.split("\n").filter(l => l.trim());
    for (const line of lines) {
      try {
        const obj = JSON.parse(line) as Record<string, unknown>;
        const evt = (obj["Event"] ?? obj) as Record<string, unknown>;
        const sys = (evt["System"] ?? {}) as Record<string, unknown>;
        const provider = (sys["Provider"] ?? {}) as Record<string, unknown>;
        const providerAttrs = (provider["#attributes"] ?? provider) as Record<string, unknown>;
        const timeCreated = (sys["TimeCreated"] ?? {}) as Record<string, unknown>;
        const timeAttrs = (timeCreated["#attributes"] ?? timeCreated) as Record<string, unknown>;
        const execAttrs = ((sys["Execution"] ?? {}) as Record<string, unknown>)["#attributes"] as Record<string, unknown> | undefined;
        const eventData = (evt["EventData"] ?? {}) as Record<string, unknown>;

        const eventId = typeof sys["EventID"] === "number" ? sys["EventID"] : parseInt(String(sys["EventID"] ?? "0"), 10);
        const timestamp = String(timeAttrs["SystemTime"] ?? "");
        const source = String(providerAttrs["Name"] ?? "");
        const computer = String(sys["Computer"] ?? "");
        const channel = String(sys["Channel"] ?? "");
        const recordId = typeof sys["EventRecordID"] === "number" ? sys["EventRecordID"] : parseInt(String(sys["EventRecordID"] ?? "0"), 10);
        const user = String(eventData["TargetUserName"] ?? eventData["SubjectUserName"] ?? "");
        const level = String(sys["Level"] ?? "");
        const message = JSON.stringify(eventData).slice(0, 500);

        events.push({ eventId, timestamp, source, computer, user, level, message, recordId, channel, raw: line.slice(0, 1000) });
      } catch {
        // Skip malformed lines
      }
    }
  } else if (raw.includes("<Event")) {
    const eventBlocks = raw.split(/<Event[\s>]/);
    for (const block of eventBlocks) {
      if (!block.trim()) continue;
      const eventId = parseInt(extractXmlValue(block, "EventID") ?? "0", 10);
      const timestamp = extractXmlValue(block, "TimeCreated", "SystemTime") ?? extractXmlValue(block, "TimeCreated") ?? "";
      const source = extractXmlValue(block, "Provider", "Name") ?? extractXmlValue(block, "Source") ?? "";
      const computer = extractXmlValue(block, "Computer") ?? "";
      const user = extractXmlValue(block, "Security", "UserID") ?? extractXmlValue(block, "TargetUserName") ?? "";
      const level = extractXmlValue(block, "Level") ?? "";
      const recordId = parseInt(extractXmlValue(block, "EventRecordID") ?? "0", 10);
      const channel = extractXmlValue(block, "Channel") ?? "";

      events.push({
        eventId,
        timestamp,
        source,
        computer,
        user,
        level,
        message: block.slice(0, 500),
        recordId,
        channel,
        raw: block.slice(0, 1000),
      });
    }
  } else {
    // Tab/line-delimited format
    const lines = raw.split("\n");
    let recordId = 0;
    let eventId = 0;
    let timestamp = "";
    let source = "";
    let computer = "";
    for (const line of lines) {
      if (line.match(/^Event number\s*:/i) || line.match(/^Record number\s*:/i)) {
        if (eventId) {
          events.push({ eventId, timestamp, source, computer, user: "", level: "", message: "", recordId, channel: "", raw: "" });
        }
        eventId = 0; timestamp = ""; source = ""; computer = ""; recordId = 0;
        const m = line.match(/(\d+)/);
        if (m) recordId = parseInt(m[1]!, 10);
      }
      if (line.match(/^Source name\s*:/i)) {
        // Start new record if we have a pending event
        if (eventId) {
          events.push({ eventId, timestamp, source, computer, user: "", level: "", message: "", recordId, channel: "", raw: "" });
          eventId = 0; timestamp = ""; computer = ""; recordId = 0;
        }
        source = line.split(":").slice(1).join(":").trim();
      }
      if (line.match(/^Event (identifier|ID)\s*:/i)) {
        const m = line.match(/(\d+)/);
        if (m) eventId = parseInt(m[1]!, 10);
      }
      if (line.match(/^Written time\s*:/i) || line.match(/^Time\s*:/i) || line.match(/^Date\s*:/i)) {
        timestamp = line.split(":").slice(1).join(":").trim();
      }
      if (line.match(/^Computer( name)?\s*:/i)) {
        computer = line.split(":").slice(1).join(":").trim();
      }
      if (line.match(/^Description\s*:/i)) {
        // ignore — description is metadata, not a field we parse
      }
    }
    if (eventId) {
      events.push({ eventId, timestamp, source, computer, user: "", level: "", message: "", recordId, channel: "", raw: "" });
    }
  }

  // Anomaly: log clearing events
  const clearEvents = events.filter(e => e.eventId === 1102 || e.eventId === 104);
  if (clearEvents.length > 0) {
    anomalies.push({
      type: "log_clearing",
      severity: "CRITICAL",
      description: `${clearEvents.length} log clearing event(s) detected (EID 1102/104)`,
      affectedItems: clearEvents.map(e => `${e.timestamp}: EID ${e.eventId} on ${e.computer}`),
    });
  }

  // Anomaly: service installs (persistence)
  const serviceEvents = events.filter(e => e.eventId === 7045 || e.eventId === 4697);
  if (serviceEvents.length > 0) {
    anomalies.push({
      type: "service_install",
      severity: "HIGH",
      description: `${serviceEvents.length} service installation event(s) — potential persistence`,
      affectedItems: serviceEvents.map(e => `${e.timestamp}: EID ${e.eventId}`).slice(0, 10),
    });
  }

  // Anomaly: failed logons
  const failedLogons = events.filter(e => e.eventId === 4625);
  if (failedLogons.length > 10) {
    anomalies.push({
      type: "brute_force_attempt",
      severity: "HIGH",
      description: `${failedLogons.length} failed logon attempts (EID 4625) — possible brute force`,
      affectedItems: failedLogons.slice(0, 5).map(e => `${e.timestamp}: user=${e.user}`),
    });
  }

  // Anomaly: PowerShell execution
  const psEvents = events.filter(e => e.eventId === 4104 || e.eventId === 4103);
  if (psEvents.length > 0) {
    anomalies.push({
      type: "powershell_execution",
      severity: "MEDIUM",
      description: `${psEvents.length} PowerShell event(s) detected`,
      affectedItems: psEvents.slice(0, 5).map(e => `${e.timestamp}: EID ${e.eventId}`),
    });
  }

  const criticalEvents = events.filter(e => CRITICAL_EVENT_IDS.has(e.eventId));
  const summary = `${events.length} events (${criticalEvents.length} forensically significant)`;

  return ok({
    summary,
    data: events,
    recordCount: events.length,
    anomalies,
    rawTruncated: false,
  });
}

function extractXmlValue(xml: string, tag: string, attr?: string): string | null {
  if (attr) {
    const re = new RegExp(`<${tag}[^>]*${attr}="([^"]*)"`, "i");
    const m = re.exec(xml);
    return m?.[1] ?? null;
  }
  const re = new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, "i");
  const m = re.exec(xml);
  return m?.[1] ?? null;
}
