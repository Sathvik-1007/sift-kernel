import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── Plaso/psort Parser ──────────────────────────────────────────────────────
// Parses JSON lines output from psort (Plaso timeline tool).

export interface PlasoEvent {
  readonly timestamp: string;
  readonly timestampDesc: string;
  readonly source: string;
  readonly sourceLong: string;
  readonly message: string;
  readonly filename: string;
  readonly inode: string;
  readonly parser: string;
  readonly extra: Record<string, unknown>;
}

export function parsePlaso(raw: string): ParseResult<readonly PlasoEvent[]> {
  const lines = raw.split("\n").filter(Boolean);
  const events: PlasoEvent[] = [];
  const anomalies: AnomalyFlag[] = [];
  const timestampCounts = new Map<string, number>(); // minute-level burst detection

  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as Record<string, unknown>;
      // Plaso timestamps can be ISO strings or microsecond epoch integers
      let ts = obj["datetime"] ?? obj["timestamp"] ?? "";
      if (typeof ts === "number") {
        ts = new Date(ts / 1000).toISOString(); // microseconds → ms → ISO
      }
      const event: PlasoEvent = {
        timestamp: String(ts),
        timestampDesc: (obj["timestamp_desc"] ?? obj["timestampDesc"] ?? "") as string,
        source: (obj["source_short"] ?? obj["source"] ?? "") as string,
        sourceLong: (obj["source_long"] ?? obj["sourceLong"] ?? "") as string,
        message: (obj["message"] ?? obj["msg"] ?? "") as string,
        filename: (obj["filename"] ?? obj["display_name"] ?? "") as string,
        inode: (obj["inode"] ?? "") as string,
        parser: (obj["parser"] ?? "") as string,
        extra: obj,
      };
      events.push(event);

      // Burst detection: count events per minute
      if (event.timestamp) {
        const minute = event.timestamp.slice(0, 16); // YYYY-MM-DDTHH:MM
        timestampCounts.set(minute, (timestampCounts.get(minute) ?? 0) + 1);
      }
    } catch {
      // Not JSON — try L2tCSV format
      const parts = line.split(",");
      if (parts.length >= 6) {
        events.push({
          timestamp: parts[0] ?? "",
          timestampDesc: parts[1] ?? "",
          source: parts[2] ?? "",
          sourceLong: parts[3] ?? "",
          message: parts.slice(5).join(","),
          filename: parts[4] ?? "",
          inode: "",
          parser: "",
          extra: {},
        });
      }
    }
  }

  // Detect burst activity (> 50 events in a single minute)
  const bursts: string[] = [];
  for (const [minute, count] of timestampCounts) {
    if (count > 50) {
      bursts.push(`${minute}: ${count} events`);
    }
  }
  if (bursts.length > 0) {
    anomalies.push({
      type: "activity_burst",
      severity: "HIGH",
      description: `${bursts.length} time period(s) with abnormally high activity (>50 events/minute)`,
      affectedItems: bursts.slice(0, 10),
    });
  }

  // Detect off-hours activity (between 00:00-05:00 local)
  const offHoursEvents = events.filter(e => {
    const hour = parseInt(e.timestamp.slice(11, 13), 10);
    return hour >= 0 && hour < 5;
  });
  if (offHoursEvents.length > 20) {
    anomalies.push({
      type: "off_hours_activity",
      severity: "MEDIUM",
      description: `${offHoursEvents.length} events during off-hours (00:00-05:00)`,
      affectedItems: offHoursEvents.slice(0, 5).map(e => `${e.timestamp}: ${e.message.slice(0, 80)}`),
    });
  }

  const summary = events.length > 0
    ? `${events.length} timeline events spanning ${events[0]?.timestamp ?? "?"} to ${events[events.length - 1]?.timestamp ?? "?"}`
    : "No timeline events parsed";

  return ok({
    summary,
    data: events,
    recordCount: events.length,
    anomalies,
    rawTruncated: raw.length > 10_000_000,
  });
}
