import { describe, it, expect } from "vitest";
import { detectTimestomping, type TimestampPair } from "../../src/intelligence/timestomping.js";
import { detectBurstActivity, type TimedEvent } from "../../src/intelligence/burst-detector.js";
import { detectLogGaps, type EventRecord } from "../../src/intelligence/log-gap.js";
import { detectKnownBadPaths, type FileEntry } from "../../src/intelligence/known-bad-paths.js";
import { detectBeaconing, type NetworkCallback } from "../../src/intelligence/beaconing.js";

describe("timestomping detector", () => {
  it("detects $SI before $FN (impossible without tampering)", () => {
    const pairs: TimestampPair[] = [{
      siCreated: new Date("2020-01-01").getTime(),
      fnCreated: new Date("2024-06-15").getTime(),
      siModified: new Date("2020-01-01").getTime(),
      fnModified: new Date("2024-06-15").getTime(),
      filename: "malware.exe",
      inode: "12345",
    }];
    const result = detectTimestomping(pairs);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0]!.type).toBe("timestomping_si_before_fn");
    expect(result[0]!.severity).toBe("CRITICAL");
  });

  it("detects identical $SI timestamps", () => {
    const ts = new Date("2023-05-01T12:00:00Z").getTime();
    const pairs: TimestampPair[] = [{
      siCreated: ts,
      fnCreated: ts + 1000,
      siModified: ts,
      fnModified: ts + 2000,
      filename: "suspicious.dll",
      inode: "999",
    }];
    const result = detectTimestomping(pairs);
    expect(result.some(a => a.type === "timestomping_identical_si")).toBe(true);
  });

  it("no false positives on normal files", () => {
    const pairs: TimestampPair[] = [{
      siCreated: new Date("2024-01-15T10:00:00Z").getTime(),
      fnCreated: new Date("2024-01-15T10:00:00Z").getTime(),
      siModified: new Date("2024-06-01T14:30:00Z").getTime(),
      fnModified: new Date("2024-01-15T10:00:00Z").getTime(),
      filename: "normal.docx",
      inode: "100",
    }];
    const result = detectTimestomping(pairs);
    expect(result.filter(a => a.severity === "CRITICAL").length).toBe(0);
  });
});

describe("burst activity detector", () => {
  it("detects spike in events", () => {
    // Normal: 2 events per minute for 60 minutes
    const events: TimedEvent[] = [];
    const baseTime = Date.now();
    for (let min = 0; min < 60; min++) {
      events.push({ timestamp: baseTime + min * 60000, label: `normal-${min}` });
      events.push({ timestamp: baseTime + min * 60000 + 30000, label: `normal-${min}b` });
    }
    // Spike: 100 events in one minute
    for (let i = 0; i < 100; i++) {
      events.push({ timestamp: baseTime + 30 * 60000 + i * 500, label: `burst-${i}` });
    }

    const result = detectBurstActivity(events);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0]!.type).toBe("activity_burst");
  });

  it("no alert on uniform activity", () => {
    const events: TimedEvent[] = Array.from({ length: 120 }, (_, i) => ({
      timestamp: Date.now() + i * 60000,
      label: `event-${i}`,
    }));
    const result = detectBurstActivity(events);
    expect(result.length).toBe(0);
  });
});

describe("log gap detector", () => {
  it("detects gaps in sequential record IDs", () => {
    const records: EventRecord[] = [
      { recordId: 1, timestamp: "2024-01-15T10:00:00", eventId: 4624, channel: "Security" },
      { recordId: 2, timestamp: "2024-01-15T10:00:01", eventId: 4624, channel: "Security" },
      { recordId: 3, timestamp: "2024-01-15T10:00:02", eventId: 4624, channel: "Security" },
      // Gap of 100 records
      { recordId: 103, timestamp: "2024-01-15T10:01:00", eventId: 4624, channel: "Security" },
      { recordId: 104, timestamp: "2024-01-15T10:01:01", eventId: 4624, channel: "Security" },
    ];
    const result = detectLogGaps(records);
    expect(result.some(a => a.type === "event_log_gap")).toBe(true);
  });

  it("detects explicit log clear events", () => {
    const records: EventRecord[] = [
      { recordId: 1, timestamp: "2024-01-15T03:00:00", eventId: 1102, channel: "Security" },
      { recordId: 2, timestamp: "2024-01-15T09:00:00", eventId: 4624, channel: "Security" },
    ];
    const result = detectLogGaps(records);
    expect(result.some(a => a.type === "log_cleared_event")).toBe(true);
    expect(result.find(a => a.type === "log_cleared_event")!.severity).toBe("CRITICAL");
  });
});

describe("known bad paths detector", () => {
  it("detects executables in temp directories", () => {
    const files: FileEntry[] = [
      { path: "C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe", name: "payload.exe", type: "file" },
      { path: "C:\\Windows\\System32\\cmd.exe", name: "cmd.exe", type: "file" },
    ];
    const result = detectKnownBadPaths(files);
    expect(result.some(a => a.type === "executables_in_temp")).toBe(true);
  });

  it("detects LOLBins outside System32", () => {
    const files: FileEntry[] = [
      { path: "C:\\Users\\Public\\certutil.exe", name: "certutil.exe", type: "file" },
    ];
    const result = detectKnownBadPaths(files);
    expect(result.some(a => a.type === "lolbins_out_of_place")).toBe(true);
  });

  it("detects double extensions", () => {
    const files: FileEntry[] = [
      { path: "C:\\Users\\Admin\\Desktop\\invoice.pdf.exe", name: "invoice.pdf.exe", type: "file" },
    ];
    const result = detectKnownBadPaths(files);
    expect(result.some(a => a.type === "double_extensions")).toBe(true);
  });
});

describe("beaconing detector", () => {
  it("detects regular callbacks", () => {
    const baseTime = Date.now();
    const callbacks: NetworkCallback[] = Array.from({ length: 20 }, (_, i) => ({
      timestamp: baseTime + i * 60_000 + Math.random() * 3000, // 60s ± 3s jitter
      dstAddr: "10.0.0.1",
      dstPort: 443,
      bytes: 500,
    }));
    const result = detectBeaconing(callbacks);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0]!.type).toBe("c2_beaconing");
  });

  it("no alert on random traffic", () => {
    const baseTime = Date.now();
    const callbacks: NetworkCallback[] = Array.from({ length: 10 }, (_, i) => ({
      timestamp: baseTime + Math.random() * 86_400_000, // random times across 24h
      dstAddr: "10.0.0.1",
      dstPort: 443,
      bytes: 500,
    }));
    const result = detectBeaconing(callbacks);
    // Random intervals should have high CV, so no beaconing detected
    expect(result.filter(a => a.confidence > 0.7).length).toBe(0);
  });
});
