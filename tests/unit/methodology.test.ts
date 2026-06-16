import { describe, it, expect } from "vitest";
import { MethodologyTracker, BASELINE_INVESTIGATION } from "../../src/domain/methodology.js";
import { Capability } from "../../src/domain/types.js";

// Every capability granted, so prerequisite-unlocking never masks a baseline tool.
const ALL_CAPS = Capability.options as readonly (typeof Capability.options)[number][];

/**
 * Drive the tracker the way the server does: ask for the next action, mark it
 * executed, repeat. Returns the ordered list of tools the FSM suggested.
 */
function driveInvestigation(t: MethodologyTracker, opts: { failTools?: Set<string> } = {}): string[] {
  const suggested: string[] = [];
  const fail = opts.failTools ?? new Set<string>();
  // Get past COLLECTION + TRIAGE deterministically.
  for (const seed of ["mount_evidence", "verify_integrity", "list_directory", "search_filename"]) {
    t.recordExecution(seed);
  }
  for (let i = 0; i < 200; i++) {
    const s = t.suggestNextAction(ALL_CAPS);
    if (!s) break;
    suggested.push(s.tool);
    if (s.tool === "generate_report") break;
    if (fail.has(s.tool)) t.recordFailure(s.tool);
    else t.recordExecution(s.tool);
  }
  return suggested;
}

describe("MethodologyTracker — comprehensive baseline coverage", () => {
  it("attempts EVERY baseline tool before reaching the report, with no signals", () => {
    const t = new MethodologyTracker();
    const seq = driveInvestigation(t);
    for (const item of BASELINE_INVESTIGATION) {
      expect(seq, `baseline tool ${item.tool} (${item.category}) must be covered`).toContain(item.tool);
    }
  });

  it("covers ALL baseline categories even when only ONE signal fired (insider)", () => {
    const t = new MethodologyTracker();
    t.emitSignal("INSIDER_INDICATORS"); // only the insider path is 'active'
    const seq = driveInvestigation(t);
    // Anti-forensics + persistence + execution are NOT the insider path — they
    // must still be covered because the baseline guarantees it.
    expect(seq).toContain("detect_log_clearing");      // anti_forensics
    expect(seq).toContain("get_persistence_keys");     // persistence
    expect(seq).toContain("parse_prefetch");           // execution_artifacts
    expect(seq).toContain("correlate_logon_events");   // event_logs
  });

  it("covers ALL baseline categories even when only the anti-forensics signal fired", () => {
    const t = new MethodologyTracker();
    t.emitSignal("ANTI_FORENSICS_DETECTED");
    const seq = driveInvestigation(t);
    // The malware/persistence/user-activity baseline must still be covered —
    // this is the exact divergence the two demo runs exhibited.
    expect(seq).toContain("scan_yara");
    expect(seq).toContain("check_scheduled_tasks");
    expect(seq).toContain("parse_lnk_files");
    expect(seq).toContain("get_usb_history");
  });

  it("does NOT count failed/unavailable tools as analytical coverage but still advances", () => {
    const t = new MethodologyTracker();
    // Simulate a tool-poor environment: half the baseline fails (missing binaries).
    const failing = new Set(BASELINE_INVESTIGATION.filter((_, i) => i % 2 === 0).map(b => b.tool));
    const seq = driveInvestigation(t, { failTools: failing });
    // Even with failures, every baseline tool was ATTEMPTED (appears in sequence)...
    for (const item of BASELINE_INVESTIGATION) {
      expect(seq).toContain(item.tool);
    }
    // ...and the FSM still progresses to the report (does not deadlock).
    expect(seq).toContain("generate_report");
    // Failed tools are not analytical coverage: overall coverage < 100%.
    expect(t.getOverallCoverage()).toBeLessThan(100);
  });

  it("two independent runs converge on the same baseline coverage (determinism)", () => {
    const runA = new MethodologyTracker();
    runA.emitSignal("MALWARE_INDICATORS");
    runA.emitSignal("INSIDER_INDICATORS");
    const seqA = driveInvestigation(runA);

    const runB = new MethodologyTracker();
    runB.emitSignal("ANTI_FORENSICS_DETECTED");
    const seqB = driveInvestigation(runB);

    // Regardless of which signals fired, both runs cover the full baseline set.
    const baselineTools = BASELINE_INVESTIGATION.map(b => b.tool);
    const coveredByA = baselineTools.every(tool => seqA.includes(tool));
    const coveredByB = baselineTools.every(tool => seqB.includes(tool));
    expect(coveredByA).toBe(true);
    expect(coveredByB).toBe(true);
  });

  it("terminates in REPORT state (no infinite loop)", () => {
    const t = new MethodologyTracker();
    driveInvestigation(t);
    expect(t.getState()).toBe("REPORT");
  });
});
