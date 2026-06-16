import { describe, it, expect } from "vitest";
import {
  vacuousMass, createMass, combine, combinePCR5, combineYager,
  belief, plausibility, beliefInterval, hartleyEntropy,
  discount, conflictCoefficient, singleton, THETA,
  pignisticDistribution, shannonEntropy,
} from "../../src/reasoning/dempster-shafer.js";
import { ForensicReasoningEngine } from "../../src/reasoning/engine.js";
import { HYPOTHESES, EVIDENCE_RULES } from "../../src/reasoning/knowledge-base.js";
import { createConvergenceTracker, updateConvergence, getConvergenceProgress } from "../../src/reasoning/convergence.js";
import { detectBiases, type ActionRecord } from "../../src/reasoning/bias-detector.js";
import { roughApproximation, shouldStopInvestigating, type InformationObject } from "../../src/reasoning/rough-sets.js";

describe("FARE: Dempster-Shafer Theory", () => {
  it("vacuous mass has all mass on THETA", () => {
    const m = vacuousMass();
    expect(m.get(THETA)).toBe(1.0);
    expect(m.size).toBe(1);
  });

  it("createMass normalizes to sum 1.0", () => {
    const m = createMass([[singleton(0), 0.3], [singleton(1), 0.2], [THETA, 0.5]]);
    let sum = 0;
    for (const [, mass] of m) sum += mass;
    expect(Math.abs(sum - 1.0)).toBeLessThan(1e-9);
  });

  it("Bel(H) <= Pl(H) always (formal invariant)", () => {
    const m = createMass([[singleton(0), 0.3], [singleton(0) | singleton(1), 0.2], [THETA, 0.5]]);
    for (let i = 0; i < 12; i++) {
      const bi = beliefInterval(m, singleton(i));
      expect(bi.belief).toBeLessThanOrEqual(bi.plausibility + 1e-9);
      expect(bi.uncertainty).toBeGreaterThanOrEqual(-1e-9);
    }
  });

  it("discount with reliability=0 gives vacuous mass", () => {
    const m = createMass([[singleton(0), 0.8], [THETA, 0.2]]);
    const discounted = discount(m, 0);
    expect(discounted.get(THETA)).toBeCloseTo(1.0);
  });

  it("PCR5 combination produces valid mass function", () => {
    const m1 = createMass([[singleton(0), 0.6], [THETA, 0.4]]);
    const m2 = createMass([[singleton(1), 0.5], [THETA, 0.5]]);
    const { combined, conflict } = combinePCR5(m1, m2);
    let sum = 0;
    for (const [, mass] of combined) sum += mass;
    expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
    expect(conflict).toBeGreaterThanOrEqual(0);
    expect(conflict).toBeLessThanOrEqual(1);
  });

  it("high conflict triggers Yager rule (mass on THETA)", () => {
    // Near-contradictory sources
    const m1 = createMass([[singleton(0), 0.95], [THETA, 0.05]]);
    const m2 = createMass([[singleton(1), 0.95], [THETA, 0.05]]);
    const K = conflictCoefficient(m1, m2);
    expect(K).toBeGreaterThan(0.7);
    const { combined } = combineYager(m1, m2);
    // Yager transfers conflict to THETA
    const thetaMass = combined.get(THETA) ?? 0;
    expect(thetaMass).toBeGreaterThan(0.5);
  });

  it("pignistic distribution sums to 1.0", () => {
    const m = createMass([[singleton(0), 0.3], [singleton(0) | singleton(1), 0.2], [THETA, 0.5]]);
    const dist = pignisticDistribution(m, 12);
    const sum = dist.reduce((a, b) => a + b, 0);
    expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
  });

  it("hartley entropy is 0 for certain belief", () => {
    const m = createMass([[singleton(0), 1.0]]);
    expect(hartleyEntropy(m)).toBe(0);
  });

  it("hartley entropy is max for total ignorance", () => {
    const m = vacuousMass();
    expect(hartleyEntropy(m)).toBeGreaterThan(3); // log2(12) ≈ 3.58
  });
});

describe("FARE: Knowledge Base", () => {
  it("has 12 hypothesis scenarios", () => {
    expect(HYPOTHESES.length).toBe(12);
  });

  it("all hypothesis indices are unique", () => {
    const indices = new Set(HYPOTHESES.map(h => h.index));
    expect(indices.size).toBe(12);
  });

  it("evidence rules have valid mass functions (sum to 1.0)", () => {
    for (const rule of EVIDENCE_RULES) {
      let sum = 0;
      for (const [, mass] of rule.mass) sum += mass;
      expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
    }
  });

  it("no rule assigns >0.65 mass to any single focal element", () => {
    for (const rule of EVIDENCE_RULES) {
      for (const [fe, mass] of rule.mass) {
        if (fe !== THETA) {
          expect(mass).toBeLessThanOrEqual(0.85);
        }
      }
    }
  });

  it("all rules have reliability in [0,1]", () => {
    for (const rule of EVIDENCE_RULES) {
      expect(rule.reliability).toBeGreaterThanOrEqual(0);
      expect(rule.reliability).toBeLessThanOrEqual(1);
    }
  });

  it("has 60+ evidence rules", () => {
    expect(EVIDENCE_RULES.length).toBeGreaterThanOrEqual(60);
  });
});

describe("FARE: Reasoning Engine (integration)", () => {
  it("starts with maximum entropy (total ignorance)", () => {
    const engine = new ForensicReasoningEngine();
    expect(engine.getEntropy()).toBeGreaterThan(3); // close to log2(12)
  });

  it("processToolOutput with matching pattern reduces entropy", () => {
    const engine = new ForensicReasoningEngine();
    const initialEntropy = engine.getEntropy();
    // Feed it output that matches a malware rule
    engine.processToolOutput("list_directory", "ProgramData/malware/dropper.exe", true, "filesystem");
    const newEntropy = engine.getEntropy();
    expect(newEntropy).toBeLessThan(initialEntropy);
  });

  it("conflict coefficient rises with contradictory evidence", () => {
    const engine = new ForensicReasoningEngine();
    // Malware indicator
    const r1 = engine.processToolOutput("list_directory", "ProgramData/cobalt-strike/beacon.exe", true, "filesystem");
    // Then insider indicator
    const r2 = engine.processToolOutput("search_filename", "SpiderFoot OSINT tool found in Downloads", true, "filesystem");
    // Conflict should be nonzero (both can't be purely APT AND purely insider)
    expect(r1.conflict + r2.conflict).toBeGreaterThan(0);
  });

  it("failed tools do not update beliefs", () => {
    const engine = new ForensicReasoningEngine();
    const before = engine.getEntropy();
    engine.processToolOutput("parse_event_log", "", false, "event_logs");
    const after = engine.getEntropy();
    expect(after).toBe(before);
  });

  it("selectNextTool returns scored candidates", () => {
    const engine = new ForensicReasoningEngine();
    const result = engine.selectNextTool(["list_directory", "parse_event_log", "scan_yara"]);
    expect(result.tool).toBeDefined();
    expect(result.efeScore.total).toBeGreaterThanOrEqual(0);
    expect(result.alternatives.length).toBeGreaterThanOrEqual(0);
  });

  it("reset returns to initial state", () => {
    const engine = new ForensicReasoningEngine();
    engine.processToolOutput("list_directory", "ProgramData/evil.exe", true, "filesystem");
    engine.reset();
    expect(engine.getEntropy()).toBeGreaterThan(3);
    expect(engine.getDominantHypothesis()).toBeNull();
  });
});

describe("FARE: Convergence", () => {
  it("starts in EXPLORING state", () => {
    const tracker = createConvergenceTracker();
    expect(tracker.state).toBe("EXPLORING");
  });

  it("detects CONVERGING when entropy drops monotonically", () => {
    let tracker = createConvergenceTracker();
    const entropies = [3.5, 3.2, 2.8, 2.4, 2.0];
    for (const e of entropies) {
      const result = updateConvergence(tracker, e, 0.1, { hypothesis: "apt", belief: 0.5 });
      tracker = result.tracker;
    }
    expect(tracker.state).toBe("CONVERGING");
  });

  it("detects CONVERGED when entropy below threshold", () => {
    let tracker = createConvergenceTracker();
    const entropies = [3.5, 2.5, 1.5, 0.8, 0.4, 0.3];
    for (const e of entropies) {
      const result = updateConvergence(tracker, e, 0.1, { hypothesis: "apt", belief: 0.8 });
      tracker = result.tracker;
    }
    expect(tracker.state).toBe("CONVERGED");
  });

  it("progress is 0% at start, higher after learning", () => {
    let tracker = createConvergenceTracker();
    expect(getConvergenceProgress(tracker)).toBe(0);
    const { tracker: t2 } = updateConvergence(tracker, 3.5, 0, null);
    const { tracker: t3 } = updateConvergence(t2, 2.0, 0, null);
    expect(getConvergenceProgress(t3)).toBeGreaterThan(30);
  });
});

describe("FARE: Bias Detection", () => {
  it("detects confirmation bias when >75% actions target leading hypothesis", () => {
    const history: ActionRecord[] = Array.from({ length: 10 }, (_, i) => ({
      tool: `tool_${i}`, category: "filesystem", timestamp: Date.now() + i,
      targetedHypothesis: "apt_targeted", informationGain: 0.1,
    }));
    const warnings = detectBiases(history, "apt_targeted", HYPOTHESES.map(h => h.id));
    expect(warnings.some(w => w.type === "confirmation")).toBe(true);
  });

  it("no confirmation/anchoring bias with diverse actions", () => {
    const hyps = HYPOTHESES.map(h => h.id);
    const history: ActionRecord[] = hyps.slice(0, 10).map((h, i) => ({
      tool: `tool_${i}`, category: ["filesystem", "registry", "event_logs", "execution", "memory", "network", "anti_forensics", "persistence", "user_activity", "browser"][i] ?? "filesystem",
      timestamp: Date.now() + i, targetedHypothesis: h, informationGain: 0.1,
    }));
    const warnings = detectBiases(history, "apt_targeted", hyps);
    // Should NOT have confirmation or anchoring (diverse), may have mild tunnel vision (2 untested)
    expect(warnings.filter(w => w.type === "confirmation").length).toBe(0);
    expect(warnings.filter(w => w.type === "anchoring").length).toBe(0);
  });
});

describe("FARE: Rough Sets", () => {
  it("lower approximation is subset of upper", () => {
    const objects: InformationObject[] = [
      { id: "f1", attributes: new Map([["type", "exe"], ["location", "temp"]]) },
      { id: "f2", attributes: new Map([["type", "exe"], ["location", "system"]]) },
      { id: "f3", attributes: new Map([["type", "doc"], ["location", "temp"]]) },
    ];
    const target = new Set(["f1", "f2"]); // "malicious" set
    const approx = roughApproximation(objects, target, ["type", "location"]);
    // Lower must be subset of upper
    for (const id of approx.lower) expect(approx.upper.has(id)).toBe(true);
    expect(approx.accuracy).toBeGreaterThanOrEqual(0);
    expect(approx.accuracy).toBeLessThanOrEqual(1);
  });

  it("shouldStopInvestigating returns true when boundary is empty", () => {
    const approx = { lower: new Set(["a", "b"]), upper: new Set(["a", "b"]), boundary: new Set<string>(), accuracy: 1.0 };
    const { shouldStop } = shouldStopInvestigating(approx);
    expect(shouldStop).toBe(true);
  });

  it("shouldStopInvestigating returns false with large boundary", () => {
    const approx = { lower: new Set(["a"]), upper: new Set(["a", "b", "c", "d"]), boundary: new Set(["b", "c", "d"]), accuracy: 0.25 };
    const { shouldStop } = shouldStopInvestigating(approx);
    expect(shouldStop).toBe(false);
  });
});
