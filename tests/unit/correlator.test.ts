import { describe, it, expect } from "vitest";
import { computeCorrelationGraph, type FindingForCorrelation } from "../../src/reasoning/correlator.js";

describe("Auto-Correlation Engine", () => {
  const baseTime = new Date("2024-03-15T14:00:00Z").getTime();

  it("returns empty graph for fewer than 2 findings", () => {
    const g = computeCorrelationGraph([]);
    expect(g.edges).toHaveLength(0);
    expect(g.chains).toHaveLength(0);
    expect(g.timeline).toHaveLength(0);
  });

  it("detects temporal proximity between findings within 30-minute window", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f1", description: "Malware found in C:\\ProgramData\\perfmon-k\\perfmon-kr.exe", temporalStart: new Date(baseTime).toISOString(), registeredAt: baseTime },
      { id: "f2", description: "Persistence via registry Run key pointing to perfmon-kr.exe", temporalStart: new Date(baseTime + 5 * 60000).toISOString(), registeredAt: baseTime + 5 * 60000 },
    ];
    const g = computeCorrelationGraph(findings);
    const temporalEdges = g.edges.filter(e => e.edgeType === "TEMPORAL_PROXIMITY");
    expect(temporalEdges.length).toBeGreaterThan(0);
    expect(temporalEdges[0]!.strength).toBeGreaterThan(0.8); // 5 min apart in 30 min window = high strength
  });

  it("does NOT link findings outside the 30-minute window", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f1", description: "Event A", temporalStart: new Date(baseTime).toISOString(), registeredAt: baseTime },
      { id: "f2", description: "Event B", temporalStart: new Date(baseTime + 60 * 60000).toISOString(), registeredAt: baseTime + 60 * 60000 },
    ];
    const g = computeCorrelationGraph(findings);
    const temporalEdges = g.edges.filter(e => e.edgeType === "TEMPORAL_PROXIMITY");
    expect(temporalEdges).toHaveLength(0);
  });

  it("detects kill chain sequence (execution → persistence)", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f1", description: "PowerShell script executed", mitreTechnique: "T1059.001", registeredAt: baseTime },
      { id: "f2", description: "Scheduled task created for persistence", mitreTechnique: "T1053.005", registeredAt: baseTime + 1000 },
    ];
    const g = computeCorrelationGraph(findings);
    const kcEdges = g.edges.filter(e => e.edgeType === "KILL_CHAIN_SEQUENCE");
    expect(kcEdges.length).toBeGreaterThan(0);
    expect(kcEdges[0]!.sourceId).toBe("f1"); // execution comes first
    expect(kcEdges[0]!.targetId).toBe("f2"); // persistence comes after
  });

  it("detects shared entities (same file referenced in two findings)", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f1", description: "Suspicious file C:\\ProgramData\\perfmon-k\\perfmon-kr.exe found on disk", registeredAt: baseTime },
      { id: "f2", description: "Registry autorun references perfmon-kr.exe for persistence", registeredAt: baseTime + 1000 },
    ];
    const g = computeCorrelationGraph(findings);
    const entityEdges = g.edges.filter(e => e.edgeType === "SHARED_ENTITY");
    expect(entityEdges.length).toBeGreaterThan(0);
    expect(entityEdges[0]!.explanation).toContain("perfmon-kr.exe");
  });

  it("builds attack chains from strongly-connected findings", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f1", description: "Phishing email opened", mitreTechnique: "T1566.001", temporalStart: new Date(baseTime).toISOString(), registeredAt: baseTime },
      { id: "f2", description: "Malware executed via PowerShell", mitreTechnique: "T1059.001", temporalStart: new Date(baseTime + 2 * 60000).toISOString(), registeredAt: baseTime + 2 * 60000 },
      { id: "f3", description: "Persistence established via scheduled task", mitreTechnique: "T1053.005", temporalStart: new Date(baseTime + 5 * 60000).toISOString(), registeredAt: baseTime + 5 * 60000 },
    ];
    const g = computeCorrelationGraph(findings);
    expect(g.chains.length).toBeGreaterThan(0);
    const chain = g.chains[0]!;
    expect(chain.findingIds.length).toBeGreaterThanOrEqual(2);
    expect(chain.killChainPhases.length).toBeGreaterThanOrEqual(2);
  });

  it("builds timeline ordered by temporal_start", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f3", description: "Third event", temporalStart: new Date(baseTime + 10 * 60000).toISOString(), registeredAt: baseTime + 10 * 60000 },
      { id: "f1", description: "First event", temporalStart: new Date(baseTime).toISOString(), registeredAt: baseTime },
      { id: "f2", description: "Second event", temporalStart: new Date(baseTime + 5 * 60000).toISOString(), registeredAt: baseTime + 5 * 60000 },
    ];
    const g = computeCorrelationGraph(findings);
    expect(g.timeline[0]!.findingId).toBe("f1");
    expect(g.timeline[1]!.findingId).toBe("f2");
    expect(g.timeline[2]!.findingId).toBe("f3");
  });

  it("handles findings without temporal data gracefully", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f1", description: "Unknown timing event with perfmon-kr.exe", registeredAt: baseTime },
      { id: "f2", description: "Another event referencing perfmon-kr.exe", registeredAt: baseTime + 500 },
    ];
    const g = computeCorrelationGraph(findings);
    // Should still find shared entity edges
    expect(g.edges.length).toBeGreaterThan(0);
    expect(g.timeline.length).toBe(2);
  });

  it("handles findings with no MITRE technique", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f1", description: "Suspicious directory found", registeredAt: baseTime },
      { id: "f2", description: "Another anomaly", registeredAt: baseTime + 100 },
    ];
    // Should not crash, just produce fewer edges
    const g = computeCorrelationGraph(findings);
    expect(g).toBeDefined();
    expect(g.chains).toBeDefined();
  });

  it("correlation strength decreases with temporal distance", () => {
    const findings: FindingForCorrelation[] = [
      { id: "f1", description: "Event A", temporalStart: new Date(baseTime).toISOString(), registeredAt: baseTime },
      { id: "f2", description: "Event B (close)", temporalStart: new Date(baseTime + 2 * 60000).toISOString(), registeredAt: baseTime + 2 * 60000 },
      { id: "f3", description: "Event C (far)", temporalStart: new Date(baseTime + 25 * 60000).toISOString(), registeredAt: baseTime + 25 * 60000 },
    ];
    const g = computeCorrelationGraph(findings);
    const edgeAB = g.edges.find(e => e.sourceId === "f1" && e.targetId === "f2" && e.edgeType === "TEMPORAL_PROXIMITY");
    const edgeAC = g.edges.find(e => e.sourceId === "f1" && e.targetId === "f3" && e.edgeType === "TEMPORAL_PROXIMITY");
    if (edgeAB && edgeAC) {
      expect(edgeAB.strength).toBeGreaterThan(edgeAC.strength);
    }
  });
});
