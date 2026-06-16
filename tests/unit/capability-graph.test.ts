import { describe, it, expect, beforeEach } from "vitest";
import { CapabilityGraph } from "../../src/domain/capability-graph.js";

describe("CapabilityGraph", () => {
  let graph: CapabilityGraph;

  beforeEach(() => {
    graph = new CapabilityGraph();
  });

  describe("canExecute", () => {
    it("allows mount_evidence with no prerequisites", () => {
      const result = graph.canExecute("mount_evidence");
      expect(result.isOk()).toBe(true);
    });

    it("blocks verify_integrity without evidence_mounted", () => {
      const result = graph.canExecute("verify_integrity");
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.missing).toContain("evidence_mounted");
      }
    });

    it("allows verify_integrity after mount_evidence produces evidence_mounted", () => {
      graph.produce("mount_evidence");
      const result = graph.canExecute("verify_integrity");
      expect(result.isOk()).toBe(true);
    });

    it("blocks list_directory without both evidence_mounted AND integrity_verified", () => {
      graph.produce("mount_evidence");
      const result = graph.canExecute("list_directory");
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.missing).toContain("integrity_verified");
      }
    });

    it("allows list_directory after both prerequisites met", () => {
      graph.produce("mount_evidence");
      graph.produce("verify_integrity");
      const result = graph.canExecute("list_directory");
      expect(result.isOk()).toBe(true);
    });

    it("returns error for unknown tool", () => {
      const result = graph.canExecute("nonexistent_tool");
      expect(result.isErr()).toBe(true);
    });

    it("allows meta-cognitive tools with no prerequisites", () => {
      expect(graph.canExecute("get_investigation_state").isOk()).toBe(true);
      expect(graph.canExecute("get_methodology_coverage").isOk()).toBe(true);
      expect(graph.canExecute("get_coverage_gaps").isOk()).toBe(true);
      expect(graph.canExecute("suggest_next_action").isOk()).toBe(true);
    });
  });

  describe("produce", () => {
    it("adds capabilities to held set", () => {
      expect(graph.getHeld()).toHaveLength(0);
      graph.produce("mount_evidence");
      expect(graph.getHeld()).toContain("evidence_mounted");
    });

    it("accumulates capabilities (never removes)", () => {
      graph.produce("mount_evidence");
      graph.produce("verify_integrity");
      const held = graph.getHeld();
      expect(held).toContain("evidence_mounted");
      expect(held).toContain("integrity_verified");
    });
  });

  describe("getPhase", () => {
    it("starts UNINITIALIZED", () => {
      expect(graph.getPhase()).toBe("UNINITIALIZED");
    });

    it("transitions through phases", () => {
      graph.produce("mount_evidence");
      expect(graph.getPhase()).toBe("MOUNTED");

      graph.produce("verify_integrity");
      expect(graph.getPhase()).toBe("TRIAGING");
    });
  });

  describe("getExecutableTools", () => {
    it("initially only shows tools with no prerequisites", () => {
      const executable = graph.getExecutableTools();
      expect(executable).toContain("mount_evidence");
      expect(executable).toContain("get_investigation_state");
      expect(executable).not.toContain("list_directory");
    });

    it("unlocks more tools as capabilities are produced", () => {
      graph.produce("mount_evidence");
      graph.produce("verify_integrity");
      const executable = graph.getExecutableTools();
      expect(executable).toContain("list_directory");
      expect(executable).toContain("generate_timeline");
    });
  });

  describe("no execute_shell exists", () => {
    it("does not have any shell execution tool", () => {
      const allTools = graph.getAllTools();
      expect(allTools).not.toContain("execute_shell");
      expect(allTools).not.toContain("run_command");
      expect(allTools).not.toContain("shell");
      expect(allTools).not.toContain("exec");
      expect(allTools).not.toContain("bash");
    });
  });
});
