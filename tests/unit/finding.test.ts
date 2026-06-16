import { describe, it, expect } from "vitest";
import { createFinding, computeConfidence, reassessFinding } from "../../src/domain/finding.js";
import type { LedgerEntryId, ArtifactCategory } from "../../src/domain/types.js";

describe("Finding Registration", () => {
  const existingIds = new Set(["entry-1", "entry-2", "entry-3", "entry-4"]);

  const getCategoryForEntry = (id: LedgerEntryId): ArtifactCategory | undefined => {
    const map: Record<string, ArtifactCategory> = {
      "entry-1": "filesystem",
      "entry-2": "event_logs",
      "entry-3": "registry",
      "entry-4": "filesystem",
    };
    return map[id as string];
  };

  describe("computeConfidence", () => {
    it("returns HYPOTHESIZED for zero evidence", () => {
      expect(computeConfidence([], getCategoryForEntry)).toBe("HYPOTHESIZED");
    });

    it("returns INFERRED for single evidence", () => {
      const evidence = ["entry-1" as unknown as LedgerEntryId];
      expect(computeConfidence(evidence, getCategoryForEntry)).toBe("INFERRED");
    });

    it("returns SUPPORTED for multiple evidence from same category", () => {
      const evidence = ["entry-1", "entry-4"] as unknown as LedgerEntryId[];
      expect(computeConfidence(evidence, getCategoryForEntry)).toBe("SUPPORTED");
    });

    it("returns CONFIRMED for evidence from different categories", () => {
      const evidence = ["entry-1", "entry-2"] as unknown as LedgerEntryId[];
      expect(computeConfidence(evidence, getCategoryForEntry)).toBe("CONFIRMED");
    });
  });

  describe("createFinding", () => {
    it("rejects finding with non-existent evidence IDs", () => {
      const result = createFinding(
        { type: "persistence", description: "Test", evidence: ["nonexistent" as unknown as LedgerEntryId] },
        existingIds,
        getCategoryForEntry,
      );
      expect(result.isErr()).toBe(true);
    });

    it("creates finding with valid evidence", () => {
      const result = createFinding(
        { type: "persistence", description: "Scheduled task created", evidence: ["entry-1" as unknown as LedgerEntryId] },
        existingIds,
        getCategoryForEntry,
      );
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.confidence).toBe("INFERRED");
        expect(result.value.type).toBe("persistence");
      }
    });

    it("rejects findings with zero evidence (critical invariant)", () => {
      const result = createFinding(
        { type: "lateral_movement", description: "Hypothesis: attacker moved laterally", evidence: [] },
        existingIds,
        getCategoryForEntry,
      );
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain("zero evidence");
      }
    });

    it("computes CONFIRMED for cross-category evidence", () => {
      const result = createFinding(
        {
          type: "lateral_movement",
          description: "RDP session detected",
          evidence: ["entry-1", "entry-2", "entry-3"] as unknown as LedgerEntryId[],
        },
        existingIds,
        getCategoryForEntry,
      );
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.confidence).toBe("CONFIRMED");
      }
    });
  });

  describe("reassessFinding", () => {
    it("upgrades confidence when additional evidence from different category", () => {
      const createResult = createFinding(
        { type: "persistence", description: "Test", evidence: ["entry-1" as unknown as LedgerEntryId] },
        existingIds,
        getCategoryForEntry,
      );
      expect(createResult.isOk()).toBe(true);
      if (!createResult.isOk()) return;

      const reassessResult = reassessFinding(
        createResult.value,
        ["entry-2" as unknown as LedgerEntryId],
        existingIds,
        getCategoryForEntry,
      );
      expect(reassessResult.isOk()).toBe(true);
      if (reassessResult.isOk()) {
        expect(reassessResult.value.confidence).toBe("CONFIRMED");
        expect(reassessResult.value.evidence).toHaveLength(2);
      }
    });
  });
});
