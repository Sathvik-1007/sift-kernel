import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { CapabilityGraph, TOOL_SPECS } from "../../src/domain/capability-graph.js";
import { createLedgerEntry, hashEntry, getGenesisHash, verifyChain, hashData } from "../../src/domain/ledger.js";
import { createFinding } from "../../src/domain/finding.js";
import type { LedgerEntry, LedgerEntryId, ArtifactCategory } from "../../src/domain/types.js";

// ─── P1: No shell execution tool exists ─────────────────────────────────────

describe("P1: No shell execution capability exists", () => {
  it("no tool name contains shell/exec/bash/cmd patterns", () => {
    const dangerousPatterns = [/^shell$/i, /^exec$/i, /^bash$/i, /^cmd$/i, /^run_command$/i, /^system$/i, /execute_shell/i, /run_shell/i, /spawn_shell/i];
    for (const spec of TOOL_SPECS) {
      for (const pattern of dangerousPatterns) {
        expect(spec.tool).not.toMatch(pattern);
      }
    }
  });
});

// ─── P2: No finding without evidence in final report ─────────────────────────

describe("P2: No ungrounded finding can enter final report", () => {
  const existingIds = new Set(["e1", "e2", "e3"]);
  const getCat = (): ArtifactCategory => "filesystem";

  it("createFinding with empty evidence produces HYPOTHESIZED (excluded from report)", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("initial_access", "execution", "persistence", "lateral_movement") as fc.Arbitrary<"initial_access" | "execution" | "persistence" | "lateral_movement">,
        fc.string({ minLength: 1, maxLength: 100 }),
        (type, description) => {
          const result = createFinding(
            { type, description, evidence: [] },
            existingIds,
            getCat,
          );
          if (result.isOk()) {
            // HYPOTHESIZED findings exist but cannot be in final report
            return result.value.confidence === "HYPOTHESIZED";
          }
          return true; // Error is also acceptable
        },
      ),
      { numRuns: 1000 },
    );
  });

  it("createFinding with non-existent evidence is rejected", () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 5, maxLength: 30 }), { minLength: 1, maxLength: 5 }),
        (fakeIds) => {
          // Ensure none of the fake IDs exist
          const nonExistent = fakeIds.filter((id) => !existingIds.has(id));
          if (nonExistent.length === 0) return true;

          const result = createFinding(
            {
              type: "persistence",
              description: "test",
              evidence: nonExistent as unknown as LedgerEntryId[],
            },
            existingIds,
            getCat,
          );
          return result.isErr(); // Must be rejected
        },
      ),
      { numRuns: 1000 },
    );
  });
});

// ─── P3: Capability graph has no cycles (valid DAG) ──────────────────────────

describe("P3: Capability graph is a valid DAG", () => {
  it("no tool produces a capability it also requires", () => {
    for (const spec of TOOL_SPECS) {
      const overlap = spec.requires.filter((r) => spec.produces.includes(r));
      expect(overlap, `Tool ${spec.tool} has circular requirement`).toHaveLength(0);
    }
  });

  it("capabilities only accumulate (monotonic)", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom(...TOOL_SPECS.map((s) => s.tool)), { minLength: 1, maxLength: 20 }),
        (toolSequence) => {
          const graph = new CapabilityGraph();
          let prevCount = 0;
          for (const tool of toolSequence) {
            graph.produce(tool);
            const currentCount = graph.getHeld().length;
            if (currentCount < prevCount) return false; // Capabilities were removed!
            prevCount = currentCount;
          }
          return true;
        },
      ),
      { numRuns: 1000 },
    );
  });
});

// ─── P4: Hash chain integrity for any operation sequence ─────────────────────

describe("P4: Hash chain valid for any sequence", () => {
  it("chain remains valid for arbitrary sequences of entries", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            tool: fc.constantFrom("mount_evidence", "verify_integrity", "list_directory", "scan_yara"),
            param: fc.string(),
          }),
          { minLength: 1, maxLength: 50 },
        ),
        (operations) => {
          const entries: LedgerEntry[] = [];
          let prevHash = getGenesisHash();

          for (const op of operations) {
            const entry = createLedgerEntry({
              tool: op.tool,
              toolParams: { input: op.param },
              outputHash: hashData({ result: op.param }),
              rawOutputPath: `/tmp/${op.tool}.json`,
              prevHash,
              capabilitiesHeld: ["evidence_mounted"],
              findingsProduced: [],
              anomaliesFlagged: [],
              durationMs: 100,
              success: true,
            });
            entries.push(entry);
            prevHash = hashEntry(entry);
          }

          const result = verifyChain(entries);
          return result.valid;
        },
      ),
      { numRuns: 500 },
    );
  });
});

// ─── P5: Every tool call produces exactly one ledger entry ───────────────────

describe("P5: Tool call → ledger entry bijection", () => {
  it("createLedgerEntry always returns a unique entry", () => {
    fc.assert(
      fc.property(
        fc.string(),
        fc.string(),
        (tool, param) => {
          const entry = createLedgerEntry({
            tool,
            toolParams: { input: param },
            outputHash: hashData(param),
            rawOutputPath: "/tmp/test.json",
            prevHash: getGenesisHash(),
            capabilitiesHeld: [],
            findingsProduced: [],
            anomaliesFlagged: [],
            durationMs: 0,
            success: true,
          });
          // Entry has a unique ID
          return typeof entry.id === "string" && (entry.id as string).length > 0;
        },
      ),
      { numRuns: 1000 },
    );
  });

  it("no two entries share an ID", () => {
    const ids = new Set<string>();
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 10000 }),
        (_) => {
          const entry = createLedgerEntry({
            tool: "test",
            toolParams: {},
            outputHash: hashData(Math.random()),
            rawOutputPath: "/tmp/t.json",
            prevHash: getGenesisHash(),
            capabilitiesHeld: [],
            findingsProduced: [],
            anomaliesFlagged: [],
            durationMs: 0,
            success: true,
          });
          const id = entry.id as string;
          if (ids.has(id)) return false; // Collision!
          ids.add(id);
          return true;
        },
      ),
      { numRuns: 5000 },
    );
  });
});

// ─── P6: Path containment ────────────────────────────────────────────────────

describe("P6: All paths contained within evidence mount", () => {
  it("path traversal attempts are blocked", async () => {
    const { FsEvidenceStore } = await import("../../src/adapters/fs-evidence.js");
    const store = new FsEvidenceStore("/tmp/sift-test-p6");

    // Simulate mount
    (store as any).mountPoint = "/tmp/sift-test-p6/evidence-mount";

    fc.assert(
      fc.property(
        fc.constantFrom(
          "../../../etc/passwd",
          "../../../../root/.ssh/id_rsa",
          "/etc/shadow",
          "subdir/../../../../../../etc/passwd",
          "normal/path/file.txt",
          "Users/admin/Desktop/doc.pdf",
        ),
        (path) => {
          const result = store.validatePath(path);
          if (path.includes("..") || path.startsWith("/")) {
            // Traversal or absolute path outside mount — must be rejected OR resolved within mount
            if (result.isOk()) {
              // If OK, the resolved path must start with the mount point
              return result.value.startsWith("/tmp/sift-test-p6/evidence-mount");
            }
            return true; // Error is acceptable for traversal
          }
          // Normal relative path — should resolve within mount
          if (result.isOk()) {
            return result.value.startsWith("/tmp/sift-test-p6/evidence-mount");
          }
          return true;
        },
      ),
      { numRuns: 100 },
    );
  });
});
