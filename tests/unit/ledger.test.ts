import { describe, it, expect } from "vitest";
import { createLedgerEntry, hashEntry, getGenesisHash, verifyChain, hashData } from "../../src/domain/ledger.js";
import type { LedgerEntry, LedgerEntryId } from "../../src/domain/types.js";

describe("Ledger Hash Chain", () => {
  function makeEntry(prevHash: string, tool: string = "test_tool"): LedgerEntry {
    return createLedgerEntry({
      tool,
      toolParams: { key: "value" },
      outputHash: hashData({ result: "test" }),
      rawOutputPath: "/tmp/test.json",
      prevHash,
      capabilitiesHeld: ["evidence_mounted"],
      findingsProduced: [],
      anomaliesFlagged: [],
      durationMs: 100,
      success: true,
    });
  }

  describe("getGenesisHash", () => {
    it("returns consistent hash", () => {
      expect(getGenesisHash()).toBe(getGenesisHash());
    });

    it("returns a 64-character hex string (SHA-256)", () => {
      expect(getGenesisHash()).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe("hashEntry", () => {
    it("produces consistent hash for same entry", () => {
      const entry = makeEntry(getGenesisHash());
      expect(hashEntry(entry)).toBe(hashEntry(entry));
    });

    it("produces different hash for different entries", () => {
      const entry1 = makeEntry(getGenesisHash(), "tool_a");
      const entry2 = makeEntry(getGenesisHash(), "tool_b");
      expect(hashEntry(entry1)).not.toBe(hashEntry(entry2));
    });
  });

  describe("verifyChain", () => {
    it("validates empty chain", () => {
      const result = verifyChain([]);
      expect(result.valid).toBe(true);
    });

    it("validates single-entry chain", () => {
      const entry = makeEntry(getGenesisHash());
      const result = verifyChain([entry]);
      expect(result.valid).toBe(true);
    });

    it("validates multi-entry chain", () => {
      const entry1 = makeEntry(getGenesisHash());
      const entry2 = makeEntry(hashEntry(entry1));
      const entry3 = makeEntry(hashEntry(entry2));
      const result = verifyChain([entry1, entry2, entry3]);
      expect(result.valid).toBe(true);
    });

    it("detects broken first entry (wrong genesis)", () => {
      const entry = makeEntry("wrong_hash");
      const result = verifyChain([entry]);
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(0);
    });

    it("detects broken chain in middle", () => {
      const entry1 = makeEntry(getGenesisHash());
      const entry2 = makeEntry(hashEntry(entry1));
      const tampered = makeEntry("tampered_hash"); // Wrong prevHash
      const result = verifyChain([entry1, entry2, tampered]);
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(2);
    });
  });
});
