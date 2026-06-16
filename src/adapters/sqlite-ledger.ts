import Database from "better-sqlite3";
import { ok, err, type Result } from "neverthrow";
import type { LedgerEntry, LedgerEntryId, FindingId, Capability } from "../domain/types.js";
import { verifyChain as verifyChainLogic } from "../domain/ledger.js";
import type { LedgerError } from "../domain/errors.js";
import type { LedgerStore } from "../ports/ledger-store.port.js";

// ─── SQLite Ledger Store ─────────────────────────────────────────────────────

export class SqliteLedgerStore implements LedgerStore {
  private readonly db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL");
    this.initialize();
  }

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ledger (
        id TEXT PRIMARY KEY,
        tool TEXT NOT NULL,
        params TEXT NOT NULL,
        output_hash TEXT NOT NULL,
        raw_output_path TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        capabilities TEXT NOT NULL DEFAULT '[]',
        findings TEXT NOT NULL DEFAULT '[]',
        anomalies TEXT NOT NULL DEFAULT '[]',
        duration_ms INTEGER NOT NULL,
        success INTEGER NOT NULL DEFAULT 1,
        error_message TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_ledger_tool ON ledger(tool);
      CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger(timestamp);

      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence TEXT NOT NULL,
        confidence TEXT NOT NULL,
        temporal_start TEXT,
        temporal_end TEXT,
        mitre_technique TEXT,
        mitre_tactic TEXT,
        affected_hosts TEXT DEFAULT '[]',
        iocs TEXT DEFAULT '[]',
        supports_hypotheses TEXT DEFAULT '[]',
        contradicts_hypotheses TEXT DEFAULT '[]',
        registered_at TEXT NOT NULL,
        last_reassessed TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
      CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence);

      CREATE TABLE IF NOT EXISTS hypotheses (
        id TEXT PRIMARY KEY,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'OPEN',
        supporting_findings TEXT NOT NULL DEFAULT '[]',
        contradicting_findings TEXT NOT NULL DEFAULT '[]',
        registered_at TEXT NOT NULL,
        resolved_at TEXT
      );

      CREATE TABLE IF NOT EXISTS anomalies (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        source_ledger_entry TEXT NOT NULL,
        affected_entries TEXT NOT NULL DEFAULT '[]',
        detected_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity);
    `);
  }

  append(entry: LedgerEntry): Result<LedgerEntryId, LedgerError> {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO ledger (id, tool, params, output_hash, raw_output_path, timestamp, prev_hash, capabilities, findings, anomalies, duration_ms, success, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        entry.id as string,
        entry.tool,
        JSON.stringify(entry.params),
        entry.outputHash,
        entry.rawOutputPath,
        entry.timestamp,
        entry.prevHash,
        JSON.stringify(entry.capabilitiesHeld),
        JSON.stringify(entry.findingsProduced),
        JSON.stringify(entry.anomaliesFlagged),
        entry.durationMs,
        entry.success ? 1 : 0,
        entry.errorMessage ?? null,
      );
      return ok(entry.id);
    } catch (e) {
      return err({
        kind: "LEDGER_ERROR",
        operation: "append",
        message: e instanceof Error ? e.message : "Unknown error appending to ledger",
        entryId: entry.id,
      });
    }
  }

  getEntry(id: LedgerEntryId): Result<LedgerEntry, LedgerError> {
    const row = this.db.prepare("SELECT * FROM ledger WHERE id = ?").get(id as string) as
      | Record<string, unknown>
      | undefined;
    if (!row) {
      return err({
        kind: "LEDGER_ERROR",
        operation: "query",
        message: `Ledger entry not found: ${id}`,
        entryId: id,
      });
    }
    try {
      return ok(this.rowToEntry(row));
    } catch (e) {
      return err({
        kind: "LEDGER_ERROR",
        operation: "query",
        message: `Failed to parse ledger entry ${id}: ${e instanceof Error ? e.message : "unknown"}`,
        entryId: id,
      });
    }
  }

  getAllEntries(): readonly LedgerEntry[] {
    const rows = this.db.prepare("SELECT * FROM ledger ORDER BY rowid ASC").all() as Array<Record<string, unknown>>;
    return rows.map((r) => this.rowToEntry(r));
  }

  getLastEntry(): LedgerEntry | null {
    const row = this.db.prepare("SELECT * FROM ledger ORDER BY rowid DESC LIMIT 1").get() as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToEntry(row) : null;
  }

  getEntriesByTool(tool: string): readonly LedgerEntry[] {
    const rows = this.db
      .prepare("SELECT * FROM ledger WHERE tool = ? ORDER BY timestamp ASC")
      .all(tool) as Array<Record<string, unknown>>;
    return rows.map((r) => this.rowToEntry(r));
  }

  verifyChain(): Result<{ valid: boolean; entryCount: number; message: string }, LedgerError> {
    try {
      const entries = this.getAllEntries();
      const result = verifyChainLogic(entries);
      return ok({ valid: result.valid, entryCount: entries.length, message: result.message });
    } catch (e) {
      return err({
        kind: "LEDGER_ERROR",
        operation: "verify_chain",
        message: e instanceof Error ? e.message : "Unknown error verifying chain",
      });
    }
  }

  traceProvenance(findingId: FindingId): readonly LedgerEntry[] {
    // Use json_each for exact membership matching — avoids LIKE substring false positives
    const rows = this.db
      .prepare(
        `SELECT l.* FROM ledger l, json_each(l.findings) je WHERE je.value = ? ORDER BY l.rowid ASC`
      )
      .all(findingId as string) as Array<Record<string, unknown>>;
    return rows.map((r) => this.rowToEntry(r));
  }

  exists(id: LedgerEntryId): boolean {
    const row = this.db.prepare("SELECT 1 FROM ledger WHERE id = ?").get(id as string);
    return row !== undefined;
  }

  getAllIds(): ReadonlySet<string> {
    const rows = this.db.prepare("SELECT id FROM ledger").all() as Array<{ id: string }>;
    return new Set(rows.map((r) => r.id));
  }

  count(): number {
    const row = this.db.prepare("SELECT COUNT(*) as cnt FROM ledger").get() as { cnt: number };
    return row.cnt;
  }

  /** Close the database connection */
  close(): void {
    this.db.close();
  }

  /** Clear all entries (for investigation reset) */
  clear(): void {
    this.db.exec("DELETE FROM ledger");
  }

  private rowToEntry(row: Record<string, unknown>): LedgerEntry {
    return {
      id: row["id"] as LedgerEntryId,
      tool: row["tool"] as string,
      params: JSON.parse(row["params"] as string) as Record<string, unknown>,
      outputHash: row["output_hash"] as string,
      rawOutputPath: row["raw_output_path"] as string,
      timestamp: row["timestamp"] as string,
      prevHash: row["prev_hash"] as string,
      capabilitiesHeld: JSON.parse(row["capabilities"] as string) as Capability[],
      findingsProduced: JSON.parse(row["findings"] as string) as FindingId[],
      anomaliesFlagged: JSON.parse(row["anomalies"] as string) as string[] as unknown as readonly import("../domain/types.js").AnomalyId[],
      durationMs: row["duration_ms"] as number,
      success: (row["success"] as number) === 1,
      errorMessage: (row["error_message"] as string | null) ?? undefined,
    };
  }
}
