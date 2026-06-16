import Database from "better-sqlite3";
import { ok, err, type Result } from "neverthrow";
import type { LedgerEntry, LedgerEntryId, FindingId, Capability, Finding, Hypothesis } from "../domain/types.js";
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

      CREATE TABLE IF NOT EXISTS investigation_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS methodology_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        current_state TEXT NOT NULL,
        attempted_tools TEXT NOT NULL DEFAULT '[]',
        failed_tools TEXT NOT NULL DEFAULT '[]',
        open_hypotheses_count INTEGER NOT NULL DEFAULT 0
      );
    `);
  }

  // ─── Findings Persistence ───────────────────────────────────────────────────

  saveFinding(f: Finding): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO findings (id, type, description, evidence, confidence, temporal_start, temporal_end, mitre_technique, mitre_tactic, affected_hosts, iocs, supports_hypotheses, contradicts_hypotheses, registered_at, last_reassessed)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      f.id as string, f.type, f.description, JSON.stringify(f.evidence), f.confidence,
      f.temporalRange?.start ?? null, f.temporalRange?.end ?? null,
      f.mitreTechnique ?? null, f.mitreTactic ?? null,
      JSON.stringify(f.affectedHosts), JSON.stringify(f.iocs),
      JSON.stringify(f.supportsHypotheses), JSON.stringify(f.contradictsHypotheses),
      f.registeredAt, f.lastReassessed ?? null
    );
  }

  getAllFindings(): Finding[] {
    const rows = this.db.prepare("SELECT * FROM findings").all() as Array<Record<string, unknown>>;
    return rows.map(r => ({
      id: r["id"] as FindingId,
      type: r["type"] as Finding["type"],
      description: r["description"] as string,
      evidence: JSON.parse(r["evidence"] as string) as readonly LedgerEntryId[],
      confidence: r["confidence"] as Finding["confidence"],
      temporalRange: r["temporal_start"] ? { start: r["temporal_start"] as string, end: r["temporal_end"] as string } : undefined,
      mitreTechnique: r["mitre_technique"] as string | undefined,
      mitreTactic: r["mitre_tactic"] as Finding["mitreTactic"],
      affectedHosts: JSON.parse(r["affected_hosts"] as string) as readonly string[],
      iocs: JSON.parse(r["iocs"] as string) as Finding["iocs"],
      supportsHypotheses: JSON.parse(r["supports_hypotheses"] as string) as readonly import("../domain/types.js").HypothesisId[],
      contradictsHypotheses: JSON.parse(r["contradicts_hypotheses"] as string) as readonly import("../domain/types.js").HypothesisId[],
      registeredAt: r["registered_at"] as string,
      lastReassessed: r["last_reassessed"] as string | undefined,
    }));
  }

  // ─── Hypotheses Persistence ─────────────────────────────────────────────────

  saveHypothesis(h: Hypothesis): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO hypotheses (id, description, status, supporting_findings, contradicting_findings, registered_at, resolved_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      h.id as string, h.description, h.status,
      JSON.stringify(h.supportingFindings), JSON.stringify(h.contradictingFindings),
      h.registeredAt, h.resolvedAt ?? null
    );
  }

  getAllHypotheses(): Hypothesis[] {
    const rows = this.db.prepare("SELECT * FROM hypotheses").all() as Array<Record<string, unknown>>;
    return rows.map(r => ({
      id: r["id"] as import("../domain/types.js").HypothesisId,
      description: r["description"] as string,
      status: r["status"] as Hypothesis["status"],
      supportingFindings: JSON.parse(r["supporting_findings"] as string) as readonly FindingId[],
      contradictingFindings: JSON.parse(r["contradicting_findings"] as string) as readonly FindingId[],
      registeredAt: r["registered_at"] as string,
      resolvedAt: r["resolved_at"] as string | undefined,
    }));
  }

  // ─── Investigation State Persistence ────────────────────────────────────────

  saveInvestigationState(state: Record<string, string>): void {
    const stmt = this.db.prepare("INSERT OR REPLACE INTO investigation_state (key, value) VALUES (?, ?)");
    const tx = this.db.transaction(() => {
      for (const [k, v] of Object.entries(state)) stmt.run(k, v);
    });
    tx();
  }

  loadInvestigationState(): Record<string, string> {
    const rows = this.db.prepare("SELECT key, value FROM investigation_state").all() as Array<{ key: string; value: string }>;
    const state: Record<string, string> = {};
    for (const r of rows) state[r.key] = r.value;
    return state;
  }

  // ─── Methodology State Persistence ──────────────────────────────────────────

  saveMethodologyState(currentState: string, attemptedTools: string[], failedTools: string[], openHypothesesCount: number): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO methodology_state (id, current_state, attempted_tools, failed_tools, open_hypotheses_count)
      VALUES (1, ?, ?, ?, ?)
    `).run(currentState, JSON.stringify(attemptedTools), JSON.stringify(failedTools), openHypothesesCount);
  }

  loadMethodologyState(): { currentState: string; attemptedTools: string[]; failedTools: string[]; openHypothesesCount: number } | null {
    const row = this.db.prepare("SELECT * FROM methodology_state WHERE id = 1").get() as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      currentState: row["current_state"] as string,
      attemptedTools: JSON.parse(row["attempted_tools"] as string),
      failedTools: JSON.parse(row["failed_tools"] as string),
      openHypothesesCount: row["open_hypotheses_count"] as number,
    };
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
