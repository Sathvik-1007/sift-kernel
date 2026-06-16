import { writeFileSync, readFileSync, existsSync, mkdirSync, renameSync } from "node:fs";
import { join, resolve, normalize, sep } from "node:path";
import { randomBytes } from "node:crypto";
import { ok, err, type Result } from "neverthrow";
import type { LedgerEntryId } from "../domain/types.js";
import type { RawOutputStore } from "../ports/raw-output-store.port.js";

// Valid ID characters (nanoid alphabet subset — no path separators)
const SAFE_ID_RE = /^[A-Za-z0-9_-]+$/;

// ─── File-based Raw Output Store ─────────────────────────────────────────────

export class FileRawOutputStore implements RawOutputStore {
  private readonly basePath: string;

  constructor(basePath: string) {
    this.basePath = resolve(basePath);
    mkdirSync(this.basePath, { recursive: true });
  }

  store(entryId: LedgerEntryId, data: string): Result<string, { message: string }> {
    const id = entryId as string;

    // Validate ID charset — prevent path traversal via malicious IDs
    if (!SAFE_ID_RE.test(id)) {
      return err({ message: `Invalid entry ID charset: ${id}` });
    }

    const filePath = this.getPath(entryId);

    // Containment check
    const normalized = normalize(filePath);
    if (normalized !== this.basePath && !normalized.startsWith(this.basePath + sep)) {
      return err({ message: `Path traversal detected for ID: ${id}` });
    }

    // Refuse overwrite — immutable store
    if (existsSync(filePath)) {
      return err({ message: `Entry already exists (immutable): ${id}` });
    }

    try {
      // Atomic write: write to temp, then rename
      const tmpPath = join(this.basePath, `.tmp-${randomBytes(8).toString("hex")}`);
      writeFileSync(tmpPath, data, "utf-8");
      renameSync(tmpPath, filePath);
      return ok(filePath);
    } catch (e) {
      return err({ message: e instanceof Error ? e.message : "Failed to store raw output" });
    }
  }

  retrieve(entryId: LedgerEntryId): Result<string, { message: string }> {
    const id = entryId as string;
    if (!SAFE_ID_RE.test(id)) {
      return err({ message: `Invalid entry ID charset: ${id}` });
    }

    try {
      const filePath = this.getPath(entryId);
      if (!existsSync(filePath)) {
        return err({ message: `Raw output not found for entry: ${id}` });
      }
      return ok(readFileSync(filePath, "utf-8"));
    } catch (e) {
      return err({ message: e instanceof Error ? e.message : "Failed to retrieve raw output" });
    }
  }

  exists(entryId: LedgerEntryId): boolean {
    const id = entryId as string;
    if (!SAFE_ID_RE.test(id)) return false;
    return existsSync(this.getPath(entryId));
  }

  getPath(entryId: LedgerEntryId): string {
    return join(this.basePath, `${entryId as string}.json`);
  }
}
