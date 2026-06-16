import { resolve, normalize, join, sep } from "node:path";
import { existsSync, openSync, readSync, closeSync, mkdirSync } from "node:fs";
import { ok, err, type Result } from "neverthrow";
import { evidenceError, pathError, type EvidenceError, type PathError } from "../domain/errors.js";
import type { EvidenceStore, ImageInfo } from "../ports/evidence-store.port.js";

// ─── Filesystem Evidence Store ───────────────────────────────────────────────

export class FsEvidenceStore implements EvidenceStore {
  private mountPoint: string | null = null;
  private imageInfo: ImageInfo | null = null;
  private readonly outputDir: string;

  constructor(outputDir: string) {
    this.outputDir = outputDir;
    mkdirSync(outputDir, { recursive: true });
  }

  async mount(imagePath: string): Promise<Result<ImageInfo, EvidenceError>> {
    const absPath = resolve(imagePath);
    if (!existsSync(absPath)) {
      return err(evidenceError("mount", absPath, `Image file not found: ${absPath}`));
    }

    const format = (await this.detectFormat(absPath)).unwrapOr("unknown");
    const mountDir = join(this.outputDir, "evidence-mount");
    mkdirSync(mountDir, { recursive: true });

    // For development/testing: we treat the image directory as the "mount point"
    // In production on SIFT, this would use mount -o ro,loop,noexec or ewfmount
    this.mountPoint = mountDir;
    this.imageInfo = {
      path: absPath,
      format,
      sizeBytes: 0, // Will be filled by actual mount
      mountPoint: mountDir,
    };

    return ok(this.imageInfo);
  }

  async unmount(): Promise<Result<void, EvidenceError>> {
    if (!this.mountPoint) {
      return err(evidenceError("mount", "", "No evidence currently mounted"));
    }
    this.mountPoint = null;
    this.imageInfo = null;
    return ok(undefined);
  }

  isMounted(): boolean {
    return this.mountPoint !== null;
  }

  getMountPoint(): string | null {
    return this.mountPoint;
  }

  validatePath(path: string): Result<string, EvidenceError> {
    if (!this.mountPoint) {
      return err(evidenceError("read", path, "No evidence mounted. Call mount_evidence first."));
    }

    // Canonicalize and check containment
    const resolved = resolve(this.mountPoint, path);
    const normalized = normalize(resolved);

    if (normalized !== this.mountPoint && !normalized.startsWith(this.mountPoint + sep)) {
      return err({
        kind: "EVIDENCE_ERROR",
        operation: "read",
        path,
        message: `Path traversal detected: "${path}" resolves outside evidence mount`,
        guidance: "Provide a relative path within the evidence image.",
      } as EvidenceError);
    }

    return ok(normalized);
  }

  async detectFormat(imagePath: string): Promise<Result<ImageInfo["format"], EvidenceError>> {
    try {
      // Read ONLY first 8 bytes — never load the full multi-GB image
      const fd = openSync(imagePath, "r");
      const magic = Buffer.alloc(8);
      readSync(fd, magic, 0, 8, 0);
      closeSync(fd);

      // EWF (E01): starts with "EVF\x09\x0d\x0a\xff\x00"
      if (magic[0] === 0x45 && magic[1] === 0x56 && magic[2] === 0x46) {
        return ok("E01");
      }
      // VMDK: starts with "KDMV" or "# Disk Desc"
      if (magic[0] === 0x4b && magic[1] === 0x44 && magic[2] === 0x4d && magic[3] === 0x56) {
        return ok("VMDK");
      }
      // AFF4: ZIP-based, starts with "PK"
      if (magic[0] === 0x50 && magic[1] === 0x4b) {
        return ok("AFF4");
      }
      // Default to raw
      return ok("raw");
    } catch (e) {
      return err(evidenceError("mount", imagePath, `Cannot read image: ${e instanceof Error ? e.message : "unknown"}`));
    }
  }
}
