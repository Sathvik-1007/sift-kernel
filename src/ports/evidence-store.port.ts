import type { Result } from "neverthrow";
import type { EvidenceError } from "../domain/errors.js";

// ─── Evidence Store Port ─────────────────────────────────────────────────────

export interface ImageInfo {
  readonly path: string;
  readonly format: "E01" | "raw" | "VMDK" | "AFF4" | "unknown";
  readonly sizeBytes: number;
  readonly mountPoint: string;
}

export interface EvidenceStore {
  /** Mount an evidence image read-only */
  mount(imagePath: string): Promise<Result<ImageInfo, EvidenceError>>;

  /** Unmount evidence */
  unmount(): Promise<Result<void, EvidenceError>>;

  /** Check if evidence is currently mounted */
  isMounted(): boolean;

  /** Get the read-only mount point path */
  getMountPoint(): string | null;

  /** Validate a path is within the evidence mount (path containment) */
  validatePath(path: string): Result<string, EvidenceError>;

  /** Get image format from magic bytes */
  detectFormat(imagePath: string): Promise<Result<ImageInfo["format"], EvidenceError>>;
}
