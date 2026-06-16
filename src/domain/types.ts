import { z } from "zod";

// ─── Branded Types ───────────────────────────────────────────────────────────
// These prevent accidental mixing of IDs across domains at compile time.

export const LedgerEntryId = z.string().brand("LedgerEntryId");
export type LedgerEntryId = z.infer<typeof LedgerEntryId>;

export const FindingId = z.string().brand("FindingId");
export type FindingId = z.infer<typeof FindingId>;

export const HypothesisId = z.string().brand("HypothesisId");
export type HypothesisId = z.infer<typeof HypothesisId>;

export const AnomalyId = z.string().brand("AnomalyId");
export type AnomalyId = z.infer<typeof AnomalyId>;

// ─── Enums ───────────────────────────────────────────────────────────────────

export const ConfidenceLevel = z.enum([
  "HYPOTHESIZED",
  "INFERRED",
  "SUPPORTED",
  "CONFIRMED",
  "CONFLICTED",
]);
export type ConfidenceLevel = z.infer<typeof ConfidenceLevel>;

export const InvestigationPhase = z.enum([
  "UNINITIALIZED",
  "MOUNTED",
  "VERIFIED",
  "TRIAGING",
  "ANALYZING",
  "CORRELATING",
  "REPORTING",
]);
export type InvestigationPhase = z.infer<typeof InvestigationPhase>;

export const Capability = z.enum([
  "evidence_mounted",
  "integrity_verified",
  "partitions_listed",
  "filesystem_accessible",
  "timeline_generated",
  "registry_accessible",
  "eventlogs_accessible",
  "execution_artifacts_parsed",
  "persistence_checked",
  "memory_profiled",
  "memory_accessible",
  "network_capture_loaded",
  "browser_accessible",
  "user_activity_parsed",
  "anti_forensics_checked",
  "linux_accessible",
  "correlation_complete",
  "findings_registered",
  "report_ready",
]);
export type Capability = z.infer<typeof Capability>;

export const ArtifactCategory = z.enum([
  "acquisition",
  "filesystem",
  "timeline",
  "registry",
  "event_logs",
  "execution_artifacts",
  "persistence",
  "memory",
  "network",
  "browser",
  "user_activity",
  "anti_forensics",
  "correlation",
  "linux",
  "reporting",
]);
export type ArtifactCategory = z.infer<typeof ArtifactCategory>;

export const MitreTactic = z.enum([
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
]);
export type MitreTactic = z.infer<typeof MitreTactic>;

export const AnomalySeverity = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
export type AnomalySeverity = z.infer<typeof AnomalySeverity>;

export const FindingType = z.enum([
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
  "anti_forensics",
  "anomaly",
  "ioc",
]);
export type FindingType = z.infer<typeof FindingType>;

export const HypothesisStatus = z.enum(["OPEN", "SUPPORTED", "REFUTED", "RESOLVED"]);
export type HypothesisStatus = z.infer<typeof HypothesisStatus>;

export const ActionPriority = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
export type ActionPriority = z.infer<typeof ActionPriority>;

// ─── Domain Interfaces ───────────────────────────────────────────────────────

export interface LedgerEntry {
  readonly id: LedgerEntryId;
  readonly tool: string;
  readonly params: Record<string, unknown>;
  readonly outputHash: string;
  readonly rawOutputPath: string;
  readonly timestamp: string;
  readonly prevHash: string;
  readonly capabilitiesHeld: readonly Capability[];
  readonly findingsProduced: readonly FindingId[];
  readonly anomaliesFlagged: readonly AnomalyId[];
  readonly durationMs: number;
  readonly success: boolean;
  readonly errorMessage?: string | undefined;
}

export interface Finding {
  readonly id: FindingId;
  readonly type: FindingType;
  readonly description: string;
  readonly evidence: readonly LedgerEntryId[];
  readonly confidence: ConfidenceLevel;
  readonly temporalRange?: { readonly start: string; readonly end: string } | undefined;
  readonly mitreTechnique?: string | undefined;
  readonly mitreTactic?: MitreTactic | undefined;
  readonly affectedHosts: readonly string[];
  readonly iocs: readonly IOC[];
  readonly supportsHypotheses: readonly HypothesisId[];
  readonly contradictsHypotheses: readonly HypothesisId[];
  readonly registeredAt: string;
  readonly lastReassessed?: string | undefined;
}

export interface IOC {
  readonly type: "ip" | "domain" | "hash" | "filename" | "path" | "email" | "url";
  readonly value: string;
}

export interface Hypothesis {
  readonly id: HypothesisId;
  readonly description: string;
  readonly status: HypothesisStatus;
  readonly supportingFindings: readonly FindingId[];
  readonly contradictingFindings: readonly FindingId[];
  readonly registeredAt: string;
  readonly resolvedAt?: string | undefined;
}

export interface Anomaly {
  readonly id: AnomalyId;
  readonly type: string;
  readonly severity: AnomalySeverity;
  readonly description: string;
  readonly sourceLedgerEntry: LedgerEntryId;
  readonly affectedEntries: readonly string[];
  readonly detectedAt: string;
}

export interface SuggestedAction {
  readonly tool: string;
  readonly params?: Record<string, unknown> | undefined;
  readonly reason: string;
  readonly priority: ActionPriority;
}

export interface InvestigationProgress {
  readonly phase: InvestigationPhase;
  readonly overallCoverage: number;
  readonly currentWorkflow: string;
  readonly workflowProgress: string;
}

export interface EnrichedResponse<T> {
  readonly data: T;
  readonly anomalies: readonly Anomaly[];
  readonly suggestedNextActions: readonly SuggestedAction[];
  readonly investigationProgress: InvestigationProgress;
  readonly ledgerEntryId: LedgerEntryId;
}

// ─── Tool Capability Specification ───────────────────────────────────────────

export interface ToolCapabilitySpec {
  readonly tool: string;
  readonly requires: readonly Capability[];
  readonly produces: readonly Capability[];
  readonly category: ArtifactCategory;
  readonly description: string;
}
