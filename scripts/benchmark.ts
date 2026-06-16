#!/usr/bin/env npx tsx
/**
 * SIFT Kernel Accuracy Benchmark
 * 
 * Validates investigation findings against ground-truth YAML files.
 * Outputs precision, recall, F1, and per-category accuracy.
 * 
 * Usage: npx tsx scripts/benchmark.ts --ground-truth ground-truth/case-001.yml --ledger sift-output/ledger.db
 */

import { readFileSync, existsSync } from "node:fs";
import Database from "better-sqlite3";

interface GroundTruth {
  case_id: string;
  verdict: "MALICE" | "SUSPICION" | "BENIGN";
  description: string;
  mitre_techniques: string[];
  iocs: { type: string; value: string; description: string }[];
  findings: { type: string; description: string; evidence_source: string }[];
}

interface BenchmarkResult {
  case_id: string;
  verdict_correct: boolean;
  mitre_precision: number;
  mitre_recall: number;
  ioc_precision: number;
  ioc_recall: number;
  finding_recall: number;
  false_positives: number;
  f1_score: number;
  confidence_breakdown: Record<string, number>;
}

function parseYaml(content: string): GroundTruth {
  // Simple YAML-like parser for ground truth files (JSON also accepted)
  if (content.trim().startsWith("{")) {
    return JSON.parse(content) as GroundTruth;
  }
  throw new Error("Ground truth must be JSON format. YAML parsing not yet implemented.");
}

function loadFindings(dbPath: string): { findings: Array<{ type: string; description: string; confidence: string; mitre_technique?: string; iocs?: Array<{ type: string; value: string }> }> } {
  if (!existsSync(dbPath)) {
    console.error(`ERROR: Ledger database not found at ${dbPath}`);
    process.exit(1);
  }

  const db = new Database(dbPath, { readonly: true });
  const entries = db.prepare("SELECT tool, params, raw_output FROM ledger WHERE tool = 'register_finding'").all() as Array<{ tool: string; params: string; raw_output: string }>;
  
  const findings = entries.map(e => {
    try {
      const params = JSON.parse(e.params);
      return {
        type: params.type ?? "unknown",
        description: params.description ?? "",
        confidence: params.confidence ?? "INFERRED",
        mitre_technique: params.mitre_technique,
        iocs: params.iocs,
      };
    } catch {
      return { type: "unknown", description: "", confidence: "HYPOTHESIZED" };
    }
  });

  db.close();
  return { findings };
}

function computeMetrics(groundTruth: GroundTruth, findings: ReturnType<typeof loadFindings>["findings"]): BenchmarkResult {
  // MITRE technique coverage
  const detectedTechniques = new Set(findings.map(f => f.mitre_technique).filter(Boolean));
  const expectedTechniques = new Set(groundTruth.mitre_techniques);
  const mitreTP = [...detectedTechniques].filter(t => expectedTechniques.has(t!)).length;
  const mitrePrecision = detectedTechniques.size > 0 ? mitreTP / detectedTechniques.size : 0;
  const mitreRecall = expectedTechniques.size > 0 ? mitreTP / expectedTechniques.size : 0;

  // IOC coverage
  const detectedIOCs = new Set(findings.flatMap(f => (f.iocs ?? []).map(i => `${i.type}:${i.value}`)));
  const expectedIOCs = new Set(groundTruth.iocs.map(i => `${i.type}:${i.value}`));
  const iocTP = [...detectedIOCs].filter(i => expectedIOCs.has(i)).length;
  const iocPrecision = detectedIOCs.size > 0 ? iocTP / detectedIOCs.size : 0;
  const iocRecall = expectedIOCs.size > 0 ? iocTP / expectedIOCs.size : 0;

  // Finding recall (how many expected findings were detected)
  const findingRecall = groundTruth.findings.length > 0
    ? findings.filter(f => groundTruth.findings.some(gf => gf.type === f.type)).length / groundTruth.findings.length
    : 0;

  // False positives (findings not in ground truth)
  const falsePositives = findings.filter(f => !groundTruth.findings.some(gf => gf.type === f.type)).length;

  // Confidence breakdown
  const confidenceBreakdown: Record<string, number> = {};
  for (const f of findings) {
    confidenceBreakdown[f.confidence] = (confidenceBreakdown[f.confidence] ?? 0) + 1;
  }

  // F1 score (harmonic mean of MITRE precision and recall)
  const f1 = (mitrePrecision + mitreRecall) > 0
    ? 2 * (mitrePrecision * mitreRecall) / (mitrePrecision + mitreRecall)
    : 0;

  // Verdict assessment
  const hasFindings = findings.length > 0;
  const verdictCorrect = (groundTruth.verdict === "MALICE" && hasFindings) ||
    (groundTruth.verdict === "BENIGN" && !hasFindings) ||
    (groundTruth.verdict === "SUSPICION" && findings.length <= 2);

  return {
    case_id: groundTruth.case_id,
    verdict_correct: verdictCorrect,
    mitre_precision: Math.round(mitrePrecision * 1000) / 1000,
    mitre_recall: Math.round(mitreRecall * 1000) / 1000,
    ioc_precision: Math.round(iocPrecision * 1000) / 1000,
    ioc_recall: Math.round(iocRecall * 1000) / 1000,
    finding_recall: Math.round(findingRecall * 1000) / 1000,
    false_positives: falsePositives,
    f1_score: Math.round(f1 * 1000) / 1000,
    confidence_breakdown: confidenceBreakdown,
  };
}

// CLI
const args = process.argv.slice(2);
const gtIdx = args.indexOf("--ground-truth");
const dbIdx = args.indexOf("--ledger");

if (gtIdx === -1 || dbIdx === -1) {
  console.log("Usage: npx tsx scripts/benchmark.ts --ground-truth <path.json> --ledger <ledger.db>");
  console.log("\nGround truth format (JSON):");
  console.log(JSON.stringify({
    case_id: "CASE-001",
    verdict: "MALICE",
    description: "APT compromise with lateral movement",
    mitre_techniques: ["T1059", "T1021", "T1078"],
    iocs: [{ type: "ip", value: "10.0.0.1", description: "C2 server" }],
    findings: [{ type: "lateral_movement", description: "RDP from WS01 to DC01", evidence_source: "evtx" }],
  }, null, 2));
  process.exit(0);
}

const gtPath = args[gtIdx + 1]!;
const dbPath = args[dbIdx + 1]!;

if (!existsSync(gtPath)) { console.error(`Ground truth file not found: ${gtPath}`); process.exit(1); }

const groundTruth = parseYaml(readFileSync(gtPath, "utf-8"));
const { findings } = loadFindings(dbPath);
const result = computeMetrics(groundTruth, findings);

console.log("\n═══════════════════════════════════════════════════════");
console.log("  SIFT KERNEL — Accuracy Benchmark Report");
console.log("═══════════════════════════════════════════════════════");
console.log(`  Case: ${result.case_id}`);
console.log(`  Verdict Correct: ${result.verdict_correct ? "YES ✓" : "NO ✗"}`);
console.log(`  MITRE Precision: ${(result.mitre_precision * 100).toFixed(1)}%`);
console.log(`  MITRE Recall:    ${(result.mitre_recall * 100).toFixed(1)}%`);
console.log(`  F1 Score:        ${(result.f1_score * 100).toFixed(1)}%`);
console.log(`  IOC Precision:   ${(result.ioc_precision * 100).toFixed(1)}%`);
console.log(`  IOC Recall:      ${(result.ioc_recall * 100).toFixed(1)}%`);
console.log(`  Finding Recall:  ${(result.finding_recall * 100).toFixed(1)}%`);
console.log(`  False Positives: ${result.false_positives}`);
console.log(`  Confidence: ${JSON.stringify(result.confidence_breakdown)}`);
console.log("═══════════════════════════════════════════════════════\n");

// Output machine-readable JSON
console.log(JSON.stringify(result, null, 2));
