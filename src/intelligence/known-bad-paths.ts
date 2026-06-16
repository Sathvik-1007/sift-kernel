import type { DetectedAnomaly } from "./index.js";

// ─── Known Bad Paths Detector ────────────────────────────────────────────────
// Flags files in locations commonly used by malware and attackers.

export interface FileEntry {
  readonly path: string;
  readonly name: string;
  readonly type: string; // "file" | "directory"
}

// Paths where legitimate executables should NOT be
const SUSPICIOUS_DIRS = [
  /\\temp\\/i,
  /\\tmp\\/i,
  /\\appdata\\local\\temp/i,
  /\\windows\\temp/i,
  /\\users\\public\\/i,
  /\\recycler\\/i,
  /\\\$recycle\.bin\\/i,
  /\\perflogs\\/i,
];

// Known LOLBin paths that are suspicious when found outside System32
const LOLBINS = new Set([
  "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "regsvr32.exe",
  "rundll32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "cscript.exe",
  "wscript.exe", "msiexec.exe", "schtasks.exe", "at.exe", "forfiles.exe",
  "pcalua.exe", "cmstp.exe", "esentutl.exe", "extrac32.exe", "findstr.exe",
  "hh.exe", "ie4uinit.exe", "infdefaultinstall.exe", "installutil.exe",
  "mavinject.exe", "microsoft.workflow.compiler.exe", "mmc.exe",
  "msconfig.exe", "msdeploy.exe", "msdt.exe", "msiexec.exe",
  "odbcconf.exe", "pcwrun.exe", "presentationhost.exe", "reg.exe",
  "regasm.exe", "regedit.exe", "regsvcs.exe", "replace.exe",
  "rpcping.exe", "sdbinst.exe", "syncappvpublishingserver.exe",
  "tttracer.exe", "verclsid.exe", "wab.exe", "xwizard.exe",
]);

// Extensions that shouldn't be in temp directories
const EXECUTABLE_EXTENSIONS = new Set([
  ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
  ".hta", ".wsf", ".wsc", ".sct", ".msi", ".cpl",
]);

export function detectKnownBadPaths(files: readonly FileEntry[]): readonly DetectedAnomaly[] {
  const anomalies: DetectedAnomaly[] = [];

  const execsInTempDirs: string[] = [];
  const lolbinsOutOfPlace: string[] = [];
  const hiddenExecutables: string[] = [];
  const doubleExtensions: string[] = [];

  for (const file of files) {
    if (file.type !== "file") continue;
    const pathLower = file.path.toLowerCase();
    const nameLower = file.name.toLowerCase();
    const dotIdx = nameLower.lastIndexOf(".");
    const ext = dotIdx >= 0 ? nameLower.slice(dotIdx) : "";

    // Executables in temp/suspicious directories
    if (EXECUTABLE_EXTENSIONS.has(ext)) {
      for (const pattern of SUSPICIOUS_DIRS) {
        if (pattern.test(pathLower)) {
          execsInTempDirs.push(file.path);
          break;
        }
      }
    }

    // LOLBins outside System32
    if (LOLBINS.has(nameLower) && !pathLower.includes("system32") && !pathLower.includes("syswow64")) {
      lolbinsOutOfPlace.push(file.path);
    }

    // Hidden executables (starting with .)
    if (nameLower.startsWith(".") && EXECUTABLE_EXTENSIONS.has(ext)) {
      hiddenExecutables.push(file.path);
    }

    // Double extensions (document.pdf.exe)
    const docExts = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"];
    for (const docExt of docExts) {
      if (nameLower.includes(docExt) && EXECUTABLE_EXTENSIONS.has(ext) && ext !== docExt) {
        doubleExtensions.push(file.path);
        break;
      }
    }
  }

  if (execsInTempDirs.length > 0) {
    anomalies.push({
      type: "executables_in_temp",
      severity: "HIGH",
      description: `${execsInTempDirs.length} executable(s) found in temp/suspicious directories`,
      evidence: execsInTempDirs.slice(0, 10).join("\n"),
      confidence: 0.7,
      falsePositiveRate: "MEDIUM",
    });
  }

  if (lolbinsOutOfPlace.length > 0) {
    anomalies.push({
      type: "lolbins_out_of_place",
      severity: "CRITICAL",
      description: `${lolbinsOutOfPlace.length} Living-off-the-Land binary(ies) found OUTSIDE System32 — strong indicator of staged tools`,
      evidence: lolbinsOutOfPlace.slice(0, 10).join("\n"),
      confidence: 0.85,
      falsePositiveRate: "LOW",
    });
  }

  if (hiddenExecutables.length > 0) {
    anomalies.push({
      type: "hidden_executables",
      severity: "HIGH",
      description: `${hiddenExecutables.length} hidden executable(s) (dot-prefixed filenames)`,
      evidence: hiddenExecutables.slice(0, 10).join("\n"),
      confidence: 0.8,
      falsePositiveRate: "LOW",
    });
  }

  if (doubleExtensions.length > 0) {
    anomalies.push({
      type: "double_extensions",
      severity: "CRITICAL",
      description: `${doubleExtensions.length} file(s) with double extensions (e.g., .pdf.exe) — social engineering tactic`,
      evidence: doubleExtensions.slice(0, 10).join("\n"),
      confidence: 0.9,
      falsePositiveRate: "LOW",
    });
  }

  return anomalies;
}
