import type { AnomalyFlag } from "../parsers/index.js";

// ─── Wiping Tools Detection ──────────────────────────────────────────────────
// Detects artifacts left by evidence destruction tools.
// These are ORIGINAL detection algorithms — not tool wrappers.

interface WipingSignature {
  readonly pattern: RegExp;
  readonly tool: string;
  readonly severity: "CRITICAL" | "HIGH" | "MEDIUM";
  readonly description: string;
}

const WIPING_SIGNATURES: readonly WipingSignature[] = [
  // CCleaner
  { pattern: /ccleaner/i, tool: "CCleaner", severity: "HIGH", description: "CCleaner artifact detected — history/temp/log destruction" },
  { pattern: /piriform/i, tool: "CCleaner", severity: "HIGH", description: "Piriform (CCleaner vendor) artifact" },
  // SDelete (Sysinternals)
  { pattern: /sdelete/i, tool: "SDelete", severity: "CRITICAL", description: "SDelete secure deletion tool detected" },
  // BleachBit
  { pattern: /bleachbit/i, tool: "BleachBit", severity: "HIGH", description: "BleachBit cleaner detected" },
  // Eraser
  { pattern: /eraser\.exe|heidi\s+eraser/i, tool: "Eraser", severity: "CRITICAL", description: "Eraser secure deletion tool detected" },
  // Timestomp (Metasploit)
  { pattern: /timestomp/i, tool: "timestomp", severity: "CRITICAL", description: "Metasploit timestomp tool detected" },
  // Windows Disk Cleanup run programmatically
  { pattern: /cleanmgr.*\/sagerun/i, tool: "cleanmgr", severity: "MEDIUM", description: "Automated disk cleanup (potential cover-up)" },
  // Event log clearing
  { pattern: /wevtutil\s+(cl|clear-log)/i, tool: "wevtutil", severity: "CRITICAL", description: "Event log clearing command detected" },
  // USN journal deletion
  { pattern: /fsutil\s+usn\s+deletejournal/i, tool: "fsutil", severity: "CRITICAL", description: "USN Journal deletion — destroys file change tracking" },
  // Shadow copy deletion
  { pattern: /vssadmin.*delete\s+shadows/i, tool: "vssadmin", severity: "CRITICAL", description: "Volume shadow copy deletion — ransomware indicator" },
  { pattern: /wmic.*shadowcopy.*delete/i, tool: "wmic", severity: "CRITICAL", description: "Shadow copy deletion via WMI" },
  // cipher /w (DOD wipe)
  { pattern: /cipher\s+\/w/i, tool: "cipher", severity: "HIGH", description: "DoD-grade free space wiping via cipher.exe" },
  // PowerShell evidence destruction
  { pattern: /Clear-EventLog|Remove-Item.*\$env:APPDATA.*\\Microsoft\\Windows\\PowerShell/i, tool: "PowerShell", severity: "CRITICAL", description: "PowerShell evidence destruction command" },
];

/**
 * Detect evidence of wiping/cleaning tools in file paths, registry, or command history.
 */
export function detectWipingTools(data: readonly string[]): readonly AnomalyFlag[] {
  const anomalies: AnomalyFlag[] = [];
  const detectedTools = new Set<string>();

  for (const item of data) {
    for (const sig of WIPING_SIGNATURES) {
      if (sig.pattern.test(item) && !detectedTools.has(sig.tool + item)) {
        detectedTools.add(sig.tool + item);
        anomalies.push({
          type: "wiping_tool_detected",
          severity: sig.severity,
          description: sig.description,
          affectedItems: [item],
        });
      }
    }
  }

  return anomalies;
}

/**
 * Detect patterns consistent with anti-analysis behavior.
 * VM detection, sandbox evasion, debugger checks.
 */
export function detectAntiAnalysis(data: readonly string[]): readonly AnomalyFlag[] {
  const anomalies: AnomalyFlag[] = [];

  const antiAnalysisPatterns = [
    { pattern: /vmware|virtualbox|vbox|qemu|hyper-v|xen/i, description: "VM detection artifact" },
    { pattern: /sandboxie|cuckoomon|sbiedll/i, description: "Sandbox detection artifact" },
    { pattern: /IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebugger/i, description: "Debugger detection API" },
    { pattern: /HARDWARE\\DEVICEMAP\\Scsi.*VMware|VBOX/i, description: "VM-specific registry key access" },
    { pattern: /GetTickCount.*Sleep.*GetTickCount/i, description: "Timing-based sandbox evasion" },
  ];

  for (const item of data) {
    for (const { pattern, description } of antiAnalysisPatterns) {
      if (pattern.test(item)) {
        anomalies.push({ type: "anti_analysis", severity: "HIGH", description, affectedItems: [item] });
      }
    }
  }

  return anomalies;
}
