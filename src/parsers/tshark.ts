import { ok } from "neverthrow";
import type { ParseResult, AnomalyFlag } from "./index.js";

// ─── tshark Parser ───────────────────────────────────────────────────────────
// Parses tshark conversation and statistics output.

export interface TsharkConversation {
  readonly srcAddr: string;
  readonly srcPort: number;
  readonly dstAddr: string;
  readonly dstPort: number;
  readonly protocol: string;
  readonly packets: number;
  readonly bytes: number;
  readonly duration: number;
  readonly direction: "A->B" | "B->A" | "both";
}

export function parseTsharkConversations(raw: string): ParseResult<readonly TsharkConversation[]> {
  const lines = raw.split("\n").filter(Boolean);
  const conversations: TsharkConversation[] = [];
  const anomalies: AnomalyFlag[] = [];

  for (const line of lines) {
    // tshark -z conv,tcp output: addr:port <-> addr:port  frmA->B bytA->B frmB->A bytB->A totFrm totByt start dur
    const tcpMatch = line.match(/([0-9a-f:.]+):(\d+)\s+<?->?>?\s+([0-9a-f:.]+):(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)/);
    if (tcpMatch) {
      conversations.push({
        srcAddr: tcpMatch[1]!,
        srcPort: parseInt(tcpMatch[2]!, 10),
        dstAddr: tcpMatch[3]!,
        dstPort: parseInt(tcpMatch[4]!, 10),
        protocol: "TCP",
        packets: parseInt(tcpMatch[9]!, 10),  // total frames
        bytes: parseInt(tcpMatch[10]!, 10),    // total bytes
        duration: parseFloat(tcpMatch[12]!),   // duration
        direction: "both",
      });
      continue;
    }
    // Simpler fallback: addr:port <-> addr:port  frames bytes [duration]
    const simpleMatch = line.match(/([0-9a-f:.]+):(\d+)\s+<?->?>?\s+([0-9a-f:.]+):(\d+)\s+(\d+)\s+(\d+)\s*([\d.]*)/);
    if (simpleMatch) {
      conversations.push({
        srcAddr: simpleMatch[1]!,
        srcPort: parseInt(simpleMatch[2]!, 10),
        dstAddr: simpleMatch[3]!,
        dstPort: parseInt(simpleMatch[4]!, 10),
        protocol: "TCP",
        packets: parseInt(simpleMatch[5]!, 10),
        bytes: parseInt(simpleMatch[6]!, 10),
        duration: parseFloat(simpleMatch[7] || "0"),
        direction: "both",
      });
      continue;
    }
  }

  // Anomaly: C2 suspicious ports
  const suspiciousPorts = new Set([4444, 5555, 8080, 8443, 1337, 31337, 6666, 6667]);
  const suspiciousConns = conversations.filter(c =>
    suspiciousPorts.has(c.dstPort) || suspiciousPorts.has(c.srcPort)
  );
  if (suspiciousConns.length > 0) {
    anomalies.push({
      type: "suspicious_ports",
      severity: "HIGH",
      description: `${suspiciousConns.length} connection(s) to known suspicious ports`,
      affectedItems: suspiciousConns.map(c => `${c.srcAddr}:${c.srcPort} -> ${c.dstAddr}:${c.dstPort}`),
    });
  }

  // Anomaly: high-volume data transfer
  const highVolume = conversations.filter(c => c.bytes > 100_000_000); // 100MB+
  if (highVolume.length > 0) {
    anomalies.push({
      type: "high_volume_transfer",
      severity: "HIGH",
      description: `${highVolume.length} connection(s) with >100MB transfer — possible exfiltration`,
      affectedItems: highVolume.map(c => `${c.srcAddr} -> ${c.dstAddr}: ${(c.bytes / 1_000_000).toFixed(1)}MB`),
    });
  }

  // Anomaly: DNS over non-standard port
  const dnsNonStd = conversations.filter(c =>
    c.dstPort === 53 && c.bytes > 1_000_000
  );
  if (dnsNonStd.length > 0) {
    anomalies.push({
      type: "dns_tunneling_suspect",
      severity: "HIGH",
      description: "High-volume DNS traffic — possible DNS tunneling/exfiltration",
      affectedItems: dnsNonStd.map(c => `${c.srcAddr} -> ${c.dstAddr}: ${c.bytes} bytes`),
    });
  }

  const totalBytes = conversations.reduce((sum, c) => sum + c.bytes, 0);
  const summary = `${conversations.length} conversations, ${(totalBytes / 1_000_000).toFixed(1)}MB total`;

  return ok({
    summary,
    data: conversations,
    recordCount: conversations.length,
    anomalies,
    rawTruncated: false,
  });
}
