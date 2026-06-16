import type { Result } from "neverthrow";
import { ok, err } from "neverthrow";

// ─── Parser Types ────────────────────────────────────────────────────────────

export interface AnomalyFlag {
  readonly type: string;
  readonly severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  readonly description: string;
  readonly affectedItems: readonly string[];
}

export interface ParsedOutput<T> {
  readonly summary: string;
  readonly data: T;
  readonly recordCount: number;
  readonly anomalies: readonly AnomalyFlag[];
  readonly rawTruncated: boolean;
}

export interface ParseError {
  readonly kind: "PARSE_ERROR";
  readonly parser: string;
  readonly message: string;
  readonly rawSnippet?: string | undefined;
}

export type ParseResult<T> = Result<ParsedOutput<T>, ParseError>;

export function parseError(parser: string, message: string, rawSnippet?: string): ParseError {
  return { kind: "PARSE_ERROR", parser, message, rawSnippet };
}

// ─── Parser Registry ─────────────────────────────────────────────────────────

export type ParserFn<T> = (raw: string) => ParseResult<T>;

import { parseFls, type FlsEntry } from "./fls.js";
import { parseMmls, type MmlsPartition } from "./mmls.js";
import { parseIstat, type IstatOutput } from "./istat.js";
import { parsePlaso, type PlasoEvent } from "./plaso.js";
import { parseEvtx, type EvtxEvent } from "./evtx.js";
import { parseYara, type YaraMatch } from "./yara.js";
import { parseTsharkConversations, type TsharkConversation } from "./tshark.js";
import { parseHashDeep, type HashEntry } from "./hash.js";
import { parseVolPsList, type VolProcess } from "./volatility.js";
import { parseRegripper, type RegripperOutput } from "./regripper.js";
import { parseBrowserHistory, type BrowserEntry } from "./browser.js";
import { parsePrefetch, type PrefetchEntry } from "./prefetch.js";
import { parseAuthLog, type AuthLogEntry } from "./auth-log.js";

export type ToolParsedData =
  | ParsedOutput<readonly FlsEntry[]>
  | ParsedOutput<readonly MmlsPartition[]>
  | ParsedOutput<IstatOutput>
  | ParsedOutput<readonly PlasoEvent[]>
  | ParsedOutput<readonly EvtxEvent[]>
  | ParsedOutput<readonly YaraMatch[]>
  | ParsedOutput<readonly TsharkConversation[]>
  | ParsedOutput<readonly HashEntry[]>
  | ParsedOutput<readonly VolProcess[]>
  | ParsedOutput<RegripperOutput>;

/** Parse raw tool output into structured data */
export function parseToolOutput(tool: string, raw: string): ParseResult<unknown> {
  switch (tool) {
    case "list_directory":
    case "search_filename":
      return parseFls(raw);
    case "list_partitions":
      return parseMmls(raw);
    case "get_file_metadata":
      return parseIstat(raw);
    case "generate_timeline":
    case "filter_timeline":
    case "get_timeline_around":
      return parsePlaso(raw);
    case "parse_event_log":
    case "search_events":
    case "get_security_events":
      return parseEvtx(raw);
    case "scan_yara":
    case "scan_memory_yara":
      return parseYara(raw);
    case "parse_pcap_summary":
    case "extract_connections":
      return parseTsharkConversations(raw);
    case "hash_and_lookup":
      return parseHashDeep(raw);
    case "list_processes":
      return parseVolPsList(raw);
    case "parse_registry_key":
    case "get_user_activity":
    case "get_system_config":
    case "get_persistence_keys":
    case "get_installed_software":
      return parseRegripper(raw);
    case "parse_browser_history":
    case "parse_browser_downloads":
      return parseBrowserHistory(raw);
    case "parse_prefetch":
      return parsePrefetch(raw);
    case "parse_auth_log":
    case "parse_syslog":
      return parseAuthLog(raw);
    default:
      // Fallback: wrap raw output in basic structure
      return ok({
        summary: raw.split("\n").slice(0, 3).join("\n"),
        data: { raw: raw.length > 10000 ? raw.slice(0, 10000) + "\n...[truncated]" : raw },
        recordCount: raw.split("\n").filter(Boolean).length,
        anomalies: [],
        rawTruncated: raw.length > 10000,
      });
  }
}
