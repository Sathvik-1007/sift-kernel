import { describe, it, expect } from "vitest";
import { parseFls } from "../../src/parsers/fls.js";
import { parseMmls } from "../../src/parsers/mmls.js";
import { parseIstat } from "../../src/parsers/istat.js";
import { parsePlaso } from "../../src/parsers/plaso.js";
import { parseEvtx } from "../../src/parsers/evtx.js";
import { parseYara } from "../../src/parsers/yara.js";
import { parseTsharkConversations } from "../../src/parsers/tshark.js";
import { parseHashDeep } from "../../src/parsers/hash.js";
import { parseVolPsList } from "../../src/parsers/volatility.js";
import { parseRegripper } from "../../src/parsers/regripper.js";

describe("fls parser", () => {
  it("parses basic fls output", () => {
    const raw = `r/r 1234:\tfile1.exe
d/d 5678:\tdirectory1
r/r * 9999(realloc):\tdeleted_file.dll (deleted)`;
    const result = parseFls(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.recordCount).toBe(3);
      expect(result.value.data[2]?.deleted).toBe(true);
    }
  });

  it("detects suspicious executables in temp dirs", () => {
    const raw = `r/r 111:\tUsers/Admin/AppData/Local/Temp/malware.exe
r/r 222:\tWindows/System32/normal.dll`;
    const result = parseFls(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.anomalies.length).toBeGreaterThan(0);
      expect(result.value.anomalies[0]?.type).toBe("suspicious_executables");
    }
  });
});

describe("mmls parser", () => {
  it("parses partition table", () => {
    const raw = `DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)
003:  -------   0001026048   0001048575   0000022528   Unallocated`;
    const result = parseMmls(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.recordCount).toBe(4);
      const ntfs = result.value.data.find(p => p.description.includes("NTFS"));
      expect(ntfs).toBeDefined();
      expect(ntfs!.start).toBe(2048);
    }
  });
});

describe("istat parser", () => {
  it("detects timestomping", () => {
    const raw = `Inode: 12345
Type: Regular
Size: 65536
$STANDARD_INFORMATION Created: 2020-01-01 00:00:00
$FILE_NAME Created: 2024-06-15 14:30:00`;
    const result = parseIstat(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.anomalies.some(a => a.type === "timestomping")).toBe(true);
    }
  });
});

describe("plaso parser", () => {
  it("parses JSON line output", () => {
    const events = [
      JSON.stringify({ datetime: "2024-01-15T10:30:00", source_short: "FILE", message: "test.exe created", filename: "C:\\test.exe" }),
      JSON.stringify({ datetime: "2024-01-15T10:30:01", source_short: "EVT", message: "Service installed", filename: "Security.evtx" }),
    ];
    const result = parsePlaso(events.join("\n"));
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.recordCount).toBe(2);
      expect(result.value.data[0]?.source).toBe("FILE");
    }
  });

  it("detects burst activity", () => {
    // 100 events in same minute
    const events = Array.from({ length: 100 }, (_, i) =>
      JSON.stringify({ datetime: "2024-01-15T10:30:00", source_short: "FILE", message: `file${i}`, filename: `f${i}` })
    );
    const result = parsePlaso(events.join("\n"));
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.anomalies.some(a => a.type === "activity_burst")).toBe(true);
    }
  });
});

describe("evtx parser", () => {
  it("detects log clearing events", () => {
    const raw = `<Event><System><EventID>1102</EventID><TimeCreated SystemTime="2024-01-15T03:00:00"/><Computer>WS01</Computer></System></Event>
<Event><System><EventID>4624</EventID><TimeCreated SystemTime="2024-01-15T09:00:00"/><Computer>WS01</Computer></System></Event>`;
    const result = parseEvtx(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.anomalies.some(a => a.type === "log_clearing")).toBe(true);
    }
  });
});

describe("yara parser", () => {
  it("parses YARA matches", () => {
    const raw = `Trojan_Generic [malware,trojan] /evidence/malware.exe
0x1000:$a1: MZ
0x2000:$b1: This program`;
    const result = parseYara(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.recordCount).toBe(1);
      expect(result.value.data[0]?.rule).toBe("Trojan_Generic");
      expect(result.value.data[0]?.strings.length).toBe(2);
      expect(result.value.anomalies.some(a => a.type === "yara_matches")).toBe(true);
    }
  });

  it("handles no matches", () => {
    const result = parseYara("");
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.recordCount).toBe(0);
      expect(result.value.anomalies.length).toBe(0);
    }
  });
});

describe("tshark parser", () => {
  it("detects suspicious ports", () => {
    const raw = `192.168.1.10:49152  <->  10.0.0.1:4444  50  65000  120.5`;
    const result = parseTsharkConversations(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.anomalies.some(a => a.type === "suspicious_ports")).toBe(true);
    }
  });
});

describe("hash parser", () => {
  it("parses sha256deep output", () => {
    const raw = `abc123def456abc123def456abc123def456abc123def456abc123def456abcdef01  /evidence/file.exe
abc123def456abc123def456abc123def456abc123def456abc123def456abcdef01  /evidence/copy.exe`;
    const result = parseHashDeep(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.recordCount).toBe(2);
      expect(result.value.anomalies.some(a => a.type === "duplicate_files")).toBe(true);
    }
  });
});

describe("volatility parser", () => {
  it("detects suspicious processes", () => {
    const raw = `PID  PPID  Name          Offset
1    0     System        0x1000
4    1     smss.exe      0x2000
500  4     cmd.exe       0x3000
600  500   powershell.exe 0x4000`;
    const result = parseVolPsList(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.recordCount).toBeGreaterThan(0);
      expect(result.value.anomalies.some(a => a.type === "suspicious_processes")).toBe(true);
    }
  });
});

describe("regripper parser", () => {
  it("detects persistence entries", () => {
    const raw = `Launching autorun
Hive: C:\\Windows\\System32\\config\\SOFTWARE
SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time: 2024-01-15 10:00:00
  Malware  REG_SZ  C:\\Temp\\evil.exe
  Legit  REG_SZ  C:\\Program Files\\Good\\app.exe`;
    const result = parseRegripper(raw);
    expect(result.isOk()).toBe(true);
    if (result.isOk()) {
      expect(result.value.data.entries.length).toBe(2);
      expect(result.value.anomalies.some(a => a.type === "persistence_registry")).toBe(true);
    }
  });
});
