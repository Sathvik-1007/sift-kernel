# Dataset Documentation

## Supported Evidence Types

SIFT Kernel processes any forensic evidence supported by the SIFT Workstation:

| Format | Extension | Mount Method | Tool |
|--------|-----------|--------------|------|
| EnCase | .E01, .E0x | ewfmount → loop mount | `ewfmount` |
| Raw/dd | .raw, .dd, .img | Direct loop mount | `mount` |
| VMDK | .vmdk | qemu-nbd → mount | `qemu-nbd` |
| AFF4 | .aff4 | aff4imager → mount | `aff4imager` |
| Memory | .raw, .mem, .vmem | Direct (no mount) | `vol` |
| PCAP | .pcap, .pcapng | Direct parse | `tshark` |
| EVTX | .evtx | Extract + parse | `evtx_dump` |

## Starter Case Data

The official FIND EVIL! hackathon provides sample evidence at:
https://sansorg.egnyte.com/fl/HhH7crTYT4JK

### SRL-2018 (Sample Reference Lab)

A multi-host enterprise compromise scenario:

| Image | Role | Key Artifacts |
|-------|------|---------------|
| base-wkstn-01-c-drive.E01 | Initial foothold | Phishing payload, initial execution |

### Validated Evidence — base-wkstn-01-c-drive.E01

Successfully processed during development (parser validation against real output):

| Property | Value |
|----------|-------|
| File size | 16 GB |
| Format | EnCase E01 |
| Filesystem | NTFS |
| Volume Serial | 82424B85424B7CC3 |
| Access method | ewfmount → Sleuth Kit direct access |
| Root entries | 32 (Windows, Users, ProgramData, $Recycle.Bin, etc.) |
| User accounts | Administrator, cbarton-a, mhill, rsydow-a, spsql |
| Anomalies found | Timestomping on bootmgr, 3 deleted files in $Recycle.Bin |
| Parser accuracy | 6/6 tests pass against real tool output |
| base-dc-cdrive.E01 | Domain Controller | Credential dumping, GPO abuse |
| base-file-cdrive.E01 | File server | Lateral movement target, data staging |
| base-rd-01-cdrive.E01 | RDP server 01 | Remote access persistence |
| base-rd-02-cdrive.E01 | RDP server 02 | Lateral movement hop |
| base-wkstn-05-cdrive.E01 | Workstation 05 | Secondary compromise |
| base-dmz-ftp-cdrive.E01 | DMZ FTP | Exfiltration staging |
| *.img (memory dumps) | Memory captures | Running processes, network connections |

### How to Use Case Data

```bash
# 1. Download from Egnyte (browser required)
# 2. Create case directory
mkdir -p /cases/srl-2018

# 3. Copy evidence files
cp base-wkstn-01-c-drive.E01* /cases/srl-2018/

# 4. Start SIFT Kernel
npx tsx src/index.ts --fresh --output ./sift-output

# 5. In your MCP client:
#    mount_evidence(image_path="/cases/srl-2018/base-wkstn-01-c-drive.E01")
#    verify_integrity(algorithm="sha256")
#    suggest_next_action()
#    # Follow the methodology engine's guidance from here
```

## Ground Truth

For accuracy measurement, define expected IOCs in YAML:

```yaml
# ground-truth/srl-2018-wkstn-01.yml
case: SRL-2018
host: WKSTN-01
expected_findings:
  - type: initial_access
    description: "Phishing document opened by user"
    mitre: T1566.001
    indicators:
      - path: "Users/*/Downloads/*.doc"
      - process: "WINWORD.EXE spawning cmd.exe"
  
  - type: execution
    description: "PowerShell download cradle"
    mitre: T1059.001
    indicators:
      - event_id: 4104
      - keyword: "IEX"
  
  - type: persistence
    description: "Scheduled task persistence"
    mitre: T1053.005
    indicators:
      - path: "Windows/System32/Tasks/*"
      - registry: "CurrentVersion\\Run"
```

## Accuracy Scoring

After investigation, run:
```
generate_report(min_confidence="INFERRED")
```

Compare findings against ground truth:
- **True Positive**: Finding matches a ground-truth IOC
- **False Positive**: Finding with no corresponding ground-truth entry
- **False Negative**: Ground-truth IOC not detected

Metrics:
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 × (Precision × Recall) / (Precision + Recall)

## Data Handling

- All evidence is mounted **read-only** (`ro,noexec,noatime`)
- Raw tool output stored in `sift-output/raw/` (excluded from git)
- Ledger stored in `sift-output/ledger.db` (SQLite, append-only)
- No evidence data is stored in the MCP server itself
- Evidence paths are validated against mount prefix (path traversal prevention)
