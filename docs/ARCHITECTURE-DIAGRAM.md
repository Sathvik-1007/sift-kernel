# Architecture Diagram

**Pattern: Custom MCP Server (Pattern #2)**

```mermaid
graph TB
    subgraph "MCP CLIENT (Any AI Agent)"
        Agent["Claude / GPT / Llama / etc."]
    end

    subgraph "TRUST BOUNDARY (MCP Protocol Layer)"
        direction TB
        MCP["MCP Protocol (stdio / HTTP+SSE)"]
    end

    subgraph "SIFT KERNEL (Custom MCP Server)"
        direction TB
        
        subgraph "Tool Layer (32 Tools Exposed)"
            Dispatchers["14 Category Dispatchers<br/>(registry, event_logs, filesystem,<br/>memory, network, persistence,<br/>execution_artifacts, browser,<br/>user_activity, timeline,<br/>anti_forensics, correlation,<br/>linux, acquisition)"]
            Kernel["18 Kernel Tools<br/>(suggest_next_action, register_finding,<br/>register_hypothesis, generate_report,<br/>verify_chain, get_coverage_gaps,<br/>get_hypothesis_status, etc.)"]
        end

        subgraph "FARE Reasoning Engine"
            DS["Dempster-Shafer / PCR5<br/>Evidence Fusion"]
            EFE["Active Inference (EFE)<br/>Tool Selection"]
            RS["Rough-Set<br/>Confidence Tiers"]
            Bias["Bias Detector +<br/>Convergence Monitor"]
        end

        subgraph "Methodology Layer"
            FSM["7-State FSM<br/>(COLLECTION→TRIAGE→CLASSIFY→<br/>INVESTIGATE→TIMELINE→<br/>CORRELATE→REPORT)"]
            DAG["Capability DAG<br/>(Prerequisite Enforcement)"]
        end

        subgraph "Security Layer [ARCHITECTURAL]"
            NoShell["No execute_shell<br/>(tool does not exist)"]
            Allowlist["Binary Allowlist<br/>(43 vetted tools)"]
            ReadOnly["Read-Only Mount<br/>(ro,noexec,noatime)"]
            Validation["Path Traversal<br/>Validation"]
        end

        subgraph "Evidence Layer"
            Ledger["Hash-Chained SQLite Ledger<br/>(SHA-256 chain + HMAC seal)"]
            Store["Raw Output Store<br/>(sift-output/raw/)"]
        end
    end

    subgraph "SIFT WORKSTATION (Forensic Tools)"
        SK["Sleuth Kit<br/>(fls, icat, istat, mmls)"]
        RR["RegRipper<br/>(rip.pl)"]
        Vol["Volatility3<br/>(vol3)"]
        Plaso["Plaso<br/>(log2timeline)"]
        YARA["YARA"]
        TS["tshark"]
        Zimm["Zimmerman Tools<br/>(.NET)"]
    end

    subgraph "EVIDENCE (Read-Only)"
        E01["Disk Images<br/>(E01/raw/dd/VMDK)"]
        MEM["Memory Dumps<br/>(.raw/.mem)"]
        PCAP["Network Captures<br/>(.pcap/.pcapng)"]
    end

    Agent -->|"MCP calls"| MCP
    MCP -->|"Validated requests"| Dispatchers
    MCP -->|"Validated requests"| Kernel
    Dispatchers -->|"operation + params"| Allowlist
    Allowlist -->|"shell:false spawn"| SK
    Allowlist -->|"shell:false spawn"| RR
    Allowlist -->|"shell:false spawn"| Vol
    Allowlist -->|"shell:false spawn"| Plaso
    Allowlist -->|"shell:false spawn"| YARA
    Allowlist -->|"shell:false spawn"| TS
    Allowlist -->|"shell:false spawn"| Zimm
    SK -->|"read-only access"| E01
    Vol -->|"read-only access"| MEM
    TS -->|"read-only access"| PCAP
    Kernel --> FSM
    Kernel --> DAG
    Kernel --> DS
    EFE -->|"scores tools"| FSM
    DS -->|"fuses evidence"| Ledger
    Allowlist --> Store

    style NoShell fill:#f99,stroke:#c00
    style ReadOnly fill:#f99,stroke:#c00
    style Validation fill:#f99,stroke:#c00
    style Allowlist fill:#ff9,stroke:#990
    style Ledger fill:#9f9,stroke:#090
    style MCP fill:#99f,stroke:#009
```

## Security Boundaries

```mermaid
graph LR
    subgraph "Agent CAN Do"
        A["Call typed forensic tools"]
        B["Register findings WITH evidence"]
        C["Query investigation state"]
        D["Activate/deactivate workflows"]
        E["Request report generation"]
    end

    subgraph "Agent CANNOT Do"
        F["Execute arbitrary commands"]:::blocked
        G["Write to evidence mount"]:::blocked
        H["Register findings without evidence"]:::blocked
        I["Skip methodology phases"]:::blocked
        J["Tamper with audit trail"]:::blocked
        K["Access files outside mount"]:::blocked
    end

    classDef blocked fill:#f99,stroke:#c00
```

## Data Flow

```
Evidence Image (E01) ──ro mount──▶ SIFT Tools ──stdout──▶ Parser ──▶ Ledger Entry
                                                                         │
                                                                         ▼
Agent ──MCP call──▶ Dispatcher ──▶ Executor ──shell:false──▶ Binary     │
                                                                         │
Ledger Entry ──evidence_id──▶ register_finding() ──▶ Finding (CONFIRMED/INFERRED)
                                                         │
Finding ──▶ FARE Fusion ──▶ Hypothesis Status (SUPPORTED/REFUTED/OPEN)
                                    │
                                    ▼
                        generate_report() ──▶ HTML/MD/JSON + HMAC seal
```
