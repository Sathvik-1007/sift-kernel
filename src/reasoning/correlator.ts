/**
 * Auto-Correlation Engine
 *
 * Deterministically links registered findings by:
 * 1. Temporal proximity (events within a configurable window)
 * 2. MITRE ATT&CK technique sequencing (kill-chain ordering)
 * 3. Shared entity references (same host, user, IP, file path)
 *
 * This replaces the LLM's unreliable multi-hop reasoning with
 * server-side deterministic correlation — reducing hallucination
 * and enabling reproducible attack narratives.
 *
 * Academic basis:
 * - Lockheed Martin Cyber Kill Chain (Hutchins, Cloppert, Amin, 2011)
 * - MITRE ATT&CK technique co-occurrence (empirical usage statistics)
 * - Diamond Model analytic pivoting (Caltagirone, Pendergast, Betz, 2013)
 */

/** Temporal proximity window in milliseconds (default: 30 minutes) */
const TEMPORAL_WINDOW_MS = 30 * 60 * 1000;

/** Kill chain phase ordering — earlier phases PRECEDE later phases */
const KILL_CHAIN_ORDER: ReadonlyMap<string, number> = new Map([
  ["reconnaissance", 1],
  ["resource-development", 2],
  ["initial-access", 3],
  ["execution", 4],
  ["persistence", 5],
  ["privilege-escalation", 6],
  ["defense-evasion", 7],
  ["credential-access", 8],
  ["discovery", 9],
  ["lateral-movement", 10],
  ["collection", 11],
  ["command-and-control", 12],
  ["exfiltration", 13],
  ["impact", 14],
]);

/** MITRE technique-to-tactic mapping (most common associations) */
const TECHNIQUE_TACTIC: ReadonlyMap<string, string> = new Map([
  ["T1036", "defense-evasion"],
  ["T1036.005", "defense-evasion"],
  ["T1547", "persistence"],
  ["T1547.001", "persistence"],
  ["T1053", "persistence"],
  ["T1053.005", "persistence"],
  ["T1543", "persistence"],
  ["T1543.003", "persistence"],
  ["T1070", "defense-evasion"],
  ["T1070.001", "defense-evasion"],
  ["T1070.004", "defense-evasion"],
  ["T1059", "execution"],
  ["T1059.001", "execution"],
  ["T1059.003", "execution"],
  ["T1078", "initial-access"],
  ["T1136", "persistence"],
  ["T1136.001", "persistence"],
  ["T1021", "lateral-movement"],
  ["T1021.001", "lateral-movement"],
  ["T1021.002", "lateral-movement"],
  ["T1003", "credential-access"],
  ["T1003.001", "credential-access"],
  ["T1074", "collection"],
  ["T1074.001", "collection"],
  ["T1005", "collection"],
  ["T1048", "exfiltration"],
  ["T1560", "collection"],
  ["T1560.001", "collection"],
  ["T1569", "execution"],
  ["T1569.002", "execution"],
  ["T1055", "defense-evasion"],
  ["T1112", "defense-evasion"],
  ["T1562", "defense-evasion"],
  ["T1562.001", "defense-evasion"],
  ["T1595", "reconnaissance"],
  ["T1595.001", "reconnaissance"],
  ["T1190", "initial-access"],
  ["T1566", "initial-access"],
  ["T1566.001", "initial-access"],
]);

export interface CorrelationEdge {
  readonly sourceId: string;
  readonly targetId: string;
  readonly edgeType: "TEMPORAL_PROXIMITY" | "KILL_CHAIN_SEQUENCE" | "SHARED_ENTITY" | "CAUSAL_INFERENCE";
  readonly strength: number; // 0.0 - 1.0
  readonly explanation: string;
}

export interface FindingForCorrelation {
  readonly id: string;
  readonly description: string;
  readonly mitreTechnique?: string | undefined;
  readonly mitreTactic?: string | undefined;
  readonly temporalStart?: string | undefined; // ISO timestamp
  readonly temporalEnd?: string | undefined;
  readonly registeredAt: number; // epoch ms (order of registration)
}

export interface CorrelationGraph {
  readonly edges: readonly CorrelationEdge[];
  readonly chains: readonly AttackChain[];
  readonly timeline: readonly TimelineEvent[];
}

export interface AttackChain {
  readonly id: string;
  readonly findingIds: readonly string[];
  readonly killChainPhases: readonly string[];
  readonly confidence: number;
  readonly narrative: string;
}

export interface TimelineEvent {
  readonly findingId: string;
  readonly timestamp: string;
  readonly phase: string;
  readonly description: string;
}

/**
 * Compute the auto-correlation graph from a set of registered findings.
 * All logic is deterministic — no LLM, no randomness.
 */
export function computeCorrelationGraph(findings: readonly FindingForCorrelation[]): CorrelationGraph {
  if (findings.length < 2) {
    return { edges: [], chains: [], timeline: [] };
  }

  const edges: CorrelationEdge[] = [];

  // Pass 1: Temporal proximity edges
  for (let i = 0; i < findings.length; i++) {
    for (let j = i + 1; j < findings.length; j++) {
      const fi = findings[i]!;
      const fj = findings[j]!;
      const temporalEdge = computeTemporalEdge(fi, fj);
      if (temporalEdge) edges.push(temporalEdge);
    }
  }

  // Pass 2: Kill chain sequence edges
  for (let i = 0; i < findings.length; i++) {
    for (let j = i + 1; j < findings.length; j++) {
      const fi = findings[i]!;
      const fj = findings[j]!;
      const kcEdge = computeKillChainEdge(fi, fj);
      if (kcEdge) edges.push(kcEdge);
    }
  }

  // Pass 3: Shared entity edges (naive — check description overlap of key terms)
  for (let i = 0; i < findings.length; i++) {
    for (let j = i + 1; j < findings.length; j++) {
      const fi = findings[i]!;
      const fj = findings[j]!;
      const entityEdge = computeSharedEntityEdge(fi, fj);
      if (entityEdge) edges.push(entityEdge);
    }
  }

  // Build attack chains from connected components of strong edges
  const chains = buildAttackChains(findings, edges);

  // Build timeline (ordered by registration time or temporal_start)
  const timeline = buildTimeline(findings);

  return { edges, chains, timeline };
}

function computeTemporalEdge(a: FindingForCorrelation, b: FindingForCorrelation): CorrelationEdge | null {
  const tA = a.temporalStart ? new Date(a.temporalStart).getTime() : a.registeredAt;
  const tB = b.temporalStart ? new Date(b.temporalStart).getTime() : b.registeredAt;

  if (isNaN(tA) || isNaN(tB)) return null;

  const delta = Math.abs(tA - tB);
  if (delta > TEMPORAL_WINDOW_MS) return null;

  // Strength inversely proportional to time gap (closer = stronger)
  const strength = Math.max(0, 1 - (delta / TEMPORAL_WINDOW_MS));

  return {
    sourceId: tA <= tB ? a.id : b.id,
    targetId: tA <= tB ? b.id : a.id,
    edgeType: "TEMPORAL_PROXIMITY",
    strength,
    explanation: `Events within ${Math.round(delta / 60000)} minutes of each other`,
  };
}

function computeKillChainEdge(a: FindingForCorrelation, b: FindingForCorrelation): CorrelationEdge | null {
  const tacticA = a.mitreTactic ?? (a.mitreTechnique ? TECHNIQUE_TACTIC.get(a.mitreTechnique) : undefined);
  const tacticB = b.mitreTactic ?? (b.mitreTechnique ? TECHNIQUE_TACTIC.get(b.mitreTechnique) : undefined);

  if (!tacticA || !tacticB) return null;

  const orderA = KILL_CHAIN_ORDER.get(tacticA);
  const orderB = KILL_CHAIN_ORDER.get(tacticB);

  if (orderA === undefined || orderB === undefined) return null;
  if (orderA === orderB) return null; // Same phase — no sequence edge

  const [source, target] = orderA < orderB ? [a, b] : [b, a];
  const phaseDiff = Math.abs(orderA - orderB);

  // Adjacent phases get strongest score; farther apart = weaker
  const strength = Math.max(0.3, 1 - (phaseDiff - 1) * 0.15);

  return {
    sourceId: source.id,
    targetId: target.id,
    edgeType: "KILL_CHAIN_SEQUENCE",
    strength,
    explanation: `Kill chain: ${tacticA} (phase ${orderA}) → ${tacticB} (phase ${orderB})`,
  };
}

function computeSharedEntityEdge(a: FindingForCorrelation, b: FindingForCorrelation): CorrelationEdge | null {
  // Extract entity-like tokens from descriptions (paths, usernames, IPs, filenames)
  const tokensA = extractEntities(a.description);
  const tokensB = extractEntities(b.description);

  const shared = tokensA.filter(t => tokensB.includes(t));
  if (shared.length === 0) return null;

  const strength = Math.min(1, shared.length * 0.3);

  return {
    sourceId: a.id,
    targetId: b.id,
    edgeType: "SHARED_ENTITY",
    strength,
    explanation: `Shared entities: ${shared.slice(0, 3).join(", ")}`,
  };
}

function extractEntities(text: string): string[] {
  const entities: string[] = [];

  // File paths (Windows-style)
  const paths = text.match(/[A-Z]:\\[\w\\.-]+/gi);
  if (paths) entities.push(...paths.map(p => p.toLowerCase()));

  // Filenames with extensions
  const files = text.match(/\b[\w-]+\.(exe|dll|ps1|bat|vbs|sys|evtx|dat)\b/gi);
  if (files) entities.push(...files.map(f => f.toLowerCase()));

  // IP addresses
  const ips = text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g);
  if (ips) entities.push(...ips);

  // Usernames (common patterns)
  const users = text.match(/\b(?:user|admin|account)\s+['"]?([\w.-]+)['"]?/gi);
  if (users) entities.push(...users.map(u => u.toLowerCase()));

  // Domain names
  const domains = text.match(/\b[\w-]+\.(?:com|org|net|io|lan|local)\b/gi);
  if (domains) entities.push(...domains.map(d => d.toLowerCase()));

  return [...new Set(entities)];
}

function buildAttackChains(
  findings: readonly FindingForCorrelation[],
  edges: readonly CorrelationEdge[]
): AttackChain[] {
  // Filter to strong edges only (strength >= 0.5)
  const strongEdges = edges.filter(e => e.strength >= 0.5);
  if (strongEdges.length === 0) return [];

  // Union-Find for connected components
  const parent = new Map<string, string>();
  const findRoot = (id: string): string => {
    if (!parent.has(id)) parent.set(id, id);
    let root = parent.get(id)!;
    while (root !== parent.get(root)) {
      root = parent.get(root)!;
    }
    parent.set(id, root);
    return root;
  };
  const unite = (a: string, b: string) => {
    const ra = findRoot(a);
    const rb = findRoot(b);
    if (ra !== rb) parent.set(ra, rb);
  };

  for (const edge of strongEdges) {
    unite(edge.sourceId, edge.targetId);
  }

  // Group findings by component
  const components = new Map<string, FindingForCorrelation[]>();
  for (const f of findings) {
    const root = findRoot(f.id);
    const group = components.get(root) ?? [];
    group.push(f);
    components.set(root, group);
  }

  // Build chains from components with 2+ findings
  const chains: AttackChain[] = [];
  let chainId = 0;
  for (const [, group] of components) {
    if (group.length < 2) continue;

    // Sort by kill chain phase, then by time
    const sorted = [...group].sort((a, b) => {
      const phaseA = getKillChainOrder(a);
      const phaseB = getKillChainOrder(b);
      if (phaseA !== phaseB) return phaseA - phaseB;
      return a.registeredAt - b.registeredAt;
    });

    const phases = sorted
      .map(f => f.mitreTactic ?? (f.mitreTechnique ? TECHNIQUE_TACTIC.get(f.mitreTechnique) : undefined))
      .filter((p): p is string => p !== undefined);

    const uniquePhases = [...new Set(phases)];

    // Narrative: join descriptions in order
    const narrative = sorted.map((f, i) => `[${i + 1}] ${f.description.slice(0, 120)}`).join(" → ");

    chains.push({
      id: `chain-${++chainId}`,
      findingIds: sorted.map(f => f.id),
      killChainPhases: uniquePhases,
      confidence: Math.min(1, group.length * 0.25),
      narrative,
    });
  }

  return chains;
}

function buildTimeline(findings: readonly FindingForCorrelation[]): TimelineEvent[] {
  return [...findings]
    .sort((a, b) => {
      const tA = a.temporalStart ? new Date(a.temporalStart).getTime() : a.registeredAt;
      const tB = b.temporalStart ? new Date(b.temporalStart).getTime() : b.registeredAt;
      return tA - tB;
    })
    .map(f => ({
      findingId: f.id,
      timestamp: f.temporalStart ?? new Date(f.registeredAt).toISOString(),
      phase: f.mitreTactic ?? (f.mitreTechnique ? (TECHNIQUE_TACTIC.get(f.mitreTechnique) ?? "unknown") : "unknown"),
      description: f.description.slice(0, 200),
    }));
}

function getKillChainOrder(f: FindingForCorrelation): number {
  const tactic = f.mitreTactic ?? (f.mitreTechnique ? TECHNIQUE_TACTIC.get(f.mitreTechnique) : undefined);
  if (!tactic) return 99;
  return KILL_CHAIN_ORDER.get(tactic) ?? 99;
}
