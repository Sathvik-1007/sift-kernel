// FARE: Forensic Abductive Reasoning Engine — Orchestrator
// Composes: DSmT/PCR5 → Pignistic → EFE → Convergence → Bias
// Rough Sets module available for confidence-tier mapping (used in report generation)
// This is the single integration point consumed by server.ts

import type {
  MassFunction, MutableMassFunction, ReasoningUpdate, ActionSelection,
  ReasoningReport, ToolReliability, BeliefInterval, EFEScore,
} from "./types.js";
import {
  vacuousMass, combine, discount, beliefInterval, hartleyEntropy,
  singleton, pignisticDistribution, shannonEntropy, THETA,
} from "./dempster-shafer.js";
import { HYPOTHESES, EVIDENCE_RULES, getToolReliability, getRulesByCategory } from "./knowledge-base.js";
import { selectNextTool } from "./active-inference.js";
import { createConvergenceTracker, updateConvergence, getLearningRate, getConvergenceProgress, generateEntropySVG, type ConvergenceTracker } from "./convergence.js";
import { detectBiases, inferTargetedHypothesis, type ActionRecord } from "./bias-detector.js";

const FRAME_SIZE = HYPOTHESES.length;
const SIGNIFICANT_UPDATE_THRESHOLD = 0.02; // belief change > this = "informative" tool call

export class ForensicReasoningEngine {
  private beliefMass: MassFunction;
  private convergenceTracker: ConvergenceTracker;
  private actionHistory: ActionRecord[] = [];
  private executedTools: Set<string> = new Set();
  private toolReliability: Map<string, ToolReliability> = new Map();
  private triggeredRules: string[] = [];
  private totalComebacks = 0;

  constructor() {
    this.beliefMass = vacuousMass(); // start with total ignorance
    this.convergenceTracker = createConvergenceTracker();
  }

  /** Process tool output: fire matching rules, fuse into belief state, update convergence */
  processToolOutput(tool: string, rawOutput: string, success: boolean, category: string): ReasoningUpdate {
    this.executedTools.add(tool);

    if (!success) {
      // Failed tools don't update beliefs but do record for bias analysis
      this.recordAction(tool, category, 0);
      return this.buildUpdate([]);
    }

    // Fire matching evidence rules against this output
    const relevantRules = [...getRulesByCategory(category), ...getRulesByCategory("filesystem")];
    const firedRules: string[] = [];
    let evidenceMass: MassFunction = vacuousMass();

    for (const rule of relevantRules) {
      if (rule.condition(rawOutput)) {
        firedRules.push(rule.id);
        this.triggeredRules.push(rule.id);
        // Discount by tool reliability × rule reliability
        const toolRel = this.getReliability(tool);
        const discounted = discount(rule.mass, toolRel * rule.reliability);
        // Fuse this rule's mass into the accumulated evidence from this tool
        const { combined } = combine(evidenceMass, discounted);
        evidenceMass = combined;
      }
    }

    // Fuse accumulated evidence into global belief state
    if (firedRules.length > 0) {
      const prevEntropy = this.getEntropy();
      const { combined, conflict } = combine(this.beliefMass, evidenceMass);
      this.beliefMass = combined;

      // Update tool reliability (adaptive)
      const newEntropy = this.getEntropy();
      const infoGain = prevEntropy - newEntropy;
      this.updateReliability(tool, infoGain > SIGNIFICANT_UPDATE_THRESHOLD);
      this.recordAction(tool, category, infoGain);

      // Update convergence tracker
      const dominant = this.getDominantHypothesis();
      const { tracker, state, comebackTriggered } = updateConvergence(
        this.convergenceTracker, newEntropy, conflict,
        dominant ? { hypothesis: dominant.id, belief: dominant.belief } : null
      );
      this.convergenceTracker = tracker;
      if (comebackTriggered) this.totalComebacks++;

      return {
        beliefState: this.getBeliefState(),
        conflict,
        entropy: newEntropy,
        convergenceState: state,
        biasWarnings: this.getBiasWarnings(),
        triggeredRules: firedRules,
        comebackTriggered,
        dominantHypothesis: dominant,
      };
    }

    // No rules fired — still record for bias analysis
    this.recordAction(tool, category, 0);
    return this.buildUpdate(firedRules);
  }

  /** Select the best next tool from candidates using Expected Free Energy */
  selectNextTool(candidates: readonly string[]): ActionSelection {
    const scores = selectNextTool(candidates, this.beliefMass, this.executedTools);
    const best = scores[0];
    if (!best) {
      return {
        tool: candidates[0] ?? "suggest_next_action",
        efeScore: { tool: "unknown", risk: 0, ambiguity: 0, total: 0, explanation: "No candidates", discriminates: [] },
        alternatives: [],
        reasoningExplanation: "No candidate tools available for EFE scoring.",
      };
    }

    return {
      tool: best.tool,
      efeScore: best,
      alternatives: scores.slice(1, 4), // top 3 alternatives
      reasoningExplanation: `Selected "${best.tool}" (EFE=${best.total.toFixed(3)}). ` +
        `Risk: ${best.risk.toFixed(3)}, Ambiguity: ${best.ambiguity.toFixed(3)}. ` +
        (best.discriminates.length > 0 ? `Discriminates: ${best.discriminates[0]}. ` : "") +
        `Convergence: ${this.convergenceTracker.state}, Progress: ${getConvergenceProgress(this.convergenceTracker).toFixed(0)}%.`,
    };
  }

  /** Generate full reasoning report for inclusion in final forensic report */
  getReasoningReport(): ReasoningReport {
    const beliefState = this.getBeliefState();
    const ranking = [...beliefState.entries()]
      .map(([id, bi]) => ({ id, belief: bi.belief, plausibility: bi.plausibility }))
      .sort((a, b) => b.belief - a.belief);

    const dominant = ranking[0] ?? null;
    const progress = getConvergenceProgress(this.convergenceTracker);

    let quality: "POOR" | "FAIR" | "GOOD" | "EXCELLENT";
    if (progress >= 80 && this.convergenceTracker.state === "CONVERGED") quality = "EXCELLENT";
    else if (progress >= 60) quality = "GOOD";
    else if (progress >= 30) quality = "FAIR";
    else quality = "POOR";

    return {
      hypothesisRanking: ranking,
      entropyCurve: this.convergenceTracker.entropyCurve,
      conflictHistory: this.convergenceTracker.conflictHistory,
      convergenceState: this.convergenceTracker.state,
      biasWarnings: this.getBiasWarnings(),
      comebacksTriggered: this.totalComebacks,
      rulesTriggered: [...new Set(this.triggeredRules)],
      dominantHypothesis: dominant,
      investigationQuality: quality,
    };
  }

  /** Generate SVG visualization of the entropy curve */
  getEntropySVG(width?: number, height?: number): string {
    return generateEntropySVG(this.convergenceTracker, width, height);
  }

  /** Get current entropy */
  getEntropy(): number {
    const dist = pignisticDistribution(this.beliefMass, FRAME_SIZE);
    return shannonEntropy(dist);
  }

  /** Get belief intervals for all hypotheses */
  getBeliefState(): ReadonlyMap<string, BeliefInterval> {
    const state = new Map<string, BeliefInterval>();
    for (const h of HYPOTHESES) {
      state.set(h.id, beliefInterval(this.beliefMass, singleton(h.index)));
    }
    return state;
  }

  /** Get the dominant hypothesis (highest belief) */
  getDominantHypothesis(): { id: string; belief: number; plausibility: number } | null {
    let best: { id: string; belief: number; plausibility: number } | null = null;
    for (const h of HYPOTHESES) {
      const bi = beliefInterval(this.beliefMass, singleton(h.index));
      if (!best || bi.belief > best.belief) {
        best = { id: h.id, belief: bi.belief, plausibility: bi.plausibility };
      }
    }
    return best && best.belief > 0.01 ? best : null;
  }

  /** Get learning rate (positive = learning, negative = diverging) */
  getLearningRate(): number {
    return getLearningRate(this.convergenceTracker);
  }

  /** Reset the engine (for new investigation) */
  reset(): void {
    this.beliefMass = vacuousMass();
    this.convergenceTracker = createConvergenceTracker();
    this.actionHistory = [];
    this.executedTools = new Set();
    this.toolReliability = new Map();
    this.triggeredRules = [];
    this.totalComebacks = 0;
  }

  // ─── Private helpers ─────────────────────────────────────────────────────────

  private buildUpdate(firedRules: readonly string[]): ReasoningUpdate {
    return {
      beliefState: this.getBeliefState(),
      conflict: 0,
      entropy: this.getEntropy(),
      convergenceState: this.convergenceTracker.state,
      biasWarnings: this.getBiasWarnings(),
      triggeredRules: firedRules,
      comebackTriggered: null,
      dominantHypothesis: this.getDominantHypothesis(),
    };
  }

  private recordAction(tool: string, category: string, informationGain: number): void {
    const activeHypotheses = [...this.getBeliefState().entries()]
      .map(([id, bi]) => ({ id, belief: bi.belief }))
      .filter(h => h.belief > 0.05);

    this.actionHistory.push({
      tool,
      category,
      timestamp: Date.now(),
      targetedHypothesis: inferTargetedHypothesis(tool, category, activeHypotheses),
      informationGain,
    });
  }

  private getBiasWarnings() {
    const leading = this.getDominantHypothesis();
    return detectBiases(
      this.actionHistory,
      leading?.id ?? null,
      HYPOTHESES.map(h => h.id)
    );
  }

  private getReliability(tool: string): number {
    const record = this.toolReliability.get(tool);
    return record?.reliability ?? getToolReliability(tool);
  }

  private updateReliability(tool: string, wasInformative: boolean): void {
    const existing = this.toolReliability.get(tool);
    if (existing) {
      existing.callCount++;
      if (wasInformative) existing.informativeCount++;
      // Adaptive: blend base reliability with observed informativeness
      const observedRate = existing.informativeCount / existing.callCount;
      existing.reliability = 0.7 * getToolReliability(tool) + 0.3 * observedRate;
    } else {
      this.toolReliability.set(tool, {
        tool,
        reliability: getToolReliability(tool),
        callCount: 1,
        informativeCount: wasInformative ? 1 : 0,
      });
    }
  }
}
