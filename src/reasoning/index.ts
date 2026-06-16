// FARE: Forensic Abductive Reasoning Engine — Public API
export { ForensicReasoningEngine } from "./engine.js";
export type {
  ReasoningUpdate, ActionSelection, ReasoningReport, BeliefInterval,
  EFEScore, ConvergenceState, ComebackTrigger, BiasWarning, BiasType,
  RoughApproximation, Hypothesis, EvidenceMassRule, MassFunction, ToolReliability,
} from "./types.js";
export { HYPOTHESES, HYPOTHESIS_MAP, EVIDENCE_RULES, getRulesByCategory } from "./knowledge-base.js";
export { generateEntropySVG } from "./convergence.js";
export { roughApproximation, shouldStopInvestigating, generateDecisionRules } from "./rough-sets.js";
export { computeCorrelationGraph } from "./correlator.js";
export type { CorrelationGraph, CorrelationEdge, AttackChain, TimelineEvent, FindingForCorrelation } from "./correlator.js";
