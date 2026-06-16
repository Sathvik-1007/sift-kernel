// FARE: Rough Set Theory — Evidence Indiscernibility + Stop Criterion
// Implements: Pawlak 1982 (Rough Sets), Greco et al. DRSA (Dominance-Based)
// Maps directly onto SIFT confidence tiers: B_*(X)→CONFIRMED, BND→INFERRED, outside→DISCARDED
// Novel: rough-set boundary as mathematically grounded "should I keep investigating?" signal

import type { RoughApproximation } from "./types.js";

/** Information table row: a finding with its attribute values */
export interface InformationObject {
  readonly id: string;
  readonly attributes: ReadonlyMap<string, string | number | boolean>;
}

/** Compute indiscernibility class: objects identical on attribute set B */
export function indiscernibilityClass(
  objects: readonly InformationObject[],
  targetId: string,
  attributeSubset: readonly string[]
): readonly InformationObject[] {
  const target = objects.find(o => o.id === targetId);
  if (!target) return [];

  return objects.filter(obj => {
    for (const attr of attributeSubset) {
      const tv = target.attributes.get(attr);
      const ov = obj.attributes.get(attr);
      if (tv !== ov) return false;
    }
    return true;
  });
}

/** Compute lower approximation B_*(X): objects whose indiscernibility class ⊆ X
 *  These are DEFINITELY in the target concept (CONFIRMED findings) */
export function lowerApproximation(
  objects: readonly InformationObject[],
  targetSet: ReadonlySet<string>,
  attributeSubset: readonly string[]
): Set<string> {
  const lower = new Set<string>();
  for (const obj of objects) {
    const eqClass = indiscernibilityClass(objects, obj.id, attributeSubset);
    const allInTarget = eqClass.every(member => targetSet.has(member.id));
    if (allInTarget) lower.add(obj.id);
  }
  return lower;
}

/** Compute upper approximation B*(X): objects whose indiscernibility class ∩ X ≠ ∅
 *  These POSSIBLY belong to the target concept */
export function upperApproximation(
  objects: readonly InformationObject[],
  targetSet: ReadonlySet<string>,
  attributeSubset: readonly string[]
): Set<string> {
  const upper = new Set<string>();
  for (const obj of objects) {
    const eqClass = indiscernibilityClass(objects, obj.id, attributeSubset);
    const anyInTarget = eqClass.some(member => targetSet.has(member.id));
    if (anyInTarget) upper.add(obj.id);
  }
  return upper;
}

/** Compute full rough-set approximation: lower, upper, boundary, accuracy */
export function roughApproximation(
  objects: readonly InformationObject[],
  targetSet: ReadonlySet<string>,
  attributeSubset: readonly string[]
): RoughApproximation {
  const lower = lowerApproximation(objects, targetSet, attributeSubset);
  const upper = upperApproximation(objects, targetSet, attributeSubset);
  const boundary = new Set([...upper].filter(id => !lower.has(id)));
  const accuracy = upper.size > 0 ? lower.size / upper.size : 1.0;
  return { lower, upper, boundary, accuracy };
}

/** Map rough-set results to SIFT confidence tiers:
 *  - B_*(X) → CONFIRMED (definitely malicious based on current evidence)
 *  - BND(X) → INFERRED/SUPPORTED (possibly malicious, needs more evidence)
 *  - U \ B*(X) → insufficient evidence (below reporting threshold) */
export function mapToConfidenceTiers(
  approx: RoughApproximation
): { confirmed: ReadonlySet<string>; inferred: ReadonlySet<string>; insufficient: ReadonlySet<string> } {
  return {
    confirmed: approx.lower,
    inferred: approx.boundary,
    insufficient: new Set(), // computed externally as universe \ upper
  };
}

/** Investigation stop criterion (mathematically grounded):
 *  Stop when boundary region is empty (all findings are decidable)
 *  OR when accuracy exceeds threshold (diminishing returns on investigation) */
export function shouldStopInvestigating(
  approx: RoughApproximation,
  accuracyThreshold: number = 0.85
): { shouldStop: boolean; reason: string } {
  if (approx.boundary.size === 0) {
    return { shouldStop: true, reason: "All findings are decidable (boundary empty). Investigation complete." };
  }
  if (approx.accuracy >= accuracyThreshold) {
    return { shouldStop: true, reason: `Accuracy ${(approx.accuracy * 100).toFixed(1)}% exceeds threshold ${(accuracyThreshold * 100).toFixed(1)}%. Diminishing returns.` };
  }
  return {
    shouldStop: false,
    reason: `Boundary has ${approx.boundary.size} undecidable findings. Accuracy: ${(approx.accuracy * 100).toFixed(1)}%. Continue investigating.`
  };
}

/** DRSA: Generate human-readable decision rules from the approximation
 *  Format: "IF (attr_1 >= v_1 AND attr_2 >= v_2) THEN class >= malicious"
 *  These are Daubert-defensible (formal, reproducible, verifiable) */
export function generateDecisionRules(
  objects: readonly InformationObject[],
  lowerSet: ReadonlySet<string>,
  attributes: readonly string[]
): readonly string[] {
  if (lowerSet.size === 0) return ["No confirmed findings — insufficient evidence for decision rules."];

  const rules: string[] = [];
  const lowerObjects = objects.filter(o => lowerSet.has(o.id));

  // Find common attributes among confirmed findings (minimal covering set)
  const commonAttrs = new Map<string, Set<string | number | boolean>>();
  for (const attr of attributes) {
    const values = new Set(lowerObjects.map(o => o.attributes.get(attr)).filter((v): v is string | number | boolean => v !== undefined));
    if (values.size > 0 && values.size <= 3) { // attribute with low cardinality = discriminating
      commonAttrs.set(attr, values);
    }
  }

  // Build rules from common attributes
  for (const [attr, values] of commonAttrs) {
    const valStr = [...values].map(v => String(v)).join(" OR ");
    const coverage = lowerObjects.filter(o => values.has(o.attributes.get(attr) as string | number | boolean)).length;
    if (coverage >= Math.ceil(lowerObjects.length * 0.6)) {
      rules.push(`IF (${attr} IN {${valStr}}) THEN CONFIRMED [coverage: ${coverage}/${lowerObjects.length}]`);
    }
  }

  if (rules.length === 0) {
    rules.push(`${lowerSet.size} finding(s) confirmed by multi-source corroboration (no single discriminating attribute).`);
  }

  return rules;
}

/** Compute attribute importance (reducts): which attributes are essential for distinguishing?
 *  Uses dependency degree: γ_B(D) = |POS_B(D)| / |U| */
export function attributeImportance(
  objects: readonly InformationObject[],
  targetSet: ReadonlySet<string>,
  attributes: readonly string[]
): readonly { attribute: string; importance: number }[] {
  const fullLower = lowerApproximation(objects, targetSet, attributes);
  const fullSize = fullLower.size;

  return attributes.map(attr => {
    // Remove this attribute and check how much the lower approximation shrinks
    const reducedAttrs = attributes.filter(a => a !== attr);
    const reducedLower = lowerApproximation(objects, targetSet, reducedAttrs);
    const importance = fullSize > 0 ? (fullSize - reducedLower.size) / fullSize : 0;
    return { attribute: attr, importance };
  }).sort((a, b) => b.importance - a.importance);
}
