// FARE: Dempster-Shafer Theory with PCR5 Proportional Conflict Redistribution
// Implements: PCR5 (Smarandache & Dezert 2006), Yager fallback (1987), Hartley entropy
// Novel application: forensic tool output fusion with conflict as self-correction signal

import type { FocalElement, MassFunction, MutableMassFunction, BeliefInterval } from "./types.js";

/** Number of hypotheses in our frame of discernment */
const FRAME_SIZE = 12;

/** THETA bitmask: all bits set (represents total ignorance) */
export const THETA: FocalElement = (1 << FRAME_SIZE) - 1;

/** Check if focal element A is a subset of B (bitmask: A & B === A) */
export function isSubset(a: FocalElement, b: FocalElement): boolean {
  return (a & b) === a;
}

/** Check if two focal elements intersect (bitmask: A & B !== 0) */
export function intersects(a: FocalElement, b: FocalElement): boolean {
  return (a & b) !== 0;
}

/** Count set bits (cardinality of a focal element) */
export function cardinality(fe: FocalElement): number {
  let n = fe;
  let count = 0;
  while (n) { count += n & 1; n >>>= 1; }
  return count;
}

/** Create a singleton focal element for hypothesis at index i */
export function singleton(index: number): FocalElement {
  return 1 << index;
}

/** Create a mass function with all mass on THETA (total ignorance) */
export function vacuousMass(): MassFunction {
  return new Map([[THETA, 1.0]]);
}

/** Create a mass function from entries, ensuring it sums to 1.0 */
export function createMass(entries: readonly [FocalElement, number][]): MassFunction {
  const m: MutableMassFunction = new Map();
  let sum = 0;
  for (const [fe, mass] of entries) {
    if (mass > 0) {
      m.set(fe, (m.get(fe) ?? 0) + mass);
      sum += mass;
    }
  }
  // Normalize if not summing to 1 (floating point tolerance)
  if (Math.abs(sum - 1.0) > 1e-9) {
    for (const [fe, mass] of m) m.set(fe, mass / sum);
  }
  return m;
}

/** Discount a mass function by source reliability α ∈ [0,1]
 *  m'(A) = α·m(A) for A≠Θ; m'(Θ) = 1 - α·(1 - m(Θ)) */
export function discount(m: MassFunction, reliability: number): MassFunction {
  if (reliability >= 1.0) return m;
  if (reliability <= 0.0) return vacuousMass();
  const result: MutableMassFunction = new Map();
  let thetaMass = 0;
  for (const [fe, mass] of m) {
    if (fe === THETA) {
      thetaMass += mass;
    } else {
      const discounted = reliability * mass;
      if (discounted > 1e-12) result.set(fe, discounted);
      thetaMass += (1 - reliability) * mass;
    }
  }
  if (thetaMass > 1e-12) result.set(THETA, thetaMass);
  return result;
}

/** Compute conflict coefficient K between two mass functions */
export function conflictCoefficient(m1: MassFunction, m2: MassFunction): number {
  let conflict = 0;
  for (const [a, ma] of m1) {
    for (const [b, mb] of m2) {
      if ((a & b) === 0) { // empty intersection
        conflict += ma * mb;
      }
    }
  }
  return conflict;
}

/** PCR5 combination rule (Smarandache & Dezert 2006)
 *  Redistributes conflict proportionally to squared masses back to their focal elements.
 *  Unlike Dempster's rule, does NOT normalize — avoids Zadeh's paradox. */
export function combinePCR5(m1: MassFunction, m2: MassFunction): { combined: MassFunction; conflict: number } {
  const K = conflictCoefficient(m1, m2);

  // Step 1: Conjunctive consensus (mass on intersections)
  const conj: MutableMassFunction = new Map();
  for (const [a, ma] of m1) {
    for (const [b, mb] of m2) {
      const intersection = a & b;
      if (intersection !== 0) {
        conj.set(intersection, (conj.get(intersection) ?? 0) + ma * mb);
      }
    }
  }

  // Step 2: PCR5 redistribution of conflicting mass
  for (const [a, ma] of m1) {
    for (const [b, mb] of m2) {
      if ((a & b) === 0 && ma > 0 && mb > 0) {
        // Redistribute to a and b proportionally to squared masses
        const denom = ma + mb;
        if (denom > 1e-15) {
          const toA = (ma * ma * mb) / denom;
          const toB = (mb * mb * ma) / denom;
          if (toA > 1e-12) conj.set(a, (conj.get(a) ?? 0) + toA);
          if (toB > 1e-12) conj.set(b, (conj.get(b) ?? 0) + toB);
        }
      }
    }
  }

  return { combined: conj, conflict: K };
}

/** Yager's rule: transfers all conflict to THETA (used when K > 0.7) */
export function combineYager(m1: MassFunction, m2: MassFunction): { combined: MassFunction; conflict: number } {
  const K = conflictCoefficient(m1, m2);
  const conj: MutableMassFunction = new Map();

  for (const [a, ma] of m1) {
    for (const [b, mb] of m2) {
      const intersection = a & b;
      if (intersection !== 0) {
        conj.set(intersection, (conj.get(intersection) ?? 0) + ma * mb);
      }
    }
  }
  // Transfer all conflict to THETA
  if (K > 1e-12) {
    conj.set(THETA, (conj.get(THETA) ?? 0) + K);
  }
  return { combined: conj, conflict: K };
}

/** Auto-selecting combination: PCR5 for K≤0.7, Yager for K>0.7 */
export function combine(m1: MassFunction, m2: MassFunction): { combined: MassFunction; conflict: number } {
  const K = conflictCoefficient(m1, m2);
  return K > 0.7 ? combineYager(m1, m2) : combinePCR5(m1, m2);
}

/** Belief function: Bel(H) = Σ m(A) for all A ⊆ H */
export function belief(m: MassFunction, hypothesis: FocalElement): number {
  let bel = 0;
  for (const [fe, mass] of m) {
    if (fe !== THETA && isSubset(fe, hypothesis)) bel += mass;
  }
  return bel;
}

/** Plausibility function: Pl(H) = Σ m(A) for all A ∩ H ≠ ∅ */
export function plausibility(m: MassFunction, hypothesis: FocalElement): number {
  let pl = 0;
  for (const [fe, mass] of m) {
    if (intersects(fe, hypothesis)) pl += mass;
  }
  return pl;
}

/** Compute belief interval [Bel, Pl] for a hypothesis */
export function beliefInterval(m: MassFunction, hypothesis: FocalElement): BeliefInterval {
  const bel = belief(m, hypothesis);
  const pl = plausibility(m, hypothesis);
  return { belief: bel, plausibility: pl, uncertainty: pl - bel };
}

/** Generalized Hartley entropy: H = Σ m(A) · log₂|A| */
export function hartleyEntropy(m: MassFunction): number {
  let H = 0;
  for (const [fe, mass] of m) {
    const card = cardinality(fe);
    if (card > 1 && mass > 0) {
      H += mass * Math.log2(card);
    }
  }
  return H;
}

/** Pignistic transformation (Smets 1990 TBM): converts mass → probability for EFE */
export function pignisticProbability(m: MassFunction, hypothesis: FocalElement): number {
  let betP = 0;
  const totalNonEmpty = 1.0; // masses already sum to 1 for non-empty sets
  for (const [fe, mass] of m) {
    if (fe === 0) continue; // skip empty set
    const card = cardinality(fe);
    if (card > 0 && isSubset(hypothesis, fe)) {
      betP += mass / card;
    } else if (card > 0 && intersects(hypothesis, fe)) {
      // For non-singleton hypothesis, count overlapping bits
      const overlap = cardinality(hypothesis & fe);
      betP += (mass * overlap) / card;
    }
  }
  return betP / totalNonEmpty;
}

/** Get pignistic probability distribution over all singletons */
export function pignisticDistribution(m: MassFunction, frameSize: number): number[] {
  const dist: number[] = new Array(frameSize).fill(0);
  for (let i = 0; i < frameSize; i++) {
    dist[i] = pignisticProbability(m, singleton(i));
  }
  // Normalize
  const sum = dist.reduce((a, b) => a + b, 0);
  if (sum > 1e-12) {
    for (let i = 0; i < frameSize; i++) { const v = dist[i]; if (v !== undefined) dist[i] = v / sum; }
  }
  return dist;
}

/** Shannon entropy of a probability distribution */
export function shannonEntropy(dist: readonly number[]): number {
  let H = 0;
  for (const p of dist) {
    if (p > 1e-12) H -= p * Math.log2(p);
  }
  return H;
}
