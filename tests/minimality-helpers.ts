import { matchesAny } from "./helpers.js";

type CandidateMask = {
  mask: bigint;
};

export function findMinimumEquivalentSetSize(
  candidates: RegExp[],
  universe: string[],
  targetRegexes: RegExp[],
): number | null {
  if (universe.length === 0) {
    return 0;
  }
  if (universe.length > 62) {
    throw new Error("Universe too large for brute-force bitmask verifier");
  }

  const targetMask = maskForRegexes(universe, targetRegexes);
  const candidateMasks = candidates
    .map((candidate) => ({ mask: maskForRegexes(universe, [candidate]) }))
    .filter(({ mask }) => mask !== 0n)
    .filter(({ mask }) => (mask & ~targetMask) === 0n);

  const suffixUnion = buildSuffixUnion(candidateMasks);
  let best = Number.POSITIVE_INFINITY;

  function dfs(index: number, selected: number, currentMask: bigint): void {
    if (selected >= best) {
      return;
    }
    if (currentMask === targetMask) {
      best = selected;
      return;
    }
    if (index >= candidateMasks.length) {
      return;
    }
    if ((currentMask & ~targetMask) !== 0n) {
      return;
    }

    const missing = targetMask & ~currentMask;
    if ((missing & ~suffixUnion[index]) !== 0n) {
      return;
    }

    dfs(index + 1, selected + 1, currentMask | candidateMasks[index].mask);
    dfs(index + 1, selected, currentMask);
  }

  dfs(0, 0, 0n);
  return Number.isFinite(best) ? best : null;
}

function maskForRegexes(universe: string[], regexes: RegExp[]): bigint {
  let mask = 0n;
  for (let i = 0; i < universe.length; i += 1) {
    if (matchesAny(regexes, universe[i])) {
      mask |= 1n << BigInt(i);
    }
  }
  return mask;
}

function buildSuffixUnion(candidates: CandidateMask[]): bigint[] {
  const out: bigint[] = Array<bigint>(candidates.length + 1).fill(0n);
  for (let i = candidates.length - 1; i >= 0; i -= 1) {
    out[i] = out[i + 1] | candidates[i].mask;
  }
  return out;
}

export function expandIPv4Forms(prefix: [number, number, number], lastOctet: number): string[] {
  const [a, b, c] = prefix;
  const canonical = `${a}.${b}.${c}.${lastOctet}`;
  const padded = `${String(a).padStart(3, "0")}.${String(b).padStart(3, "0")}.${String(c).padStart(3, "0")}.${String(lastOctet).padStart(3, "0")}`;
  return [canonical, padded];
}

export function expandIPv6Forms(prefix7: string, lastHextet: number): string[] {
  const lower = `${prefix7}:${lastHextet.toString(16).padStart(4, "0")}`;
  return [lower, lower.toUpperCase()];
}
