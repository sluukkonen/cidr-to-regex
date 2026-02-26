import { cidrToRegex } from "../src/index.js";

export type FixtureCase = {
  cidr: string;
  normalized: string;
  inside: string[];
  outside: string[];
};

function safeTest(regex: RegExp, value: string): boolean {
  regex.lastIndex = 0;
  return regex.test(value);
}

export function matchesAny(regexes: RegExp[], value: string): boolean {
  return regexes.some((regex) => safeTest(regex, value));
}

export function compile(cidr: string): RegExp[] {
  const regexes = cidrToRegex(cidr);
  if (!Array.isArray(regexes)) {
    throw new TypeError("cidrToRegex must return an array");
  }
  if (regexes.length === 0) {
    throw new TypeError("cidrToRegex must return at least one regex for valid CIDR");
  }
  for (const regex of regexes) {
    if (!(regex instanceof RegExp)) {
      throw new TypeError("cidrToRegex array entries must be RegExp instances");
    }
  }
  return regexes;
}

export function assertBehavior(regexes: RegExp[], inside: string[], outside: string[]): void {
  for (const addr of inside) {
    expect(matchesAny(regexes, addr)).toBe(true);
    expect(matchesAny(regexes, `x${addr}`)).toBe(false);
    expect(matchesAny(regexes, `${addr}x`)).toBe(false);
  }
  for (const addr of outside) {
    expect(matchesAny(regexes, addr)).toBe(false);
  }
}

export function assertEquivalentOnSamples(
  left: RegExp[],
  right: RegExp[],
  samples: string[],
): void {
  for (const sample of samples) {
    expect(matchesAny(left, sample)).toBe(matchesAny(right, sample));
  }
}

export function uppercaseIPv6(addr: string): string {
  return addr.toUpperCase();
}
