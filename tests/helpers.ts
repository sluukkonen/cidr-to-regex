import { type CidrToRegexOptions, cidrToRegex } from "../src/index.js";

export type FixtureCase = {
  cidr: string;
  normalized: string;
  inside: string[];
  outside: string[];
};

type RegexInput = RegExp | RegExp[];

function safeTest(regex: RegExp, value: string): boolean {
  regex.lastIndex = 0;
  return regex.test(value);
}

function asRegexArray(regexes: RegexInput): RegExp[] {
  return Array.isArray(regexes) ? regexes : [regexes];
}

export function matchesAny(regexes: RegexInput, value: string): boolean {
  return asRegexArray(regexes).some((regex) => safeTest(regex, value));
}

export function compile(cidr: string, options?: CidrToRegexOptions): RegExp {
  const regex = cidrToRegex(cidr, options);
  if (!(regex instanceof RegExp)) {
    throw new TypeError("cidrToRegex must return a RegExp");
  }
  return regex;
}

export function assertBehavior(regexes: RegexInput, inside: string[], outside: string[]): void {
  const strict = asRegexArray(regexes).every(isAnchoredRegex);
  for (const addr of inside) {
    expect(matchesAny(regexes, addr)).toBe(true);
    if (strict) {
      expect(matchesAny(regexes, `x${addr}`)).toBe(false);
      expect(matchesAny(regexes, `${addr}x`)).toBe(false);
    }
  }
  for (const addr of outside) {
    expect(matchesAny(regexes, addr)).toBe(false);
  }
}

export function assertEquivalentOnSamples(
  left: RegexInput,
  right: RegexInput,
  samples: string[],
): void {
  for (const sample of samples) {
    expect(matchesAny(left, sample)).toBe(matchesAny(right, sample));
  }
}

export function uppercaseIPv6(addr: string): string {
  return addr.toUpperCase();
}

function isAnchoredRegex(regex: RegExp): boolean {
  return regex.source.startsWith("^(?:") && regex.source.endsWith(")$");
}
