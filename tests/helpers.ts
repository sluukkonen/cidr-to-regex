import { cidrToRegex } from "../src/index.js";

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

export function compile(cidr: string): RegExp {
  const regex = cidrToRegex(cidr);
  if (!(regex instanceof RegExp)) {
    throw new TypeError("cidrToRegex must return a RegExp");
  }
  return regex;
}

export function assertBehavior(regexes: RegexInput, inside: string[], outside: string[]): void {
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
