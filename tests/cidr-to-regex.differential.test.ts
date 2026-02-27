import fixtures from "./fixtures/differential-samples.json" with { type: "json" };
import { assertEquivalentOnSamples, compile, matchesAny } from "./helpers.js";

type IPv4Sample = {
  addr: string;
  padded: string;
  expected: boolean;
};

type IPv6Sample = {
  addr: string;
  upper: string;
  expected: boolean;
};

type IPv4Case = {
  cidr: string;
  normalized: string;
  samples: IPv4Sample[];
};

type IPv6Case = {
  cidr: string;
  normalized: string;
  samples: IPv6Sample[];
};

type DifferentialFixture = {
  meta: {
    seed: number;
    ipv4Cases: number;
    ipv6Cases: number;
    samplesPerCase: number;
  };
  ipv4: IPv4Case[];
  ipv6: IPv6Case[];
};

const data = fixtures as DifferentialFixture;

describe("cidrToRegex differential fixtures", () => {
  describe("IPv4", () => {
    it.each(data.ipv4.map((entry) => [entry.cidr, entry] as const))(
      "matches ipaddress semantics for %s",
      (_cidr, entry) => {
        const regexes = compile(entry.cidr);
        const normalized = compile(entry.normalized);

        for (const sample of entry.samples) {
          expect(matchesAny(regexes, sample.addr)).toBe(sample.expected);
          expect(matchesAny(regexes, sample.padded)).toBe(
            sample.expected && isCanonicalIPv4(sample.padded),
          );
        }

        assertEquivalentOnSamples(
          regexes,
          normalized,
          entry.samples.flatMap((sample) => [sample.addr, sample.padded]),
        );
      },
    );
  });

  describe("IPv6", () => {
    it.each(data.ipv6.map((entry) => [entry.cidr, entry] as const))(
      "matches ipaddress semantics for %s",
      (_cidr, entry) => {
        const regexes = compile(entry.cidr);
        const normalized = compile(entry.normalized);

        for (const sample of entry.samples) {
          expect(matchesAny(regexes, sample.addr)).toBe(sample.expected);
          expect(matchesAny(regexes, sample.upper)).toBe(sample.expected);
        }

        assertEquivalentOnSamples(
          regexes,
          normalized,
          entry.samples.flatMap((sample) => [sample.addr, sample.upper]),
        );
      },
    );
  });
});

function isCanonicalIPv4(addr: string): boolean {
  const parts = addr.split(".");
  if (parts.length !== 4) {
    return false;
  }
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return false;
    }
    if (part.length > 1 && part.startsWith("0")) {
      return false;
    }
    const value = Number.parseInt(part, 10);
    if (value < 0 || value > 255) {
      return false;
    }
  }
  return true;
}
