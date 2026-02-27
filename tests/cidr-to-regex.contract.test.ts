import fixtures from "./fixtures/cidr-samples.json" with { type: "json" };
import {
  type FixtureCase,
  assertBehavior,
  assertEquivalentOnSamples,
  compile,
  matchesAny,
  uppercaseIPv6,
} from "./helpers.js";

type FixtureData = {
  meta: { seed: number };
  ipv4: FixtureCase[];
  ipv6: FixtureCase[];
};

const data = fixtures as FixtureData;
const ipv4NormalizationCases = data.ipv4
  .slice(0, 15)
  .map((fixture) => [fixture.cidr, fixture] as const);
const ipv6NormalizationCases = data.ipv6
  .slice(0, 20)
  .map((fixture) => [fixture.cidr, fixture] as const);
const ipv4FixtureCases = data.ipv4.map((fixture) => [fixture.cidr, fixture] as const);
const ipv6FixtureCases = data.ipv6.map((fixture) => [fixture.cidr, fixture] as const);

describe("cidrToRegex contract", () => {
  describe("invalid CIDR input", () => {
    it.each([
      "",
      "10.0.0.1",
      "10.0.0.1/",
      "10.0.0.1/-1",
      "10.0.0.1/33",
      "300.0.0.1/24",
      "10.0.256.1/24",
      "010.000.256.001/24",
      "10.0.0.1/abc",
      "2001:db8::1/64/32",
      "2001:db8::zzzz/64",
      "2001:db8::1/129",
      "not-a-cidr",
    ])("throws for %s", (cidr) => {
      expect(() => compile(cidr)).toThrow();
    });
  });

  describe("return shape", () => {
    it("returns RegExp for valid IPv4 CIDR", () => {
      const regex = compile("10.0.0.1/24");
      expect(regex).toBeInstanceOf(RegExp);
    });

    it("returns RegExp for valid IPv6 CIDR", () => {
      const regex = compile("2001:0db8:0000:0000:0000:0000:0000:0001/64");
      expect(regex).toBeInstanceOf(RegExp);
    });
  });

  describe("single regex output", () => {
    it.each(["10.0.0.0/23", "10.0.0.0/22", "2001:db8::/47", "2001:db8::/33", "::/1"])(
      "returns RegExp for %s",
      (cidr) => {
        expect(compile(cidr)).toBeInstanceOf(RegExp);
      },
    );
  });

  describe("exact match semantics", () => {
    it("matches only exact address for IPv4 /32", () => {
      const regexes = compile("198.51.100.23/32");
      assertBehavior(regexes, ["198.51.100.23"], ["198.51.100.22", "198.51.100.24"]);
    });

    it("matches only exact address for IPv6 /128", () => {
      const target = "2001:0db8:0000:0000:0000:0000:0000:00ff";
      const regexes = compile(`${target}/128`);
      assertBehavior(regexes, [target], ["2001:0DB8:0000:0000:0000:0000:0000:0100"]);
    });
  });

  describe("maximal representation only", () => {
    it("does not match IPv4 shorthand forms", () => {
      const regexes = compile("10.0.0.0/24");
      expect(matchesAny(regexes, "10.0.0.1")).toBe(true);
      expect(matchesAny(regexes, "10.0.1")).toBe(false);
    });

    it("does not match IPv6 compressed forms", () => {
      const regexes = compile("2001:0db8:0000:0000:0000:0000:0000:0000/112");
      expect(matchesAny(regexes, "2001:0db8:0000:0000:0000:0000:0000:00ab")).toBe(true);
      expect(matchesAny(regexes, "2001:db8::ab")).toBe(false);
    });
  });

  describe("liberal CIDR input parsing", () => {
    it("accepts compressed IPv6 CIDR input", () => {
      const left = compile("2001:db8::1/64");
      const right = compile("2001:0db8:0000:0000:0000:0000:0000:0001/64");
      assertEquivalentOnSamples(left, right, [
        "2001:0db8:0000:0000:0000:0000:0000:0000",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "2001:0db8:0000:0000:ffff:ffff:ffff:ffff",
        "2001:0db8:0000:0001:0000:0000:0000:0000",
      ]);
    });

    it("accepts compressed IPv6 CIDR like ::ff/16", () => {
      const left = compile("::ff/16");
      const right = compile("0000:0000:0000:0000:0000:0000:0000:00ff/16");
      assertEquivalentOnSamples(left, right, [
        "0000:0000:0000:0000:0000:0000:0000:0000",
        "0000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "0001:0000:0000:0000:0000:0000:0000:0000",
      ]);
      expect(matchesAny(left, "::ff")).toBe(false);
    });
  });

  describe("IPv4 leading zeros", () => {
    it("accepts leading-zero forms for addresses in-range", () => {
      const regexes = compile("10.0.0.0/24");
      expect(matchesAny(regexes, "010.000.000.001")).toBe(true);
      expect(matchesAny(regexes, "010.00.0.001")).toBe(true);
      expect(matchesAny(regexes, "10.000.000.1")).toBe(true);
      expect(matchesAny(regexes, "010.000.001.001")).toBe(false);
      expect(matchesAny(regexes, "010.000.000.256")).toBe(false);
    });

    it("accepts leading-zero CIDR input with equivalent behavior", () => {
      const left = compile("010.000.000.255/24");
      const right = compile("10.0.0.255/24");
      assertEquivalentOnSamples(left, right, [
        "10.0.0.0",
        "10.0.0.1",
        "010.000.000.001",
        "010.00.0.001",
        "10.000.000.1",
        "10.0.0.255",
        "010.000.000.255",
        "10.0.1.0",
        "010.000.000.256",
      ]);
    });
  });

  describe("IPv6 case-insensitive hex acceptance", () => {
    const cidr = "2001:0db8:0000:0000:0000:0000:0000:0000/120";
    const insideLower = "2001:0db8:0000:0000:0000:0000:0000:00af";
    const insideUpper = uppercaseIPv6(insideLower);

    it("accepts lowercase and uppercase forms", () => {
      const regexes = compile(cidr);
      expect(matchesAny(regexes, insideLower)).toBe(true);
      expect(matchesAny(regexes, insideUpper)).toBe(true);
    });
  });

  describe("normalization behavior", () => {
    it.each(ipv4NormalizationCases)("normalizes IPv4 host bits for %s", (_cidr, fixture) => {
      const left = compile(fixture.cidr);
      const right = compile(fixture.normalized);
      assertEquivalentOnSamples(left, right, [...fixture.inside, ...fixture.outside]);
    });

    it.each(ipv6NormalizationCases)("normalizes IPv6 host bits for %s", (_cidr, fixture) => {
      const left = compile(fixture.cidr);
      const right = compile(fixture.normalized);
      const uppercaseSamples = fixture.inside.map(uppercaseIPv6);
      assertEquivalentOnSamples(left, right, [
        ...fixture.inside,
        ...fixture.outside,
        ...uppercaseSamples,
      ]);
    });
  });

  describe("family boundary checks", () => {
    it("IPv4 CIDR regexes do not match IPv6 input", () => {
      const regexes = compile("10.0.0.0/8");
      expect(matchesAny(regexes, "2001:0db8:0000:0000:0000:0000:0000:0001")).toBe(false);
    });

    it("IPv6 CIDR regexes do not match IPv4 input", () => {
      const regexes = compile("2001:0db8:0000:0000:0000:0000:0000:0000/32");
      expect(matchesAny(regexes, "10.0.0.1")).toBe(false);
    });
  });

  describe("generated IPv4 fixtures", () => {
    it.each(ipv4FixtureCases)("%s", (_cidr, fixture) => {
      const regexes = compile(fixture.cidr);
      assertBehavior(regexes, fixture.inside, fixture.outside);
    });
  });

  describe("generated IPv6 fixtures", () => {
    it.each(ipv6FixtureCases)("%s", (_cidr, fixture) => {
      const regexes = compile(fixture.cidr);
      assertBehavior(regexes, fixture.inside, fixture.outside);

      for (const inside of fixture.inside) {
        expect(matchesAny(regexes, uppercaseIPv6(inside))).toBe(true);
      }
      for (const outside of fixture.outside) {
        expect(matchesAny(regexes, uppercaseIPv6(outside))).toBe(false);
      }
    });
  });
});
