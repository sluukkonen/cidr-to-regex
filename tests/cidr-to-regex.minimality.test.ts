import { compile } from "./helpers.js";
import {
  expandIPv4Forms,
  expandIPv6Forms,
  findMinimumEquivalentSetSize,
} from "./minimality-helpers.js";

function flattenRegexes(cidrs: string[]): RegExp[] {
  return cidrs.flatMap((cidr) => compile(cidr));
}

describe("cidrToRegex brute-force minimality checks", () => {
  it("IPv4: /30 needs at least two child-regexes if direct /30 regex is unavailable", () => {
    const target = compile("192.0.2.0/30");
    expect(target).toHaveLength(1);

    const universe = Array.from({ length: 8 }, (_, i) => expandIPv4Forms([192, 0, 2], i)).flat();

    const childAndDecoyCandidates = flattenRegexes([
      "192.0.2.0/31",
      "192.0.2.2/31",
      "192.0.2.0/32",
      "192.0.2.1/32",
      "192.0.2.2/32",
      "192.0.2.3/32",
      "192.0.2.4/30",
      "192.0.2.0/29",
    ]);

    const minWithoutDirect = findMinimumEquivalentSetSize(
      childAndDecoyCandidates,
      universe,
      target,
    );
    expect(minWithoutDirect).toBe(2);

    const minWithDirect = findMinimumEquivalentSetSize(
      [...childAndDecoyCandidates, ...target],
      universe,
      target,
    );
    expect(minWithDirect).toBe(target.length);
  });

  it("IPv6: /126 needs at least two child-regexes if direct /126 regex is unavailable", () => {
    const target = compile("2001:db8::/126");
    expect(target).toHaveLength(1);

    const prefix7 = "2001:0db8:0000:0000:0000:0000:0000";
    const universe = Array.from({ length: 8 }, (_, i) => expandIPv6Forms(prefix7, i)).flat();

    const childAndDecoyCandidates = flattenRegexes([
      "2001:db8::/127",
      "2001:db8::2/127",
      "2001:db8::/128",
      "2001:db8::1/128",
      "2001:db8::2/128",
      "2001:db8::3/128",
      "2001:db8::4/126",
      "2001:db8::/125",
    ]);

    const minWithoutDirect = findMinimumEquivalentSetSize(
      childAndDecoyCandidates,
      universe,
      target,
    );
    expect(minWithoutDirect).toBe(2);

    const minWithDirect = findMinimumEquivalentSetSize(
      [...childAndDecoyCandidates, ...target],
      universe,
      target,
    );
    expect(minWithDirect).toBe(target.length);
  });
});
