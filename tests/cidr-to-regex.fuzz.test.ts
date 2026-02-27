import { compile, matchesAny } from "./helpers.js";

const FUZZ_SEED = 0x9e3779b1;
const IPV4_CASES = 200;
const IPV6_CASES = 200;
const SAMPLES_PER_CASE = 18;

class XorShift32 {
  private state: number;

  constructor(seed: number) {
    this.state = seed | 0;
    if (this.state === 0) {
      this.state = 1;
    }
  }

  nextU32(): number {
    let x = this.state;
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    this.state = x | 0;
    return this.state >>> 0;
  }

  nextInt(maxExclusive: number): number {
    return this.nextU32() % maxExclusive;
  }

  nextBool(): boolean {
    return (this.nextU32() & 1) === 1;
  }
}

describe("cidrToRegex fuzz stress", () => {
  it("matches expected membership for random IPv4 CIDRs and addresses", () => {
    const rng = new XorShift32(FUZZ_SEED);

    for (let i = 0; i < IPV4_CASES; i += 1) {
      const raw = randomIPv4Value(rng);
      const prefix = rng.nextInt(33);
      const cidr = formatIPv4Cidr(raw, prefix, rng.nextBool());
      const regexes = compile(cidr);

      const [start, end] = normalizedRange(raw, 32, prefix);
      const probeSet = new Set<bigint>([
        start,
        end,
        start > 0n ? start - 1n : 0n,
        end < (1n << 32n) - 1n ? end + 1n : end,
      ]);
      while (probeSet.size < SAMPLES_PER_CASE) {
        probeSet.add(randomIPv4Value(rng));
      }

      for (const probe of probeSet) {
        const expected = probe >= start && probe <= end;
        const canonical = formatIPv4Canonical(probe);
        const padded = formatIPv4Padded(probe, rng);
        const paddedExpected = expected && isCanonicalIPv4(padded);
        expect(matchesAny(regexes, canonical)).toBe(expected);
        expect(matchesAny(regexes, padded)).toBe(paddedExpected);
      }
    }
  });

  it("matches expected membership for random IPv6 CIDRs and addresses", () => {
    const rng = new XorShift32(FUZZ_SEED ^ 0xa5a5a5a5);

    for (let i = 0; i < IPV6_CASES; i += 1) {
      const raw = randomIPv6Value(rng);
      const prefix = rng.nextInt(129);
      const cidr = formatIPv6Cidr(raw, prefix, rng);
      const regexes = compile(cidr);

      const [start, end] = normalizedRange(raw, 128, prefix);
      const max = (1n << 128n) - 1n;
      const probeSet = new Set<bigint>([
        start,
        end,
        start > 0n ? start - 1n : 0n,
        end < max ? end + 1n : end,
      ]);
      while (probeSet.size < SAMPLES_PER_CASE) {
        probeSet.add(randomIPv6Value(rng));
      }

      for (const probe of probeSet) {
        const expected = probe >= start && probe <= end;
        const canonical = formatIPv6Canonical(probe);
        const upper = canonical.toUpperCase();
        expect(matchesAny(regexes, canonical)).toBe(expected);
        expect(matchesAny(regexes, upper)).toBe(expected);
      }
    }
  });
});

function normalizedRange(value: bigint, bits: number, prefix: number): [bigint, bigint] {
  const hostBits = bits - prefix;
  const hostMask = hostBits === 0 ? 0n : (1n << BigInt(hostBits)) - 1n;
  const start = value & ~hostMask;
  const end = start | hostMask;
  return [start, end];
}

function randomIPv4Value(rng: XorShift32): bigint {
  return BigInt(rng.nextU32());
}

function randomIPv6Value(rng: XorShift32): bigint {
  let value = 0n;
  for (let i = 0; i < 4; i += 1) {
    value = (value << 32n) | BigInt(rng.nextU32());
  }
  return value;
}

function formatIPv4Canonical(value: bigint): string {
  const octets = [
    Number((value >> 24n) & 0xffn),
    Number((value >> 16n) & 0xffn),
    Number((value >> 8n) & 0xffn),
    Number(value & 0xffn),
  ];
  return octets.join(".");
}

function formatIPv4Padded(value: bigint, rng: XorShift32): string {
  return formatIPv4Canonical(value)
    .split(".")
    .map((part) => part.padStart(1 + rng.nextInt(3), "0"))
    .join(".");
}

function formatIPv4Cidr(value: bigint, prefix: number, padded: boolean): string {
  if (!padded) {
    return `${formatIPv4Canonical(value)}/${prefix}`;
  }
  return `${formatIPv4Canonical(value)
    .split(".")
    .map((part) => part.padStart(3, "0"))
    .join(".")}/${prefix}`;
}

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

function formatIPv6Canonical(value: bigint): string {
  const hextets: string[] = [];
  for (let i = 0; i < 8; i += 1) {
    const shift = BigInt((7 - i) * 16);
    hextets.push(
      Number((value >> shift) & 0xffffn)
        .toString(16)
        .padStart(4, "0"),
    );
  }
  return hextets.join(":");
}

function formatIPv6Compressed(value: bigint): string {
  const parts = formatIPv6Canonical(value).split(":");

  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;

  for (let i = 0; i <= parts.length; i += 1) {
    const isZero = i < parts.length && parts[i] === "0000";
    if (isZero && runStart < 0) {
      runStart = i;
    }
    if (!isZero && runStart >= 0) {
      const len = i - runStart;
      if (len > bestLen) {
        bestLen = len;
        bestStart = runStart;
      }
      runStart = -1;
    }
  }

  const short = parts.map((part) => part.replace(/^0+([0-9a-f])/, "$1").replace(/^0+$/, "0"));
  if (bestLen >= 2) {
    const left = short.slice(0, bestStart).join(":");
    const right = short.slice(bestStart + bestLen).join(":");
    if (left.length === 0 && right.length === 0) {
      return "::";
    }
    if (left.length === 0) {
      return `::${right}`;
    }
    if (right.length === 0) {
      return `${left}::`;
    }
    return `${left}::${right}`;
  }

  return short.join(":");
}

function formatIPv6EmbeddedIPv4(value: bigint): string {
  const canonical = formatIPv6Canonical(value).split(":");
  const high = Number.parseInt(canonical[6], 16);
  const low = Number.parseInt(canonical[7], 16);
  const ipv4 = `${(high >> 8) & 255}.${high & 255}.${(low >> 8) & 255}.${low & 255}`;
  return `${canonical.slice(0, 6).join(":")}:${ipv4}`;
}

function formatIPv6Cidr(value: bigint, prefix: number, rng: XorShift32): string {
  const mode = rng.nextInt(4);
  const address =
    mode === 0
      ? formatIPv6Canonical(value)
      : mode === 1
        ? formatIPv6Compressed(value)
        : mode === 2
          ? formatIPv6Canonical(value).toUpperCase()
          : formatIPv6EmbeddedIPv4(value);
  return `${address}/${prefix}`;
}
