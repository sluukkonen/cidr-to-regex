type ParsedCidr =
  | { family: "ipv4"; address: bigint; prefix: number }
  | { family: "ipv6"; address: bigint; prefix: number };

const IPV4_BITS = 32;
const IPV6_BITS = 128;

const IPV4_ANY_OCTET = "(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])";
const IPV6_ANY_HEXTET = "[0-9a-f]{4}";
const HEX_DIGITS = "0123456789abcdef";

export function cidrToRegex(cidr: string): RegExp {
  const parsed = parseCidr(cidr);

  if (parsed.family === "ipv4") {
    const [start, end] = normalizeRange(parsed.address, IPV4_BITS, parsed.prefix);
    const startOctets = ipv4ToOctets(start);
    const endOctets = ipv4ToOctets(end);
    const patterns = minimizePatternSet(
      uniquePatterns(buildIPv4Patterns(startOctets, endOctets, 0)),
      "\\.",
      4,
    );
    return buildRegex(patterns);
  }

  const [start, end] = normalizeRange(parsed.address, IPV6_BITS, parsed.prefix);
  const startHextets = ipv6ToHextets(start);
  const endHextets = ipv6ToHextets(end);
  const patterns = minimizePatternSet(
    uniquePatterns(buildIPv6Patterns(startHextets, endHextets, 0)),
    ":",
    8,
  );
  return buildRegex(patterns, "i");
}

function buildRegex(patterns: string[], flags?: string): RegExp {
  return new RegExp(`^(?:${orPattern(patterns)})$`, flags);
}

function parseCidr(input: string): ParsedCidr {
  if (typeof input !== "string") {
    throw new Error("Invalid CIDR");
  }

  const trimmed = input.trim();
  const parts = trimmed.split("/");
  if (parts.length !== 2) {
    throw new Error("Invalid CIDR");
  }

  const [addressText, prefixText] = parts;
  if (!addressText || !/^\d+$/.test(prefixText)) {
    throw new Error("Invalid CIDR");
  }

  const prefix = Number.parseInt(prefixText, 10);
  if (!Number.isFinite(prefix) || !Number.isInteger(prefix)) {
    throw new Error("Invalid CIDR");
  }

  if (addressText.includes(":")) {
    if (prefix < 0 || prefix > IPV6_BITS) {
      throw new Error("Invalid CIDR");
    }
    const address = parseIPv6(addressText);
    if (address === null) {
      throw new Error("Invalid CIDR");
    }
    return { family: "ipv6", address, prefix };
  }

  if (prefix < 0 || prefix > IPV4_BITS) {
    throw new Error("Invalid CIDR");
  }
  const address = parseIPv4(addressText);
  if (address === null) {
    throw new Error("Invalid CIDR");
  }
  return { family: "ipv4", address, prefix };
}

function parseIPv4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) {
    return null;
  }

  let value = 0n;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const octet = parseByte(part);
    if (octet === null) {
      return null;
    }
    value = (value << 8n) | BigInt(octet);
  }

  return value;
}

function parseByte(part: string): number | null {
  if (part.length === 0) {
    return null;
  }

  let value = 0;
  for (let i = 0; i < part.length; i += 1) {
    const code = part.charCodeAt(i);
    if (code < 48 || code > 57) {
      return null;
    }
    value = value * 10 + (code - 48);
    if (value > 255) {
      return null;
    }
  }
  return value;
}

function parseIPv6(text: string): bigint | null {
  let normalized = text.toLowerCase();
  normalized = expandEmbeddedIPv4(normalized);
  if (normalized.length === 0) {
    return null;
  }

  const doubleColonCount = (normalized.match(/::/g) ?? []).length;
  if (doubleColonCount > 1) {
    return null;
  }

  const hasCompression = normalized.includes("::");
  const [leftRaw, rightRaw = ""] = hasCompression ? normalized.split("::") : [normalized, ""];
  const leftParts = leftRaw.length === 0 ? [] : leftRaw.split(":");
  const rightParts = hasCompression && rightRaw.length > 0 ? rightRaw.split(":") : [];

  if (leftParts.some((part) => part.length === 0) || rightParts.some((part) => part.length === 0)) {
    return null;
  }

  const parsedLeft = parseHextetParts(leftParts);
  const parsedRight = parseHextetParts(rightParts);
  if (parsedLeft === null || parsedRight === null) {
    return null;
  }

  let hextets: number[];
  if (hasCompression) {
    const fixedCount = parsedLeft.length + parsedRight.length;
    if (fixedCount >= 8) {
      return null;
    }
    const missing = 8 - fixedCount;
    hextets = [...parsedLeft, ...Array<number>(missing).fill(0), ...parsedRight];
  } else {
    if (parsedLeft.length !== 8) {
      return null;
    }
    hextets = parsedLeft;
  }

  if (hextets.length !== 8) {
    return null;
  }

  let value = 0n;
  for (const hextet of hextets) {
    value = (value << 16n) | BigInt(hextet);
  }
  return value;
}

function expandEmbeddedIPv4(text: string): string {
  if (!text.includes(".")) {
    return text;
  }

  const lastColon = text.lastIndexOf(":");
  if (lastColon < 0) {
    return "";
  }

  const ipv4Part = text.slice(lastColon + 1);
  if (!ipv4Part || ipv4Part.includes(":")) {
    return "";
  }

  const ipv4 = parseIPv4(ipv4Part);
  if (ipv4 === null) {
    return "";
  }

  const high = Number((ipv4 >> 16n) & 0xffffn).toString(16);
  const low = Number(ipv4 & 0xffffn).toString(16);
  return `${text.slice(0, lastColon)}:${high}:${low}`;
}

function parseHextetParts(parts: string[]): number[] | null {
  const out: number[] = [];
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) {
      return null;
    }
    out.push(Number.parseInt(part, 16));
  }
  return out;
}

function normalizeRange(value: bigint, bits: number, prefix: number): [bigint, bigint] {
  const hostBits = bits - prefix;
  const prefixMask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(hostBits);
  const hostMask = hostBits === 0 ? 0n : (1n << BigInt(hostBits)) - 1n;
  const start = value & prefixMask;
  const end = start | hostMask;
  return [start, end];
}

function ipv4ToOctets(value: bigint): number[] {
  return [
    Number((value >> 24n) & 0xffn),
    Number((value >> 16n) & 0xffn),
    Number((value >> 8n) & 0xffn),
    Number(value & 0xffn),
  ];
}

function ipv6ToHextets(value: bigint): number[] {
  const hextets: number[] = [];
  for (let i = 0; i < 8; i += 1) {
    const shift = BigInt((7 - i) * 16);
    hextets.push(Number((value >> shift) & 0xffffn));
  }
  return hextets;
}

function buildIPv4Patterns(start: number[], end: number[], index: number): string[] {
  if (index === 4) {
    return [""];
  }
  if (isFullRange(start, end, index, 0, 255)) {
    return [ipv4AnySuffix(4 - index)];
  }

  const low = start[index];
  const high = end[index];

  if (low === high) {
    return combineWithSuffix(
      octetRangePattern(low, high),
      buildIPv4Patterns(start, end, index + 1),
      "\\.",
    );
  }

  const patterns: string[] = [];

  const firstEnd = start.slice();
  firstEnd[index] = low;
  for (let i = index + 1; i < 4; i += 1) {
    firstEnd[i] = 255;
  }
  patterns.push(
    ...combineWithSuffix(
      octetRangePattern(low, low),
      buildIPv4Patterns(start, firstEnd, index + 1),
      "\\.",
    ),
  );

  if (low + 1 <= high - 1) {
    const middle = octetRangePattern(low + 1, high - 1);
    const suffix = ipv4AnySuffix(4 - index - 1);
    patterns.push(suffix ? `${middle}\\.${suffix}` : middle);
  }

  const lastStart = end.slice();
  lastStart[index] = high;
  for (let i = index + 1; i < 4; i += 1) {
    lastStart[i] = 0;
  }
  patterns.push(
    ...combineWithSuffix(
      octetRangePattern(high, high),
      buildIPv4Patterns(lastStart, end, index + 1),
      "\\.",
    ),
  );

  return uniquePatterns(patterns);
}

function buildIPv6Patterns(start: number[], end: number[], index: number): string[] {
  if (index === 8) {
    return [""];
  }
  if (isFullRange(start, end, index, 0, 0xffff)) {
    return [ipv6AnySuffix(8 - index)];
  }

  const low = start[index];
  const high = end[index];

  if (low === high) {
    return combineWithSuffix(
      hextetRangePattern(low, high),
      buildIPv6Patterns(start, end, index + 1),
      ":",
    );
  }

  const patterns: string[] = [];

  const firstEnd = start.slice();
  firstEnd[index] = low;
  for (let i = index + 1; i < 8; i += 1) {
    firstEnd[i] = 0xffff;
  }
  patterns.push(
    ...combineWithSuffix(
      hextetRangePattern(low, low),
      buildIPv6Patterns(start, firstEnd, index + 1),
      ":",
    ),
  );

  if (low + 1 <= high - 1) {
    const middle = hextetRangePattern(low + 1, high - 1);
    const suffix = ipv6AnySuffix(8 - index - 1);
    patterns.push(suffix ? `${middle}:${suffix}` : middle);
  }

  const lastStart = end.slice();
  lastStart[index] = high;
  for (let i = index + 1; i < 8; i += 1) {
    lastStart[i] = 0;
  }
  patterns.push(
    ...combineWithSuffix(
      hextetRangePattern(high, high),
      buildIPv6Patterns(lastStart, end, index + 1),
      ":",
    ),
  );

  return uniquePatterns(patterns);
}

function combineWithSuffix(head: string, suffixes: string[], separator: string): string[] {
  return suffixes.map((suffix) => (suffix.length === 0 ? head : `${head}${separator}${suffix}`));
}

function isFullRange(
  start: number[],
  end: number[],
  fromIndex: number,
  minValue: number,
  maxValue: number,
): boolean {
  for (let i = fromIndex; i < start.length; i += 1) {
    if (start[i] !== minValue || end[i] !== maxValue) {
      return false;
    }
  }
  return true;
}

function ipv4AnySuffix(count: number): string {
  if (count <= 0) {
    return "";
  }
  return Array<string>(count).fill(IPV4_ANY_OCTET).join("\\.");
}

function ipv6AnySuffix(count: number): string {
  if (count <= 0) {
    return "";
  }
  return Array<string>(count).fill(IPV6_ANY_HEXTET).join(":");
}

function octetRangePattern(start: number, end: number): string {
  if (start === 0 && end === 255) {
    return IPV4_ANY_OCTET;
  }

  const parts: string[] = [];
  for (let value = start; value <= end; value += 1) {
    parts.push(octetValuePattern(value));
  }
  return orPattern(parts);
}

function octetValuePattern(value: number): string {
  return String(value);
}

const hextetRangeCache = new Map<string, string>();

function hextetRangePattern(start: number, end: number): string {
  const key = `${start}-${end}`;
  const cached = hextetRangeCache.get(key);
  if (cached) {
    return cached;
  }

  let pattern: string;
  if (start === 0 && end === 0xffff) {
    pattern = IPV6_ANY_HEXTET;
  } else if (start === end) {
    pattern = start.toString(16).padStart(4, "0");
  } else {
    const low = start.toString(16).padStart(4, "0");
    const high = end.toString(16).padStart(4, "0");
    pattern = orPattern(hexRangeParts(low, high));
  }

  hextetRangeCache.set(key, pattern);
  return pattern;
}

function hexRangeParts(low: string, high: string): string[] {
  if (low.length !== high.length) {
    return [];
  }
  if (low === high) {
    return [low];
  }

  const length = low.length;
  if (low === "0".repeat(length) && high === "f".repeat(length)) {
    return [hexWildcard(length)];
  }

  let splitIndex = 0;
  while (splitIndex < length && low[splitIndex] === high[splitIndex]) {
    splitIndex += 1;
  }

  if (splitIndex === length) {
    return [low];
  }

  const prefix = low.slice(0, splitIndex);
  const lowDigit = hexValue(low[splitIndex]);
  const highDigit = hexValue(high[splitIndex]);
  const suffixLength = length - splitIndex - 1;

  const parts: string[] = [];

  const lowerLowTail = low.slice(splitIndex + 1);
  const lowerHighTail = "f".repeat(suffixLength);
  for (const suffix of hexRangeParts(lowerLowTail, lowerHighTail)) {
    parts.push(`${prefix}${hexDigitRange(lowDigit, lowDigit)}${suffix}`);
  }

  if (lowDigit + 1 <= highDigit - 1) {
    parts.push(
      `${prefix}${hexDigitRange(lowDigit + 1, highDigit - 1)}${hexWildcard(suffixLength)}`,
    );
  }

  const upperLowTail = "0".repeat(suffixLength);
  const upperHighTail = high.slice(splitIndex + 1);
  for (const suffix of hexRangeParts(upperLowTail, upperHighTail)) {
    parts.push(`${prefix}${hexDigitRange(highDigit, highDigit)}${suffix}`);
  }

  return uniquePatterns(parts);
}

function hexWildcard(length: number): string {
  if (length <= 0) {
    return "";
  }
  if (length === 1) {
    return "[0-9a-f]";
  }
  return `[0-9a-f]{${length}}`;
}

function hexDigitRange(start: number, end: number): string {
  if (start === end) {
    return HEX_DIGITS[start];
  }

  const parts: string[] = [];
  let current = start;
  while (current <= end) {
    if (current <= 9) {
      const segmentEnd = Math.min(end, 9);
      parts.push(
        current === segmentEnd
          ? HEX_DIGITS[current]
          : `${HEX_DIGITS[current]}-${HEX_DIGITS[segmentEnd]}`,
      );
      current = segmentEnd + 1;
      continue;
    }

    const segmentEnd = Math.min(end, 15);
    parts.push(
      current === segmentEnd
        ? HEX_DIGITS[current]
        : `${HEX_DIGITS[current]}-${HEX_DIGITS[segmentEnd]}`,
    );
    current = segmentEnd + 1;
  }

  return `[${parts.join("")}]`;
}

function hexValue(char: string): number {
  const value = HEX_DIGITS.indexOf(char);
  if (value < 0) {
    throw new Error("Invalid hex digit");
  }
  return value;
}

function orPattern(parts: string[]): string {
  const unique = uniquePatterns(parts);
  if (unique.length === 0) {
    return "(?!)";
  }
  if (unique.length === 1) {
    return unique[0];
  }
  return `(?:${unique.join("|")})`;
}

function uniquePatterns(parts: string[]): string[] {
  return [...new Set(parts)];
}

function minimizePatternSet(patterns: string[], separator: string, segmentCount: number): string[] {
  if (patterns.length <= 1) {
    return patterns;
  }

  let rows = uniquePatternRows(
    patterns.map((pattern) => splitPattern(pattern, separator, segmentCount)),
  );

  let changed = true;
  while (changed) {
    changed = false;
    for (let index = 0; index < segmentCount; index += 1) {
      const grouped = new Map<string, { template: string[]; variants: string[] }>();

      for (const row of rows) {
        const keyParts = row.slice();
        keyParts[index] = "\u0000";
        const key = keyParts.join("\u0001");
        const existing = grouped.get(key);
        if (existing) {
          existing.variants.push(row[index]);
        } else {
          grouped.set(key, { template: row.slice(), variants: [row[index]] });
        }
      }

      const mergedRows: string[][] = [];
      for (const entry of grouped.values()) {
        const variants = uniquePatterns(entry.variants);
        const merged = variants.length === 1 ? variants[0] : orPattern(variants);
        if (variants.length > 1) {
          changed = true;
        }
        const next = entry.template.slice();
        next[index] = merged;
        mergedRows.push(next);
      }

      rows = uniquePatternRows(mergedRows);
    }
  }

  return rows.map((row) => row.join(separator));
}

function splitPattern(pattern: string, separator: string, segmentCount: number): string[] {
  const parts: string[] = [];
  let start = 0;
  let parenDepth = 0;
  let inCharClass = false;
  let escaped = false;

  for (let i = 0; i < pattern.length; i += 1) {
    if (!escaped && !inCharClass && parenDepth === 0 && pattern.startsWith(separator, i)) {
      parts.push(pattern.slice(start, i));
      i += separator.length - 1;
      start = i + 1;
      continue;
    }

    const char = pattern[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (inCharClass) {
      if (char === "]") {
        inCharClass = false;
      }
      continue;
    }
    if (char === "[") {
      inCharClass = true;
      continue;
    }
    if (char === "(") {
      parenDepth += 1;
      continue;
    }
    if (char === ")" && parenDepth > 0) {
      parenDepth -= 1;
    }
  }

  parts.push(pattern.slice(start));
  if (parts.length !== segmentCount) {
    throw new Error("Internal pattern split error");
  }
  return parts;
}

function uniquePatternRows(rows: string[][]): string[][] {
  const out = new Map<string, string[]>();
  for (const row of rows) {
    const key = row.join("\u0002");
    if (!out.has(key)) {
      out.set(key, row);
    }
  }
  return [...out.values()];
}
