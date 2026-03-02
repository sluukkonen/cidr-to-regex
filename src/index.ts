type ParsedCidr =
  | { family: "ipv4"; address: bigint; prefix: number }
  | { family: "ipv6"; address: bigint; prefix: number };

type IPv6HextetRange = { start: number; end: number };
type SegmentTrieNode = { children: Map<string, SegmentTrieNode> };

const IPV4_BITS = 32;
const IPV6_BITS = 128;
const IPV6_MINIMIZE_THRESHOLD = 80;
const IPV6_ANY_HEXTET = "[0-9a-f]{1,4}";
const IPV4_MAX = 0xffffffffn;
const IPV6_MAPPED_IPV4_START = 0xffffn << 32n;
const IPV6_MAPPED_IPV4_END = IPV6_MAPPED_IPV4_START | IPV4_MAX;

const IPV4_ANY_OCTET = "(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])";
const HEX_DIGITS = "0123456789abcdef";

export type CidrToRegexOptions = {
  anchored?: boolean;
  ignoreCase?: boolean;
  global?: boolean;
};

export function cidrToRegex(cidr: string, options?: CidrToRegexOptions): RegExp {
  const parsed = parseCidr(cidr);
  const { anchored = false, ignoreCase = false, global = false } = options ?? {};

  if (parsed.family === "ipv4") {
    const [start, end] = normalizeRange(parsed.address, IPV4_BITS, parsed.prefix);
    const startOctets = ipv4ToOctets(start);
    const endOctets = ipv4ToOctets(end);
    const patterns = minimizePatternSet(buildIPv4Patterns(startOctets, endOctets, 0), "\\.", 4);
    return buildRegex(patterns, "ipv4", anchored, global, false);
  }

  const [start, end] = normalizeRange(parsed.address, IPV6_BITS, parsed.prefix);
  const startHextets = ipv6ToHextets(start);
  const endHextets = ipv6ToHextets(end);
  const rawPatterns = buildIPv6TextPatterns(startHextets, endHextets);
  const ipv6Patterns =
    rawPatterns.length >= IPV6_MINIMIZE_THRESHOLD
      ? factorIPv6SegmentTrie(factorIPv6AnyHextetRuns(minimizeIPv6PatternSet(rawPatterns)))
      : rawPatterns;
  const mappedIPv4Patterns = buildIPv4MappedPatterns(start, end);
  if (mappedIPv4Patterns.length === 0) {
    return buildRegex(ipv6Patterns, "ipv6", anchored, global, ignoreCase);
  }

  return buildRegex(
    uniquePatterns([...ipv6Patterns, ...mappedIPv4Patterns]),
    "mixed",
    anchored,
    global,
    ignoreCase,
  );
}

function buildRegex(
  patterns: string[],
  family: "ipv4" | "ipv6" | "mixed",
  anchored: boolean,
  global: boolean,
  ignoreCase: boolean,
): RegExp {
  const core = orPattern(patterns);
  const boundaryClass =
    family === "ipv4" ? "[0-9.]" : family === "ipv6" ? "[0-9A-Fa-f:]" : "[0-9A-Fa-f:.]";
  const source = anchored ? `^${core}$` : `(?<!${boundaryClass})${core}(?!${boundaryClass})`;
  const flags = `${global ? "g" : ""}${ignoreCase ? "i" : ""}`;
  return new RegExp(source, flags);
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

function parseIPv4DottedQuad(text: string): bigint | null {
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

function parseIPv4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length === 0 || parts.length > 4) {
    return null;
  }

  if (parts.length === 4) {
    return parseIPv4DottedQuad(text);
  }

  if (parts.length === 1) {
    const value = parseUintDecimal(parts[0], 0xffffffff);
    return value === null ? null : BigInt(value);
  }

  if (parts.length === 2) {
    const first = parseUintDecimal(parts[0], 255);
    const rest = parseUintDecimal(parts[1], 0xffffff);
    if (first === null || rest === null) {
      return null;
    }
    return (BigInt(first) << 24n) | BigInt(rest);
  }

  const first = parseUintDecimal(parts[0], 255);
  const second = parseUintDecimal(parts[1], 255);
  const rest = parseUintDecimal(parts[2], 0xffff);
  if (first === null || second === null || rest === null) {
    return null;
  }
  return (BigInt(first) << 24n) | (BigInt(second) << 16n) | BigInt(rest);
}

function parseByte(part: string): number | null {
  return parseUintDecimal(part, 255);
}

function parseUintDecimal(part: string, max: number): number | null {
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
    if (value > max) {
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

  const firstDoubleColon = normalized.indexOf("::");
  if (firstDoubleColon >= 0 && normalized.indexOf("::", firstDoubleColon + 1) >= 0) {
    return null;
  }

  const hasCompression = firstDoubleColon >= 0;
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

  const ipv4 = parseIPv4DottedQuad(ipv4Part);
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

function buildIPv6TextPatterns(start: number[], end: number[]): string[] {
  const row: IPv6HextetRange[] = [];
  for (let i = 0; i < 8; i += 1) {
    row.push({ start: start[i], end: end[i] });
  }
  return uniquePatterns(expandIPv6RowPatterns(row));
}

function buildIPv4MappedPatterns(start: bigint, end: bigint): string[] {
  const overlapStart = start > IPV6_MAPPED_IPV4_START ? start : IPV6_MAPPED_IPV4_START;
  const overlapEnd = end < IPV6_MAPPED_IPV4_END ? end : IPV6_MAPPED_IPV4_END;
  if (overlapStart > overlapEnd) {
    return [];
  }

  const ipv4Start = overlapStart - IPV6_MAPPED_IPV4_START;
  const ipv4End = overlapEnd - IPV6_MAPPED_IPV4_START;
  const startOctets = ipv4ToOctets(ipv4Start);
  const endOctets = ipv4ToOctets(ipv4End);
  return minimizePatternSet(buildIPv4Patterns(startOctets, endOctets, 0), "\\.", 4);
}

function expandIPv6RowPatterns(row: IPv6HextetRange[]): string[] {
  const hextetPatterns = row.map((part) => hextetTextPattern(part.start, part.end));
  const patterns = [hextetPatterns.join(":")];

  for (let runStart = 0; runStart < 8; runStart += 1) {
    if (row[runStart].start !== 0) {
      continue;
    }
    if (runStart > 0 && isGuaranteedZeroIPv6RangePart(row[runStart - 1])) {
      continue;
    }

    let maxRunEnd = runStart;
    while (maxRunEnd + 1 < 8 && row[maxRunEnd + 1].start === 0) {
      maxRunEnd += 1;
    }

    const minRunEnd = runStart + 1; // RFC 5952: do not compress a single 0 field.
    if (maxRunEnd < minRunEnd) {
      continue;
    }

    const left = hextetPatterns.slice(0, runStart).join(":");
    const rights: string[] = [];
    for (let runEnd = minRunEnd; runEnd <= maxRunEnd; runEnd += 1) {
      if (runEnd < 7 && isGuaranteedZeroIPv6RangePart(row[runEnd + 1])) {
        continue;
      }
      rights.push(hextetPatterns.slice(runEnd + 1).join(":"));
    }
    if (rights.length === 0) {
      continue;
    }
    patterns.push(buildIPv6CompressionPattern(left, rights));
  }

  return uniquePatterns(patterns);
}

function isGuaranteedZeroIPv6RangePart(part: IPv6HextetRange): boolean {
  return part.start === 0 && part.end === 0;
}

function buildIPv6CompressionPattern(left: string, rights: string[]): string {
  const uniqueRights = uniquePatterns(rights);
  const prefix = left.length === 0 ? "::" : `${left}::`;

  if (uniqueRights.length === 1) {
    return `${prefix}${uniqueRights[0]}`;
  }

  let hasEmpty = false;
  const nonEmpty: string[] = [];
  for (const right of uniqueRights) {
    if (right.length === 0) {
      hasEmpty = true;
    } else {
      nonEmpty.push(right);
    }
  }

  if (nonEmpty.length === 0) {
    return prefix;
  }

  let rightPattern = orPattern(nonEmpty);
  if (hasEmpty) {
    rightPattern = `(?:${rightPattern})?`;
  }
  return `${prefix}${rightPattern}`;
}

function hextetTextPattern(start: number, end: number): string {
  if (start === 0 && end === 0xffff) {
    return "[0-9a-f]{1,4}";
  }

  if ((start & 0x0fff) === 0 && (end & 0x0fff) === 0x0fff) {
    const upperStart = start >> 12;
    const upperEnd = end >> 12;
    const upperPattern = `${hexDigitRange(upperStart, upperEnd)}[0-9a-f]{3}`;
    if (upperStart === 0) {
      return `${hexDigitRange(0, upperEnd)}?[0-9a-f]{1,3}`;
    }
    return upperPattern;
  }

  if (start === 0 && end <= 0x0fff && (end & 0x00ff) === 0x00ff) {
    const upper = end >> 8;
    return `0?${hexDigitRange(0, upper)}?[0-9a-f]{1,2}`;
  }

  if (start === 0 && end <= 0xff && (end & 0x000f) === 0x000f) {
    const upper = end >> 4;
    return `0{0,2}${hexDigitRange(0, upper)}?[0-9a-f]`;
  }

  if (start === 0 && end <= 0x0fff) {
    if (end <= 0x0f) {
      return `0{0,3}${hexDigitRange(0, end)}`;
    }
    if (end <= 0xff) {
      const twoDigit = orPattern(hexRangeParts("00", end.toString(16).padStart(2, "0")));
      return orPattern(["[0-9a-f]", `0{0,2}${twoDigit}`]);
    }
    const threeDigit = orPattern(hexRangeParts("000", end.toString(16).padStart(3, "0")));
    return orPattern(["[0-9a-f]{1,2}", `0?${threeDigit}`]);
  }

  const parts: string[] = [];
  for (let width = 1; width <= 4; width += 1) {
    const max = (1 << (width * 4)) - 1;
    if (start > max) {
      continue;
    }
    const low = start.toString(16).padStart(width, "0");
    const high = Math.min(end, max).toString(16).padStart(width, "0");
    parts.push(orPattern(hexRangeParts(low, high)));
  }

  return orPattern(parts);
}

function minimizeIPv6PatternSet(patterns: string[]): string[] {
  const grouped = new Map<number, string[]>();
  for (const pattern of uniquePatterns(patterns)) {
    const segmentCount = countTopLevelSegments(pattern, ":");
    const existing = grouped.get(segmentCount);
    if (existing) {
      existing.push(pattern);
    } else {
      grouped.set(segmentCount, [pattern]);
    }
  }

  const minimized: string[] = [];
  for (const [segmentCount, segmentPatterns] of grouped.entries()) {
    minimized.push(...minimizePatternSetOnePass(segmentPatterns, ":", segmentCount));
  }
  return uniquePatterns(minimized);
}

function minimizePatternSetOnePass(
  patterns: string[],
  separator: string,
  segmentCount: number,
): string[] {
  if (patterns.length <= 1) {
    return patterns;
  }

  let rows = uniquePatternRows(
    patterns.map((pattern) => splitPattern(pattern, separator, segmentCount)),
  );

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
      const next = entry.template.slice();
      next[index] = merged;
      mergedRows.push(next);
    }

    rows = uniquePatternRows(mergedRows);
  }

  return rows.map((row) => row.join(separator));
}

function factorIPv6AnyHextetRuns(patterns: string[]): string[] {
  return uniquePatterns(patterns.map((pattern) => factorIPv6AnyHextetRunsInPattern(pattern)));
}

function factorIPv6AnyHextetRunsInPattern(pattern: string): string {
  const segments = pattern.split(":");
  const out: string[] = [];

  let index = 0;
  while (index < segments.length) {
    if (segments[index] !== IPV6_ANY_HEXTET) {
      out.push(segments[index]);
      index += 1;
      continue;
    }

    let end = index + 1;
    while (end < segments.length && segments[end] === IPV6_ANY_HEXTET) {
      end += 1;
    }
    const runLength = end - index;
    if (runLength === 1) {
      out.push(IPV6_ANY_HEXTET);
    } else {
      out.push(`${IPV6_ANY_HEXTET}(?::${IPV6_ANY_HEXTET}){${runLength - 1}}`);
    }
    index = end;
  }

  return out.join(":");
}

function factorIPv6SegmentTrie(patterns: string[]): string[] {
  if (patterns.length <= 1) {
    return patterns;
  }

  const grouped = new Map<number, string[]>();
  for (const pattern of uniquePatterns(patterns)) {
    const segmentCount = countTopLevelSegments(pattern, ":");
    const existing = grouped.get(segmentCount);
    if (existing) {
      existing.push(pattern);
    } else {
      grouped.set(segmentCount, [pattern]);
    }
  }

  const factored: string[] = [];
  for (const [segmentCount, groupPatterns] of grouped.entries()) {
    factored.push(...factorPatternSegmentTrie(groupPatterns, ":", segmentCount));
  }

  return uniquePatterns(factored);
}

function factorPatternSegmentTrie(
  patterns: string[],
  separator: string,
  segmentCount: number,
): string[] {
  if (patterns.length <= 1) {
    return patterns;
  }

  const root = createSegmentTrieNode();
  for (const pattern of patterns) {
    insertTrieSegments(root, splitPattern(pattern, separator, segmentCount));
  }

  const emitted = emitTriePattern(root, 0, segmentCount, separator);
  const flat = orPattern(patterns);
  return [emitted.length < flat.length ? emitted : flat];
}

function createSegmentTrieNode(): SegmentTrieNode {
  return { children: new Map<string, SegmentTrieNode>() };
}

function insertTrieSegments(root: SegmentTrieNode, segments: string[]): void {
  let node = root;
  for (const segment of segments) {
    let next = node.children.get(segment);
    if (!next) {
      next = createSegmentTrieNode();
      node.children.set(segment, next);
    }
    node = next;
  }
}

function emitTriePattern(
  node: SegmentTrieNode,
  depth: number,
  segmentCount: number,
  separator: string,
): string {
  if (depth >= segmentCount) {
    return "";
  }

  const parts: string[] = [];
  for (const [segment, child] of node.children.entries()) {
    const suffix = emitTriePattern(child, depth + 1, segmentCount, separator);
    parts.push(suffix.length === 0 ? segment : `${segment}${separator}${suffix}`);
  }
  return orPattern(parts);
}

function countTopLevelSegments(pattern: string, separator: string): number {
  let segments = 1;
  let parenDepth = 0;
  let inCharClass = false;
  let escaped = false;

  for (let i = 0; i < pattern.length; i += 1) {
    if (!escaped && !inCharClass && parenDepth === 0 && pattern.startsWith(separator, i)) {
      segments += 1;
      i += separator.length - 1;
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

  return segments;
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

function octetRangePattern(start: number, end: number): string {
  if (start === 0 && end === 255) {
    return IPV4_ANY_OCTET;
  }
  if (start === end) {
    return String(start);
  }

  const parts: string[] = [];
  for (let value = start; value <= end; value += 1) {
    parts.push(String(value));
  }
  return orPattern(parts);
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
  if (parts.length === 0) {
    return "(?!)";
  }
  const unique = uniquePatterns(parts);
  if (unique.length === 1) {
    return unique[0];
  }
  return `(?:${unique.join("|")})`;
}

function uniquePatterns(parts: string[]): string[] {
  if (parts.length <= 1) {
    return parts.slice();
  }
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
  if (rows.length <= 1) {
    return rows.slice();
  }
  const out = new Map<string, string[]>();
  for (const row of rows) {
    const key = row.join("\u0002");
    if (!out.has(key)) {
      out.set(key, row);
    }
  }
  return [...out.values()];
}
