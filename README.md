# cidr-to-regex

Convert IPv4 and IPv6 CIDR blocks into regular expressions.

## Install

```bash
pnpm add cidr-to-regex
```

## Usage

```ts
import { cidrToRegex } from "cidr-to-regex";

const regex = cidrToRegex("2001:db8::/48");
const ok = regex.test("2001:0db8:0000:0000:0000:0000:0000:0001");
```

## API

### `cidrToRegex(cidr: string, options?: CidrToRegexOptions): RegExp`

```ts
type CidrToRegexOptions = {
  anchored?: boolean; // default false
  ignoreCase?: boolean; // default false
  global?: boolean; // default false
};
```

- Accepts IPv4 and IPv6 CIDR input.
- CIDR parsing is liberal (for example compressed IPv6 like `::ff/16` is accepted).
- CIDR network bits are normalized (host bits in the input address are ignored).
- By default, returned regex is not full-string anchored.
- `options.anchored` controls whether `^...$` anchors are included.
- `options.ignoreCase` enables case-insensitive IPv6 matching (adds `i` flag).
- `options.global` adds the `g` flag to the returned regex.
- Output matching currently targets maximal address strings:
  - IPv4: exactly 4 dotted octets (`a.b.c.d`), no leading zeros.
  - IPv6: exactly 8 groups of 4 hex digits (no `::` output match).

## Compatibility

- Node.js: `>=14`
- Browser compatibility with default options (`anchored: false`):
  - Chrome `67+`
  - Firefox `78+`
  - Safari `16.4+`
- Browser compatibility with `anchored: true` (no regex lookbehind requirement):
  - Chrome `67+`
  - Firefox `68+`
  - Safari `14+`

## Development

```bash
pnpm install
pnpm run check
```

Linting and formatting:

```bash
pnpm run lint
pnpm run lint:fix
pnpm run format
pnpm run format:check
```

### Fixture generation

```bash
pnpm run generate:fixtures
pnpm run generate:differential-fixtures
```

These scripts use Python's `ipaddress` module to generate deterministic test fixtures. The generated fixtures are committed; test execution itself is pure TypeScript.

### Benchmark

```bash
pnpm run bench
```

Optional environment variables:

- `BENCH_ITERS` (default `5000`)
- `BENCH_WARMUP` (default `300`)
