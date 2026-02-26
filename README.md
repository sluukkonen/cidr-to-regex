# cidr-to-regex

Convert IPv4 and IPv6 CIDR blocks into regular expressions.

## Install

```bash
pnpm add cidr-to-regex
```

## Usage

```ts
import { cidrToRegex } from "cidr-to-regex";

const regexes = cidrToRegex("2001:db8::/48");
const ok = regexes.some((re) => re.test("2001:0db8:0000:0000:0000:0000:0000:0001"));
```

## API

### `cidrToRegex(cidr: string): RegExp[]`

- Accepts IPv4 and IPv6 CIDR input.
- CIDR parsing is liberal (for example compressed IPv6 like `::ff/16` is accepted).
- CIDR network bits are normalized (host bits in the input address are ignored).
- Returned regexes are full-string anchored.
- Output matching currently targets maximal address strings:
  - IPv4: exactly 4 dotted octets (`a.b.c.d`), leading zeros allowed.
  - IPv6: exactly 8 groups of 4 hex digits (no `::` output match).

## Development

```bash
pnpm install
pnpm run check
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
