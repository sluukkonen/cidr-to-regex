import { performance } from "node:perf_hooks";
import { cidrToRegex } from "../dist/index.js";

const ITERATIONS = Number.parseInt(process.env.BENCH_ITERS ?? "5000", 10);
const WARMUP = Number.parseInt(process.env.BENCH_WARMUP ?? "300", 10);

const CASES = [
  "0.0.0.0/0",
  "10.0.0.0/8",
  "10.0.0.0/16",
  "10.0.0.0/24",
  "10.0.0.1/32",
  "010.000.000.001/24",
  "::/0",
  "::/1",
  "2001:db8::/32",
  "2001:db8::/48",
  "2001:db8::/64",
  "2001:db8::1/128",
  "::ffff:192.0.2.1/112",
];

function percentile(sorted, p) {
  if (sorted.length === 0) {
    return 0;
  }
  const index = Math.min(sorted.length - 1, Math.floor(sorted.length * p));
  return sorted[index];
}

function benchmarkCase(cidr) {
  for (let i = 0; i < WARMUP; i += 1) {
    cidrToRegex(cidr);
  }

  const samples = [];
  let regexCount = 0;

  for (let i = 0; i < ITERATIONS; i += 1) {
    const start = performance.now();
    const regexes = cidrToRegex(cidr);
    const elapsedMicros = (performance.now() - start) * 1000;
    samples.push(elapsedMicros);
    regexCount = regexes.length;
  }

  samples.sort((a, b) => a - b);
  const total = samples.reduce((sum, value) => sum + value, 0);

  return {
    cidr,
    regexes: regexCount,
    avg_us: Number((total / samples.length).toFixed(2)),
    p50_us: Number(percentile(samples, 0.5).toFixed(2)),
    p95_us: Number(percentile(samples, 0.95).toFixed(2)),
    max_us: Number(samples[samples.length - 1].toFixed(2)),
  };
}

function main() {
  if (!Number.isFinite(ITERATIONS) || ITERATIONS <= 0) {
    throw new Error("BENCH_ITERS must be a positive integer");
  }
  if (!Number.isFinite(WARMUP) || WARMUP < 0) {
    throw new Error("BENCH_WARMUP must be a non-negative integer");
  }

  const started = performance.now();
  const rows = CASES.map(benchmarkCase);
  const totalMs = performance.now() - started;

  console.log("cidr-to-regex benchmark");
  console.log(`iterations=${ITERATIONS}, warmup=${WARMUP}, total=${totalMs.toFixed(1)}ms`);
  console.table(rows);
}

main();
