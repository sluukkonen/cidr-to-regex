#!/usr/bin/env python3
"""Generate deterministic CIDR test fixtures for IPv4 and IPv6."""

from __future__ import annotations

import ipaddress
import json
import random
from dataclasses import dataclass
from pathlib import Path

SEED = 1729
INSIDE_COUNT = 6
OUTSIDE_COUNT = 6


@dataclass
class FixtureCase:
    cidr: str
    normalized: str
    inside: list[str]
    outside: list[str]


def ipv4_str(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def ipv6_str(value: int) -> str:
    return ipaddress.IPv6Address(value).exploded


def unique_stable(values: list[str]) -> list[str]:
    seen = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def pick_inside(
    rng: random.Random,
    start: int,
    end: int,
    to_str,
    desired_count: int,
) -> list[str]:
    picks = [to_str(start), to_str(end)]
    span = end - start + 1
    if span > 1:
        for _ in range(desired_count * 3):
            offset = rng.randrange(span)
            picks.append(to_str(start + offset))
    return unique_stable(picks)[:desired_count]


def pick_outside(
    rng: random.Random,
    start: int,
    end: int,
    maximum: int,
    to_str,
    desired_count: int,
) -> list[str]:
    picks: list[str] = []
    if start > 0:
        picks.append(to_str(start - 1))
    if end < maximum:
        picks.append(to_str(end + 1))

    while len(unique_stable(picks)) < desired_count:
        candidate = rng.randrange(maximum + 1)
        if candidate < start or candidate > end:
            picks.append(to_str(candidate))
        if end - start == maximum:
            break

    return unique_stable(picks)[:desired_count]


def build_ipv4_cases(rng: random.Random) -> list[FixtureCase]:
    prefixes = [0, 1, 2, 7, 8, 9, 15, 16, 17, 23, 24, 25, 30, 31, 32]
    max_addr = (1 << 32) - 1
    cases: list[FixtureCase] = []
    for prefix in prefixes:
        for _ in range(3):
            raw = rng.randrange(max_addr + 1)
            cidr = f"{ipv4_str(raw)}/{prefix}"
            network = ipaddress.ip_network(cidr, strict=False)
            start = int(network.network_address)
            end = int(network.broadcast_address)
            inside = pick_inside(rng, start, end, ipv4_str, INSIDE_COUNT)
            outside = pick_outside(rng, start, end, max_addr, ipv4_str, OUTSIDE_COUNT)
            cases.append(
                FixtureCase(
                    cidr=cidr,
                    normalized=str(network),
                    inside=inside,
                    outside=outside,
                )
            )
    return cases


def build_ipv6_cases(rng: random.Random) -> list[FixtureCase]:
    prefixes = [
        0,
        1,
        15,
        16,
        17,
        31,
        32,
        33,
        47,
        48,
        49,
        63,
        64,
        65,
        79,
        80,
        81,
        95,
        96,
        97,
        111,
        112,
        113,
        127,
        128,
    ]
    max_addr = (1 << 128) - 1
    cases: list[FixtureCase] = []
    for prefix in prefixes:
        for _ in range(2):
            raw = rng.randrange(max_addr + 1)
            cidr = f"{ipv6_str(raw)}/{prefix}"
            network = ipaddress.ip_network(cidr, strict=False)
            start = int(network.network_address)
            end = int(network.broadcast_address)
            inside = pick_inside(rng, start, end, ipv6_str, INSIDE_COUNT)
            outside = pick_outside(rng, start, end, max_addr, ipv6_str, OUTSIDE_COUNT)
            cases.append(
                FixtureCase(
                    cidr=cidr,
                    normalized=f"{network.network_address.exploded}/{network.prefixlen}",
                    inside=inside,
                    outside=outside,
                )
            )
    return cases


def main() -> None:
    rng = random.Random(SEED)
    data = {
        "meta": {"seed": SEED},
        "ipv4": [case.__dict__ for case in build_ipv4_cases(rng)],
        "ipv6": [case.__dict__ for case in build_ipv6_cases(rng)],
    }
    out_path = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "cidr-samples.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
