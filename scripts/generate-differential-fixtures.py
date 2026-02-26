#!/usr/bin/env python3
"""Generate deterministic differential test fixtures using ipaddress."""

from __future__ import annotations

import ipaddress
import json
import random
from pathlib import Path

SEED = 104729
IPV4_CASES = 80
IPV6_CASES = 80
SAMPLES_PER_CASE = 14


def append_unique(items: list[int], value: int) -> None:
    if value not in items:
        items.append(value)


def padded_ipv4(value: int, rng: random.Random) -> str:
    parts = str(ipaddress.IPv4Address(value)).split(".")
    return ".".join(part.zfill(rng.randint(1, 3)) for part in parts)


def mixed_ipv6_with_embedded_ipv4(value: int) -> str:
    exploded = ipaddress.IPv6Address(value).exploded.split(":")
    last32 = (int(exploded[6], 16) << 16) | int(exploded[7], 16)
    return f"{':'.join(exploded[:6])}:{ipaddress.IPv4Address(last32)}"


def pick_ipv6_input(value: int, rng: random.Random) -> str:
    addr = ipaddress.IPv6Address(value)
    options = [str(addr), addr.exploded, str(addr).upper()]
    if rng.random() < 0.25:
        options.append(mixed_ipv6_with_embedded_ipv4(value))
    return options[rng.randrange(len(options))]


def ipv4_case(rng: random.Random) -> dict:
    max_addr = (1 << 32) - 1
    raw = rng.randrange(max_addr + 1)
    prefix = rng.randrange(33)
    network = ipaddress.ip_network(f"{ipaddress.IPv4Address(raw)}/{prefix}", strict=False)
    start = int(network.network_address)
    end = int(network.broadcast_address)

    samples: list[int] = []
    append_unique(samples, start)
    append_unique(samples, end)
    if start > 0:
        append_unique(samples, start - 1)
    if end < max_addr:
        append_unique(samples, end + 1)
    while len(samples) < SAMPLES_PER_CASE:
        append_unique(samples, rng.randrange(max_addr + 1))

    return {
        "cidr": f"{padded_ipv4(raw, rng)}/{prefix}",
        "normalized": str(network),
        "samples": [
            {
                "addr": str(ipaddress.IPv4Address(value)),
                "padded": padded_ipv4(value, rng),
                "expected": start <= value <= end,
            }
            for value in samples
        ],
    }


def ipv6_case(rng: random.Random) -> dict:
    max_addr = (1 << 128) - 1
    raw = rng.randrange(max_addr + 1)
    prefix = rng.randrange(129)
    network = ipaddress.ip_network(f"{ipaddress.IPv6Address(raw)}/{prefix}", strict=False)
    start = int(network.network_address)
    end = int(network.broadcast_address)

    samples: list[int] = []
    append_unique(samples, start)
    append_unique(samples, end)
    if start > 0:
        append_unique(samples, start - 1)
    if end < max_addr:
        append_unique(samples, end + 1)
    while len(samples) < SAMPLES_PER_CASE:
        append_unique(samples, rng.randrange(max_addr + 1))

    return {
        "cidr": f"{pick_ipv6_input(raw, rng)}/{prefix}",
        "normalized": f"{network.network_address.exploded}/{network.prefixlen}",
        "samples": [
            {
                "addr": ipaddress.IPv6Address(value).exploded,
                "upper": ipaddress.IPv6Address(value).exploded.upper(),
                "expected": start <= value <= end,
            }
            for value in samples
        ],
    }


def main() -> None:
    rng = random.Random(SEED)
    payload = {
        "meta": {
            "seed": SEED,
            "ipv4Cases": IPV4_CASES,
            "ipv6Cases": IPV6_CASES,
            "samplesPerCase": SAMPLES_PER_CASE,
        },
        "ipv4": [ipv4_case(rng) for _ in range(IPV4_CASES)],
        "ipv6": [ipv6_case(rng) for _ in range(IPV6_CASES)],
    }

    out_path = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "differential-samples.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
