#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

DNS_TYPE_A = 1
DNS_TYPE_SOA = 6
DNS_CLASS_IN = 1
FLAG_QR_AA_RD_RA = 0x8580
FLAG_RD = 0x0100
DNS_HEADER_SIZE = 12


@dataclass(frozen=True)
class CacheHitVector:
    name: str
    stored_response: bytes
    query: bytes
    question_offset: int
    question_size: int
    ttl_offsets: tuple[int, ...]
    stored_at_ns: int
    hit_at_ns: int
    lifetime_seconds: int
    expected_response: bytes | None


def dns_name(text: str) -> bytes:
    encoded = bytearray()
    for label in text.rstrip(".").split("."):
        label_bytes = label.encode("ascii")
        if not 0 < len(label_bytes) <= 63:
            raise ValueError(f"invalid DNS label length in {text!r}")
        encoded.append(len(label_bytes))
        encoded.extend(label_bytes)
    encoded.append(0)
    if len(encoded) > 255:
        raise ValueError(f"DNS name exceeds 255 bytes: {text!r}")
    return bytes(encoded)


def header(transaction_id: int, flags: int, answers: int, authorities: int = 0) -> bytes:
    return struct.pack("!HHHHHH", transaction_id, flags, 1, answers, authorities, 0)


def question(name_wire: bytes) -> bytes:
    return name_wire + struct.pack("!HH", DNS_TYPE_A, DNS_CLASS_IN)


def resource_record(owner: bytes, rr_type: int, ttl: int, rdata: bytes) -> bytes:
    return owner + struct.pack("!HHIH", rr_type, DNS_CLASS_IN, ttl, len(rdata)) + rdata


def soa_rdata() -> bytes:
    return b"".join(
        (
            dns_name("ns.example.com"),
            dns_name("hostmaster.example.com"),
            struct.pack("!IIIII", 1, 3600, 600, 86400, 30),
        )
    )


def response_template(
    *,
    transaction_id: int,
    question_name: bytes,
    answer_ttl: int,
    answer_address: bytes,
    authority_ttl: int | None = None,
) -> tuple[bytes, tuple[int, ...]]:
    owner = b"\xc0\x0c"
    question_wire = question(question_name)
    answer = resource_record(owner, DNS_TYPE_A, answer_ttl, answer_address)
    authorities = 1 if authority_ttl is not None else 0
    message = bytearray(header(transaction_id, FLAG_QR_AA_RD_RA, 1, authorities) + question_wire + answer)
    ttl_offsets = [DNS_HEADER_SIZE + len(question_wire) + len(owner) + 4]
    if authority_ttl is not None:
        authority_start = len(message)
        message.extend(resource_record(owner, DNS_TYPE_SOA, authority_ttl, soa_rdata()))
        ttl_offsets.append(authority_start + len(owner) + 4)
    return bytes(message), tuple(ttl_offsets)


def query_message(transaction_id: int, question_name: bytes) -> bytes:
    return header(transaction_id, FLAG_RD, 0) + question(question_name)


def apply_expected_hit(
    stored_response: bytes,
    query: bytes,
    question_offset: int,
    question_size: int,
    ttl_offsets: tuple[int, ...],
    elapsed_ns: int,
) -> bytes:
    result = bytearray(stored_response)
    result[0:2] = query[0:2]
    result[question_offset : question_offset + question_size] = query[
        question_offset : question_offset + question_size
    ]
    for offset in ttl_offsets:
        original_ttl = struct.unpack_from("!I", stored_response, offset)[0]
        remaining_ns = original_ttl * 1_000_000_000 - elapsed_ns
        remaining_ttl = max(0, remaining_ns // 1_000_000_000)
        struct.pack_into("!I", result, offset, remaining_ttl)
    return bytes(result)


def generate_vectors() -> list[CacheHitVector]:
    stored_question = dns_name("example.com")
    current_question = dns_name("ExaMPlE.coM")
    question_size = len(question(stored_question))
    base_response, base_offsets = response_template(
        transaction_id=0x1234,
        question_name=stored_question,
        answer_ttl=300,
        answer_address=bytes((1, 2, 3, 4)),
    )
    base_query = query_message(0xBEEF, current_question)

    multi_response, multi_offsets = response_template(
        transaction_id=0x4321,
        question_name=stored_question,
        answer_ttl=120,
        answer_address=bytes((5, 6, 7, 8)),
        authority_ttl=60,
    )
    multi_query = query_message(0xCAFE, dns_name("EXAMPLE.coM"))

    vectors = [
        CacheHitVector(
            "sub-second residence rounds remaining TTL down",
            base_response,
            base_query,
            DNS_HEADER_SIZE,
            question_size,
            base_offsets,
            0,
            500_000_000,
            300,
            apply_expected_hit(base_response, base_query, DNS_HEADER_SIZE, question_size, base_offsets, 500_000_000),
        ),
        CacheHitVector(
            "entry remains hittable immediately before expiry",
            base_response,
            base_query,
            DNS_HEADER_SIZE,
            question_size,
            base_offsets,
            0,
            299_999_999_999,
            300,
            apply_expected_hit(
                base_response,
                base_query,
                DNS_HEADER_SIZE,
                question_size,
                base_offsets,
                299_999_999_999,
            ),
        ),
        CacheHitVector(
            "entry misses exactly at expiry",
            base_response,
            base_query,
            DNS_HEADER_SIZE,
            question_size,
            base_offsets,
            0,
            300_000_000_000,
            300,
            None,
        ),
        CacheHitVector(
            "all RR TTLs age and the current question is echoed",
            multi_response,
            multi_query,
            DNS_HEADER_SIZE,
            question_size,
            multi_offsets,
            1_000_000_000,
            2_250_000_000,
            60,
            apply_expected_hit(
                multi_response,
                multi_query,
                DNS_HEADER_SIZE,
                question_size,
                multi_offsets,
                1_250_000_000,
            ),
        ),
    ]
    validate_vectors(vectors)
    return vectors


def validate_vectors(vectors: list[CacheHitVector]) -> None:
    if len(vectors) != 4:
        raise ValueError(f"expected four Cache Hit vectors, got {len(vectors)}")
    if len({vector.name for vector in vectors}) != len(vectors):
        raise ValueError("Cache Hit vector names must be unique")

    for vector in vectors:
        if len(vector.stored_response) > 512 or len(vector.query) > 512:
            raise ValueError(f"{vector.name}: DNS message exceeds 512 bytes")
        if vector.question_offset != DNS_HEADER_SIZE:
            raise ValueError(f"{vector.name}: unexpected Question offset")
        for offset in vector.ttl_offsets:
            if offset + 4 > len(vector.stored_response):
                raise ValueError(f"{vector.name}: TTL offset is out of range")


def render_toml(vectors: list[CacheHitVector]) -> str:
    lines = [
        "# Generated by tests/vectors/cache_hit/generate.py. Do not edit.",
        "format_version = 1",
        'generator = "tests/vectors/cache_hit/generate.py"',
        "",
    ]
    for vector in vectors:
        lines.extend(
            (
                "[[vectors]]",
                f"name = {json.dumps(vector.name)}",
                f'stored_response_hex = "{vector.stored_response.hex()}"',
                f'query_hex = "{vector.query.hex()}"',
                f"question_offset = {vector.question_offset}",
                f"question_size = {vector.question_size}",
                f"ttl_offsets = {list(vector.ttl_offsets)}",
                f"stored_at_ns = {vector.stored_at_ns}",
                f"hit_at_ns = {vector.hit_at_ns}",
                f"lifetime_seconds = {vector.lifetime_seconds}",
                f"expected_hit = {'true' if vector.expected_response is not None else 'false'}",
            )
        )
        if vector.expected_response is not None:
            lines.append(f'expected_response_hex = "{vector.expected_response.hex()}"')
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} OUTPUT", file=sys.stderr)
        return 2

    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_toml(generate_vectors()), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
