#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_TYPE_NS = 2
DNS_TYPE_OPT = 41
DNS_CLASS_IN = 1
DNS_CLASS_CH = 3

FLAG_QR = 0x8000
FLAG_OPCODE_STATUS = 0x0800
FLAG_RD = 0x0100
FLAG_AD = 0x0020
FLAG_CD = 0x0010


@dataclass(frozen=True)
class QuestionFact:
    name_wire: bytes
    qtype: int
    qclass: int


@dataclass(frozen=True)
class Vector:
    name: str
    condition: str
    message: bytes
    eligible: bool = False
    question: QuestionFact | None = None


def dns_name(text: str) -> bytes:
    if text in ("", "."):
        return b"\x00"

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


def header(flags: int, questions: int, answers: int = 0, authorities: int = 0, additional: int = 0) -> bytes:
    return struct.pack("!HHHHHH", 0x1234, flags, questions, answers, authorities, additional)


def question(name_wire: bytes, qtype: int = DNS_TYPE_A, qclass: int = DNS_CLASS_IN) -> bytes:
    return name_wire + struct.pack("!HH", qtype, qclass)


def resource_record(owner: bytes, rr_type: int, rr_class: int, ttl: int, rdata: bytes) -> bytes:
    return owner + struct.pack("!HHIH", rr_type, rr_class, ttl, len(rdata)) + rdata


def query_message(
    *,
    flags: int = FLAG_RD,
    name_wire: bytes,
    qtype: int = DNS_TYPE_A,
    qclass: int = DNS_CLASS_IN,
    answers: tuple[bytes, ...] = (),
    authorities: tuple[bytes, ...] = (),
    additional: tuple[bytes, ...] = (),
) -> bytes:
    return b"".join(
        (
            header(flags, 1, len(answers), len(authorities), len(additional)),
            question(name_wire, qtype, qclass),
            *answers,
            *authorities,
            *additional,
        )
    )


def opt_record(*, ttl: int = 0, rdata: bytes = b"") -> bytes:
    return resource_record(dns_name("."), DNS_TYPE_OPT, 1232, ttl, rdata)


def generate_vectors() -> list[Vector]:
    qname = dns_name("www.example")
    pointer_owner = b"\xc0\x0c"
    answer = resource_record(pointer_owner, DNS_TYPE_A, DNS_CLASS_IN, 30, bytes((1, 2, 3, 4)))
    authority = resource_record(
        pointer_owner,
        DNS_TYPE_NS,
        DNS_CLASS_IN,
        30,
        dns_name("ns.example"),
    )
    ecs = struct.pack("!HHHBB", 8, 7, 1, 24, 0) + bytes((192, 0, 2))

    vectors = [
        Vector(
            "uncompressed recursive A IN Query",
            "baseline",
            query_message(name_wire=qname),
            eligible=True,
            question=QuestionFact(qname, DNS_TYPE_A, DNS_CLASS_IN),
        ),
        Vector("QR marks a Response", "qr", query_message(flags=FLAG_QR | FLAG_RD, name_wire=qname)),
        Vector("non-QUERY opcode", "opcode", query_message(flags=FLAG_OPCODE_STATUS | FLAG_RD, name_wire=qname)),
        Vector("zero Questions", "qdcount_zero", header(FLAG_RD, 0)),
        Vector(
            "multiple Questions",
            "qdcount_multiple",
            header(FLAG_RD, 2) + question(qname) + question(dns_name("x.example")),
        ),
        Vector("Query with an Answer Section", "ancount", query_message(name_wire=qname, answers=(answer,))),
        Vector(
            "Query with an Authority Section",
            "nscount",
            query_message(name_wire=qname, authorities=(authority,)),
        ),
        Vector("RD is clear", "rd", query_message(flags=0, name_wire=qname)),
        Vector("CD is set", "cd", query_message(flags=FLAG_RD | FLAG_CD, name_wire=qname)),
        Vector("Query AD is set", "ad", query_message(flags=FLAG_RD | FLAG_AD, name_wire=qname)),
        Vector("AAAA Question", "qtype", query_message(name_wire=qname, qtype=DNS_TYPE_AAAA)),
        Vector("non-IN Question", "qclass", query_message(name_wire=qname, qclass=DNS_CLASS_CH)),
        Vector("EDNS OPT Additional Section", "edns", query_message(name_wire=qname, additional=(opt_record(),))),
        Vector(
            "EDNS DO signaling",
            "dnssec_do",
            query_message(name_wire=qname, additional=(opt_record(ttl=0x00008000),)),
        ),
        Vector(
            "EDNS Client Subnet option",
            "ecs",
            query_message(name_wire=qname, additional=(opt_record(rdata=ecs),)),
        ),
        Vector("compressed Question name", "compressed_qname", header(FLAG_RD, 1) + question(b"\xc0\x0c")),
        Vector("reserved QNAME label prefix", "reserved_label", header(FLAG_RD, 1) + question(b"\x40")),
        Vector("truncated QNAME label", "qname_truncated", header(FLAG_RD, 1) + b"\x03ww"),
        Vector(
            "truncated Question type and class",
            "question_fields_truncated",
            header(FLAG_RD, 1) + qname + b"\x00",
        ),
    ]
    validate_vectors(vectors)
    return vectors


def validate_vectors(vectors: list[Vector]) -> None:
    if len(vectors) != 19:
        raise ValueError(f"expected 19 vectors, got {len(vectors)}")
    if len({vector.condition for vector in vectors}) != len(vectors):
        raise ValueError("vector conditions must be unique")
    if len({vector.message for vector in vectors}) != len(vectors):
        raise ValueError("generated DNS messages must be unique")
    if sum(vector.eligible for vector in vectors) != 1:
        raise ValueError("exactly one baseline vector must be eligible")

    for vector in vectors:
        if len(vector.message) > 512:
            raise ValueError(f"{vector.condition}: message exceeds 512 bytes")
        if vector.eligible != (vector.question is not None):
            raise ValueError(f"{vector.condition}: only eligible vectors carry Question facts")


def render_toml(vectors: list[Vector]) -> str:
    lines = [
        "# Generated by tests/vectors/query_eligibility/generate.py. Do not edit.",
        "format_version = 1",
        'generator = "tests/vectors/query_eligibility/generate.py"',
        "",
    ]
    for vector in vectors:
        lines.extend(
            (
                "[[vectors]]",
                f"name = {json.dumps(vector.name)}",
                f"condition = {json.dumps(vector.condition)}",
                f'message_hex = "{vector.message.hex()}"',
                f"eligible = {'true' if vector.eligible else 'false'}",
            )
        )
        if vector.question is not None:
            lines.extend(
                (
                    "[vectors.question]",
                    f'name_wire_hex = "{vector.question.name_wire.hex()}"',
                    f"type = {vector.question.qtype}",
                    f"class = {vector.question.qclass}",
                )
            )
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
