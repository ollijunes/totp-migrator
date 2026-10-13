"""A minimal protobuf wire-format reader and writer.

Just enough for the Google Authenticator migration payload: varints and
length-delimited fields. Other wire types are skipped safely so they can be
reported as unknown fields instead of crashing the parser.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import MigratorError

VARINT = 0
FIXED64 = 1
LENGTH_DELIMITED = 2
FIXED32 = 5

_MAX_VARINT_BYTES = 10


@dataclass(frozen=True)
class Field:
    number: int
    wire_type: int
    value: int | bytes


def read_varint(buf: bytes, index: int) -> tuple[int, int]:
    """Return (value, next_index) for the varint that starts at ``index``."""
    value = 0
    for position in range(_MAX_VARINT_BYTES):
        if index >= len(buf):
            raise MigratorError("protobuf payload is truncated")
        byte = buf[index]
        index += 1
        value |= (byte & 0x7F) << (7 * position)
        if not byte & 0x80:
            if value >> 64:
                raise MigratorError("protobuf varint is larger than 64 bits")
            return value, index
    raise MigratorError("protobuf varint is too long")


def parse_fields(buf: bytes) -> list[Field]:
    """Split one message into its top-level fields, in wire order."""
    fields: list[Field] = []
    index = 0
    while index < len(buf):
        key, index = read_varint(buf, index)
        number, wire_type = key >> 3, key & 0x07
        if number == 0:
            raise MigratorError("protobuf field number 0 is invalid")
        if wire_type == VARINT:
            value, index = read_varint(buf, index)
            fields.append(Field(number, wire_type, value))
        elif wire_type == LENGTH_DELIMITED:
            length, index = read_varint(buf, index)
            end = index + length
            if end > len(buf):
                raise MigratorError("protobuf payload is truncated")
            fields.append(Field(number, wire_type, buf[index:end]))
            index = end
        elif wire_type in (FIXED64, FIXED32):
            index += 8 if wire_type == FIXED64 else 4
            if index > len(buf):
                raise MigratorError("protobuf payload is truncated")
            fields.append(Field(number, wire_type, b""))
        else:
            raise MigratorError(f"protobuf wire type {wire_type} is not supported")
    return fields


def as_int32(value: int) -> int:
    """Interpret a decoded varint as a signed 32-bit protobuf int32."""
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


def encode_varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while True:
        piece = value & 0x7F
        value >>= 7
        if value:
            out.append(piece | 0x80)
        else:
            out.append(piece)
            return bytes(out)


def encode_field(number: int, value: int | bytes) -> bytes:
    """Encode an int as a varint field and bytes as a length-delimited field."""
    if isinstance(value, bytes):
        return encode_varint(number << 3 | LENGTH_DELIMITED) + encode_varint(len(value)) + value
    return encode_varint(number << 3 | VARINT) + encode_varint(value)
