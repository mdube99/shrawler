"""Per-row dictionary compression for the large Jev JSON columns.

Prompts, questions, directory contexts and per-file features are JSON documents
that no SQL query parses with ``json_extract``; they are only decoded in
Python. They share a lot of structure between rows (the objective text, rubric
keys, ISO timestamps, path prefixes), so each column is compressed against a
small static dictionary. On these rows that is roughly two to three times
smaller than plain per-row zlib.

Blob layout for the dictionary format::

    b"\\x03" + kind (1 byte) + raw deflate stream

The kind selects the dictionary on decode, so readers do not need to know
which column they are reading. ``decode`` also accepts plain text and the
earlier plain-zlib blobs, so a database written before this change keeps
working and is migrated lazily or by the explicit migration.
"""

import json
import zlib
from typing import Any

from .config import DEFAULT_OBJECTIVE

_FORMAT_PLAIN = 0x01
_FORMAT_DICT = 0x03

KIND_FEATURE = 1
KIND_CONTEXT = 2
KIND_PAYLOAD = 3
KIND_STATE = 4
KIND_QUESTION = 5
KIND_DISTRIBUTION = 6

# (table, column) -> codec kind, in migration order.
KINDS = {
    ("request_batches", "payload_json"): KIND_PAYLOAD,
    ("request_batches", "state_json"): KIND_STATE,
    ("request_batches", "question_json"): KIND_QUESTION,
    ("assessment_files", "feature_json"): KIND_FEATURE,
    ("directory_contexts", "context_json"): KIND_CONTEXT,
    ("decision_results", "distribution_json"): KIND_DISTRIBUTION,
}

# Repeated row scaffolding. Placed as-is so the deflate matcher finds it.
_FEATURE_SCAFFOLD = (
    b'{"file_id":"","file_name":"","host":"","is_directory":false,'
    b'"mtime_utc":"2026-01-01T00:00:00+00:00","readable_size":"",'
    b'"remote_path":"","scan_timestamp_utc":"2026-09-05T00:00:00+00:00",'
    b'"share":"","share_name":"","size_bytes":0,"unc_path":"\\\\\\\\"}'
)
_CONTEXT_SCAFFOLD = (
    b'{"ancestors":[],"complete":true,"context_version":"2","directory":"",'
    b'"enumeration":"observed listing complete",'
    b'"extensions":[{"count":0,"extension":""}],"host":"","observed_files":0,'
    b'"share":"","sibling_markers":[]}'
)
_QUESTION_SCAFFOLD = (
    b'{"criteria":{"0":null,"1":null,"2":null,"3":null,"4":null},'
    b'"instructions":"Rate  in D000001.","type":"choice"}'
)
DISTRIBUTION_SCAFFOLD = b'{"0":0.0,"1":0.0,"2":0.0,"3":0.0,"4":0.0}'

_OBJECTIVE = DEFAULT_OBJECTIVE.encode("utf-8")

# The dictionary for a kind. Kept under zlib's 32 KiB window.
_DICTS = {
    KIND_FEATURE: _FEATURE_SCAFFOLD * 3,
    KIND_CONTEXT: _CONTEXT_SCAFFOLD * 3,
    KIND_PAYLOAD: _QUESTION_SCAFFOLD * 2
    + b'{"model":"","questions":{},"state":"'
    + _OBJECTIVE
    + b'"}',
    KIND_STATE: _OBJECTIVE + b"\n\n",
    KIND_QUESTION: _QUESTION_SCAFFOLD * 3,
    KIND_DISTRIBUTION: DISTRIBUTION_SCAFFOLD * 2,
}


def encode(value: str, kind: int | None = None) -> bytes:
    data = value.encode("utf-8")
    dictionary = _DICTS.get(kind) if kind is not None else None
    if dictionary is None:
        return bytes([_FORMAT_PLAIN]) + zlib.compress(data, 6)
    compressor = zlib.compressobj(
        9, zlib.DEFLATED, -15, 8, zlib.Z_DEFAULT_STRATEGY, zdict=dictionary
    )
    body = compressor.compress(data) + compressor.flush()
    return bytes([_FORMAT_DICT, kind]) + body


def decode(value: Any) -> str:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return str(value)
    blob = bytes(value)
    if blob[:1] == b"\x01":
        return zlib.decompress(blob[1:]).decode("utf-8")
    if blob[:1] == b"\x03" and len(blob) >= 2:
        kind = blob[1]
        dictionary = _DICTS.get(kind)
        if dictionary is None:
            raise ValueError(f"unknown Jev codec dictionary {kind}")
        decompressor = zlib.decompressobj(-15, zdict=dictionary)
        return (decompressor.decompress(blob[2:]) + decompressor.flush()).decode(
            "utf-8"
        )
    # Legacy plain-zlib blob written with zlib.compress (starts with 0x78).
    return zlib.decompress(blob).decode("utf-8")


def decode_json(value: Any) -> Any:
    return json.loads(decode(value))
