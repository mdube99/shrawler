"""Per-row zlib packing for the large Jev JSON columns.

Prompts, questions, directory contexts and per-file features are JSON documents
that no SQL query parses with ``json_extract``; they are only decoded in Python.
They compress to a fraction of their stored size, so they are written as zlib
blobs and decoded at the few read sites.

``decode`` also accepts plain text, so a database written before this change
(and every test fixture that inserts raw JSON) keeps working unchanged.
"""

import json
import zlib
from typing import Any


def encode(value: str) -> bytes:
    return zlib.compress(value.encode("utf-8"), 6)


def decode(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return zlib.decompress(bytes(value)).decode("utf-8")
    return str(value)


def decode_json(value: Any) -> Any:
    return json.loads(decode(value))
