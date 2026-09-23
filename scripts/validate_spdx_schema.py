#!/usr/bin/env python3
"""Validate an SPDX document against a vendored official SPDX JSON schema.

Usage: validate_spdx_schema.py <spdx.json> <schema.json>

Covers both SPDX serializations bomwerk emits: 2.3 (classic flat JSON,
draft-07) and 3.0.1 (JSON-LD, draft 2020-12). The JSON Schema draft is chosen
from the schema's own "$schema" rather than hardcoded, so one script validates
either. This is structural validation only: the 3.0.1 JSON-LD "@context" is not
resolved and no SHACL/semantic rules are applied; "SPDX output schema-valid"
(the acceptance criterion) is exactly this JSON Schema structural check, the
same shape as scripts/validate_cyclonedx_schema.py.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator, Draft202012Validator


def select_validator_class(schema):
    """Pick the validator matching the schema's declared JSON Schema draft.

    Substring match rather than exact URI so a trailing '#' or http/https
    variation cannot silently drop us to the wrong draft. An absent/unknown
    "$schema" falls back to the newest draft the SPDX schemas use, so a schema
    is never under-validated by guessing an older draft.
    """
    declared = schema.get("$schema", "")
    if "2020-12" in declared:
        return Draft202012Validator
    if "draft-07" in declared:
        return Draft7Validator
    return Draft202012Validator


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <spdx.json> <schema.json>", file=sys.stderr)
        return 2

    document_path = Path(sys.argv[1])
    schema_path = Path(sys.argv[2])

    document = json.loads(document_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    validator = select_validator_class(schema)(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        for error in errors:
            location = "/".join(str(part) for part in error.path) or "<root>"
            print(f"schema violation at {location}: {error.message}", file=sys.stderr)
        return 1

    print(f"OK: {document_path} conforms to {schema_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
