#!/usr/bin/env python3
"""Validate a CycloneDX JSON document against the vendored official schema.

Usage: validate_cyclonedx_schema.py <bom.json> <schema-dir>
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

SCHEMA_FILES = ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <bom.json> <schema-dir>", file=sys.stderr)
        return 2

    bom_path = Path(sys.argv[1])
    schema_dir = Path(sys.argv[2])

    bom = json.loads(bom_path.read_text(encoding="utf-8"))

    resources = []
    bom_schema = None
    for schema_file in SCHEMA_FILES:
        schema = json.loads((schema_dir / schema_file).read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema)))
        if schema_file == "bom-1.6.schema.json":
            bom_schema = schema
    registry = Registry().with_resources(resources)

    validator = Draft7Validator(bom_schema, registry=registry)
    errors = sorted(validator.iter_errors(bom), key=lambda error: list(error.path))
    if errors:
        for error in errors:
            location = "/".join(str(part) for part in error.path) or "<root>"
            print(f"schema violation at {location}: {error.message}", file=sys.stderr)
        return 1

    print(f"OK: {bom_path} conforms to CycloneDX 1.6 schema")
    return 0


if __name__ == "__main__":
    sys.exit(main())
