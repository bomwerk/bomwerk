#!/usr/bin/env python3
"""Run `bomwerk binscan` end to end and check what the binaries proved.

Usage: run_binscan_case.py <bomwerk-binary> <fixture-dir>

The binary pass acceptance check: dynamic dependencies appear as Binary evidence. The
unit tests cover the pieces separately -- test_byte_cursor for the bounds
checks every reader trusts, test_elf_read and test_archive_read for the two
formats, test_binary_map for attribution, test_link_map for pulling outputs off
a trace -- and none of them drives the real binary, so none can catch a wiring
mistake between them. This does: real CLI parsing, the real SBOM reader
restoring each component's root from evidence.occurrences, the real trace
reader, the real artifact collection, the real attribution, the real sidecar,
and the real exit-code contract, once, end to end. Same role run_trim_case.py
plays for the trace reader and the golden harness plays for `scan`.

Why the binaries are GENERATED here rather than committed: see
fixtures/binscan/SOURCES.md. In short -- CI runs macOS too, where a real build
emits Mach-O; a committed blob cannot be reviewed; and the statically linked
case is not one a local toolchain reliably produces on demand.

Why the trace carries "@FIXTURE_ROOT@" placeholders: a real trace records the
ABSOLUTE paths the build system used, which cannot be committed to a repository
that gets checked out somewhere different every time. This script substitutes
the temp copy's own absolute path, using the same local-fixture approach as
run_trim_case.py and other integration tests.

Why the assertions read the SIDECAR and the enriched SBOM rather than
byte-diffing stdout: what this fixture exists to pin is the ANSWER -- which
component gained which evidence, on what proof -- not the column widths a
summary line happens to print at. The golden harness byte-diffs because SBOM
bytes ARE the product artifact (hard rule 3); a console summary is not, and
pinning its spacing would turn every cosmetic wording change into a failing
test with nothing to say. The determinism that DOES matter is checked directly:
the sidecar is written twice and the two must be byte-identical.
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

FIXTURE_ROOT_TOKEN = "@FIXTURE_ROOT@"

# `metadata.timestamp` honors SOURCE_DATE_EPOCH and otherwise reads the wall
# clock at one-second resolution, so two back-to-back runs straddling a second
# boundary would differ in that one field. Same value and same reason as
# run_trim_case.py and run_golden_case.py (2025-01-01T00:00:00Z).
BINSCAN_SOURCE_DATE_EPOCH = "1735689600"


def fail(message):
    print(f"binscan case FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def check(condition, message):
    if not condition:
        fail(message)


# --------------------------------------------------------------------------
# Fixture generators. Deliberately the smallest ELF and `ar` images that are
# still self-consistent for the questions bomwerk asks: it reads e_ident, the
# section table, .dynamic, .dynstr and .dynsym, and nothing else.
# --------------------------------------------------------------------------

SHT_STRTAB, SHT_DYNAMIC, SHT_DYNSYM = 3, 6, 11
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME = 0, 1, 5, 10, 14
ET_EXEC, ET_DYN = 2, 3
STB_GLOBAL_STT_FUNC = 0x12


def build_elf(needed=(), soname="", symbols=(), static=False):
    """A 64-bit little-endian ELF image carrying exactly what is asked for."""
    strings = b"\0"
    offsets = {}

    def intern(text):
        nonlocal strings
        if text not in offsets:
            offsets[text] = len(strings)
            strings += text.encode() + b"\0"
        return offsets[text]

    for name in list(needed) + ([soname] if soname else []) + list(symbols):
        intern(name)

    dynamic = [] if static else (
        [(DT_NEEDED, offsets[name]) for name in needed]
        + ([(DT_SONAME, offsets[soname])] if soname else [])
    )

    def align8(value):
        return (value + 7) & ~7

    header_size, dyn_size, sym_size, shdr_size = 64, 16, 24, 64
    symbol_count = 1 + len(symbols) if symbols else 0
    # DT_STRTAB, DT_STRSZ and the terminating DT_NULL close the array.
    dynamic_count = len(dynamic) + 3 if not static else 0

    strings_offset = header_size
    dynamic_offset = align8(strings_offset + len(strings))
    symbols_offset = align8(dynamic_offset + dyn_size * dynamic_count)
    sections_offset = align8(symbols_offset + sym_size * symbol_count)

    sections = [(0, 0, 0, 0), (SHT_STRTAB, strings_offset, len(strings), 0)]
    if not static:
        sections.append((SHT_DYNAMIC, dynamic_offset, dyn_size * dynamic_count, 1))
    if symbols:
        sections.append((SHT_DYNSYM, symbols_offset, sym_size * symbol_count, 1))

    image = bytearray()
    image += b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)          # e_ident: 64-bit, LSB
    image += struct.pack("<HHI", ET_EXEC if static else ET_DYN, 62, 1)
    image += struct.pack("<QQQ", 0, 0, sections_offset)         # e_entry, e_phoff, e_shoff
    image += struct.pack("<IHHHHHH", 0, header_size, 56, 0, shdr_size, len(sections), 0)

    image += bytes(strings_offset - len(image)) + strings
    image += bytes(dynamic_offset - len(image))
    for tag, value in dynamic:
        image += struct.pack("<QQ", tag, value)
    if not static:
        image += struct.pack("<QQ", DT_STRTAB, strings_offset)  # identity map: address == offset
        image += struct.pack("<QQ", DT_STRSZ, len(strings))
        image += struct.pack("<QQ", DT_NULL, 0)

    image += bytes(symbols_offset - len(image))
    if symbols:
        image += struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)       # the reserved null symbol
        for name in symbols:
            image += struct.pack("<IBBHQQ", offsets[name], STB_GLOBAL_STT_FUNC, 0, 1, 0, 0)

    image += bytes(sections_offset - len(image))
    for section_type, offset, size, link in sections:
        image += struct.pack("<IIQQQQIIQQ", 0, section_type, 0, offset, offset, size, link, 0, 1, 0)
    return bytes(image)


def build_archive(members, symbols=()):
    """A GNU `ar` archive: an optional big-endian symbol index, then members."""
    image = bytearray(b"!<arch>\n")

    def put_member(name, data):
        image.extend(f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'644':<8}{len(data):<10}".encode())
        image.extend(b"`\n")
        image.extend(data)
        if len(data) % 2:
            image.extend(b"\n")

    if symbols:
        index = struct.pack(">I", len(symbols))
        index += b"".join(struct.pack(">I", 0) for _ in symbols)  # member offsets, unused here
        index += b"".join(symbol.encode() + b"\0" for symbol in symbols)
        put_member("/", index)
    for name, data in members:
        put_member(name + "/", data)
    return bytes(image)


def write_artifacts(tree):
    """Materialize the binaries the trace refers to."""
    vendor = tree / "third_party" / "vendored-crypto"
    build = tree / "build"
    build.mkdir(parents=True, exist_ok=True)

    # Serves two purposes at once: it is linked by path (so it is an artifact
    # in its own right, attributed to the component it LIVES in), and its mere
    # existence is what lets build/app's DT_NEEDED soname resolve. That
    # existence check is what separates binary evidence from a name-shaped
    # guess.
    (vendor / "libvendcrypto.so.1").write_bytes(
        build_elf(needed=["libc.so.6"], soname="libvendcrypto.so.1", symbols=["AES_encrypt"])
    )
    (vendor / "libvendcrypto.a").write_bytes(
        build_archive([("aes.o", b"aes"), ("sha256.o", b"sha")],
                      symbols=["AES_encrypt", "SHA256_Init"])
    )
    (build / "app").write_bytes(
        build_elf(needed=["libvendcrypto.so.1", "libc.so.6"], symbols=["main"])
    )
    (build / "tool-static").write_bytes(build_elf(static=True))
    (build / "libzlib.a").write_bytes(build_archive([("adler32.o", b"adler")],
                                                    symbols=["adler32"]))


def run(command, cwd, phase):
    """Run one phase, echoing its output so a CI failure is readable."""
    completed = subprocess.run(
        command, cwd=str(cwd), capture_output=True, text=True,
        env=dict(os.environ, SOURCE_DATE_EPOCH=BINSCAN_SOURCE_DATE_EPOCH),
    )
    print(f"=== {phase}: {' '.join(str(part) for part in command)} ===")
    print(f"--- exit {completed.returncode} ---")
    if completed.stdout:
        print(completed.stdout)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr)
    return completed


def binary_evidence_by_purl(document):
    """The `bomwerk:binary` properties the enriched SBOM carries, per component."""
    found = {}
    for component in document.get("components", []):
        values = sorted(
            entry["value"]
            for entry in component.get("properties", [])
            if entry.get("name") == "bomwerk:binary"
        )
        if values:
            found[component.get("purl", "")] = values
    return found


def main():
    if len(sys.argv) != 3:
        fail(f"usage: {Path(sys.argv[0]).name} <bomwerk> <fixture-dir>")
    bomwerk_binary = Path(sys.argv[1]).resolve()
    fixture_directory = Path(sys.argv[2]).resolve()
    expected = json.loads((fixture_directory / "expected.binscan.json").read_text())

    with tempfile.TemporaryDirectory(prefix="bomwerk_binscan_") as temporary_root:
        workspace = Path(temporary_root) / "case"
        shutil.copytree(fixture_directory, workspace)
        # resolve() because macOS puts the system temp dir behind a symlink
        # (/var -> /private/var); baking the unresolved spelling into the trace
        # would make this test assert the symlink handling by accident.
        workspace = workspace.resolve()
        write_artifacts(workspace / "tree")

        trace_path = workspace / "trace.jsonl"
        trace_path.write_text(
            trace_path.read_text().replace(FIXTURE_ROOT_TOKEN, str(workspace))
        )

        # Paths are RELATIVE and the command runs inside the workspace, so
        # nothing temp-dir-specific can leak into what is asserted on.
        command = [bomwerk_binary, "binscan", "sbom.cdx.json", "--trace", "trace.jsonl",
                   "--root", "tree", "--sidecar", "binscan.json", "-o", "enriched.cdx.json"]
        binscan = run(command, cwd=workspace, phase="binscan")
        check(
            binscan.returncode == expected["exit_code"],
            f"exit {binscan.returncode}, expected {expected['exit_code']} "
            "(0 clean / 1 warnings / 2 incomplete -- hard rule 2)",
        )
        check(
            expected["warning_must_mention"] in binscan.stderr,
            "a statically linked output must SAY so: the operator has to be able to tell "
            "'this product has no dynamic dependencies' from 'bomwerk found none'. "
            f"stderr never mentioned {expected['warning_must_mention']!r}",
        )

        sidecar = json.loads((workspace / "binscan.json").read_text())
        check(
            sidecar["counters"] == expected["counters"],
            f"counters:\n  reported: {sidecar['counters']}\n  expected: {expected['counters']}",
        )
        artifacts = {entry["path"]: entry for entry in sidecar["artifacts"]}
        check(
            sorted(artifacts) == expected["artifact_paths"],
            f"artifacts scanned {sorted(artifacts)}, expected {expected['artifact_paths']}",
        )
        for path, shape in expected["artifact_shapes"].items():
            check(
                artifacts[path]["shape"] == shape,
                f"{path}: shape {artifacts[path]['shape']}, expected {shape}",
            )
        check(
            sidecar["unmatched_needed"] == expected["unmatched_needed"],
            f"unmatched dynamic deps {sidecar['unmatched_needed']}, "
            f"expected {expected['unmatched_needed']}",
        )
        for path, members in expected["archive_members"].items():
            check(
                artifacts[path]["members"] == members,
                f"{path}: members {artifacts[path]['members']}, expected {members}",
            )
        for path, symbols in expected["symbols"].items():
            check(
                artifacts[path]["symbols"] == symbols,
                f"{path}: symbols {artifacts[path]['symbols']}, expected {symbols}",
            )

        attributed = {entry["root"]: entry for entry in sidecar["attributed"]}
        check(
            sorted(attributed) == sorted(expected["attributed"]),
            f"attributed roots {sorted(attributed)}, expected {sorted(expected['attributed'])}",
        )
        for root, claim in expected["attributed"].items():
            check(
                attributed[root]["needed"] == claim["needed"],
                f"{root}: resolved deps {attributed[root]['needed']}, expected {claim['needed']}",
            )
            check(
                attributed[root]["archive_members"] == claim["archive_members"],
                f"{root}: archive members {attributed[root]['archive_members']}, "
                f"expected {claim['archive_members']}",
            )
            check(
                attributed[root]["shared_objects"] == claim["shared_objects"],
                f"{root}: prebuilt shared objects {attributed[root]['shared_objects']}, "
                f"expected {claim['shared_objects']} -- a vendored .so under a component "
                "root is that component, the same as a vendored .a",
            )

        # The issue's "Done when", checked where a consumer would actually look:
        # the SBOM itself, not bomwerk's own working file.
        enriched = json.loads((workspace / "enriched.cdx.json").read_text())
        reported_evidence = binary_evidence_by_purl(enriched)
        wanted_evidence = {purl: sorted(values)
                           for purl, values in expected["binary_evidence"].items()}
        check(
            reported_evidence == wanted_evidence,
            "the dynamic dependencies did not reach the SBOM as Binary evidence.\n"
            f"  reported: {reported_evidence}\n  expected: {wanted_evidence}",
        )
        check(
            enriched["metadata"]["component"]["name"] == "widget-firmware",
            "the enriched SBOM lost the product identity from the SBOM it enriched",
        )

        # Hard rule 3: two runs, byte-identical -- both artifacts.
        first_sidecar = (workspace / "binscan.json").read_bytes()
        first_sbom = (workspace / "enriched.cdx.json").read_bytes()
        rerun_command = list(command)
        rerun_command[rerun_command.index("binscan.json")] = "binscan-again.json"
        rerun_command[rerun_command.index("enriched.cdx.json")] = "enriched-again.cdx.json"
        rerun = run(rerun_command, cwd=workspace, phase="binscan again (determinism)")
        check(rerun.returncode == expected["exit_code"], "the second run exited differently")
        check(
            (workspace / "binscan-again.json").read_bytes() == first_sidecar,
            "two binscan runs produced different sidecar bytes (hard rule 3)",
        )
        check(
            (workspace / "enriched-again.cdx.json").read_bytes() == first_sbom,
            "two binscan runs produced different SBOM bytes (hard rule 3)",
        )

    print("binscan case: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
