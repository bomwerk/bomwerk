#!/usr/bin/env python3
"""Fails when docs/warning-codes.md drifts from core::WarningCode's real ids.

`src/core/warning_code.cpp` is the permanent contract (an id is never renumbered or
reused once shipped); the markdown table is a rendering of it for a human deciding
what to put in `bomwerk.toml`'s `[warnings] suppress`. The two must agree exactly,
the same way `docs/vuln-cache-schema.md` is checked against the cache's real schema.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = REPOSITORY_ROOT / "src" / "core" / "warning_code.cpp"
DOC_PATH = REPOSITORY_ROOT / "docs" / "warning-codes.md"

CASE_PATTERN = re.compile(
    r'case WarningCode::\w+:\s*\{\s*static constexpr WarningCodeInfo kInfo\{\s*'
    r'"([^"]+)",\s*"([^"]+)"\s*\};',
    re.DOTALL,
)
DOC_ROW_PATTERN = re.compile(r"^\| `(BW-[A-Z]+-\d+)` \| (.+) \|$", re.MULTILINE)

# Reachable only through a caller misusing the lookup API, or through the switch's
# defensive fallback: never a cause a real scan raises, so never something an
# operator would suppress. The doc explains both in prose instead of a table row.
NON_SUPPRESSIBLE_IDS = frozenset({"BW-EXT-000", "BW-UNKNOWN"})


def lowercase_first_letter(text: str) -> str:
    return text[:1].lower() + text[1:] if text else text


class WarningCodesReferenceTest(unittest.TestCase):
    def test_every_suppressible_code_is_documented_with_a_matching_title(self) -> None:
        # Given every (id, title) pair core::warning_code_info() actually returns,
        # When the reference doc's table is read,
        # Then the two name exactly the same codes, with the same meaning.
        source_text = SOURCE_PATH.read_text(encoding="utf-8")
        source_entries = CASE_PATTERN.findall(source_text)
        self.assertGreater(
            len(source_entries), 0, "regex matched nothing; did warning_code.cpp's shape change?"
        )
        source_codes = {
            code_id: title for code_id, title in source_entries if code_id not in NON_SUPPRESSIBLE_IDS
        }

        doc_text = DOC_PATH.read_text(encoding="utf-8")
        doc_codes = dict(DOC_ROW_PATTERN.findall(doc_text))
        self.assertGreater(len(doc_codes), 0, "no `| `BW-...` | ... |` rows found in the doc")

        missing_from_doc = sorted(set(source_codes) - set(doc_codes))
        stale_in_doc = sorted(set(doc_codes) - set(source_codes))
        self.assertEqual(missing_from_doc, [], f"codes in source but not documented: {missing_from_doc}")
        self.assertEqual(stale_in_doc, [], f"documented codes no longer in source: {stale_in_doc}")

        mismatched_titles = sorted(
            code_id
            for code_id, source_title in source_codes.items()
            if lowercase_first_letter(doc_codes[code_id]) != source_title
        )
        self.assertEqual(
            mismatched_titles, [], f"documented meaning drifted from source for: {mismatched_titles}"
        )

    def test_non_suppressible_ids_stay_out_of_the_table(self) -> None:
        # Given the two fallback ids that never fire from a real scan,
        # Then they never appear as a table row a reader could mistake for
        # something worth adding to `[warnings] suppress`.
        doc_text = DOC_PATH.read_text(encoding="utf-8")
        documented_ids = {code_id for code_id, _ in DOC_ROW_PATTERN.findall(doc_text)}
        overlap = documented_ids & NON_SUPPRESSIBLE_IDS
        self.assertEqual(overlap, set(), f"{overlap} should not appear in the suppressible-codes table")


if __name__ == "__main__":
    unittest.main()
