// ctest unit test for the shared ASCII text helpers (core/text).
#include <cassert>
#include <cstdio>
#include <string>
#include <string_view>

#include "core/text.hpp"
#include "support/check.hpp"

using bomwerk::core::equals_ascii_ignore_case;
using bomwerk::core::escaped_for_diagnostic;
using bomwerk::core::is_hex_digits;
using bomwerk::core::is_hex_object_id;
using bomwerk::core::leading_space_count;
using bomwerk::core::normalized_object_id;
using bomwerk::core::to_lower_ascii;
using bomwerk::core::to_upper_ascii;
using bomwerk::core::trimmed;
using bomwerk::core::trimmed_view;

int main()
{
  // Given mixed-case ASCII, when lowered, then only 'A'..'Z' change: bytes
  // outside that range (digits, punctuation, UTF-8 continuation bytes) pass
  // through, independent of the C locale.
  {
    assert(to_lower_ascii("GIT_TAG") == "git_tag");
    assert(to_lower_ascii("MiXeD-1.2.3") == "mixed-1.2.3");
    assert(to_lower_ascii('Z') == 'z');
    assert(to_lower_ascii('_') == '_');
    assert(to_lower_ascii("\xC3\x9C") == "\xC3\x9C");  // 'Ü' in UTF-8: untouched
  }

  // Given mixed-case ASCII, when uppered, then only 'a'..'z' change: the exact
  // mirror of to_lower_ascii, so a CVE id typed in any casing reaches its one
  // canonical spelling without the C locale getting a vote.
  {
    assert(to_upper_ascii("cve-2026-1234") == "CVE-2026-1234");
    assert(to_upper_ascii("CVE-2026-1234") == "CVE-2026-1234");
    assert(to_upper_ascii("MiXeD-1.2.3") == "MIXED-1.2.3");
    assert(to_upper_ascii('z') == 'Z');
    assert(to_upper_ascii('_') == '_');
    assert(to_upper_ascii("") == "");
    assert(to_upper_ascii("\xC3\xBC") == "\xC3\xBC");  // 'ü' in UTF-8: untouched
  }

  // Given two strings differing only in ASCII case, when compared, then they
  // are equal; a prefix relationship or different text is not.
  {
    assert(equals_ascii_ignore_case("URL_HASH", "url_hash"));
    assert(equals_ascii_ignore_case("", ""));
    assert(!equals_ascii_ignore_case("URL", "URL_HASH"));
    assert(!equals_ascii_ignore_case("GIT_TAG", "GIT_TAB"));
  }

  // Given surrounding whitespace, when trimmed, then spaces, tabs, carriage
  // returns and newlines are stripped from both ends only.
  {
    assert(trimmed("  v1.2 \r\n") == "v1.2");
    assert(trimmed("\tmain\n") == "main");
    assert(trimmed("a b") == "a b");
    assert(trimmed(" \t\r\n").empty());
    assert(trimmed("").empty());
  }

  // Given an identifier containing quotes, slashes, controls and UTF-8, when
  // rendered for a diagnostic, then hostile bytes become visible escapes
  // without normalizing or otherwise changing printable Unicode.
  {
    const std::string hostile = "line\nbreak\t\\\"\x01 caf\xC3\xA9";
    assert(escaped_for_diagnostic(hostile) == "line\\nbreak\\t\\\\\\\"\\u0001 caf\xC3\xA9");
  }

  // Given a live buffer, when trimmed_view is taken, then it is a view into
  // that buffer (no allocation) with the same content trimmed() would return.
  {
    const std::string buffer = "  ref: refs/heads/main \n";
    const std::string_view view = trimmed_view(buffer);
    BOMWERK_TEST_CHECK(view == "ref: refs/heads/main");
    BOMWERK_TEST_CHECK(view.data() >= buffer.data() && view.data() < buffer.data() + buffer.size());
  }

  // Given candidate object ids, when validated, then exactly 40- or 64-char
  // all-hex strings pass: anything else (length, non-hex chars) fails.
  {
    assert(is_hex_object_id(std::string(40, 'a')));
    assert(is_hex_object_id(std::string(64, '0')));
    assert(is_hex_object_id("0123456789abcdefABCDEF0123456789abcdef01"));
    assert(!is_hex_object_id(std::string(39, 'a')));
    assert(!is_hex_object_id(std::string(41, 'a')));
    assert(!is_hex_object_id("v1.14.0"));
    assert(!is_hex_object_id(std::string(40, 'g')));
    assert(!is_hex_object_id(""));
  }

  // Given values that may or may not be object ids, when normalized, then only
  // a real object id is lower-cased; everything else is returned byte-exact.
  // An object id has one canonical spelling, so capitals must not fork an
  // artifact into a second identity: but a tag is operator text.
  {
    assert(normalized_object_id(std::string(40, 'A')) == std::string(40, 'a'));
    assert(normalized_object_id(std::string(64, 'A')) == std::string(64, 'a'));
    assert(normalized_object_id("0123456789ABCDEF0123456789abcdef01234567") ==
           "0123456789abcdef0123456789abcdef01234567");
    assert(normalized_object_id("v2.0-RC1") == "v2.0-RC1");
    assert(normalized_object_id("ABCDEF") == "ABCDEF");  // hex, but not an object-id length
    assert(normalized_object_id(std::string(41, 'A')) == std::string(41, 'A'));
    assert(normalized_object_id("") == "");
  }

  // Given candidate hash values, when validated as hex, then any non-empty
  // all-hex string of any length passes and anything else: empty, separators,
  // a crafted query-string injection: fails.
  {
    assert(is_hex_digits("deadBEEF"));
    assert(is_hex_digits("0"));
    assert(is_hex_digits(std::string(64, 'f')));
    assert(!is_hex_digits(""));
    assert(!is_hex_digits("dead beef"));
    assert(!is_hex_digits("abc&download_url=evil"));
    assert(!is_hex_digits("0x1234"));
  }

  // Given indented lines, when their indentation is measured, then only leading
  // spaces count. A tab reads as zero, so an indentation-structured lockfile
  // written with tabs degrades to "unindented" rather than mis-nesting silently
  // (Gemfile.lock, yarn.lock and pnpm-lock.yaml are all space-indented).
  {
    assert(leading_space_count("    version: 1") == 4);
    assert(leading_space_count("  resolution: \"a@npm:1\"") == 2);
    assert(leading_space_count("no-indent") == 0);
    assert(leading_space_count("\tversion: 1") == 0);
    assert(leading_space_count(" \tversion: 1") == 1);
    assert(leading_space_count("    ") == 4);  // an all-space line has no content
    assert(leading_space_count("") == 0);
  }

  std::puts("test_text: OK");
  return 0;
}
