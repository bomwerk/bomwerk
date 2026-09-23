#include <cstdio>
#include <string>
#include <vector>

#include "core/base64.hpp"
#include "support/check.hpp"

using bomwerk::core::base64_encode;
using bomwerk::core::base64url_decode;

int main()
{
  // Given the canonical RFC 4648 §10 vectors, when encoded, then each matches
  // the published expected output (covers all three padding cases).
  BOMWERK_TEST_CHECK(base64_encode("") == "");
  BOMWERK_TEST_CHECK(base64_encode("f") == "Zg==");
  BOMWERK_TEST_CHECK(base64_encode("fo") == "Zm8=");
  BOMWERK_TEST_CHECK(base64_encode("foo") == "Zm9v");
  BOMWERK_TEST_CHECK(base64_encode("foob") == "Zm9vYg==");
  BOMWERK_TEST_CHECK(base64_encode("fooba") == "Zm9vYmE=");
  BOMWERK_TEST_CHECK(base64_encode("foobar") == "Zm9vYmFy");

  // Given the classic "Man"/"Ma"/"M" trio, when encoded, then padding is
  // applied per the number of leftover bytes (0, 1, 2).
  BOMWERK_TEST_CHECK(base64_encode("Man") == "TWFu");
  BOMWERK_TEST_CHECK(base64_encode("Ma") == "TWE=");
  BOMWERK_TEST_CHECK(base64_encode("M") == "TQ==");

  // Given bytes with the high bit set (0xFF 0xFE 0xFD): a logo is binary, not
  // text: when encoded, then they encode without sign-extension corruption.
  {
    const std::string binary_bytes = std::string("\xFF\xFE\xFD", 3);
    BOMWERK_TEST_CHECK(base64_encode(binary_bytes) == "//79");
  }

  // Given an embedded NUL, when encoded, then it is data like any other byte
  // (length comes from the string_view, not a C-string terminator).
  {
    const std::string with_nul = std::string("a\0b", 3);
    BOMWERK_TEST_CHECK(base64_encode(with_nul) == "YQBi");
  }

  // Given the unpadded RFC 4648 vectors, when decoded as Base64url, then the
  // original bytes are recovered without requiring padding.
  {
    BOMWERK_TEST_CHECK(base64url_decode("").value() == "");
    BOMWERK_TEST_CHECK(base64url_decode("Zg").value() == "f");
    BOMWERK_TEST_CHECK(base64url_decode("Zm8").value() == "fo");
    BOMWERK_TEST_CHECK(base64url_decode("Zm9v").value() == "foo");
    BOMWERK_TEST_CHECK(base64url_decode("Zm9vYg").value() == "foob");
    BOMWERK_TEST_CHECK(base64url_decode("Zm9vYmE").value() == "fooba");
    BOMWERK_TEST_CHECK(base64url_decode("Zm9vYmFy").value() == "foobar");
  }

  // Given URL-safe symbols and binary bytes, when decoded, then '-' and '_'
  // carry their RFC values and embedded NUL bytes remain data.
  {
    BOMWERK_TEST_CHECK(base64url_decode("_v8").value() == std::string("\xFE\xFF", 2));
    BOMWERK_TEST_CHECK(base64url_decode("YQBi").value() == std::string("a\0b", 3));
  }

  // Given non-URL alphabets, padding, whitespace, impossible lengths, or
  // alternate encodings with non-zero unused bits, when decoded, then the
  // strict decoder rejects every spelling.
  {
    const std::vector<std::string> rejected_spellings = {
        "+w", "/w", "Zg=", "Zg==", "Z g", "Z\tg", "Z\ng", "Z\rg", std::string("Z\xC2\xA0g", 4),
        "A",  "Zh", "Zm9"};
    for (const std::string& rejected : rejected_spellings)
    {
      BOMWERK_TEST_CHECK(!base64url_decode(rejected).has_value());
    }
  }

  std::puts("test_base64: OK");
  return 0;
}
