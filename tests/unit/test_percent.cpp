// ctest unit test for core percent-encoding (framework-free on purpose).
#include <cstdio>
#include <string>

#include "core/percent.hpp"
#include "support/check.hpp"

using bomwerk::core::percent_decode;
using bomwerk::core::percent_encode;
using bomwerk::core::percent_encode_purl_namespace;

int main()
{
  // Given text made only of RFC 3986 unreserved characters, when encoded,
  // then it passes through unchanged.
  BOMWERK_TEST_CHECK(percent_encode("AZaz09-._~") == "AZaz09-._~");

  // Given text with reserved and non-ASCII bytes, when encoded, then each such
  // byte becomes %XX with upper-case hex: the documented example.
  BOMWERK_TEST_CHECK(percent_encode("git+https://x.y/a b") == "git%2Bhttps%3A%2F%2Fx.y%2Fa%20b");

  // Given an npm scope, when encoded as a plain component, then the '@'
  // becomes %40: the seam the pkg:npm namespace depends on.
  BOMWERK_TEST_CHECK(percent_encode("@scope") == "%40scope");

  // Given empty input, when encoded, then the result is empty (no crash).
  BOMWERK_TEST_CHECK(percent_encode("").empty());

  // Given a namespace path with several segments, when namespace-encoded, then
  // the structural '/' separators stay literal while each segment is encoded.
  BOMWERK_TEST_CHECK(percent_encode_purl_namespace("group/sub") == "group/sub");
  BOMWERK_TEST_CHECK(percent_encode_purl_namespace("github.com/gorilla") == "github.com/gorilla");
  BOMWERK_TEST_CHECK(percent_encode_purl_namespace("broken)/ok") == "broken%29/ok");

  // Given a namespace with empty segments (leading/trailing/double slash),
  // when namespace-encoded, then the slashes are preserved as-is: the
  // function never invents or drops structure.
  BOMWERK_TEST_CHECK(percent_encode_purl_namespace("/a//b/") == "/a//b/");

  // Given a single segment with no slash, when namespace-encoded, then it is
  // equivalent to plain percent_encode.
  BOMWERK_TEST_CHECK(percent_encode_purl_namespace("@scope") == "%40scope");

  // Given a Yarn `patch:` inner locator, when decoded, then the escaped ':' and
  // '/' come back: this is the seam the patch resolution depends on.
  BOMWERK_TEST_CHECK(percent_decode("@material-ui%2Fpickers@npm%3A3.3.11") ==
                     "@material-ui/pickers@npm:3.3.11");
  BOMWERK_TEST_CHECK(percent_decode("root%40workspace%3A.") == "root@workspace:.");

  // Given text with no escapes, when decoded, then it passes through unchanged.
  BOMWERK_TEST_CHECK(percent_decode("plain-text.1_2~3") == "plain-text.1_2~3");
  BOMWERK_TEST_CHECK(percent_decode("").empty());

  // Given a malformed or truncated escape, when decoded, then the '%' and every
  // byte behind it survive: a hostile manifest must never make text vanish
  // (Hard Rule 1). Lower-case hex decodes the same as upper-case.
  BOMWERK_TEST_CHECK(percent_decode("100%") == "100%");
  BOMWERK_TEST_CHECK(percent_decode("%A") == "%A");
  BOMWERK_TEST_CHECK(percent_decode("%ZZ") == "%ZZ");
  BOMWERK_TEST_CHECK(percent_decode("%%3A") == "%:");
  BOMWERK_TEST_CHECK(percent_decode("%3a") == ":");

  // Given any text, when encoded and then decoded, then the original returns :
  // the two functions are inverses over arbitrary bytes.
  {
    const std::string original = "git+https://x.y/a b@npm:^1.2.3";
    BOMWERK_TEST_CHECK(percent_decode(percent_encode(original)) == original);
  }

  std::puts("test_percent: OK");
  return 0;
}
