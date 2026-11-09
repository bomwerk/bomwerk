// libFuzzer harness for Package URL parsing (T40): every purl a producer
// emits, every purl read back from an SBOM and every finding key goes through
// `core::Purl::parse`. Oracle: a purl that parses has a canonical form that
// parses again to itself.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "core/percent.hpp"
#include "core/purl.hpp"
#include "fuzz/fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const std::string_view text = bomwerk::fuzz::as_text(data, size);
  const auto parsed = bomwerk::core::Purl::parse(text);
  if (parsed.complete)
  {
    const auto reparsed = bomwerk::core::Purl::parse(parsed.value.canonical());
    bomwerk::fuzz::require(reparsed.complete, "a canonical purl does not parse again");
    bomwerk::fuzz::require(reparsed.value.canonical() == parsed.value.canonical(),
                           "canonicalizing a canonical purl changes it");
  }
  const std::string_view identity = bomwerk::core::purl_identity_part(text);
  static_cast<void>(bomwerk::core::purl_type_of(text));
  static_cast<void>(bomwerk::core::purl_version_of(identity));
  static_cast<void>(bomwerk::core::purl_name_of(identity));
  static_cast<void>(bomwerk::core::percent_decode(text));
  return 0;
}
