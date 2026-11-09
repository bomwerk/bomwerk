// libFuzzer harness for the `ar` archive reader (T40). Oracles: member names
// and indexed symbols are sorted and deduplicated, and within their caps.
#include <cstddef>
#include <cstdint>

#include "binscan/archive_read.hpp"
#include "binscan/bounds.hpp"
#include "fuzz/fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto contents =
      bomwerk::binscan::read_archive_bytes("fuzz.a", bomwerk::fuzz::as_text(data, size));
  bomwerk::fuzz::require(bomwerk::fuzz::sorted_and_unique(contents.value.member_names),
                         "member names are not sorted and unique");
  bomwerk::fuzz::require(bomwerk::fuzz::sorted_and_unique(contents.value.indexed_symbols),
                         "indexed symbols are not sorted and unique");
  bomwerk::fuzz::require(contents.value.member_names.size() <= bomwerk::binscan::kMaxArchiveMembers,
                         "member list exceeds its cap");
  bomwerk::fuzz::require(
      contents.value.indexed_symbols.size() <= bomwerk::binscan::kMaxSymbolSample,
      "symbol sample exceeds its cap");
  return 0;
}
