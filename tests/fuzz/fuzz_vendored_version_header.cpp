// libFuzzer harness for vendored version headers (T40): the input is tried
// as every header the version tables know, inside a folder named for that
// header's library. Oracle: a recognized version is short and single-line.
#include <cstddef>
#include <cstdint>
#include <string>

#include "fuzz/fuzz_support.hpp"
#include "heuristics/vendored_cpp.hpp"

namespace vendored_cpp = bomwerk::heuristics::vendored_cpp;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto header = bomwerk::fuzz::as_text(data, size);
  for (const vendored_cpp::VersionHeaderRow& row : vendored_cpp::version_header_signatures())
  {
    const auto match = vendored_cpp::match_version_header(
        row.canonical_name,
        std::string(row.canonical_name) + "/" + std::string(row.header_filename), header);
    if (match.has_value())
    {
      bomwerk::fuzz::require(!match->version.empty(), "a matched version is empty");
      bomwerk::fuzz::require(match->version.find('\n') == std::string::npos,
                             "a matched version spans lines");
    }
  }
  return 0;
}
