// libFuzzer harness for the maven producer (T40): the input is one
// `pom.xml` or `gradle.lockfile` file, parsed through `parse_bytes` exactly as a scan parses it.
// BOMWERK_FUZZ_VARIANT names the file (see scripts/fuzz_targets.json), so a
// crash input is a plain manifest that can be committed as-is under
// fixtures/maven/hostile/.
#include <cstddef>
#include <cstdint>

#include "fuzz/fuzz_support.hpp"
#include "parsers/lockfiles/maven.hpp"

#ifndef BOMWERK_FUZZ_VARIANT
#error "BOMWERK_FUZZ_VARIANT must name the file this harness parses"
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto result = bomwerk::parsers::lockfiles::maven::parse_bytes(
      BOMWERK_FUZZ_VARIANT, bomwerk::fuzz::as_text(data, size), {});
  bomwerk::fuzz::require_valid_purls(result);
  return 0;
}
