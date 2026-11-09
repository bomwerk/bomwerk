// libFuzzer harness for registry license responses (T40): network input.
// BOMWERK_FUZZ_VARIANT is `crates_io`, `pypi`, `rubygems` or `cached`.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "fuzz/fuzz_support.hpp"
#include "vuln/license_enrichment.hpp"

#ifndef BOMWERK_FUZZ_VARIANT
#error "BOMWERK_FUZZ_VARIANT must be crates_io, pypi, rubygems or cached"
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  constexpr std::string_view kVariant = BOMWERK_FUZZ_VARIANT;
  const std::string payload(bomwerk::fuzz::as_text(data, size));
  if constexpr (kVariant == "cached")
  {
    static_cast<void>(bomwerk::vuln::parse_cached_license_payload(payload));
  }
  else
  {
    constexpr bomwerk::vuln::LicenseRegistry kRegistry =
        kVariant == "crates_io" ? bomwerk::vuln::LicenseRegistry::CratesIo
        : kVariant == "pypi"    ? bomwerk::vuln::LicenseRegistry::PyPi
                                : bomwerk::vuln::LicenseRegistry::RubyGems;
    static_cast<void>(bomwerk::vuln::parse_registry_license_payload(kRegistry, payload));
  }
  return 0;
}
