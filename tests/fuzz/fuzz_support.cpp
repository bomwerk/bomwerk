#include "fuzz/fuzz_support.hpp"

#include <spdlog/spdlog.h>

#include <cstdio>
#include <cstdlib>

#include "core/purl.hpp"
#include "core/warning_code.hpp"

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/)
{
  // Parsers log at debug level; millions of inputs must not become millions
  // of log lines, and logging is not what is under test.
  spdlog::set_level(spdlog::level::off);
  return 0;
}

namespace bomwerk::fuzz
{

std::string_view as_text(const std::uint8_t* data, std::size_t size)
{
  if (size == 0)
  {
    return {};
  }
  return std::string_view(reinterpret_cast<const char*>(data), size);
}

void require(bool condition, const char* invariant)
{
  if (!condition)
  {
    std::fprintf(stderr, "fuzz invariant violated: %s\n", invariant);
    std::abort();
  }
}

void require_valid_purls(const core::Result<std::vector<core::Component>>& result)
{
  for (const core::Warning& warning : result.warnings)
  {
    require(warning.code != core::WarningCode::kPurlValidationFailed,
            "a producer reported a purl that does not parse back");
  }
  for (const core::Component& component : result.value)
  {
    require(component.purl.empty() || core::Purl::parse(component.purl).complete,
            "a producer emitted a purl that does not parse back");
  }
}

std::pair<std::string_view, std::string_view> split_at_first_newline(std::string_view text)
{
  const std::size_t newline = text.find('\n');
  if (newline == std::string_view::npos)
  {
    return {text, std::string_view{}};
  }
  return {text.substr(0, newline), text.substr(newline + 1)};
}

}  // namespace bomwerk::fuzz
