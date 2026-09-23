#pragma once
#include <spdlog/spdlog.h>

#include <filesystem>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "core/warning.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::cli
{

/// Shared log+accumulate+degrade sink for `core::Warning`, replacing seven
/// near-duplicate `record_warning(s)` copies that used to live one per CLI command file.
/// A warning covered by `suppressed_codes` (bomwerk.toml `[warnings] suppress`, scan-only) is
/// still logged and collected: suppression never hides a warning from any artifact: it only
/// stops that warning from marking the run degraded, which is what lets `--fail-on warnings` (the
/// default) stop failing on a cause the repo owner has reviewed. Entries may be bare codes or
/// `CODE:ecosystem` pairs.
class WarningRecorder
{
 public:
  explicit WarningRecorder(std::set<std::string> suppressed_codes = {})
      : suppressed_codes_(std::move(suppressed_codes))
  {
  }

  void record(const core::Warning& warning)
  {
    // "{}" so a warning containing braces (paths, purls) is never a fmt pattern.
    // spdlog owns the "warning:" level prefix; the shared formatter supplies the coded payload.
    spdlog::warn("{}", core::format_for_console(warning));
    collected_.push_back(warning);
    if (!core::is_warning_suppressed(warning, suppressed_codes_))
    {
      degraded_ = true;
    }
  }

  void record(core::WarningCode code, std::string message, std::string ecosystem = {},
              std::filesystem::path affected_path = {})
  {
    record(core::Warning{code, std::move(message), std::move(ecosystem), std::move(affected_path)});
  }

  void record_all(const std::vector<core::Warning>& warnings)
  {
    for (const core::Warning& warning : warnings)
    {
      record(warning);
    }
  }

  [[nodiscard]] bool degraded() const { return degraded_; }
  [[nodiscard]] const std::vector<core::Warning>& collected() const { return collected_; }

  /// Hands over ownership of everything collected so far (e.g. to an HTML report context).
  /// Recording after this call is still valid; `collected()`/`degraded()` simply restart
  /// empty/false for whatever is recorded afterward.
  [[nodiscard]] std::vector<core::Warning> take_collected() { return std::move(collected_); }

 private:
  std::set<std::string> suppressed_codes_;
  std::vector<core::Warning> collected_;
  bool degraded_ = false;
};

}  // namespace bomwerk::cli
