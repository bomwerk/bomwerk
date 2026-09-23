#pragma once
#include <filesystem>
#include <set>
#include <string>

#include "core/warning_code.hpp"

namespace bomwerk::core
{

/// One diagnostic raised by a producer or command. `code` is the permanent,
/// machine-readable identity (see warning_code.hpp); `message` is the human-readable text
/// shown today, unchanged; `ecosystem` and `affected_path` are optional structured data a
/// `--warnings` manifest groups and deduplicates on, left empty when the cause has no
/// natural ecosystem or isn't about one specific file.
struct Warning
{
  WarningCode code;
  std::string message;
  std::string ecosystem;                ///< "npm", "vcpkg", ...; empty when not applicable
  std::filesystem::path affected_path;  ///< root-relative; empty when not about one file
  WarningCodeInfo external_code{};      ///< set only when `code` is `kExternallyDefined`
};

/// The id and title to show for `warning`, wherever its code was defined. Every consumer
/// (console, `--warnings` manifest, HTML report) resolves through this rather than through
/// `warning_code_info`, so a code owned by a composed module prints exactly like a local one.
[[nodiscard]] inline WarningCodeInfo code_info_of(const Warning& warning)
{
  if (warning.code == WarningCode::kExternallyDefined)
  {
    return warning.external_code;
  }
  return warning_code_info(warning.code);
}

/// The coded payload every stderr-facing warning uses when the code must be visible:
/// `[BW-XXX]: <message>`. The stderr logger owns the `warning:` level prefix, so keeping
/// it out of this payload prevents `warning: warning[BW-XXX]` from being printed.
[[nodiscard]] inline std::string format_for_console(WarningCode code, const std::string& message)
{
  return "[" + std::string(warning_code_info(code).id) + "]: " + message;
}

[[nodiscard]] inline std::string format_for_console(const Warning& warning)
{
  return "[" + std::string(code_info_of(warning).id) + "]: " + warning.message;
}

/// Returns whether a code id is covered by a suppression entry. A bare code suppresses that
/// cause for every ecosystem; `CODE:ecosystem` narrows it to one ecosystem.
[[nodiscard]] inline bool is_warning_suppressed(const std::string& code_id,
                                                const std::string& ecosystem,
                                                const std::set<std::string>& suppressed_entries)
{
  if (suppressed_entries.find(code_id) != suppressed_entries.end())
  {
    return true;
  }
  return suppressed_entries.find(code_id + ":" + ecosystem) != suppressed_entries.end();
}

[[nodiscard]] inline bool is_warning_suppressed(const Warning& warning,
                                                const std::set<std::string>& suppressed_entries)
{
  return is_warning_suppressed(std::string(code_info_of(warning).id), warning.ecosystem,
                               suppressed_entries);
}

}  // namespace bomwerk::core
