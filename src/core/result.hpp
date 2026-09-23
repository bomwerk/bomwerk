#pragma once
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "core/warning.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::core
{

/// Error/warning policy (docs/CONTRIBUTING.md hard rule 1): producers never throw across
/// module boundaries; they return a value plus warnings. Exit codes derive
/// from this: any non-suppressed warning => `kExitCompletedWithWarnings`,
/// `complete == false` => `kExitIncomplete` (see core/exit_codes.hpp).
template <typename T>
struct Result
{
  T value{};
  std::vector<Warning> warnings;
  bool complete = true;  ///< false => something was skipped => exit-code-2 path

  /// Records one warning. `code` is the permanent cause identity; `message` is
  /// the human-readable text shown today; `ecosystem`/`affected_path` are optional
  /// structured data a `--warnings` manifest groups on, left empty when not applicable.
  void warn(WarningCode code, std::string message, std::string ecosystem = {},
            std::filesystem::path affected_path = {})
  {
    warnings.push_back(
        Warning{code, std::move(message), std::move(ecosystem), std::move(affected_path)});
  }

  /// Records one warning whose code is owned by a module composed on top of this library:
  /// `info` must name static storage (a `constexpr` table entry), because `Warning` keeps
  /// the views, not copies.
  void warn(WarningCodeInfo info, std::string message, std::string ecosystem = {},
            std::filesystem::path affected_path = {})
  {
    warnings.push_back(Warning{WarningCode::kExternallyDefined, std::move(message),
                               std::move(ecosystem), std::move(affected_path), info});
  }

  /// Re-records an already-built Warning, e.g. one propagated up from a lower-level
  /// Result<U> whose own warnings this Result absorbs unchanged.
  void warn(Warning warning) { warnings.push_back(std::move(warning)); }
};

}  // namespace bomwerk::core
