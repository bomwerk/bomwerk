#pragma once
#include <filesystem>
#include <string_view>

namespace bomwerk::cli
{

/// Write one generated artifact (SBOM, sidecar, report, trace) atomically
/// through `core::write_file_atomically`, so a failed or interrupted write
/// never leaves a truncated file where a whole one used to be.
///
/// On failure the explanation (failed step, path, reason, the state of the
/// destination, what to check) is logged at `error` and false is returned; the
/// caller then returns `core::kExitIncomplete`. `artifact_label` names the
/// artifact in that message, e.g. "SBOM" or "HTML report".
[[nodiscard]] bool write_artifact(const std::filesystem::path& path, std::string_view contents,
                                  std::string_view artifact_label);

}  // namespace bomwerk::cli
