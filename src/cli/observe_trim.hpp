#pragma once
#include <filesystem>
#include <optional>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "observe/compile_map.hpp"
#include "observe/link_map.hpp"

namespace bomwerk::cli
{

/// Same default as `bomwerk observe --trace`, so observe, scan and trim
/// compose without the operator having to repeat a path.
inline constexpr const char* kDefaultObserveTracePath = ".bomwerk/trace.jsonl";

/// What an SBOM with no rooted component means. Only submodule and vendored
/// producers record where a component lives, so a lockfile-only inventory is
/// valid but cannot be judged by a compile trace.
inline constexpr const char* kNoRootedComponentsExplanation =
    "no component in this SBOM records where it lives in the repository, so a compile trace has "
    "nothing to attribute compiles to. Only vendored source and git submodules carry a location; "
    "components read from a lockfile (npm, conan, vcpkg, ...) never can.";

/// Everything the CLI needs after one trace has been mapped onto components.
/// Kept in cli rather than output so the output module never learns about
/// observe (module dependency law).
struct ObserveTraceApplication
{
  observe::UsedSetSummary summary;
  observe::CompileMap compile_map;
  observe::LinkMap link_map;
};

/// Resolve the trace `scan` should use. An explicit `--trace` wins, followed
/// by BOMWERK_TRACE, `<scan-root>/.bomwerk/trace.jsonl`, then the same path
/// under the current directory. Missing implicit candidates mean "no build
/// evidence" and do not warn; an invalid BOMWERK_TRACE does warn because the
/// operator explicitly selected it through the environment.
///
/// Never throws (rule 1): filesystem probes use error-code overloads.
[[nodiscard]] core::Result<std::optional<std::filesystem::path>> resolve_scan_trace_path(
    const std::filesystem::path& scan_root, const std::filesystem::path& explicit_trace_path = {});

/// Read `trace_path`, map its compile and link evidence onto `components`, and
/// set each rooted component's used_in_build verdict. Call only after
/// core::merge_all. An empty/unreadable trace returns `complete == false` and
/// leaves the components untouched so a missing observation can never turn
/// every located dependency into a false unused claim.
///
/// Warnings from every producer step are preserved in deterministic pipeline
/// order. Never throws across the CLI boundary (rule 1).
[[nodiscard]] core::Result<ObserveTraceApplication> apply_observe_trace(
    const std::filesystem::path& trace_path, const std::filesystem::path& scan_root,
    std::vector<core::Component>& components);

}  // namespace bomwerk::cli
