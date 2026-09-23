#pragma once
#include <array>
#include <string>
#include <string_view>

namespace bomwerk::observe
{

/// The tool names bomwerk shims. A build invokes these by bare
/// name, so a directory of identically-named executables placed first on PATH
/// observes every compile and link without the build system knowing. `ld` and
/// `ar` ride along because link and archive lines carry the evidence the link scan needs
/// to tell a genuinely linked component from a merely declared one.
inline constexpr std::array<std::string_view, 8> kShimmedToolNames{"cc",    "c++",     "gcc", "g++",
                                                                   "clang", "clang++", "ld",  "ar"};

/// Environment variable naming the trace file. A shim with this unset does no
/// logging at all and execs straight through, which is what makes a persistent
/// shim directory inert outside a `bomwerk observe` run.
inline constexpr std::string_view kTraceEnvVarName = "BOMWERK_TRACE";

/// Prefix of the per-tool variables carrying the ABSOLUTE path of the real
/// tool, e.g. `BOMWERK_REAL_CC=/usr/bin/cc`. Absolute is the whole point: a
/// shim must never search PATH, which begins with the shim directory itself.
inline constexpr std::string_view kRealToolEnvVarPrefix = "BOMWERK_REAL_";

/// Suffix of the sidecar file recorded next to each shim (`cc` => `cc.real`),
/// holding the same absolute path as the environment variable. The fallback
/// matters: a CMake cache configured under observe stores the shim's absolute
/// path, so a later PLAIN `cmake --build` invokes the shim with none of our
/// variables set. Without the sidecar that build would die at exit 127; with
/// it the shim quietly execs the real tool and the developer's tree keeps
/// working.
inline constexpr std::string_view kRealToolSidecarSuffix = ".real";

/// Environment variable name carrying the real path of `tool_name`, e.g.
/// `"c++"` => `"BOMWERK_REAL_CPP"`. Upper-cased, `+` becomes `P`, and anything
/// else outside `[A-Za-z0-9]` becomes `_` so the result is always a legal
/// variable name. Empty input yields an empty string. Both the parent (which
/// sets the variables) and the shim (which reads them) go through here: the
/// two must never disagree.
[[nodiscard]] std::string shim_env_var_name(std::string_view tool_name);

/// Whether `tool_name` is one of `kShimmedToolNames`.
[[nodiscard]] bool is_shimmed_tool_name(std::string_view tool_name);

}  // namespace bomwerk::observe
