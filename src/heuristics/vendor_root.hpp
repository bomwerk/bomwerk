#pragma once
#include <filesystem>
#include <optional>

namespace bomwerk::heuristics
{

/// The "vendor root" a file belongs to: the first (outermost) trigger-directory
/// path component plus its immediate subfolder, e.g.
/// `third_party/zlib/src/inflate.c` -> `third_party/zlib`. The trigger names
/// are `third_party`, `thirdparty`, `vendor`, `external`, `deps` and `libs`.
///
/// Returns nullopt, meaning "this file belongs to no vendored library", when:
/// - the path contains no trigger directory at all;
/// - the file sits directly in a trigger directory with no subfolder to name a
///   library;
/// - the trigger sits below a test or fixture directory, which describes test
///   data rather than a dependency the product ships;
/// - the resulting root's own name is a DNS-style namespace container
///   (`github.com`, `k8s.io`, `gopkg.in`). Ecosystem lockfiles are the
///   authoritative identity for a `vendor/github.com/owner/repository` tree, so
///   nothing here may invent a `github.com` placeholder component for it.
///
/// A nested trigger name INSIDE an already-claimed root
/// (`third_party/boost/libs/algorithm`: `libs` is itself a trigger word, but
/// `boost` is not) stops at `boost`, because the outer trigger's immediate
/// subfolder already names a specific library. But when that immediate
/// subfolder is ITSELF a trigger word (`third_party/libs/zlib` and
/// `third_party/libs/openssl`: `libs` right after `third_party` is generic, not
/// a library name), the chain keeps consuming trigger-named components until it
/// reaches one that is not, so the two libraries get distinct roots instead of
/// collapsing into `third_party/libs`.
///
/// `relative_path` must be root-relative and lexically normal, as every path in
/// a `core::FileIndex` already is.
///
/// Shared rather than private to one producer: `vendored_cpp` names the
/// component for a root and the fingerprint matcher scores that same root by
/// content, and the two join on the root path. Two copies of this rule would
/// eventually disagree, and a disagreement here looks like a library the
/// matcher found and the SBOM has no component for.
[[nodiscard]] std::optional<std::filesystem::path> vendor_root_for(
    const std::filesystem::path& relative_path);

}  // namespace bomwerk::heuristics
