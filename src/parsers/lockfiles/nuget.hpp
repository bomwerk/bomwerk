#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::nuget
{

/// Per-file read cap. Larger than the 1 MiB manifest default: a
/// `packages.lock.json` repeats every transitive package per target framework
/// with its content hash and can run to megabytes.
inline constexpr std::size_t kMaxNugetLockfileBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxNugetLockfileBytes;  ///< per-file read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< lockfiles parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for .NET dependencies across every `packages.lock.json`,
/// `.csproj`, `packages.config` and `Directory.Packages.props`, returning
/// each package as a `pkg:nuget` component.
///
/// Confidence is a ladder, same shape as maven.cpp's pom.xml/gradle.lockfile
/// split:
/// - `packages.lock.json` -> High: the lockfile is NuGet's own resolver
///   output. `"type": "Project"` entries are project references :
///   first-party, skipped silently (the npm workspace-link precedent);
///   `Direct`, `Transitive` and `CentralTransitive` all emit. `contentHash`
///   is a base64 sha512 -> evidence detail, never `Component::sha256`.
/// - `.csproj` (`<PackageReference Include="Name" Version="1.2.3" />`) and
///   `packages.config` (`<package id="Name" version="1.2.3" />`) -> Medium: a
///   manifest declares a version, it does not resolve one: no lockfile
///   backs it. Only the attribute-based form is read; a `.csproj` version
///   given as a nested `<Version>` element (rare) degrades to a skip, not a
///   crash.
/// - A `.csproj` `PackageReference` with NO `Version` attribute at all is
///   Central Package Management's shape: its version resolves against the
///   nearest `Directory.Packages.props` `<PackageVersion Include="Name"
///   Version="1.2.3" />` entry, walking from the `.csproj`'s own directory
///   up to `root`: the same directory-scoped lookup MSBuild itself performs
///   for CPM. Also Medium: still a declaration, one file removed. No
///   covering `Directory.Packages.props`, or no matching entry in it,
///   degrades to the same missing-Version skip as a plain `.csproj` with no
///   `Version`.
/// - A `.csproj` `Include` or `Version` (and a central `PackageVersion`'s
///   `Version`) written as an MSBuild property, `$(Name)`, is expanded from
///   the properties in scope: the `<PropertyGroup>` entries of the project,
///   of every ancestor `Directory.Build.props` / `Directory.Packages.props`,
///   of whatever those `<Import>` from inside the scan root, and of the root's
///   `eng/Versions.props` and `eng/Version.Details.props` (the .NET Arcade
///   layout, always read when present). A property defined twice with
///   different values is ambiguous and never expands. The exact-version
///   notation `[1.2.3]` is read as `1.2.3`. A purl never carries an
///   unexpanded reference: an `Include` that stays unresolved drops the entry,
///   a `Version` that stays unresolved keeps it without a version at Low
///   confidence, and each case warns with file and line. `Condition`
///   attributes are not evaluated, and MSBuild property functions
///   (`$([MSBuild]::...)`) are never run: both count as unresolved.
///
/// The same package resolved/declared under several target frameworks or
/// manifests becomes ONE component with one evidence entry per source :
/// `core::merge_all` keeps the highest confidence across them. Package
/// casing is preserved (NuGet names are case-insensitive; the manifest's own
/// spelling is the identity recorded: CPM's name-to-version lookup alone is
/// case-insensitive, matching NuGet's own resolution). None of these
/// manifests mark dev-only packages, so scope is never guessed.
///
/// Reads files only: never invokes dotnet/nuget (Hard Rule 9). Never throws
/// past this producer's boundary: hostile input degrades to warnings (Hard
/// Rule 1). Output is deduplicated and purl-ordered via `core::merge_all`
/// (Rule 3).
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

/// As above, with caller-supplied limits.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root,
                                                               const ParseOptions& options);

/// As above, but scans a pre-built `core::FileIndex` instead of walking the
/// tree itself: the exclusion set that produced `file_index` is the one that
/// applies (`options.excluded_subtrees` is not consulted). `run_scan` uses this
/// to share its single walk.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               const ParseOptions& options);

}  // namespace bomwerk::parsers::lockfiles::nuget
