#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::maven
{

/// Per-file read cap. Larger than the 1 MiB manifest default: a
/// `gradle.lockfile` of a large multi-configuration build lists every resolved
/// module per configuration and can run to megabytes; a `pom.xml` never comes
/// close, so one cap serves both.
inline constexpr std::size_t kMaxMavenFileBytes = 8u * 1024u * 1024u;

/// Runtime-tunable safety limits for `parse`. Numeric defaults suit real
/// projects; exceeding a limit returns partial output with a warning and
/// `complete = false`, and never crashes (Hard Rule 1).
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxMavenFileBytes;  ///< per-file read cap (8 MiB)
  std::size_t max_scanned_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< maven files parsed per scan
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;

  /// Subtree roots to skip, `root`-relative and lexically normal (e.g. the
  /// submodules producer's `Component::root` values): a vendored submodule is
  /// one component, not a source of nested manifests.
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan `root` for JVM dependencies across every `pom.xml` and
/// `gradle.lockfile`, returning each dependency as a `pkg:maven` component
/// (`groupId` is the purl namespace, `artifactId` the name).
///
/// Confidence ladder:
/// - `gradle.lockfile` lines (`group:artifact:version=configurations`) ->
///   High: they are Gradle's own resolver output. An entry whose every
///   configuration name starts with `test` gets CycloneDX `Scope::Excluded` :
///   the lockfile itself says test-only, nothing is guessed.
/// - a pom.xml's own `groupId`/`artifactId`/`version` (its "self-identity"
///   component, one per file) -> High: a hardcoded fact declared in the file
///   itself, not a resolved or interpolated reference.
/// - `pom.xml` `<dependency>` elements -> Medium: a pom declares, it does not
///   resolve. `<scope>test</scope>` => `Scope::Excluded`;
///   `<optional>true</optional>` => `Scope::Optional`; other declared scopes
///   (`provided`, `runtime`, …) stay Required with the scope recorded in the
///   evidence detail. A dependency whose `<groupId>`/`<artifactId>` could not
///   be fully resolved from `<properties>` is downgraded to Low instead (see
///   below): the one way a pom.xml entry lands below Medium.
///
/// pom.xml is read by a deliberately minimal XML scanner, not a full parser
/// (a minimal parse by design; no XML dependency: an explicit human
/// decision). Its exact scope, everything else degrades to warn-and-skip:
/// - comments and CDATA sections are stripped/unwrapped first;
/// - `<dependencyManagement>` spans are removed (version pins, not
///   dependencies), as are `<exclusions>` spans (their nested
///   groupId/artifactId would poison the flat extraction);
/// - a `${property}` version is resolved ONE level against the same pom's
///   `<properties>` block plus the `project.version` / `project.groupId` /
///   `project.parent.version` pseudo-properties; the pom's own coordinates
///   come from the nearest `<groupId>`/`<version>` before the first
///   `<dependencies>` block (conventional pom order), falling back to the
///   `<parent>` coordinates. No recursion, no cross-file inheritance;
/// - those same coordinates are ALSO emitted as one `pkg:maven`
///   self-identity component per pom.xml, unconditionally :
///   Maven has no directory-shape signal like vcpkg's `ports/<name>/` to
///   scope this to "vendored module" only, so a self-scan of one's own
///   top-level Maven project will list that project as a component of its
///   own SBOM. Skipped (with one warning, not silently) when `groupId`,
///   `artifactId` or `version` is unresolvable. Carries the pom's own
///   `<licenses><license><name>` text verbatim when present (first
///   `<license>` entry only; no SPDX normalization: parsers/ never
///   includes output/);
/// - `<groupId>`/`<artifactId>` get the SAME one-level `${property}`
///   resolution as `<version>`, sharing its exact lookup rules
///   (no recursion; a value only partially containing `${` is unresolvable).
///   Unlike `<version>`, an unresolved `<groupId>`/`<artifactId>` is never
///   dropped: the raw, unresolved text is kept as the component's identity
///   (so a `${project.groupId}` inherited from a parent reactor pom this
///   parser deliberately never reads surfaces verbatim, rather than
///   vanishing), the dependency's confidence is downgraded to Low, and it is
///   counted into one per-file warning: matching how every other producer
///   in this codebase treats an identifier it cannot fully resolve
///   (`cmake_deps`, vcpkg, Python, submodules, conan): downgrade and report,
///   never guess, but never make the finding disappear either;
/// - a dependency whose version is absent or stays unresolved is counted and
///   reported once per file: never emitted with a guessed version;
/// - XML entities are not decoded, and `<dependency>` elements inside
///   `<profiles>` or `<build>` plugin sections are scanned like any other:
///   built-in manifest defaults are scan candidates, not proof of use.
///
/// Reads files only: never invokes mvn/gradle (Hard Rule 9). Never throws
/// past this producer's boundary: hostile input degrades to warnings (Hard
/// Rule 1). Output is deduplicated and purl-ordered via `core::merge_all`
/// (Rule 3), so the same artifact declared in a pom and locked by Gradle
/// becomes ONE component with layered evidence.
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

}  // namespace bomwerk::parsers::lockfiles::maven
