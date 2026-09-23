#pragma once
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "core/result.hpp"

namespace bomwerk::core
{

/// True when `actual_filename` is the canonical `manifest_name` or a supported
/// naming-family member. `requirements.txt` enables the case-sensitive
/// `requirements-<name>.txt`, `requirements_<name>.txt` and
/// `requirements.<name>.txt` prefix families, and the `<name>.requirements.txt`
/// suffix family; `.csproj` matches any filename ending in `.csproj` (a
/// project file is named after the project, not a fixed literal); every
/// other manifest name remains an exact match.
[[nodiscard]] bool matches_manifest_name(std::string_view actual_filename,
                                         std::string_view manifest_name);

/// Manifest filenames bomwerk recognizes out of the box (the M1 parser
/// targets). Sorted container so iteration is deterministic (rule 3).
const std::set<std::string>& default_manifest_names();

/// Load manifest filenames from `list_path` (see core/name_list.hpp for the
/// file format). Never throws (rule 1): an unreadable or empty file degrades
/// to the built-in list with a warning, so a scan always has something to
/// look for.
Result<std::set<std::string>> load_manifest_names(const std::filesystem::path& list_path);

/// One ecosystem's manifest landscape: what bomwerk parses today, what it
/// recognizes as a real lockfile but has no parser for yet, and the loose
/// manifest that declares version ranges instead of resolved versions.
/// Entries move left as parsers land.
struct EcosystemManifests
{
  std::string_view ecosystem;                       ///< "npm", "composer", …
  std::vector<std::string_view> supported_locks;    ///< a producer reads these today
  std::vector<std::string_view> unsupported_locks;  ///< a real lockfile, no parser yet
  std::vector<std::string_view> loose_manifests;    ///< ranges only, no resolved versions
};

/// The per-ecosystem manifest table, ordered by ecosystem name (rule 3).
[[nodiscard]] const std::vector<EcosystemManifests>& ecosystem_manifests();

/// One ecosystem's unparsed-manifest finding. A scan produces at most ONE of
/// these per ecosystem, so a monorepo holding hundreds of `package.json` files
/// yields a single sentence rather than hundreds of warnings.
struct UnparsedManifestReport
{
  std::string ecosystem;                     ///< "npm", "composer", …
  std::string filename;                      ///< the reported manifest's filename
  std::vector<std::filesystem::path> paths;  ///< root-relative, sorted
  bool is_lockfile = false;                  ///< true => a real lockfile we cannot read
};

/// Find the dependency manifests in `files` that name a real dependency set
/// bomwerk cannot read yet, so a scan can report what it did NOT check instead
/// of presenting an empty SBOM as a clean one.
///
/// `files` are root-relative and sorted: a `core::FileIndex::files`. A
/// candidate is suppressed when a supported lockfile for the same ecosystem
/// sits in its own directory or in any ANCESTOR directory. That is what keeps
/// a cargo workspace's member `Cargo.toml` files silent under a single root
/// `Cargo.lock`, while still reporting a `bun.lock` living in a subtree
/// unrelated to some other subtree's `package-lock.json`.
///
/// A real-but-unreadable lockfile outranks a loose manifest, so a repo holding
/// both `bun.lock` and `package.json` reports the lockfile only: one problem,
/// not two. Never throws (rule 1); reports are ordered by ecosystem (rule 3).
[[nodiscard]] std::vector<UnparsedManifestReport> find_unparsed_manifests(
    const std::vector<std::filesystem::path>& files);

}  // namespace bomwerk::core
