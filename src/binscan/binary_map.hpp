#pragma once
#include <cstddef>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "binscan/elf_read.hpp"
#include "core/model.hpp"
#include "core/result.hpp"

namespace bomwerk::binscan
{

/// What one scanned path turned out to hold.
enum class ArtifactKind
{
  Unreadable,    ///< missing, permission-denied, or over the size cap
  Unrecognized,  ///< opened fine, but is neither ELF nor `ar`
  Elf,           ///< see `ElfShape` for which kind
  Archive        ///< `ar`, either dialect
};

/// Protocol token for a kind, as written to the sidecar. Never user-facing
/// text; never localized. Same shape as `core::to_string(Scope)`.
constexpr const char* to_string(ArtifactKind kind)
{
  switch (kind)
  {
    case ArtifactKind::Unreadable:
      return "unreadable";
    case ArtifactKind::Unrecognized:
      return "unrecognized";
    case ArtifactKind::Elf:
      return "elf";
    case ArtifactKind::Archive:
      return "archive";
  }
  return "unrecognized";  // unreachable: all enumerators handled above
}

/// One artifact bomwerk opened, in the form the sidecar stores it. This is the
/// record the fingerprint matcher reads back, which is why it keeps the
/// per-artifact sample rather than only the aggregate the SBOM carries.
struct ScannedArtifact
{
  std::filesystem::path path;  ///< root-relative, so two machines write the same bytes
  ArtifactKind kind = ArtifactKind::Unrecognized;
  ElfShape shape = ElfShape::NotElf;  ///< meaningful only when `kind == Elf`
  std::string soname;                 ///< DT_SONAME, when the artifact declares one
  std::vector<std::string> needed;    ///< DT_NEEDED, sorted
  std::vector<std::string> members;   ///< archive member names, sorted
  std::vector<std::string> symbols;   ///< exported/indexed symbol sample, sorted
  bool needed_truncated = false;
  bool members_truncated = false;
  bool symbols_truncated = false;
  bool symbols_unavailable = false;
};

/// The tally behind every line of the summary block, and the reason the
/// exit code is what it is.
///
/// These exist so that "bomwerk found no dynamic dependencies" and "this
/// product HAS no dynamic dependencies" are never the same output. A pass over
/// a statically linked product legitimately produces no evidence, and an
/// operator must be able to tell that apart from a pass that was pointed at
/// the wrong tree: so each way of learning less than hoped gets its own
/// counter rather than being folded into one "skipped" number.
struct BinaryScanCounters
{
  std::size_t artifacts_scanned = 0;
  std::size_t elf_artifacts = 0;      ///< carried ELF magic; the four below partition it exactly
  std::size_t dynamic_artifacts = 0;  ///< carried a READABLE dynamic section
  std::size_t static_artifacts = 0;   ///< ELF, executable, no dynamic section at all
  std::size_t relocatable_artifacts = 0;   ///< ELF `.o`; cannot declare dependencies
  std::size_t malformed_artifacts = 0;     ///< ELF magic, but its structure could not be read
  std::size_t dynamic_without_needed = 0;  ///< a READABLE dynamic section listing nothing
  std::size_t archives = 0;
  std::size_t unrecognized_artifacts = 0;  ///< Mach-O on a macOS build, scripts, empty files
  std::size_t unreadable_artifacts = 0;
  std::size_t truncated_samples = 0;  ///< an artifact where some cap was hit
};

/// What the binaries proved about one component root.
struct BinaryEvidence
{
  std::filesystem::path root;
  std::vector<std::string> needed_sonames;  ///< DT_NEEDED entries resolved to a file under `root`
  std::size_t archive_member_count = 0;     ///< members of archives lying under `root`
  std::size_t shared_object_count = 0;      ///< prebuilt `.so` files lying under `root`
  /// The artifact that DECLARED `needed_sonames`, kept apart from the two
  /// below because it is a different artifact making a different claim: an
  /// archive under this root declares nothing, so quoting it as the declarer
  /// would put a false statement into the SBOM.
  std::filesystem::path first_declaring_artifact;
  std::string first_member;                   ///< sorted-first archive member
  std::filesystem::path first_shared_object;  ///< sorted-first prebuilt `.so` under `root`
};

/// Everything one binary pass learned.
struct BinaryMap
{
  std::map<std::filesystem::path, BinaryEvidence> evidence_by_root;
  std::vector<ScannedArtifact> artifacts;   ///< every path opened, sorted, for the sidecar
  std::set<std::string> unmatched_sonames;  ///< DT_NEEDED naming nothing inside this repository
  BinaryScanCounters counters;
};

/// Open every path in `artifacts` and attribute what it holds to
/// `component_roots`, relative to `scan_root`.
///
/// Two attribution pathways, and they are deliberately not the same claim:
///
///   * THE ARTIFACT'S OWN LOCATION. A `.a` or `.so` sitting under a component
///     root is that component, so its member names and symbols attribute
///     directly: this is the only view bomwerk has into a prebuilt vendored
///     archive.
///   * A `DT_NEEDED` SONAME. A soname carries no path, so matching it to a
///     component is a GUESS, and an unverified guess is invented evidence.
///     It is therefore checked against the repository: the same rule
///     `observe::map_links_to_roots` already applies to a bare `-lNAME`: by
///     looking for a file of that name under a component root, longest root
///     winning as everywhere else. A soname matching nothing lands in
///     `unmatched_sonames`: it is almost always a system library
///     (`libc.so.6`), which is the NORMAL case and therefore reported as
///     progress, never as a warning. Warning on every system library would
///     make the warning channel useless on the first real run.
///
/// Never throws (rule 1). Every degraded artifact is counted (see
/// `BinaryScanCounters`) and warned about; the pass always completes.
[[nodiscard]] core::Result<BinaryMap> map_binaries_to_roots(
    const std::vector<std::filesystem::path>& artifacts, const std::filesystem::path& scan_root,
    const std::set<std::filesystem::path>& component_roots);

/// Append `core::Source::Binary` evidence to every component `map` has
/// something to say about, and return how many components received it.
///
/// Deliberately does NOT touch `used_in_build`. That verdict belongs to
/// `observe::mark_used_in_build` alone: two places deciding one flag are two
/// places that can disagree, and a component this pass marked used but the
/// trim pass dropped would be the worst possible disagreement to ship.
///
/// Call this AFTER `core::merge_all`, for the same reason
/// `mark_used_in_build` documents: merging unions evidence, so evidence added
/// before a merge can be silently duplicated or reordered.
std::size_t apply_binary_evidence(std::vector<core::Component>& components, const BinaryMap& map);

}  // namespace bomwerk::binscan
