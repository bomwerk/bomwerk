#include "binscan/binary_map.hpp"

#include <algorithm>
#include <optional>
#include <string_view>
#include <utility>

#include "binscan/archive_read.hpp"
#include "binscan/bounds.hpp"
#include "core/exclusions.hpp"
#include "core/file_index.hpp"
#include "core/file_io.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::binscan
{
namespace
{

/// Enough bytes to tell the two formats apart by magic (`\x7fELF` is four,
/// `!<arch>\n` is eight) without reading a whole artifact twice.
///
/// Dispatching on a peek rather than trying each reader in turn is what keeps
/// an unreadable file from producing two identical warnings, one per reader.
constexpr std::size_t kMagicPeekBytes = 8;

constexpr std::string_view kElfMagic =
    "\x7F"
    "ELF";
constexpr std::string_view kArchiveMagic = "!<arch>\n";

/// Extension a shared object always carries somewhere in its name, before any
/// soname version.
constexpr std::string_view kSharedObjectExtension = ".so";

/// How many trailing numeric segments a soname may carry (`libz.so.1.2.3` has
/// three) before bomwerk stops looking for the `.so` underneath. Real sonames
/// are at most major.minor.patch: the same limit `observe::link_map` applies
/// to the same question on the other side of the build.
constexpr std::size_t kMaxSonameVersionSegments = 3;

/// `libfoo.so` from `libfoo.so.1.2.3`, or nothing when `name` is not a shared
/// object at all.
///
/// A build links against `libfoo.so` and records `libfoo.so.1` in DT_NEEDED,
/// so matching a soname to a vendored file has to see through the version or
/// the common case never matches.
[[nodiscard]] std::optional<std::string> shared_object_base_name(std::string_view name)
{
  std::string_view candidate = name;
  for (std::size_t stripped = 0; stripped <= kMaxSonameVersionSegments; ++stripped)
  {
    const std::size_t last_dot = candidate.rfind('.');
    if (last_dot == std::string_view::npos)
    {
      return std::nullopt;
    }
    if (candidate.substr(last_dot) == kSharedObjectExtension)
    {
      return std::string(candidate);
    }
    const std::string_view extension = candidate.substr(last_dot + 1);
    if (extension.empty() ||
        !std::all_of(extension.begin(), extension.end(),
                     [](unsigned char character) { return character >= '0' && character <= '9'; }))
    {
      return std::nullopt;
    }
    candidate = candidate.substr(0, last_dot);
  }
  return std::nullopt;
}

/// The longest root in `roots` containing `relative_path`, or nothing.
///
/// Longest-first is what attributes a file under `third_party/zlib` to zlib
/// rather than to a `third_party` component sitting above it: the same rule
/// `observe::enclosing_root` applies to compiles and links. It is restated
/// here rather than shared because the module dependency law (docs/CONTRIBUTING.md)
/// forbids a producer including another producer, and that boundary is worth
/// more than the six lines.
[[nodiscard]] const fs::path* longest_enclosing_root(const fs::path& relative_path,
                                                     const std::set<fs::path>& roots)
{
  const fs::path* best = nullptr;
  for (const fs::path& root : roots)
  {
    const fs::path::iterator root_end = root.end();
    fs::path::iterator root_part = root.begin();
    fs::path::iterator path_part = relative_path.begin();
    const fs::path::iterator path_end = relative_path.end();
    while (root_part != root_end && path_part != path_end && *root_part == *path_part)
    {
      ++root_part;
      ++path_part;
    }
    if (root_part != root_end)
    {
      continue;  // `relative_path` is not inside this root
    }
    if (best == nullptr || root.native().size() > best->native().size())
    {
      best = &root;
    }
  }
  return best;
}

/// Every shared-object filename living under a component root, mapped to the
/// root that owns it.
///
/// Built once from `core::build_file_index` rather than searched per soname: a
/// real product declares dozens of DT_NEEDED entries and a vendored tree holds
/// thousands of files, and walking the tree once is the difference between a
/// scan and a quadratic one.
class SharedObjectIndex
{
 public:
  void build(const fs::path& scan_root, const std::set<fs::path>& component_roots,
             core::Result<BinaryMap>& outcome);

  /// The component root owning a file that could answer to `soname`, or
  /// nothing. Both the versioned spelling and its unversioned base are tried,
  /// because a repository holds `libfoo.so` while the binary names
  /// `libfoo.so.1`.
  [[nodiscard]] const fs::path* root_for_soname(const std::string& soname) const;

 private:
  void remember(const std::string& file_name, const fs::path& root);

  std::map<std::string, fs::path> root_by_file_name_;
};

void SharedObjectIndex::remember(const std::string& file_name, const fs::path& root)
{
  const auto existing = root_by_file_name_.find(file_name);
  if (existing == root_by_file_name_.end())
  {
    root_by_file_name_.emplace(file_name, root);
    return;
  }
  // Same filename vendored under two components: the more specific root wins,
  // and ties go to the one already there. `build_file_index` returns a sorted
  // list, so "already there" is a deterministic choice (rule 3), not an
  // accident of directory order.
  if (root.native().size() > existing->second.native().size())
  {
    existing->second = root;
  }
}

void SharedObjectIndex::build(const fs::path& scan_root, const std::set<fs::path>& component_roots,
                              core::Result<BinaryMap>& outcome)
{
  if (component_roots.empty())
  {
    return;  // nothing to attribute to; walking the tree would prove nothing
  }
  core::Result<core::FileIndex> index =
      core::build_file_index(scan_root, core::default_excluded_dir_names(), {}, component_roots);
  for (core::Warning& warning : index.warnings)
  {
    outcome.warn(std::move(warning));
  }
  for (const fs::path& relative_path : index.value.files)
  {
    const std::string file_name = relative_path.filename().string();
    if (!shared_object_base_name(file_name))
    {
      continue;
    }
    const fs::path* root = longest_enclosing_root(relative_path, component_roots);
    if (root != nullptr)
    {
      remember(file_name, *root);
    }
  }
}

const fs::path* SharedObjectIndex::root_for_soname(const std::string& soname) const
{
  const auto exact = root_by_file_name_.find(soname);
  if (exact != root_by_file_name_.end())
  {
    return &exact->second;
  }
  const std::optional<std::string> base = shared_object_base_name(soname);
  if (!base || *base == soname)
  {
    return nullptr;
  }
  const auto unversioned = root_by_file_name_.find(*base);
  if (unversioned != root_by_file_name_.end())
  {
    return &unversioned->second;
  }
  return nullptr;
}

/// Which format an artifact is, decided from its first bytes.
enum class MagicKind
{
  Unreadable,
  Elf,
  Archive,
  Unrecognized
};

[[nodiscard]] MagicKind peek_magic(const fs::path& absolute_path, const fs::path& relative_path,
                                   core::Result<BinaryMap>& outcome)
{
  const core::BoundedFileRead peek = core::read_file_bounded(absolute_path, kMagicPeekBytes);
  if (!peek.readable)
  {
    outcome.warn(core::WarningCode::kBinaryUnreadable,
                 relative_path.generic_string() +
                     ": named by the build trace but cannot be read now; skipped");
    return MagicKind::Unreadable;
  }
  const std::string_view head(peek.bytes);
  if (head.starts_with(kElfMagic))
  {
    return MagicKind::Elf;
  }
  if (head.starts_with(kArchiveMagic))
  {
    return MagicKind::Archive;
  }
  return MagicKind::Unrecognized;
}

/// Evidence sentences for one root: one per resolved soname, plus one for
/// archive contents.
///
/// Per soname rather than one summary line, because these strings do not stay
/// in memory: `output::write_cyclonedx` emits each as a `bomwerk:binary`
/// property, so a consumer reading the SBOM sees the actual library name.
/// "3 dynamic dependencies resolved" would be a fact about bomwerk; "DT_NEEDED
/// libvendcrypto.so.1" is a fact about the product.
///
/// The two kinds are kept apart because they rest on different proof: what a
/// binary DECLARES it loads, and what an archive lying inside the component
/// CONTAINS.
[[nodiscard]] std::vector<std::string> evidence_details(const BinaryEvidence& evidence)
{
  std::vector<std::string> details;
  for (const std::string& soname : evidence.needed_sonames)
  {
    details.push_back("binary: DT_NEEDED " + soname + " resolves under " +
                      evidence.root.generic_string() + " (declared by " +
                      evidence.first_declaring_artifact.generic_string() + ")");
  }
  if (evidence.archive_member_count > 0)
  {
    details.push_back("binary: " + std::to_string(evidence.archive_member_count) +
                      " archive member(s) under " + evidence.root.generic_string() + " (e.g. " +
                      evidence.first_member + ")");
  }
  if (evidence.shared_object_count > 0)
  {
    details.push_back("binary: " + std::to_string(evidence.shared_object_count) +
                      " prebuilt shared object(s) under " + evidence.root.generic_string() +
                      " (e.g. " + evidence.first_shared_object.generic_string() + ")");
  }
  return details;
}

/// Whether any cap was hit while reading one artifact.
[[nodiscard]] bool sample_was_truncated(const ScannedArtifact& artifact)
{
  return artifact.needed_truncated || artifact.members_truncated || artifact.symbols_truncated;
}

}  // namespace

core::Result<BinaryMap> map_binaries_to_roots(const std::vector<fs::path>& artifacts,
                                              const fs::path& scan_root,
                                              const std::set<fs::path>& component_roots)
{
  core::Result<BinaryMap> outcome;

  SharedObjectIndex shared_objects;
  shared_objects.build(scan_root, component_roots, outcome);

  // Sorted so the "e.g." examples below, and the sidecar's artifact list, do
  // not depend on the order the trace happened to record links in (rule 3).
  std::vector<fs::path> ordered_artifacts = artifacts;
  std::sort(ordered_artifacts.begin(), ordered_artifacts.end());
  ordered_artifacts.erase(std::unique(ordered_artifacts.begin(), ordered_artifacts.end()),
                          ordered_artifacts.end());

  BinaryScanCounters& counters = outcome.value.counters;
  for (const fs::path& relative_path : ordered_artifacts)
  {
    ++counters.artifacts_scanned;
    const fs::path absolute_path = scan_root / relative_path;

    ScannedArtifact artifact;
    artifact.path = relative_path;

    const MagicKind magic = peek_magic(absolute_path, relative_path, outcome);
    if (magic == MagicKind::Unreadable)
    {
      ++counters.unreadable_artifacts;
      artifact.kind = ArtifactKind::Unreadable;
      outcome.value.artifacts.push_back(std::move(artifact));
      continue;
    }
    if (magic == MagicKind::Unrecognized)
    {
      ++counters.unrecognized_artifacts;
      artifact.kind = ArtifactKind::Unrecognized;
      outcome.value.artifacts.push_back(std::move(artifact));
      continue;
    }

    if (magic == MagicKind::Elf)
    {
      core::Result<ElfImage> image = read_elf(absolute_path);
      for (core::Warning& warning : image.warnings)
      {
        outcome.warn(std::move(warning));
      }
      ++counters.elf_artifacts;
      artifact.kind = ArtifactKind::Elf;
      artifact.shape = image.value.shape;
      artifact.soname = std::move(image.value.soname);
      artifact.needed = std::move(image.value.needed);
      artifact.symbols = std::move(image.value.exported_symbols);
      artifact.needed_truncated = image.value.needed_truncated;
      artifact.symbols_truncated = image.value.symbols_truncated;
      artifact.symbols_unavailable = image.value.symbols_unavailable;

      // Every file carrying ELF magic lands in exactly one bucket, so the
      // summary's breakdown always reconciles with `elf_artifacts`. A file
      // whose structure could not be read is `Malformed`, never folded into
      // `static_artifacts` -- "statically linked" is a claim about the
      // product, and an unreadable file has not earned it.
      if (image.value.shape == ElfShape::StaticExecutable)
      {
        ++counters.static_artifacts;
      }
      else if (image.value.shape == ElfShape::Relocatable)
      {
        ++counters.relocatable_artifacts;
      }
      else if (image.value.shape == ElfShape::Dynamic)
      {
        ++counters.dynamic_artifacts;
        // An empty NEEDED list is only a statement about the product when the
        // names were actually readable; otherwise it is an admission, and it
        // is counted as one.
        if (image.value.names_unavailable)
        {
          ++counters.malformed_artifacts;
        }
        else if (artifact.needed.empty())
        {
          ++counters.dynamic_without_needed;
        }
      }
      else
      {
        ++counters.malformed_artifacts;
      }
    }
    else
    {
      core::Result<ArchiveContents> contents = read_archive(absolute_path);
      for (core::Warning& warning : contents.warnings)
      {
        outcome.warn(std::move(warning));
      }
      ++counters.archives;
      artifact.kind = ArtifactKind::Archive;
      artifact.members = std::move(contents.value.member_names);
      artifact.symbols = std::move(contents.value.indexed_symbols);
      artifact.members_truncated = contents.value.members_truncated;
      artifact.symbols_truncated = contents.value.symbols_truncated;
      artifact.symbols_unavailable = contents.value.symbols_unavailable;
    }

    if (sample_was_truncated(artifact))
    {
      ++counters.truncated_samples;
    }

    // Pathway one: what this artifact DECLARES it loads. A soname is only
    // attributed once a file answering to it is found in the repository --
    // an unverified guess would be invented evidence.
    for (const std::string& soname : artifact.needed)
    {
      const fs::path* root = shared_objects.root_for_soname(soname);
      if (root == nullptr)
      {
        outcome.value.unmatched_sonames.insert(soname);
        continue;
      }
      BinaryEvidence& evidence = outcome.value.evidence_by_root[*root];
      evidence.root = *root;
      if (std::find(evidence.needed_sonames.begin(), evidence.needed_sonames.end(), soname) ==
          evidence.needed_sonames.end())
      {
        evidence.needed_sonames.push_back(soname);
      }
      if (evidence.first_declaring_artifact.empty())
      {
        evidence.first_declaring_artifact = relative_path;
      }
    }

    // Pathway two: where this artifact LIVES. A prebuilt archive or shared
    // object under a component root IS that component, so its contents are
    // evidence about it directly -- the only view bomwerk ever gets into a
    // library whose sources it never watches compile.
    const bool is_contained_binary =
        artifact.kind == ArtifactKind::Archive ||
        (artifact.kind == ArtifactKind::Elf && artifact.shape == ElfShape::Dynamic);
    if (is_contained_binary)
    {
      const fs::path* root = longest_enclosing_root(relative_path, component_roots);
      if (root != nullptr)
      {
        BinaryEvidence& evidence = outcome.value.evidence_by_root[*root];
        evidence.root = *root;
        if (artifact.kind == ArtifactKind::Archive && !artifact.members.empty())
        {
          evidence.archive_member_count += artifact.members.size();
          if (evidence.first_member.empty())
          {
            evidence.first_member = artifact.members.front();
          }
        }
        else if (artifact.kind == ArtifactKind::Elf)
        {
          ++evidence.shared_object_count;
          if (evidence.first_shared_object.empty())
          {
            evidence.first_shared_object = relative_path;
          }
        }
      }
    }

    outcome.value.artifacts.push_back(std::move(artifact));
  }

  // Sort each root's soname list once, here, so the "e.g." example in the
  // evidence text is the same on every run (rule 3).
  for (auto& entry : outcome.value.evidence_by_root)
  {
    std::sort(entry.second.needed_sonames.begin(), entry.second.needed_sonames.end());
  }

  // Aggregated diagnostics. Each of these is a distinct way of learning less
  // than hoped, and collapsing them would lose exactly the distinction an
  // operator needs: a statically linked product HAS no dynamic dependencies,
  // which is not the same as bomwerk failing to find any.
  // The whole family below shares one code, kBinaryEvidenceLimited: each is a distinct reason
  // this run's dynamic-dependency evidence is partial rather than a distinct cause in its own
  // right (this mapping).
  if (counters.static_artifacts > 0)
  {
    outcome.warn(core::WarningCode::kBinaryEvidenceLimited,
                 std::to_string(counters.static_artifacts) +
                     " build output(s) are statically linked; they declare no dynamic "
                     "dependencies");
  }
  if (counters.relocatable_artifacts > 0)
  {
    outcome.warn(core::WarningCode::kBinaryEvidenceLimited,
                 std::to_string(counters.relocatable_artifacts) +
                     " build output(s) are relocatable objects, which cannot declare "
                     "dependencies");
  }
  if (counters.dynamic_without_needed > 0)
  {
    outcome.warn(core::WarningCode::kBinaryEvidenceLimited,
                 std::to_string(counters.dynamic_without_needed) +
                     " build output(s) carry a dynamic section that names no library");
  }
  if (counters.malformed_artifacts > 0)
  {
    outcome.warn(core::WarningCode::kBinaryEvidenceLimited,
                 std::to_string(counters.malformed_artifacts) +
                     " build output(s) carry ELF magic but a structure bomwerk could not read; "
                     "what they declare is unknown, not absent");
  }
  if (counters.unrecognized_artifacts > 0)
  {
    outcome.warn(core::WarningCode::kBinaryEvidenceLimited,
                 std::to_string(counters.unrecognized_artifacts) +
                     " build output(s) are neither ELF nor ar archives; bomwerk reads no dynamic "
                     "dependencies from them (a macOS build emits Mach-O, which this pass does "
                     "not parse)");
  }
  if (counters.truncated_samples > 0)
  {
    outcome.warn(core::WarningCode::kBinaryEvidenceLimited,
                 std::to_string(counters.truncated_samples) +
                     " artifact(s) declare more entries than bomwerk records; their samples are "
                     "partial");
  }
  if (counters.elf_artifacts == 0 && counters.archives == 0 && counters.artifacts_scanned > 0)
  {
    outcome.warn(core::WarningCode::kBinaryEvidenceLimited,
                 "no build output could be read as a binary; this pass proved nothing");
  }
  // Two very different reasons to have attributed nothing, and saying the
  // wrong one sends an operator looking in the wrong place.
  if (outcome.value.evidence_by_root.empty() && counters.artifacts_scanned > 0)
  {
    if (outcome.value.unmatched_sonames.empty())
    {
      outcome.warn(
          core::WarningCode::kBinaryEvidenceLimited,
          "no binary evidence attributed to any component; no build output declared a dynamic "
          "dependency or lay inside a component's directory");
    }
    else
    {
      outcome.warn(
          core::WarningCode::kBinaryEvidenceLimited,
          "no binary evidence attributed to any component; every dynamic dependency named a "
          "library outside this repository");
    }
  }

  return outcome;
}

std::size_t apply_binary_evidence(std::vector<core::Component>& components, const BinaryMap& map)
{
  std::size_t components_marked = 0;
  for (core::Component& component : components)
  {
    const fs::path root = core::normalized_subtree_path(component.root);
    if (root.empty())
    {
      continue;
    }
    const auto found = map.evidence_by_root.find(root);
    if (found == map.evidence_by_root.end())
    {
      continue;
    }
    const std::vector<std::string> details = evidence_details(found->second);
    if (details.empty())
    {
      continue;
    }
    for (const std::string& detail : details)
    {
      component.evidence.push_back(
          core::Evidence{core::Source::Binary, detail, core::Confidence::High});
    }
    ++components_marked;
  }
  return components_marked;
}

}  // namespace bomwerk::binscan
