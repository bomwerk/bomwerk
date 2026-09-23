#include "binscan/sidecar.hpp"

#include <nlohmann/json.hpp>
#include <utility>
#include <vector>

namespace bomwerk::binscan
{
namespace
{

/// One artifact's record. Only the fields that apply to its kind are emitted:
/// an archive has no soname, an ELF image has no members, and writing empty
/// keys for the other half would make the document say "this archive declares
/// no dynamic dependencies": a claim about a question that was never asked.
[[nodiscard]] nlohmann::json artifact_to_json(const ScannedArtifact& artifact)
{
  nlohmann::json entry;
  entry["path"] = artifact.path.generic_string();
  entry["kind"] = to_string(artifact.kind);

  if (artifact.kind == ArtifactKind::Elf)
  {
    entry["shape"] = to_string(artifact.shape);
    if (!artifact.soname.empty())
    {
      entry["soname"] = artifact.soname;
    }
    entry["needed"] = artifact.needed;
    entry["needed_truncated"] = artifact.needed_truncated;
  }
  else if (artifact.kind == ArtifactKind::Archive)
  {
    entry["members"] = artifact.members;
    entry["members_truncated"] = artifact.members_truncated;
  }

  if (artifact.kind == ArtifactKind::Elf || artifact.kind == ArtifactKind::Archive)
  {
    entry["symbols"] = artifact.symbols;
    entry["symbols_truncated"] = artifact.symbols_truncated;
    entry["symbols_unavailable"] = artifact.symbols_unavailable;
  }
  return entry;
}

/// The counter block, written in full even where every field is zero: a reader
/// comparing two runs needs the same keys present in both, and an absent key
/// would be indistinguishable from a counter this version does not have.
[[nodiscard]] nlohmann::json counters_to_json(const BinaryScanCounters& counters)
{
  nlohmann::json entry;
  entry["artifacts_scanned"] = counters.artifacts_scanned;
  entry["elf_artifacts"] = counters.elf_artifacts;
  entry["dynamic_artifacts"] = counters.dynamic_artifacts;
  entry["static_artifacts"] = counters.static_artifacts;
  entry["relocatable_artifacts"] = counters.relocatable_artifacts;
  entry["malformed_artifacts"] = counters.malformed_artifacts;
  entry["dynamic_without_needed"] = counters.dynamic_without_needed;
  entry["archives"] = counters.archives;
  entry["unrecognized_artifacts"] = counters.unrecognized_artifacts;
  entry["unreadable_artifacts"] = counters.unreadable_artifacts;
  entry["truncated_samples"] = counters.truncated_samples;
  return entry;
}

}  // namespace

std::string render_binscan_sidecar(const BinaryMap& map)
{
  nlohmann::json document;
  document["schema"] = kSidecarSchemaVersion;

  // `map.artifacts` is already in sorted path order (map_binaries_to_roots
  // sorts its input before opening anything), so this preserves that order
  // rather than choosing a second, possibly different one.
  nlohmann::json artifacts = nlohmann::json::array();
  for (const ScannedArtifact& artifact : map.artifacts)
  {
    artifacts.push_back(artifact_to_json(artifact));
  }
  document["artifacts"] = std::move(artifacts);

  // A std::set, so this is sorted by construction.
  document["unmatched_needed"] =
      std::vector<std::string>(map.unmatched_sonames.begin(), map.unmatched_sonames.end());

  nlohmann::json attributed = nlohmann::json::array();
  for (const auto& [root, evidence] : map.evidence_by_root)
  {
    nlohmann::json entry;
    entry["root"] = root.generic_string();
    entry["needed"] = evidence.needed_sonames;
    entry["archive_members"] = evidence.archive_member_count;
    entry["shared_objects"] = evidence.shared_object_count;
    attributed.push_back(std::move(entry));
  }
  document["attributed"] = std::move(attributed);

  document["counters"] = counters_to_json(map.counters);

  return document.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace bomwerk::binscan
