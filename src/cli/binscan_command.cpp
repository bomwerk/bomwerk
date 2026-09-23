#include "cli/binscan_command.hpp"

#include <spdlog/spdlog.h>

#include <cstddef>
#include <cstdio>
#include <fstream>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "binscan/binary_map.hpp"
#include "binscan/sidecar.hpp"
#include "cli/app.hpp"
#include "cli/warning_recorder.hpp"
#include "core/exit_codes.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/warning_code.hpp"
#include "observe/compile_map.hpp"
#include "observe/link_map.hpp"
#include "observe/trace_read.hpp"
#include "output/cyclonedx.hpp"
#include "output/tool_info.hpp"
#include "sbom/document.hpp"
#include "sbom/read.hpp"
#include "vuln/cpe.hpp"

namespace fs = std::filesystem;

namespace bomwerk::cli
{
namespace
{

// User-facing strings kept together (future --lang de|es, docs/CONTRIBUTING.md style).

constexpr const char* kBinscanDescription =
    "Read the binaries a recorded build produced and report the dynamic dependencies, archive "
    "contents and symbols they carry.";

/// Same default as `bomwerk observe --trace` and `bomwerk trim --trace`, so
/// the three commands compose without the operator repeating a path.
constexpr const char* kDefaultTracePath = ".bomwerk/trace.jsonl";

/// The stored symbol sample lives beside the trace, in the same working
/// directory `bomwerk observe` already owns and `.gitignore` already covers.
constexpr const char* kDefaultSidecarPath = ".bomwerk/binscan.json";

/// Column width every "label: value" summary line aligns to, matching `scan`
/// and `trim` so the three read as one product, not three.
constexpr int kSummaryLabelWidth = 16;

/// How many unmatched sonames are listed before the rest are summarized. A
/// real product names a dozen or so system libraries and an operator wants to
/// see them; a pathological one should not fill the terminal.
constexpr std::size_t kMaxListedUnmatchedSonames = 20;

/// What a trace with no readable binary in it means. A trace recorded over a
/// configure-only run, or one whose build tree has since been deleted, is not
/// a broken input: it is simply not something the binary pass can speak to,
/// and saying that plainly beats printing "0 dynamic dependencies".
constexpr const char* kNoArtifactsExplanation =
    "this trace names no build output bomwerk can open. `binscan` reads the files a build WROTE, "
    "so the build tree must still exist; re-record with `bomwerk observe -- <build command>` if "
    "it was cleaned.";

/// What an SBOM with no rooted component means. Only the submodule and
/// vendored-code producers record where a component lives in the tree, so an
/// SBOM built purely from lockfiles is not a broken input: there is simply
/// nothing a binary can be attributed TO, and saying that plainly beats
/// reporting every dynamic dependency as "outside this repository", which
/// implies the comparison happened. Same explanation `trim` prints for the
/// same shape of input.
constexpr const char* kNoRootedComponentsExplanation =
    "no component in this SBOM records where it lives in the repository, so a binary has nothing "
    "to be attributed to. Only vendored source and git submodules carry a location; components "
    "read from a lockfile (npm, conan, vcpkg, ...) never can.";

/// One artifact's line, in the same column shape as `trim`'s listing. Product
/// output on stdout, never a log line: this is the result the operator asked
/// for (the logging rule in docs/CONTRIBUTING.md).
void print_artifact(const binscan::ScannedArtifact& artifact)
{
  std::string detail;
  if (artifact.kind == binscan::ArtifactKind::Elf)
  {
    detail = std::to_string(artifact.needed.size()) + " dynamic dep(s), " +
             std::to_string(artifact.symbols.size()) + " symbol(s)";
  }
  else if (artifact.kind == binscan::ArtifactKind::Archive)
  {
    detail = std::to_string(artifact.members.size()) + " member(s), " +
             std::to_string(artifact.symbols.size()) + " symbol(s)";
  }
  const char* shape = artifact.kind == binscan::ArtifactKind::Elf
                          ? binscan::to_string(artifact.shape)
                          : binscan::to_string(artifact.kind);
  std::printf("  - %-52s %-12s %s\n", artifact.path.generic_string().c_str(), shape,
              detail.c_str());
}

/// Write a text artifact, reporting the two ways that can fail. Shared by the
/// sidecar and the enriched SBOM because both must reach the exit code
/// identically: a sample that silently failed to store is worse than one that
/// was never asked for.
bool write_text_file(const fs::path& path, const std::string& contents)
{
  // `.bomwerk/` is the observe working directory, which may not exist yet on a
  // machine that has only ever run `scan`. A failure here is not reported on
  // its own: the open below is the authoritative test, and a directory that
  // already exists reports an error on some platforms.
  if (path.has_parent_path() && !path.parent_path().empty())
  {
    std::error_code directory_error;
    fs::create_directories(path.parent_path(), directory_error);
  }
  std::ofstream output_stream(path, std::ios::binary);
  if (!output_stream)
  {
    spdlog::error("failed to open output file: {}", path.string());
    return false;
  }
  output_stream << contents;
  if (!output_stream)
  {
    spdlog::error("failed to write output file: {}", path.string());
    return false;
  }
  return true;
}

/// Print the dynamic dependencies that named nothing inside this repository.
///
/// Deliberately stdout progress output rather than a warning: `libc.so.6` not
/// being a component of the scanned repo is the NORMAL case for every product
/// that links anything at all, and warning on each one would make the warning
/// channel useless on the first real run (see binscan/binary_map.hpp).
void print_unmatched_sonames(const std::set<std::string>& sonames)
{
  if (sonames.empty())
  {
    return;
  }
  std::printf("%-*s %zu dynamic dep(s) name a library outside this repository\n",
              kSummaryLabelWidth, "external:", sonames.size());
  std::size_t listed = 0;
  for (const std::string& soname : sonames)
  {
    if (listed >= kMaxListedUnmatchedSonames)
    {
      std::printf("    ... and %zu more\n", sonames.size() - listed);
      break;
    }
    std::printf("    %s\n", soname.c_str());
    ++listed;
  }
}

}  // namespace

CLI::App* register_binscan_command(CLI::App& application, BinscanOptions& options)
{
  CLI::App* binscan_command = application.add_subcommand("binscan", kBinscanDescription);
  binscan_command
      ->add_option("sbom", options.sbom_path, "CycloneDX SBOM to enrich (from `bomwerk scan`)")
      ->required()
      ->check(CLI::ExistingFile);
  binscan_command
      ->add_option("--trace", options.trace_path, "JSONL trace recorded by `bomwerk observe`")
      ->default_val(kDefaultTracePath)
      ->capture_default_str();
  // A trace records absolute paths while a component's location is
  // repo-relative, so the two can only be compared through the repository the
  // SBOM describes: the same reason `trim` needs this.
  binscan_command->add_option("--root", options.root_directory, "The repository the SBOM describes")
      ->default_val(".")
      ->capture_default_str()
      ->check(CLI::ExistingDirectory);
  binscan_command
      ->add_option("--sidecar", options.sidecar_path,
                   "Where to store the per-artifact record and symbol sample")
      ->default_val(kDefaultSidecarPath)
      ->capture_default_str();
  binscan_command->add_flag("--no-sidecar", options.no_sidecar,
                            "Report only; do not store the per-artifact record");
  binscan_command->add_option("-o,--output", options.output_path,
                              "Write a CycloneDX SBOM carrying the new Binary evidence "
                              "(default: report only, write no SBOM)");
  binscan_command->add_flag("-q,--quiet", options.quiet,
                            "Skip the per-artifact console listing (summary lines still print)");
  // Same opt-in scope as `scan --all-cpes`; requires --output because a
  // report-only binscan has nowhere to publish the synthesized identifiers.
  binscan_command->add_flag(
      "--all-cpes", options.all_cpes,
      "Synthesize CPE identifiers for every safely convertible versioned component, not just "
      "types with no OSV ecosystem mapping; requires --output");
  return binscan_command;
}

int run_binscan(const BinscanOptions& options)
{
  // Checked before any file is even read: there is nothing else this flag
  // could write the synthesized CPEs to, and failing fast beats a report-only
  // run that silently drops them.
  if (options.all_cpes && options.output_path.empty())
  {
    spdlog::error("--all-cpes requires --output (there is nothing else to publish it to)");
    return core::kExitIncomplete;
  }

  WarningRecorder recorder;

  core::Result<sbom::SbomDocument> document = sbom::load_sbom_file(options.sbom_path);
  recorder.record_all(document.warnings);
  if (document.value.components.empty())
  {
    spdlog::error("no components could be read from {}; there is nothing to attribute evidence to",
                  options.sbom_path.string());
    return core::kExitIncomplete;
  }

  core::Result<std::vector<observe::TraceRecord>> trace = observe::read_trace(options.trace_path);
  recorder.record_all(trace.warnings);
  if (trace.value.empty())
  {
    spdlog::error(
        "no usable records in {}; record a build with `bomwerk observe -- <build command>` first",
        options.trace_path.string());
    return core::kExitIncomplete;
  }

  // Read the product identity BEFORE the component list is moved out below, so
  // an enriched document describes the same product as the one it enriched.
  const core::ReleaseMeta release_meta{
      document.value.product_id, document.value.product_version, {}};

  std::vector<core::Component> components = std::move(document.value.components);
  vuln::populate_cpe_identifiers(components, options.all_cpes
                                                 ? vuln::CpePopulationScope::AllVersioned
                                                 : vuln::CpePopulationScope::UnmappedOnly);
  const std::set<fs::path> component_roots = observe::component_roots_of(components);

  core::Result<observe::BuildArtifacts> artifacts =
      observe::collect_build_artifacts(trace.value, options.root_directory);
  recorder.record_all(artifacts.warnings);

  const std::vector<fs::path> artifact_paths = artifacts.value.all_paths();
  core::Result<binscan::BinaryMap> binaries =
      binscan::map_binaries_to_roots(artifact_paths, options.root_directory, component_roots);
  recorder.record_all(binaries.warnings);

  const std::size_t components_marked = binscan::apply_binary_evidence(components, binaries.value);
  const binscan::BinaryScanCounters& counters = binaries.value.counters;

  std::printf("bomwerk %s\n", version());
  std::printf("%-*s %s (%zu components)\n", kSummaryLabelWidth,
              "sbom:", options.sbom_path.string().c_str(), components.size());
  std::printf(
      "%-*s %s (%zu build artifact(s): %zu link output(s), %zu archive(s), %zu linked "
      "librar(ies))\n",
      kSummaryLabelWidth, "trace:", options.trace_path.string().c_str(), artifact_paths.size(),
      artifacts.value.link_outputs.size(), artifacts.value.archive_outputs.size(),
      artifacts.value.linked_archives.size());
  std::printf(
      "%-*s %zu ELF (%zu dynamic, %zu static, %zu relocatable), %zu archive(s), %zu "
      "unrecognized, %zu unreadable\n",
      kSummaryLabelWidth, "read:", counters.elf_artifacts, counters.dynamic_artifacts,
      counters.static_artifacts, counters.relocatable_artifacts, counters.archives,
      counters.unrecognized_artifacts, counters.unreadable_artifacts);
  std::printf("%-*s %zu of %zu components gained binary evidence\n", kSummaryLabelWidth,
              "evidence:", components_marked, components.size());

  if (!options.quiet)
  {
    for (const binscan::ScannedArtifact& artifact : binaries.value.artifacts)
    {
      print_artifact(artifact);
    }
  }
  print_unmatched_sonames(binaries.value.unmatched_sonames);

  if (artifact_paths.empty())
  {
    // Same "no build output could be read" family as binscan/binary_map.hpp's summary
    // diagnostics (this mapping): checked here, earlier, only because an empty trace never
    // reaches map_binaries_to_roots at all.
    recorder.record(core::WarningCode::kBinaryEvidenceLimited, kNoArtifactsExplanation);
  }
  if (component_roots.empty())
  {
    recorder.record(core::WarningCode::kObserveNoRootedComponents, kNoRootedComponentsExplanation);
  }

  if (!options.no_sidecar)
  {
    if (!write_text_file(options.sidecar_path, binscan::render_binscan_sidecar(binaries.value)))
    {
      return core::kExitIncomplete;
    }
    std::printf("%-*s %s (%zu artifact(s))\n", kSummaryLabelWidth,
                "sidecar:", options.sidecar_path.string().c_str(), binaries.value.artifacts.size());
  }

  if (!options.output_path.empty())
  {
    const std::string enriched =
        output::write_cyclonedx(components, output::ToolInfo{"bomwerk", version()}, release_meta);
    if (!write_text_file(options.output_path, enriched))
    {
      return core::kExitIncomplete;
    }
    std::printf("%-*s %s (%zu components)\n", kSummaryLabelWidth,
                "output:", options.output_path.string().c_str(), components.size());
  }

  return recorder.degraded() ? core::kExitCompletedWithWarnings : core::kExitClean;
}

}  // namespace bomwerk::cli
