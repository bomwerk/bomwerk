#include "cli/trim_command.hpp"

#include <spdlog/spdlog.h>

#include <cstddef>
#include <cstdio>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "cli/app.hpp"
#include "cli/observe_trim.hpp"
#include "cli/warning_recorder.hpp"
#include "core/exit_codes.hpp"
#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/warning_code.hpp"
#include "output/cyclonedx.hpp"
#include "output/html.hpp"
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

constexpr const char* kTrimDescription =
    "Compare an SBOM against a recorded build trace and report which components the build "
    "actually compiled, linked, or included.";

/// Column width every "label: value" summary line aligns to, matching the
/// scan command's summary block so the two read as one product, not two.
constexpr int kSummaryLabelWidth = 16;

/// One component's verdict, in the same column shape as `scan`'s listing.
/// Product output on stdout, never a log line: this is the result the operator
/// asked for (the logging rule in docs/CONTRIBUTING.md).
///
/// The verdict itself is read from `used_in_build`, which `mark_used_in_build`
/// has already decided: never re-derived from the map here. Two places
/// deciding the same thing is two places that can disagree, and the one thing
/// this listing must never do is print "used" beside a component the trimmed
/// SBOM went on to drop. The map is consulted only for the parenthetical
/// detail, which is cosmetic.
void print_component_verdict(const core::Component& component, const observe::CompileMap& map)
{
  const std::string identity = component.purl.empty() ? component.name : component.purl;
  // Through the same normalizer `component_roots_of` keyed the map with: an
  // SBOM may spell a location "third_party/zlib/" and the map is keyed
  // "third_party/zlib", and looking up the raw spelling would quietly find
  // nothing.
  const fs::path root = core::normalized_subtree_path(component.root);
  const auto found = map.usage_by_root.find(root);

  std::string qualifier;
  if (found != map.usage_by_root.end())
  {
    if (found->second.signal == observe::UsageSignal::CompiledSource)
    {
      qualifier = " (" + std::to_string(found->second.compiled_source_count) + " sources)";
    }
    else if (found->second.signal == observe::UsageSignal::Linked)
    {
      qualifier = " (" + std::to_string(found->second.linked_input_count) + " link input(s))";
    }
    else if (found->second.signal == observe::UsageSignal::IncludePath)
    {
      qualifier = " (headers only)";
    }
  }
  std::printf("  - %-44s %-8s %s%s\n", identity.c_str(),
              component.used_in_build ? "used" : "UNUSED", root.generic_string().c_str(),
              qualifier.c_str());
}

/// Write the trimmed document. Kept separate from the reporting above because
/// only this half can fail in a way that must reach the exit code.
bool write_trimmed_sbom(const fs::path& output_path, const core::ReleaseMeta& release_meta,
                        const std::vector<core::Component>& components)
{
  const std::string trimmed =
      output::write_cyclonedx(components, output::ToolInfo{"bomwerk", version()}, release_meta);

  std::ofstream output_stream(output_path, std::ios::binary);
  if (!output_stream)
  {
    spdlog::error("failed to open output file: {}", output_path.string());
    return false;
  }
  output_stream << trimmed;
  if (!output_stream)
  {
    spdlog::error("failed to write output file: {}", output_path.string());
    return false;
  }
  return true;
}

}  // namespace

CLI::App* register_trim_command(CLI::App& application, TrimOptions& options)
{
  CLI::App* trim_command = application.add_subcommand("trim", kTrimDescription);
  trim_command
      ->add_option("sbom", options.sbom_path, "CycloneDX SBOM to judge (from `bomwerk scan`)")
      ->required()
      ->check(CLI::ExistingFile);
  trim_command
      ->add_option("--trace", options.trace_path, "JSONL trace recorded by `bomwerk observe`")
      ->default_val(kDefaultObserveTracePath)
      ->capture_default_str();
  // A trace records absolute paths while a component's location is
  // repo-relative, so the two can only be compared through the repository the
  // SBOM describes. Defaulting to "." matches `scan`, whose own default root
  // is the directory the operator is standing in.
  trim_command->add_option("--root", options.root_directory, "The repository the SBOM describes")
      ->default_val(".")
      ->capture_default_str()
      ->check(CLI::ExistingDirectory);
  trim_command->add_option("-o,--output", options.output_path,
                           "Write a CycloneDX SBOM with the proven-unused components dropped "
                           "(default: report only, write nothing)");
  trim_command->add_option(
      "--html", options.html_report_path,
      "Write a self-contained HTML report with the unused-component count and detail");
  trim_command->add_flag("-q,--quiet", options.quiet,
                         "Skip the per-component console listing (summary lines still print)");
  // Same opt-in scope as `scan --all-cpes`; requires --output because a
  // report-only trim has nowhere to publish the synthesized identifiers.
  trim_command->add_flag(
      "--all-cpes", options.all_cpes,
      "Synthesize CPE identifiers for every safely convertible versioned component, not just "
      "types with no OSV ecosystem mapping; requires --output");
  return trim_command;
}

int run_trim(const TrimOptions& options)
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
    spdlog::error("no components could be read from {}; there is nothing to judge",
                  options.sbom_path.string());
    return core::kExitIncomplete;
  }

  // Read the product identity BEFORE the component list is moved out below:
  // the trimmed document must describe the same product as the one it trimmed,
  // and a BOM that renamed its own subject would be worse than no BOM at all.
  const core::ReleaseMeta release_meta{
      document.value.product_id, document.value.product_version, {}};

  std::vector<core::Component> components = std::move(document.value.components);
  vuln::populate_cpe_identifiers(components, options.all_cpes
                                                 ? vuln::CpePopulationScope::AllVersioned
                                                 : vuln::CpePopulationScope::UnmappedOnly);
  core::Result<ObserveTraceApplication> trace_application =
      apply_observe_trace(options.trace_path, options.root_directory, components);
  recorder.record_all(trace_application.warnings);
  if (!trace_application.complete)
  {
    spdlog::error(
        "no usable records in {}; record a build with `bomwerk observe -- <build command>` first",
        options.trace_path.string());
    return core::kExitIncomplete;
  }
  const observe::UsedSetSummary& summary = trace_application.value.summary;
  const observe::CompileMap& compile_map = trace_application.value.compile_map;
  const observe::LinkMap& link_map = trace_application.value.link_map;

  std::printf("bomwerk %s\n", version());
  std::printf("%-*s %s (%zu components)\n", kSummaryLabelWidth,
              "sbom:", options.sbom_path.string().c_str(), components.size());
  std::printf("%-*s %s (%zu compile invocations, %zu source file(s) in this repo)\n",
              kSummaryLabelWidth, "trace:", options.trace_path.string().c_str(),
              compile_map.compile_invocations, compile_map.compiled_sources.size());
  std::printf("%-*s %zu link invocation(s), %zu unresolved -l<name>\n", kSummaryLabelWidth,
              "links:", link_map.link_invocations, link_map.unresolved_library_names);
  std::printf("%-*s %zu of %zu located components compiled, linked, or included\n",
              kSummaryLabelWidth, "used:", summary.used, summary.judged);

  if (!options.quiet)
  {
    for (const core::Component& component : components)
    {
      if (!component.root.empty())
      {
        print_component_verdict(component, compile_map);
      }
    }
  }

  // What was NOT judged is part of the result, the same reason `scan` prints
  // its skipped-submodule and no-OSV-coverage lines: an operator reading "5 of
  // 7 used" must not be left thinking the other components were cleared.
  if (summary.not_judgeable > 0)
  {
    std::printf(
        "%-*s %zu component(s) record no location in the repository; a compile trace "
        "cannot speak to them\n",
        kSummaryLabelWidth, "not judged:", summary.not_judgeable);
  }
  if (compile_map.out_of_tree_sources > 0)
  {
    std::printf("%-*s %zu compiled source(s) lie outside %s\n", kSummaryLabelWidth,
                "out of tree:", compile_map.out_of_tree_sources,
                options.root_directory.string().c_str());
  }

  if (summary.judged == 0)
  {
    recorder.record(core::WarningCode::kObserveNoRootedComponents, kNoRootedComponentsExplanation);
  }

  if (!options.output_path.empty())
  {
    std::vector<core::Component> kept;
    kept.reserve(components.size());
    for (const core::Component& component : components)
    {
      if (component.used_in_build)
      {
        kept.push_back(component);
      }
    }
    if (!write_trimmed_sbom(options.output_path, release_meta, kept))
    {
      return core::kExitIncomplete;
    }
    std::printf("%-*s %s (%zu components, %zu dropped)\n", kSummaryLabelWidth,
                "output:", options.output_path.string().c_str(), kept.size(),
                components.size() - kept.size());
  }

  if (!options.html_report_path.empty())
  {
    output::ReportContext report_context;
    report_context.tool = output::ToolInfo{"bomwerk", version()};
    report_context.release_meta = release_meta;
    report_context.scanned_root = options.root_directory.string();
    report_context.scan_file_count_available = false;
    report_context.build_trace_applied = true;
    report_context.vulnerability_check_enabled = false;
    report_context.vulnerability_check_applicable = false;
    report_context.warnings = recorder.collected();

    const std::string report_document = output::write_html_report(components, report_context);
    std::ofstream report_stream(options.html_report_path, std::ios::binary);
    if (!report_stream)
    {
      spdlog::error("failed to open report file: {}", options.html_report_path.string());
      return core::kExitIncomplete;
    }
    report_stream << report_document;
    if (!report_stream)
    {
      spdlog::error("failed to write report file: {}", options.html_report_path.string());
      return core::kExitIncomplete;
    }
    std::printf("%-*s %s (self-contained HTML)\n", kSummaryLabelWidth,
                "report:", options.html_report_path.string().c_str());
  }

  return recorder.degraded() ? core::kExitCompletedWithWarnings : core::kExitClean;
}

}  // namespace bomwerk::cli
