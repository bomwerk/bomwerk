#pragma once
#include <cstddef>
#include <filesystem>
#include <map>
#include <string>

#include "core/result.hpp"

namespace bomwerk::observe
{

/// What a finished trace contains.
struct TraceStats
{
  std::size_t total_lines = 0;      ///< lines present in the file
  std::size_t malformed_lines = 0;  ///< lines that did not parse as a trace record
  std::size_t sorted_lines = 0;     ///< well-formed lines rewritten in canonical order
  std::map<std::string, std::size_t> invocations_by_tool;  ///< ordered by tool name
};

/// Read the finished trace, verify every line, then rewrite the file with the
/// well-formed lines sorted.
///
/// Verifying matters because the writer's `flock` cannot be proven correct on
/// every filesystem a build might live on (a network mount is the known weak
/// spot). Checking afterwards turns a silent corruption into a counted warning,
/// so the compile scan never inherits a file it cannot trust.
///
/// Sorting costs nothing extra: the validation pass already holds the lines :
/// and makes the trace byte-identical across two runs of the same build despite
/// `-j` scheduling (hard rule 3). Line order carries no meaning: the compile and link scans
/// reconstruct what happened from each record's content and `pid`.
///
/// Malformed lines are counted and dropped from the rewrite, never repaired.
/// `complete` stays true throughout: a partly readable trace beats none
/// (rule 1); the caller decides what the counts mean for the exit code.
[[nodiscard]] core::Result<TraceStats> validate_and_sort_trace(
    const std::filesystem::path& trace_path);

}  // namespace bomwerk::observe
