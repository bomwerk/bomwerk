#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "core/result.hpp"

namespace bomwerk::observe
{

/// A huge build can emit hundreds of thousands of invocations, and every
/// consumer of a trace holds them all in memory at once. Past this many lines
/// the rest of the file is skipped and counted, which degrades the analysis
/// rather than the run (rule 1).
inline constexpr std::size_t kMaxTraceLines = 1'000'000;

/// No real compile command approaches this. A longer line is corruption (two
/// interleaved writes) rather than a record.
inline constexpr std::size_t kMaxTraceLineBytes = 1024u * 1024u;

/// One tool invocation, exactly as a shim recorded it. The inverse of
/// `build_trace_line`, and the shape every trace consumer (the compile
/// mapping, the link lines) starts from.
///
/// `working_directory` is not decoration: a build system compiles from its own
/// build tree, so most of `arguments` is relative to this and to nothing else.
/// Resolving a source path without it lands in the wrong repo, or in no repo.
struct TraceRecord
{
  std::string tool;                    ///< "cc", "clang++", "ld", "ar"
  std::vector<std::string> arguments;  ///< argv as the shim saw it, argv[0] included
  std::string working_directory;       ///< the invocation's cwd; relative argv resolves against it
  long process_id = 0;                 ///< correlates a compile with the process that ran it
};

/// Parse one trace line into `record`. False => the line is not a well-formed
/// record, and `record` is left untouched.
///
/// This is the ONE definition of "well-formed" in the codebase: both the
/// post-build validation pass (`validate_and_sort_trace`) and every consumer
/// go through here, so a line one accepts can never be a line the other
/// rejects. Hostile input is expected: the trace is written by processes a
/// scanned repo's own build system spawned: so an over-long line, invalid
/// JSON, a missing key and a wrong-typed field are all plain `false`, never a
/// throw (rule 1).
[[nodiscard]] bool parse_trace_record(const std::string& line, TraceRecord& record);

/// Read a whole trace file into records.
///
/// Malformed lines are counted into one warning and dropped, never repaired:
/// a partly readable trace still says what got as far as compiling, and
/// partial output beats none (rule 1). `complete` stays true even for a
/// missing file: a trace that was never written means "nothing observed",
/// which is a degraded result for the caller to weigh, not a crash.
[[nodiscard]] core::Result<std::vector<TraceRecord>> read_trace(
    const std::filesystem::path& trace_path);

}  // namespace bomwerk::observe
