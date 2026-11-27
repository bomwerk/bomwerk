#include "observe/trace_check.hpp"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "core/atomic_file.hpp"
#include "core/warning_code.hpp"
#include "observe/trace_read.hpp"

namespace fs = std::filesystem;

namespace bomwerk::observe
{
namespace
{

/// Whether one line is a well-formed trace record, and which tool it names.
///
/// The judgement itself belongs to `parse_trace_record`, deliberately: this
/// pass decides which lines survive into the rewritten file, and every later
/// consumer decides which lines it can act on. Were the two definitions
/// separate, a line could pass validation here and be dropped there: the
/// trace would look clean while a compiled component silently went missing.
/// Building the whole record only to keep its tool name is a few string
/// copies against a file this function is about to sort anyway.
bool is_trace_record(const std::string& line, std::string& tool_name)
{
  TraceRecord record;
  if (!parse_trace_record(line, record))
  {
    return false;
  }
  tool_name = std::move(record.tool);
  return true;
}

/// Replace the trace with `lines` through the shared atomic write, so an
/// interrupted rewrite cannot leave a half-written trace where a whole one
/// used to be.
core::AtomicWriteOutcome rewrite_trace(const fs::path& trace_path,
                                       const std::vector<std::string>& lines)
{
  std::size_t total_bytes = 0;
  for (const std::string& line : lines)
  {
    total_bytes += line.size() + 1;
  }
  std::string contents;
  contents.reserve(total_bytes);
  for (const std::string& line : lines)
  {
    contents += line;
    contents += '\n';
  }
  return core::write_file_atomically(trace_path, contents);
}

}  // namespace

core::Result<TraceStats> validate_and_sort_trace(const fs::path& trace_path)
{
  core::Result<TraceStats> outcome;

  std::ifstream input_stream(trace_path, std::ios::binary);
  if (!input_stream)
  {
    outcome.warn(core::WarningCode::kObserveTraceNotWritten,
                 "no trace file was written at " + trace_path.string());
    return outcome;
  }

  std::vector<std::string> well_formed_lines;
  std::string line;
  bool exceeded_line_budget = false;
  while (std::getline(input_stream, line))
  {
    if (!line.empty() && line.back() == '\r')
    {
      line.pop_back();
    }
    if (line.empty())
    {
      continue;
    }
    ++outcome.value.total_lines;

    std::string tool_name;
    if (!is_trace_record(line, tool_name))
    {
      ++outcome.value.malformed_lines;
      continue;
    }
    ++outcome.value.invocations_by_tool[tool_name];

    if (well_formed_lines.size() < kMaxTraceLines)
    {
      well_formed_lines.push_back(line);
    }
    else
    {
      exceeded_line_budget = true;
    }
  }

  if (outcome.value.malformed_lines > 0)
  {
    outcome.warn(core::WarningCode::kObserveTraceMalformedLines,
                 std::to_string(outcome.value.malformed_lines) + " of " +
                     std::to_string(outcome.value.total_lines) +
                     " trace lines were unreadable and have been dropped. Concurrent writes may "
                     "have interleaved; the recorded build is incomplete");
  }

  if (exceeded_line_budget)
  {
    outcome.warn(core::WarningCode::kObserveTraceExceedsLimit,
                 "trace exceeds " + std::to_string(kMaxTraceLines) +
                     " lines; left in write order instead of canonical order");
    return outcome;
  }

  std::sort(well_formed_lines.begin(), well_formed_lines.end());
  const core::AtomicWriteOutcome rewrite = rewrite_trace(trace_path, well_formed_lines);
  if (!rewrite.written)
  {
    outcome.warn(core::WarningCode::kObserveTraceRewriteFailed,
                 "could not rewrite " + trace_path.string() +
                     " in canonical order; it is still valid but not byte-reproducible. " +
                     core::describe_atomic_write_failure("sorted trace", trace_path, rewrite));
    return outcome;
  }
  outcome.value.sorted_lines = well_formed_lines.size();
  return outcome;
}

}  // namespace bomwerk::observe
