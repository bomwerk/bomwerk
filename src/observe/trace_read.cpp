#include "observe/trace_read.hpp"

#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>

#include "core/json_utils.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::observe
{
namespace
{

/// Depth cap for one trace record. The writer emits an object holding one
/// array of strings, two levels, so this leaves slack and still refuses the
/// deeply nested document whose only purpose is to make nlohmann's
/// recursive-descent parser exhaust the stack before `allow_exceptions=false`
/// can help (rule 1, the same guard every manifest parser applies).
constexpr int kMaxTraceRecordJsonDepth = 4;

/// Strip the trailing CR a trace copied through a Windows-aware tool may
/// carry, so a record is not rejected over a line ending.
void drop_trailing_carriage_return(std::string& line)
{
  if (!line.empty() && line.back() == '\r')
  {
    line.pop_back();
  }
}

}  // namespace

bool parse_trace_record(const std::string& line, TraceRecord& record)
{
  if (line.size() > kMaxTraceLineBytes)
  {
    return false;
  }
  if (core::json_utils::exceeds_json_nesting_depth(line, kMaxTraceRecordJsonDepth))
  {
    return false;
  }
  const nlohmann::json parsed = nlohmann::json::parse(line, nullptr, false);
  if (parsed.is_discarded() || !parsed.is_object())
  {
    return false;
  }

  const auto tool_field = parsed.find("tool");
  if (tool_field == parsed.end() || !tool_field->is_string())
  {
    return false;
  }
  const auto argv_field = parsed.find("argv");
  if (argv_field == parsed.end() || !argv_field->is_array())
  {
    return false;
  }
  const auto cwd_field = parsed.find("cwd");
  if (cwd_field == parsed.end() || !cwd_field->is_string())
  {
    return false;
  }
  const auto pid_field = parsed.find("pid");
  if (pid_field == parsed.end() || !pid_field->is_number_integer())
  {
    return false;
  }
  std::vector<std::string> arguments;
  arguments.reserve(argv_field->size());
  for (const nlohmann::json& argument : *argv_field)
  {
    // A non-string argv entry means the line was not written by a shim. Take
    // the whole record down rather than silently compiling a shorter argv:
    // a dropped argument is a dropped source file, i.e. a false "unused".
    if (!argument.is_string())
    {
      return false;
    }
    arguments.push_back(argument.get<std::string>());
  }

  record.tool = tool_field->get<std::string>();
  record.arguments = std::move(arguments);
  record.working_directory = cwd_field->get<std::string>();
  record.process_id = pid_field->get<long>();
  return true;
}

core::Result<std::vector<TraceRecord>> read_trace(const fs::path& trace_path)
{
  core::Result<std::vector<TraceRecord>> outcome;

  std::ifstream input_stream(trace_path, std::ios::binary);
  if (!input_stream)
  {
    outcome.warn(core::WarningCode::kObserveTraceNotWritten,
                 "no trace file to read at " + trace_path.string() +
                     "; nothing was observed, so no component can be shown to be used");
    return outcome;
  }

  std::size_t total_lines = 0;
  std::size_t malformed_lines = 0;
  bool exceeded_line_budget = false;
  std::string line;
  while (std::getline(input_stream, line))
  {
    drop_trailing_carriage_return(line);
    if (line.empty())
    {
      continue;
    }
    ++total_lines;
    if (outcome.value.size() >= kMaxTraceLines)
    {
      exceeded_line_budget = true;
      break;
    }

    TraceRecord record;
    if (!parse_trace_record(line, record))
    {
      ++malformed_lines;
      continue;
    }
    outcome.value.push_back(std::move(record));
  }

  if (malformed_lines > 0)
  {
    outcome.warn(core::WarningCode::kObserveTraceMalformedLines,
                 std::to_string(malformed_lines) + " of " + std::to_string(total_lines) +
                     " trace lines were unreadable and have been dropped; the recorded build is "
                     "incomplete, so a component may be reported unused that was in fact compiled");
  }
  if (exceeded_line_budget)
  {
    outcome.warn(core::WarningCode::kObserveTraceExceedsLimit,
                 "trace exceeds " + std::to_string(kMaxTraceLines) +
                     " lines; the rest was not read, so a component may be reported unused that "
                     "was in fact compiled");
  }
  return outcome;
}

}  // namespace bomwerk::observe
