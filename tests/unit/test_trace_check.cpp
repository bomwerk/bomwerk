// ctest unit test for trace validation and canonical ordering
// (observe/trace_check).
//
// The writer's lock cannot be proven correct on every filesystem a build might
// live on, so the trace is verified after the fact. These cases pin the two
// things that matter: corruption is counted and reported rather than passed
// silently to the compile scan, and a good trace comes out in a reproducible order.
#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "core/result.hpp"
#include "observe/trace_check.hpp"
#include "observe/trace_line.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Result;
using bomwerk::observe::build_trace_line;
using bomwerk::observe::TraceStats;
using bomwerk::observe::validate_and_sort_trace;
using bomwerk::test::TempTree;

namespace
{

void write_raw_trace(const std::filesystem::path& path, const std::vector<std::string>& lines)
{
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  for (const std::string& line : lines)
  {
    stream << line << '\n';
  }
}

std::vector<std::string> read_lines(const std::filesystem::path& path)
{
  std::vector<std::string> lines;
  std::ifstream stream(path, std::ios::binary);
  std::string line;
  while (std::getline(stream, line))
  {
    lines.push_back(line);
  }
  return lines;
}

std::string trace_line_for(const std::string& tool_name, const std::string& source_file)
{
  std::string line = build_trace_line(tool_name, {tool_name, "-c", source_file}, "/build", 1);
  line.pop_back();  // build_trace_line terminates the line; the writer here adds it back
  return line;
}

}  // namespace

int main()
{
  // Given a trace whose lines arrived in scheduling order, when it is
  // validated, then the file comes back sorted: two runs of the same parallel
  // build must produce byte-identical traces (hard rule 3).
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    write_raw_trace(trace_path, {trace_line_for("cc", "zebra.c"), trace_line_for("cc", "apple.c"),
                                 trace_line_for("cc", "mango.c")});

    const Result<TraceStats> outcome = validate_and_sort_trace(trace_path);
    assert(outcome.complete);
    assert(outcome.warnings.empty());
    assert(outcome.value.total_lines == 3);
    assert(outcome.value.malformed_lines == 0);
    assert(outcome.value.sorted_lines == 3);

    const std::vector<std::string> lines = read_lines(trace_path);
    assert(lines.size() == 3);
    assert(std::is_sorted(lines.begin(), lines.end()));
  }

  // Given a trace carrying a corrupted line: what an interleaved concurrent
  // write leaves behind: when it is validated, then the damage is counted and
  // warned about, and the line is dropped rather than repaired or passed on.
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    write_raw_trace(trace_path, {trace_line_for("cc", "good.c"), "{\"argv\":[\"cc\",\"half-a-li",
                                 trace_line_for("ld", "app")});

    const Result<TraceStats> outcome = validate_and_sort_trace(trace_path);
    assert(outcome.complete);  // partial output beats none (rule 1)
    assert(outcome.value.total_lines == 3);
    assert(outcome.value.malformed_lines == 1);
    assert(outcome.value.sorted_lines == 2);
    assert(outcome.warnings.size() == 1);

    const std::vector<std::string> lines = read_lines(trace_path);
    assert(lines.size() == 2);
  }

  // Given a line that parses as JSON but is not a trace record, when it is
  // validated, then it is rejected too: structure, not mere parseability, is
  // what the compile scan depends on.
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    write_raw_trace(trace_path, {"{\"argv\":\"not-an-array\",\"cwd\":\"/w\",\"pid\":1,"
                                 "\"tool\":\"cc\"}",
                                 "[1,2,3]", "{\"cwd\":\"/w\"}", trace_line_for("cc", "good.c")});

    const Result<TraceStats> outcome = validate_and_sort_trace(trace_path);
    assert(outcome.value.total_lines == 4);
    assert(outcome.value.malformed_lines == 3);
    assert(outcome.value.sorted_lines == 1);
  }

  // Given a trace of several tools, when it is validated, then invocations are
  // counted per tool, in a stable order.
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    write_raw_trace(trace_path, {trace_line_for("cc", "a.c"), trace_line_for("cc", "b.c"),
                                 trace_line_for("ld", "app"), trace_line_for("ar", "lib.a")});

    const Result<TraceStats> outcome = validate_and_sort_trace(trace_path);
    assert(outcome.value.invocations_by_tool.size() == 3);
    assert(outcome.value.invocations_by_tool.at("cc") == 2);
    assert(outcome.value.invocations_by_tool.at("ld") == 1);
    assert(outcome.value.invocations_by_tool.at("ar") == 1);
  }

  // Given an empty trace: the build never reached a compiler: when it is
  // validated, then the counts are zero and nothing is reported as broken.
  // The CLI turns this into the "CMake cache bypassed PATH" warning.
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    write_raw_trace(trace_path, {});

    const Result<TraceStats> outcome = validate_and_sort_trace(trace_path);
    assert(outcome.complete);
    assert(outcome.value.total_lines == 0);
    assert(outcome.value.malformed_lines == 0);
    assert(outcome.warnings.empty());
  }

  // Given no trace file at all, when validation runs, then it warns instead of
  // throwing or inventing an empty result.
  {
    TempTree tree;
    const Result<TraceStats> outcome = validate_and_sort_trace(tree.root() / "absent.jsonl");
    assert(outcome.value.total_lines == 0);
    assert(outcome.warnings.size() == 1);
  }

  // Given blank lines mixed into a trace, when it is validated, then they are
  // skipped rather than counted as corruption.
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    write_raw_trace(trace_path, {trace_line_for("cc", "a.c"), "", trace_line_for("cc", "b.c")});

    const Result<TraceStats> outcome = validate_and_sort_trace(trace_path);
    assert(outcome.value.total_lines == 2);
    assert(outcome.value.malformed_lines == 0);
  }

  return 0;
}
