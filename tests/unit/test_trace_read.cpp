// ctest unit test for reading a trace back (observe/trace_read.hpp): the
// inverse of observe::build_trace_line, and the first half of turning a
// recorded build into a used-set.
//
// The trace is written by processes the SCANNED repository's own build system
// spawned, so every line here is untrusted input. What these cases pin is that
// a bad line costs exactly one record and a counted warning -- never a throw,
// never a partially-filled record, and never a silent drop, because a dropped
// compile is a component wrongly reported unused.
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "core/result.hpp"
#include "observe/trace_line.hpp"
#include "observe/trace_read.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Result;
using bomwerk::observe::build_trace_line;
using bomwerk::observe::parse_trace_record;
using bomwerk::observe::read_trace;
using bomwerk::observe::TraceRecord;
using bomwerk::test::TempTree;

namespace
{

void write_raw_trace(const fs::path& path, const std::vector<std::string>& lines)
{
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  for (const std::string& line : lines)
  {
    stream << line << '\n';
  }
}

/// One line exactly as a shim would have written it, minus the terminator the
/// writer above adds back.
std::string shim_line(const std::string& tool_name, const std::vector<std::string>& arguments,
                      const std::string& working_directory, long process_id)
{
  std::string line = build_trace_line(tool_name, arguments, working_directory, process_id);
  line.pop_back();
  return line;
}

}  // namespace

int main()
{
  // Given a line the trace writer produced, when it is parsed, then every
  // field comes back exactly as the shim saw it -- the writer and this reader
  // are inverses, and a round trip is the only way to keep them so.
  {
    const std::string line = shim_line("clang++", {"clang++", "-c", "src/main.cpp", "-o", "main.o"},
                                       "/work/build", 4321);
    TraceRecord record;
    BOMWERK_TEST_CHECK(parse_trace_record(line, record));
    BOMWERK_TEST_CHECK(record.tool == "clang++");
    BOMWERK_TEST_CHECK(record.arguments.size() == 5);
    BOMWERK_TEST_CHECK(record.arguments[0] == "clang++");
    BOMWERK_TEST_CHECK(record.arguments[2] == "src/main.cpp");
    BOMWERK_TEST_CHECK(record.working_directory == "/work/build");
    BOMWERK_TEST_CHECK(record.process_id == 4321);
  }

  // Given each way a line can be malformed, when it is parsed, then every one
  // is a plain false and none of them throws. Hostile input is the expected
  // case here, not the exceptional one (rule 1).
  {
    TraceRecord record;
    BOMWERK_TEST_CHECK(!parse_trace_record("", record));
    BOMWERK_TEST_CHECK(!parse_trace_record("not json at all", record));
    BOMWERK_TEST_CHECK(!parse_trace_record(R"({"argv":["cc"],"cwd":"/w","pid":1)", record));
    BOMWERK_TEST_CHECK(!parse_trace_record(R"(["cc","-c","a.c"])", record));  // array, not object
    BOMWERK_TEST_CHECK(!parse_trace_record(R"({"argv":["cc"],"cwd":"/w","pid":1})", record));
    BOMWERK_TEST_CHECK(!parse_trace_record(R"({"tool":"cc","cwd":"/w","pid":1})", record));
    BOMWERK_TEST_CHECK(!parse_trace_record(R"({"tool":"cc","argv":["cc"],"pid":1})", record));
    BOMWERK_TEST_CHECK(!parse_trace_record(R"({"tool":"cc","argv":["cc"],"cwd":"/w"})", record));
    // argv present but not an array, and cwd/tool/pid present but wrong-typed.
    BOMWERK_TEST_CHECK(
        !parse_trace_record(R"({"tool":"cc","argv":"cc -c a.c","cwd":"/w","pid":1})", record));
    BOMWERK_TEST_CHECK(
        !parse_trace_record(R"({"tool":7,"argv":["cc"],"cwd":"/w","pid":1})", record));
    BOMWERK_TEST_CHECK(
        !parse_trace_record(R"({"tool":"cc","argv":["cc"],"cwd":7,"pid":1})", record));
    BOMWERK_TEST_CHECK(
        !parse_trace_record(R"({"tool":"cc","argv":["cc"],"cwd":"/w","pid":"one"})", record));
  }

  // Given an argv holding a non-string entry, when the line is parsed, then
  // the WHOLE record is rejected rather than the bad argument skipped. A
  // silently shortened argv is a silently dropped source file, which surfaces
  // later as a component wrongly reported unused.
  {
    TraceRecord record;
    BOMWERK_TEST_CHECK(
        !parse_trace_record(R"({"tool":"cc","argv":["cc",7,"a.c"],"cwd":"/w","pid":1})", record));
  }

  // Given a line longer than the per-line cap, when it is parsed, then it is
  // refused: no real compile command is a megabyte, so that is two interleaved
  // writes, not a record.
  {
    const std::string oversized_argument(bomwerk::observe::kMaxTraceLineBytes, 'a');
    TraceRecord record;
    BOMWERK_TEST_CHECK(!parse_trace_record(
        R"({"tool":"cc","argv":["cc","-c",")" + oversized_argument + R"("],"cwd":"/w","pid":1})",
        record));
  }

  // Given a deeply nested document dropped into the trace, when it is parsed,
  // then the depth guard refuses it before nlohmann's recursive-descent parser
  // can walk it. A record is two levels deep by construction.
  {
    const std::string nested = std::string(64, '[') + std::string(64, ']');
    TraceRecord record;
    BOMWERK_TEST_CHECK(!parse_trace_record(
        R"({"tool":"cc","argv":["cc"],"cwd":"/w","pid":1,"x":)" + nested + "}", record));
  }

  // Given a whole trace file, when it is read, then well-formed lines become
  // records, malformed ones are counted into ONE warning and dropped, and
  // blank lines are neither.
  {
    TempTree tree;
    const fs::path trace_path = tree.root() / "trace.jsonl";
    write_raw_trace(trace_path,
                    {shim_line("cc", {"cc", "-c", "a.c"}, "/build", 1), "",
                     "{ this is not a record", shim_line("ar", {"ar", "rcs"}, "/build", 2)});

    const Result<std::vector<TraceRecord>> outcome = read_trace(trace_path);
    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(outcome.value.size() == 2);
    BOMWERK_TEST_CHECK(outcome.value[0].tool == "cc");
    BOMWERK_TEST_CHECK(outcome.value[1].tool == "ar");
    BOMWERK_TEST_CHECK(outcome.warnings.size() == 1);
  }

  // Given a trace with a trailing carriage return on every line (a file that
  // travelled through a Windows-aware tool), when it is read, then the records
  // still parse -- a line ending must never cost a compile.
  {
    TempTree tree;
    const fs::path trace_path = tree.root() / "trace.jsonl";
    std::ofstream stream(trace_path, std::ios::binary | std::ios::trunc);
    stream << shim_line("cc", {"cc", "-c", "a.c"}, "/build", 1) << "\r\n";
    stream.close();

    const Result<std::vector<TraceRecord>> outcome = read_trace(trace_path);
    BOMWERK_TEST_CHECK(outcome.value.size() == 1);
    BOMWERK_TEST_CHECK(outcome.warnings.empty());
  }

  // Given no trace file at all, when it is read, then it warns instead of
  // throwing -- "nothing was observed" is a result the caller weighs, not a
  // failure that aborts the run (rule 1).
  {
    TempTree tree;
    const Result<std::vector<TraceRecord>> outcome = read_trace(tree.root() / "absent.jsonl");
    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(outcome.value.empty());
    BOMWERK_TEST_CHECK(outcome.warnings.size() == 1);
  }

  return 0;
}
