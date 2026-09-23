// ctest unit test for the trace-line writer (observe/trace_line).
//
// The line is hand-built without a JSON library (the shim links nothing), so
// every assertion here re-parses it with nlohmann: the trace is only worth
// writing if the reader can read it back.
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "observe/trace_line.hpp"
#include "support/check.hpp"

using bomwerk::observe::build_trace_line;

namespace
{

nlohmann::json parse_line(const std::string& line)
{
  const nlohmann::json parsed = nlohmann::json::parse(line, nullptr, false);
  BOMWERK_TEST_CHECK(!parsed.is_discarded());
  return parsed;
}

}  // namespace

int main()
{
  // Given an ordinary compile invocation, when a line is built, then it is one
  // newline-terminated JSON object carrying argv, cwd, pid and tool.
  {
    const std::vector<std::string> arguments{"cc", "-c", "src/foo.c", "-o", "foo.o"};
    const std::string line = build_trace_line("cc", arguments, "/home/dev/project", 4711);
    BOMWERK_TEST_CHECK(!line.empty());
    BOMWERK_TEST_CHECK(line.back() == '\n');
    BOMWERK_TEST_CHECK(line.find('\n') == line.size() - 1);  // exactly one line

    const nlohmann::json record = parse_line(line);
    BOMWERK_TEST_CHECK(record["tool"] == "cc");
    BOMWERK_TEST_CHECK(record["cwd"] == "/home/dev/project");
    BOMWERK_TEST_CHECK(record["pid"] == 4711);
    BOMWERK_TEST_CHECK(record["argv"].size() == arguments.size());
    BOMWERK_TEST_CHECK(record["argv"][2] == "src/foo.c");
  }

  // Given any invocation, when a line is built, then the keys appear in sorted
  // order: canonical JSON is the output contract (hard rule 3), and two runs
  // of the same build must produce byte-identical traces.
  {
    const std::string line = build_trace_line("ld", {"ld", "-o", "app"}, "/build", 1);
    const std::size_t argv_position = line.find("\"argv\"");
    const std::size_t cwd_position = line.find("\"cwd\"");
    const std::size_t pid_position = line.find("\"pid\"");
    const std::size_t tool_position = line.find("\"tool\"");
    BOMWERK_TEST_CHECK(argv_position < cwd_position);
    BOMWERK_TEST_CHECK(cwd_position < pid_position);
    BOMWERK_TEST_CHECK(pid_position < tool_position);
  }

  // Given an invocation, when a line is built, then it carries NO timestamp: a
  // wall clock would make two identical builds differ.
  {
    const std::string line = build_trace_line("cc", {"cc"}, "/tmp", 2);
    const nlohmann::json record = parse_line(line);
    BOMWERK_TEST_CHECK(record.size() == 4);
    BOMWERK_TEST_CHECK(!record.contains("time"));
    BOMWERK_TEST_CHECK(!record.contains("timestamp"));
  }

  // Given arguments containing JSON metacharacters, when a line is built, then
  // they survive the round trip exactly: a -D flag with a quoted string in it
  // is completely routine.
  {
    const std::vector<std::string> arguments{"cc", "-DGREETING=\"hi\"", "-DPATH=C:\\tmp\\x",
                                             "-DTAB=\t"};
    const std::string line = build_trace_line("cc", arguments, "/w", 3);
    const nlohmann::json record = parse_line(line);
    BOMWERK_TEST_CHECK(record["argv"][1] == "-DGREETING=\"hi\"");
    BOMWERK_TEST_CHECK(record["argv"][2] == "-DPATH=C:\\tmp\\x");
    BOMWERK_TEST_CHECK(record["argv"][3] == "-DTAB=\t");
  }

  // Given an argument holding a newline, when a line is built, then it is
  // escaped and the record stays ONE physical line: otherwise a single odd
  // argument would split into two unreadable trace entries.
  {
    const std::string line = build_trace_line("cc", {"cc", "a\nb"}, "/w", 4);
    BOMWERK_TEST_CHECK(line.find('\n') == line.size() - 1);
    const nlohmann::json record = parse_line(line);
    BOMWERK_TEST_CHECK(record["argv"][1] == "a\nb");
  }

  // Given a control character, when a line is built, then it is escaped as
  // \u00XX rather than emitted raw (raw control bytes are invalid in JSON).
  {
    const std::string argument_with_control(1, '\x01');
    const std::string line = build_trace_line("cc", {"cc", argument_with_control}, "/w", 5);
    BOMWERK_TEST_CHECK(line.find("\\u0001") != std::string::npos);
    const nlohmann::json record = parse_line(line);
    BOMWERK_TEST_CHECK(record["argv"][1] == argument_with_control);
  }

  // Given valid multi-byte UTF-8 in a path, when a line is built, then it
  // passes through untouched.
  {
    const std::string unicode_path = "/home/dev/pr\xC3\xB6jekt/\xE2\x9C\x93";
    const std::string line = build_trace_line("cc", {"cc", "-c", "x.c"}, unicode_path, 6);
    const nlohmann::json record = parse_line(line);
    BOMWERK_TEST_CHECK(record["cwd"] == unicode_path);
  }

  // Given a filename that is NOT valid UTF-8: legal on POSIX, illegal in JSON
  //: when a line is built, then the line still parses and the bad bytes have
  // become U+FFFD. One odd filename must cost that argument's fidelity, never
  // the whole invocation (rule 1).
  {
    const std::string latin1_name = "caf\xE9.c";  // 0xE9 is a lone lead byte here
    const std::string line = build_trace_line("cc", {"cc", latin1_name}, "/w", 7);
    const nlohmann::json record = parse_line(line);
    const std::string recorded = record["argv"][1].get<std::string>();
    BOMWERK_TEST_CHECK(recorded != latin1_name);
    BOMWERK_TEST_CHECK(recorded.find("\xEF\xBF\xBD") != std::string::npos);
    BOMWERK_TEST_CHECK(recorded.rfind("caf", 0) == 0);
    BOMWERK_TEST_CHECK(recorded.size() > 4);
  }

  // Given a truncated UTF-8 sequence at the very end of a string, when a line
  // is built, then it degrades the same way instead of reading past the end.
  {
    const std::string truncated = "x\xE2\x9C";  // first two bytes of a 3-byte glyph
    const std::string line = build_trace_line("cc", {truncated}, "/w", 8);
    const nlohmann::json record = parse_line(line);
    BOMWERK_TEST_CHECK(record["argv"][0].get<std::string>().rfind("x", 0) == 0);
  }

  // Given no arguments at all, when a line is built, then argv is an empty
  // array rather than malformed JSON.
  {
    const std::string line = build_trace_line("ar", {}, "/w", 9);
    const nlohmann::json record = parse_line(line);
    BOMWERK_TEST_CHECK(record["argv"].is_array());
    BOMWERK_TEST_CHECK(record["argv"].empty());
  }

  return 0;
}
