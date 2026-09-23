// ctest unit test for the locked trace append (observe/trace_writer).
//
// This is the test that justifies the lock. `make -j8` has many shim processes
// appending at the same instant, and write() is only guaranteed atomic below
// PIPE_BUF (4 KiB): which real C++ compile commands exceed routinely with
// long -I lists. The concurrency case below deliberately writes lines far
// larger than that: without the lock it interleaves and the JSON stops
// parsing, which is precisely the corruption the compile scan must never inherit.
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "observe/trace_line.hpp"
#include "observe/trace_writer.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::observe::append_trace_line;
using bomwerk::observe::build_trace_line;
using bomwerk::test::TempTree;

namespace
{

// Comfortably past PIPE_BUF, so a single write() is not guaranteed atomic and
// the lock is doing real work.
constexpr std::size_t kLargeArgumentBytes = 8192;
constexpr int kWriterThreadCount = 8;
constexpr int kLinesPerThread = 64;

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

}  // namespace

int main()
{
  // Given a trace path that does not exist yet, when a line is appended, then
  // the file is created holding exactly that line.
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    const std::string line = build_trace_line("cc", {"cc", "-c", "a.c"}, "/w", 1);
    BOMWERK_TEST_CHECK(append_trace_line(trace_path.string().c_str(), line));

    const std::vector<std::string> lines = read_lines(trace_path);
    BOMWERK_TEST_CHECK(lines.size() == 1);
    BOMWERK_TEST_CHECK(!nlohmann::json::parse(lines[0], nullptr, false).is_discarded());
  }

  // Given an existing trace, when more lines are appended, then they are added
  // rather than replacing what is there.
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    for (int invocation_index = 0; invocation_index < 3; ++invocation_index)
    {
      const std::string line =
          build_trace_line("cc", {"cc", std::to_string(invocation_index)}, "/w", invocation_index);
      BOMWERK_TEST_CHECK(append_trace_line(trace_path.string().c_str(), line));
    }
    BOMWERK_TEST_CHECK(read_lines(trace_path).size() == 3);
  }

  // Given many processes appending oversized lines at once: a parallel build
  //: when they all finish, then every line is intact, none is lost and none
  // is duplicated. Each append opens its own descriptor, exactly as separate
  // shim processes do.
  {
    TempTree tree;
    const std::filesystem::path trace_path = tree.root() / "trace.jsonl";
    const std::string trace_path_text = trace_path.string();
    const std::string large_argument(kLargeArgumentBytes, 'x');

    std::vector<std::thread> writer_threads;
    writer_threads.reserve(kWriterThreadCount);
    for (int thread_index = 0; thread_index < kWriterThreadCount; ++thread_index)
    {
      writer_threads.emplace_back(
          [&trace_path_text, &large_argument, thread_index]()
          {
            for (int line_index = 0; line_index < kLinesPerThread; ++line_index)
            {
              const std::string line = build_trace_line(
                  "cc",
                  {"cc", large_argument, std::to_string(thread_index), std::to_string(line_index)},
                  "/w", thread_index);
              BOMWERK_TEST_CHECK(append_trace_line(trace_path_text.c_str(), line));
            }
          });
    }
    for (std::thread& writer_thread : writer_threads)
    {
      writer_thread.join();
    }

    const std::vector<std::string> lines = read_lines(trace_path);
    BOMWERK_TEST_CHECK(lines.size() ==
                       static_cast<std::size_t>(kWriterThreadCount * kLinesPerThread));

    std::set<std::pair<std::string, std::string>> observed_identities;
    for (const std::string& line : lines)
    {
      const nlohmann::json record = nlohmann::json::parse(line, nullptr, false);
      BOMWERK_TEST_CHECK(!record.is_discarded());  // an interleaved write would land here
      BOMWERK_TEST_CHECK(record["argv"].size() == 4);
      BOMWERK_TEST_CHECK(record["argv"][1].get<std::string>().size() == kLargeArgumentBytes);
      observed_identities.emplace(record["argv"][2].get<std::string>(),
                                  record["argv"][3].get<std::string>());
    }
    // Every (thread, line) pair present exactly once: nothing lost, nothing
    // written twice, nothing shredded.
    BOMWERK_TEST_CHECK(observed_identities.size() ==
                       static_cast<std::size_t>(kWriterThreadCount * kLinesPerThread));
  }

  // Given an unwritable trace path, when a line is appended, then it fails by
  // returning false: never by throwing. The shim execs the real tool anyway:
  // observation must not be the reason a build breaks (rule 1).
  {
    TempTree tree;
    const std::filesystem::path directory_path = tree.root() / "not-a-file";
    std::filesystem::create_directories(directory_path);
    BOMWERK_TEST_CHECK(!append_trace_line(directory_path.string().c_str(), "{}\n"));
  }

  // Given no trace path at all, when a line is appended, then it degrades
  // quietly to false: this is the ordinary "not running under observe" case.
  {
    BOMWERK_TEST_CHECK(!append_trace_line(nullptr, "{}\n"));
    BOMWERK_TEST_CHECK(!append_trace_line("", "{}\n"));
  }

  return 0;
}
