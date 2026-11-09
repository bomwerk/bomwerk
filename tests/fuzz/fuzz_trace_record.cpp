// libFuzzer harness for build trace lines (T40): the input is split into
// lines the way `read_trace` reads a trace file, and each line is parsed with
// `parse_trace_record`. No code under src/observe/ is changed for this.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "fuzz/fuzz_support.hpp"
#include "observe/trace_read.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  std::string_view remaining = bomwerk::fuzz::as_text(data, size);
  while (!remaining.empty())
  {
    const std::size_t newline = remaining.find('\n');
    const std::string line(remaining.substr(0, newline));
    bomwerk::observe::TraceRecord record;
    static_cast<void>(bomwerk::observe::parse_trace_record(line, record));
    remaining =
        newline == std::string_view::npos ? std::string_view{} : remaining.substr(newline + 1);
  }
  return 0;
}
