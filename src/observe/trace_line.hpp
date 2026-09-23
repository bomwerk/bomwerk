#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace bomwerk::observe
{

/// Build the single JSON line a shim appends for one tool invocation.
///
/// Keys are emitted in sorted order: `argv`, `cwd`, `pid`, `tool`: because
/// canonical JSON is the output contract (hard rule 3) and the trace is an
/// artifact users diff between runs.
///
/// Deliberately carries NO timestamp: a wall clock would make two otherwise
/// identical builds produce different traces, breaking that same rule. `pid`
/// is what the compile and link scans use to correlate a compile with the process that ran it.
///
/// Hostile input is expected: argv and paths are attacker-influenced on an
/// untrusted repo. Quotes, backslashes and control characters are escaped, and
/// bytes that are not valid UTF-8 (legal in a POSIX filename, illegal in JSON)
/// become U+FFFD so one odd filename degrades that argument instead of
/// corrupting the line (rule 1).
///
/// The returned string ends with `\n` and is ready to append verbatim.
[[nodiscard]] std::string build_trace_line(std::string_view tool_name,
                                           const std::vector<std::string>& arguments,
                                           std::string_view working_directory, long process_id);

}  // namespace bomwerk::observe
