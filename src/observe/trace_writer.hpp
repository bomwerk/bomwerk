#pragma once
#include <string_view>

namespace bomwerk::observe
{

/// Append one already-built line to the trace, safely against every other shim
/// process appending at the same moment.
///
/// Why a lock and not bare `O_APPEND`: a parallel build (`make -j8`) has many
/// shims writing at once, and `write()` is only guaranteed atomic below
/// PIPE_BUF (4 KiB). Real C++ compile commands routinely exceed that with long
/// `-I` lists, so an unlocked append would interleave and corrupt lines
/// precisely on the large builds that matter most. `flock` costs microseconds
/// against a multi-second compile, so contention is noise.
///
/// `trace_path` is a C string, not a `std::filesystem::path`, on purpose: this
/// runs once per compile and the value comes straight from `getenv`, so the
/// shim avoids pulling `<filesystem>` into its startup path.
///
/// Never throws. Returns false when the trace could not be opened, locked or
/// fully written; the caller treats that as "no logging" and execs anyway :
/// observation must never break the build (rule 1).
[[nodiscard]] bool append_trace_line(const char* trace_path, std::string_view line);

}  // namespace bomwerk::observe
