#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "core/result.hpp"

namespace bomwerk::parsers::cpp
{

/// One recognized CMake command invocation. `name` is the command as written
/// (original case preserved; callers lower-case for matching). `arguments` is
/// the argument list already reduced to literal text: bare, `"quoted"` and
/// `[[bracket]]` arguments are all unwrapped to the value CMake would see.
/// `line` is the 1-based line where the command name begins, for warnings.
struct CmakeCommand
{
  std::string name;
  std::vector<std::string> arguments;
  std::size_t line = 0;

  /// False when the invocation did not parse cleanly: an unterminated quote,
  /// bracket or paren, or a size/complexity cap tripped mid-command. The parsed
  /// `arguments` are then a best-effort partial (Hard Rule 1), and consumers
  /// should treat anything derived from them as low-confidence.
  bool well_formed = true;
};

/// Tokenize `text` (the contents of a `CMakeLists.txt` or `*.cmake` file) into
/// its command invocations. Pure and IO-free, so it can be unit-tested and
/// fuzzed against in-memory buffers.
///
/// Comment- and quoting-aware: `#` line comments and `#[[ ]]` / `#[=[ ]=]`
/// bracket comments are stripped, but a `#` inside a quoted or bracket argument
/// (e.g. a URL fragment `gh:owner/repo#tag`) is preserved. Arguments are read as
/// CMake sees them: bare tokens, `"double quoted"` (with `\"` / `\\` escapes)
/// and `[[ ]]` / `[=[ ]=]` bracket arguments: so a `)` or `#` inside an
/// argument never ends the call early.
///
/// Never throws. Hostile input only degrades: exceeding a size/complexity bound
/// (`kMax*` below) appends a warning and stops early, and `complete` stays true
///: a malformed file is warn-level, never the exit-2 path (Hard Rule 1).
///
/// Example: `scan_cmake_commands("CPMAddPackage(NAME fmt VERSION 10.2.1)")`
/// yields one `CmakeCommand{name: "CPMAddPackage", arguments: {"NAME", "fmt",
/// "VERSION", "10.2.1"}, line: 1}`.
[[nodiscard]] core::Result<std::vector<CmakeCommand>> scan_cmake_commands(std::string_view text);

}  // namespace bomwerk::parsers::cpp
