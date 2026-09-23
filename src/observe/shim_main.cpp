// bomwerk-shim: the fake compiler.
//
// One tiny program, symlinked into the shim directory under every name in
// kShimmedToolNames. `argv[0]` says which tool the build meant; the shim
// appends one JSON line describing the invocation, then execs the real tool
// with the arguments untouched. The build sees identical behaviour and an
// identical exit code (this is the ccache pattern).
//
// Two properties this file must never lose:
//
//  1. It NEVER searches PATH. The shim directory is first on PATH, so a search
//     would find this very program and exec it forever: a fork bomb on the
//     developer's machine. The real tool's ABSOLUTE path comes from the
//     environment, or from the `<tool>.real` sidecar, or the shim fails loudly.
//  2. It stays cheap. A build execs this thousands of times, so it links no
//     bomwerk library, no spdlog and no JSON library: getcwd, one locked
//     write, execv.
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "observe/shim_names.hpp"
#include "observe/trace_line.hpp"
#include "observe/trace_writer.hpp"

namespace
{

/// The status a POSIX shell reports for "command found but could not be
/// executed". Using the convention keeps build tools' error reporting sane.
constexpr int kExecFailureStatus = 127;

/// Enough for any real path; the getcwd loop grows from here if needed.
constexpr std::size_t kInitialCwdCapacity = 512;
constexpr std::size_t kMaxCwdCapacity = 64 * 1024;

/// A recorded tool path is one line; anything longer is not a path we wrote.
constexpr std::size_t kMaxSidecarBytes = 4096;

/// Last path component of `argv[0]`: the name the build actually invoked.
/// CMake calls the shim by absolute path, a Makefile usually by bare name;
/// both must map to the same tool.
std::string_view invoked_tool_name(const char* program_path)
{
  if (program_path == nullptr)
  {
    return std::string_view();
  }
  const std::string_view full_path(program_path);
  const std::size_t last_separator = full_path.find_last_of('/');
  if (last_separator == std::string_view::npos)
  {
    return full_path;
  }
  return full_path.substr(last_separator + 1);
}

/// Directory holding `argv[0]`, or empty when it carries no separator. Empty is
/// the PATH-lookup case, which only happens when the shim directory is on PATH,
/// which only happens under `bomwerk observe`: where the environment variables
/// are set and the sidecar fallback is never needed.
std::string_view invoked_directory(const char* program_path)
{
  if (program_path == nullptr)
  {
    return std::string_view();
  }
  const std::string_view full_path(program_path);
  const std::size_t last_separator = full_path.find_last_of('/');
  if (last_separator == std::string_view::npos)
  {
    return std::string_view();
  }
  return full_path.substr(0, last_separator);
}

std::string current_working_directory()
{
  std::string buffer(kInitialCwdCapacity, '\0');
  while (::getcwd(buffer.data(), buffer.size()) == nullptr)
  {
    if (errno != ERANGE || buffer.size() >= kMaxCwdCapacity)
    {
      return std::string();  // unknowable cwd is a blank field, never a failure
    }
    buffer.resize(buffer.size() * 2);
  }
  return std::string(buffer.c_str());
}

/// Read the `<tool>.real` sidecar next to the invoked shim. Raw POSIX calls
/// rather than `<fstream>` keep the startup path light, and this is only
/// reached when the environment variable is absent.
std::string read_real_tool_sidecar(std::string_view shim_directory, std::string_view tool_name)
{
  if (shim_directory.empty() || tool_name.empty())
  {
    return std::string();
  }
  std::string sidecar_path(shim_directory);
  sidecar_path.push_back('/');
  sidecar_path.append(tool_name);
  sidecar_path.append(bomwerk::observe::kRealToolSidecarSuffix);

  const int file_descriptor = ::open(sidecar_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (file_descriptor < 0)
  {
    return std::string();
  }
  std::string contents(kMaxSidecarBytes, '\0');
  const ssize_t bytes_read = ::read(file_descriptor, contents.data(), contents.size());
  ::close(file_descriptor);
  if (bytes_read <= 0)
  {
    return std::string();
  }
  contents.resize(static_cast<std::size_t>(bytes_read));
  while (!contents.empty() && (contents.back() == '\n' || contents.back() == '\r'))
  {
    contents.pop_back();
  }
  return contents;
}

/// Best-effort logging: an unset, unwritable or full trace degrades to a plain
/// pass-through. Observation must never be the reason a build fails (rule 1).
void record_invocation(std::string_view tool_name, int argc, char** argv)
{
  const char* trace_path = std::getenv(std::string(bomwerk::observe::kTraceEnvVarName).c_str());
  if (trace_path == nullptr || *trace_path == '\0')
  {
    return;
  }
  std::vector<std::string> arguments;
  arguments.reserve(static_cast<std::size_t>(argc));
  for (int argument_index = 0; argument_index < argc; ++argument_index)
  {
    arguments.emplace_back(argv[argument_index] != nullptr ? argv[argument_index] : "");
  }
  const std::string line = bomwerk::observe::build_trace_line(
      tool_name, arguments, current_working_directory(), static_cast<long>(::getpid()));
  (void)bomwerk::observe::append_trace_line(trace_path, line);
}

}  // namespace

int main(int argc, char** argv)
{
  const char* program_path = argc > 0 ? argv[0] : nullptr;
  const std::string_view tool_name = invoked_tool_name(program_path);

  // Resolve the real tool BEFORE logging: a shim that cannot exec anything has
  // nothing worth recording.
  std::string real_tool_path;
  const std::string real_tool_variable = bomwerk::observe::shim_env_var_name(tool_name);
  if (!real_tool_variable.empty())
  {
    const char* from_environment = std::getenv(real_tool_variable.c_str());
    if (from_environment != nullptr && *from_environment != '\0')
    {
      real_tool_path = from_environment;
    }
  }
  if (real_tool_path.empty())
  {
    // A CMake cache configured under observe stores this shim's absolute path,
    // so a later plain build invokes it with none of our variables set. The
    // sidecar is what keeps that build working.
    real_tool_path = read_real_tool_sidecar(invoked_directory(program_path), tool_name);
  }

  if (real_tool_path.empty())
  {
    std::fprintf(stderr,
                 "bomwerk-shim: no real tool recorded for '%.*s' (%s unset and no sidecar "
                 "beside the shim). Refusing to search PATH: this directory is first on it, "
                 "so the search would re-exec this shim endlessly. Re-run the build under "
                 "`bomwerk observe`, or delete the shim directory and reconfigure.\n",
                 static_cast<int>(tool_name.size()), tool_name.data(),
                 real_tool_variable.empty() ? "BOMWERK_REAL_*" : real_tool_variable.c_str());
    return kExecFailureStatus;
  }

  record_invocation(tool_name, argc, argv);

  // argv[1..] is forwarded verbatim. argv[0] is rewritten to real_tool_path:
  // real_tool_path is already resolved per invoked name (the `c++` shim
  // resolves to the real `c++`, `clang++` to the real `clang++`, ...), so
  // language-mode dispatch on the driver's own name is unaffected. Leaving
  // argv[0] as the shim's own path instead breaks gcc, whose driver derives
  // GCC_EXEC_PREFIX (where it looks for cc1/cc1plus) from argv[0]'s directory:
  // invoked through the shim directory, it searches there for cc1 and fails.
  argv[0] = const_cast<char*>(real_tool_path.c_str());
  ::execv(real_tool_path.c_str(), argv);

  // execv only returns on failure.
  std::fprintf(stderr, "bomwerk-shim: cannot exec %s: %s\n", real_tool_path.c_str(),
               std::strerror(errno));
  return kExecFailureStatus;
}
