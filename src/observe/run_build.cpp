#include "observe/run_build.hpp"

#include <spawn.h>
#include <sys/wait.h>

#include <cerrno>
#include <cstring>

/// The process environment. `apply_environment_overlay` has already added the
/// shim PATH and the BOMWERK_REAL_* variables to it, so passing it through is
/// what puts the child under observation.
extern char** environ;

namespace bomwerk::observe
{

BuildOutcome run_build_command(const std::vector<std::string>& command)
{
  BuildOutcome outcome;
  if (command.empty())
  {
    outcome.failure_detail = "no build command given";
    return outcome;
  }

  // posix_spawn wants a mutable, null-terminated argv. The strings themselves
  // outlive the call, so pointing into them is safe.
  std::vector<char*> argument_pointers;
  argument_pointers.reserve(command.size() + 1);
  for (const std::string& argument : command)
  {
    argument_pointers.push_back(const_cast<char*>(argument.c_str()));
  }
  argument_pointers.push_back(nullptr);

  pid_t child_process_id = 0;
  const int spawn_result = ::posix_spawnp(&child_process_id, command[0].c_str(), nullptr, nullptr,
                                          argument_pointers.data(), environ);
  if (spawn_result != 0)
  {
    outcome.failure_detail =
        std::string("cannot run '") + command[0] + "': " + std::strerror(spawn_result);
    return outcome;
  }
  outcome.started = true;

  int wait_status = 0;
  while (::waitpid(child_process_id, &wait_status, 0) < 0)
  {
    if (errno != EINTR)
    {
      outcome.failure_detail =
          std::string("lost track of the build process: ") + std::strerror(errno);
      outcome.started = false;
      return outcome;
    }
  }

  if (WIFEXITED(wait_status))
  {
    outcome.exit_status = WEXITSTATUS(wait_status);
  }
  else if (WIFSIGNALED(wait_status))
  {
    outcome.terminating_signal = WTERMSIG(wait_status);
  }
  return outcome;
}

}  // namespace bomwerk::observe
