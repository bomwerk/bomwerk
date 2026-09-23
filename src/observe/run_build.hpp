#pragma once
#include <string>
#include <vector>

namespace bomwerk::observe
{

/// How the wrapped build command ended.
struct BuildOutcome
{
  bool started = false;        ///< false => the command could not be spawned at all
  int exit_status = -1;        ///< the child's own exit code; meaningless unless `started`
  int terminating_signal = 0;  ///< non-zero => the child died on this signal
  std::string failure_detail;  ///< why the spawn failed, when `started` is false
};

/// Run `command` (argv[0] resolved against PATH) and wait for it.
///
/// Rule 9 forbids PRODUCERS from shelling out while scanning untrusted code.
/// This is the one command whose entire purpose is to run what the user typed,
/// so the rule's intent is honoured differently: there is no `system()`, no
/// `popen()` and no shell anywhere on this path. The argv vector reaches
/// `posix_spawnp` exactly as CLI11 captured it, so nothing in the scanned repo
/// can inject a word, expand a glob or chain a second command.
///
/// The child inherits this process's environment, which the caller has already
/// primed with `apply_environment_overlay`.
///
/// Never throws.
[[nodiscard]] BuildOutcome run_build_command(const std::vector<std::string>& command);

}  // namespace bomwerk::observe
