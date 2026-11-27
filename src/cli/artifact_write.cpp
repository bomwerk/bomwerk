#include "cli/artifact_write.hpp"

#include <spdlog/spdlog.h>

#include "core/atomic_file.hpp"

namespace bomwerk::cli
{

bool write_artifact(const std::filesystem::path& path, std::string_view contents,
                    std::string_view artifact_label)
{
  const core::AtomicWriteOutcome outcome = core::write_file_atomically(path, contents);
  if (!outcome.written)
  {
    spdlog::error("{}", core::describe_atomic_write_failure(artifact_label, path, outcome));
    return false;
  }
  return true;
}

}  // namespace bomwerk::cli
