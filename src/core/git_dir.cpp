#include "core/git_dir.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ios>
#include <string_view>
#include <system_error>

#include "core/file_io.hpp"
#include "core/text.hpp"

namespace fs = std::filesystem;

namespace bomwerk::core
{
namespace
{

// Git plumbing files (HEAD, a loose ref, the ".git" pointer) are a few dozen
// bytes; packed-refs can be larger but is git-generated. Cap both so a crafted
// repo cannot make us read an unbounded amount (rule 1).
constexpr std::size_t kMaxRefFileBytes = 4u * 1024u;
constexpr std::size_t kMaxPackedRefsBytes = 4u * 1024u * 1024u;

/// True when `candidate` (already absolute and lexically normal) is
/// `containment_root` itself or nested under it. A submodule's (or vendored
/// folder's) `.git` file legitimately points OUTSIDE its own working
/// directory: real git lays the gitdir out at `<root>/.git/modules/<name>` :
/// so containment is checked against the overall scanned root, not the
/// working directory itself; a hostile pointer that escapes the whole scanned
/// tree is what this rejects.
bool is_within_root(const fs::path& candidate, const fs::path& containment_root)
{
  const fs::path relative = candidate.lexically_relative(containment_root);
  if (relative.empty())
  {
    return false;
  }
  return *relative.begin() != "..";
}

/// Find the object id a ref points to in `<git_dir>/packed-refs`. Skips the
/// header (`#`) and peeled-tag (`^`) lines. Bounded: an oversized file is
/// ignored rather than read.
std::string commit_from_packed_refs(const fs::path& git_dir, const std::string& ref)
{
  const fs::path packed_refs = git_dir / "packed-refs";
  std::error_code size_error;
  const std::uintmax_t size = fs::file_size(packed_refs, size_error);
  if (size_error || size > kMaxPackedRefsBytes)
  {
    return {};
  }
  std::ifstream stream(packed_refs, std::ios::binary);
  if (!stream)
  {
    return {};
  }
  std::string line;
  while (std::getline(stream, line))
  {
    const std::string entry = trimmed(line);
    if (entry.empty() || entry.front() == '#' || entry.front() == '^')
    {
      continue;
    }
    const std::size_t space = entry.find(' ');
    if (space == std::string::npos)
    {
      continue;
    }
    const std::string object_id = entry.substr(0, space);
    const std::string ref_name = trimmed(std::string_view(entry).substr(space + 1));
    if (ref_name == ref && is_hex_object_id(object_id))
    {
      return object_id;
    }
  }
  return {};
}

}  // namespace

bool is_contained_relative_path(const fs::path& relative_path)
{
  if (relative_path.empty() || relative_path.is_absolute())
  {
    return false;
  }
  for (const fs::path& part : relative_path.lexically_normal())
  {
    if (part == "..")
    {
      return false;
    }
  }
  return true;
}

fs::path resolve_git_dir(const fs::path& work_dir, const fs::path& containment_root)
{
  const fs::path git_entry = work_dir / ".git";
  std::error_code status_error;
  const fs::file_status link_status = fs::symlink_status(git_entry, status_error);
  if (status_error || fs::is_symlink(link_status))
  {
    return {};
  }
  if (fs::is_directory(link_status))
  {
    return git_entry;
  }
  if (!fs::is_regular_file(link_status))
  {
    return {};
  }

  const std::string pointer = read_first_line_bounded(git_entry, kMaxRefFileBytes);
  constexpr std::string_view kGitDirPrefix = "gitdir:";
  if (!pointer.starts_with(kGitDirPrefix))
  {
    return {};
  }
  const std::string target = trimmed(std::string_view(pointer).substr(kGitDirPrefix.size()));
  if (target.empty())
  {
    return {};
  }
  const fs::path target_path(target);
  const fs::path candidate = target_path.is_absolute() ? target_path : (work_dir / target_path);
  const fs::path resolved = candidate.lexically_normal();

  std::error_code absolute_error;
  const fs::path absolute_resolved = fs::absolute(resolved, absolute_error).lexically_normal();
  if (absolute_error || !is_within_root(absolute_resolved, containment_root))
  {
    return {};  // gitdir escapes the scanned tree; never read outside it
  }
  return resolved;
}

std::string read_head_commit(const fs::path& git_dir)
{
  const std::string head = read_first_line_bounded(git_dir / "HEAD", kMaxRefFileBytes);
  if (head.empty())
  {
    return {};
  }
  constexpr std::string_view kRefPrefix = "ref:";
  if (!head.starts_with(kRefPrefix))
  {
    return is_hex_object_id(head) ? head : std::string{};
  }
  const std::string ref = trimmed(std::string_view(head).substr(kRefPrefix.size()));
  if (ref.empty() || !is_contained_relative_path(fs::path(ref)))
  {
    return {};  // reject before ever joining an untrusted ref onto a path
  }
  const std::string loose = read_first_line_bounded(git_dir / fs::path(ref), kMaxRefFileBytes);
  if (is_hex_object_id(loose))
  {
    return loose;
  }
  return commit_from_packed_refs(git_dir, ref);
}

}  // namespace bomwerk::core
