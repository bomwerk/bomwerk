#include "observe/compile_map.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "core/file_index.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::observe
{

using core::contains;

namespace
{

/// Compiler drivers whose command line names source files. A subset of
/// `kShimmedToolNames` on purpose: `ld` and `ar` are shimmed too, but their
/// arguments are objects and archives, not sources.
constexpr std::array<std::string_view, 6> kCompilerToolNames{"cc",  "c++",   "gcc",
                                                             "g++", "clang", "clang++"};

/// Suffixes a compiler driver treats as a translation unit. Compared
/// lower-cased, so gcc's `.C`/`.S` (C++ and preprocessed assembly) and a
/// Windows-authored `.CPP` all land here without separate entries.
constexpr std::array<std::string_view, 8> kSourceFileExtensions{".c",   ".cc", ".cpp", ".cxx",
                                                                ".c++", ".m",  ".mm",  ".s"};

/// Options that name a directory to search for headers. Each accepts both the
/// separated form (`-I dir`) and the joined one (`-Idir`), which is why they
/// are matched by prefix rather than by equality.
constexpr std::array<std::string_view, 4> kIncludePathOptions{"-I", "-isystem", "-iquote",
                                                              "-idirafter"};

/// Options that swallow the FOLLOWING argument. Without this table a compile
/// line's output name (`-o out.c`), forced header (`-include prefix.h`) or
/// dependency-file name (`-MF foo.d`) would each be read as a compiled source,
/// inventing usage that never happened.
constexpr std::array<std::string_view, 21> kOptionsConsumingNextArgument{
    "-o",        "-include", "-imacros", "-D",
    "-U",        "-L",       "-l",       "-MF",
    "-MT",       "-MQ",      "-x",       "--sysroot",
    "-isysroot", "-Xclang",  "-Xlinker", "-Xpreprocessor",
    "-T",        "-u",       "-e",       "-arch",
    "-framework"};

/// Leading character of a response file argument (`@objects.rsp`).
constexpr char kResponseFilePrefix = '@';

/// The single-dash argument meaning "read the translation unit from stdin".
/// There is no path to attribute, so it is skipped rather than resolved.
constexpr std::string_view kStdinArgument = "-";

/// The bare linker's own tool name, as `kShimmedToolNames` spells it.
constexpr std::string_view kBareLinkerToolName = "ld";

/// Options that stop a compiler driver before it links: with any of these
/// present, the invocation is a compile (the compile scan's evidence), not a link (the link
/// scan's).
constexpr std::array<std::string_view, 3> kCompileOnlyOptions{"-c", "-S", "-E"};

/// Whether `argument` names a translation unit by suffix.
bool has_source_file_extension(std::string_view argument)
{
  const std::string extension = core::to_lower_ascii(fs::path(argument).extension().string());
  return contains(kSourceFileExtensions, extension);
}

/// The include directory `argument` carries, or nothing. `consumed_next` is
/// set when the value came from the following argv entry, so the caller skips
/// it instead of re-reading it as a source file.
std::string_view include_path_value(std::string_view argument, std::string_view next_argument,
                                    bool& consumed_next)
{
  consumed_next = false;
  for (const std::string_view option : kIncludePathOptions)
  {
    if (argument == option)
    {
      consumed_next = true;
      return next_argument;
    }
    if (argument.size() > option.size() && argument.starts_with(option))
    {
      return argument.substr(option.size());
    }
  }
  return {};
}

/// Evidence text for a component the build compiled. States the count and one
/// example: the count is the strength of the claim, the example is what lets a
/// reviewer check it by hand.
std::string compiled_source_detail(const ComponentUsage& usage)
{
  return "observed build: " + std::to_string(usage.compiled_source_count) +
         " source file(s) compiled under " + usage.root.generic_string() + " (e.g. " +
         usage.first_compiled_source.generic_string() + ")";
}

/// Evidence text for a component only ever named as an include directory.
/// Says plainly that nothing was compiled, because that is the difference
/// between this claim and the one above.
std::string include_path_detail(const ComponentUsage& usage)
{
  return "observed build: no source compiled, but " + std::to_string(usage.include_path_count) +
         " compile line(s) added " + usage.first_include_path.generic_string() +
         " to the include search path";
}

/// Evidence text for a component whose object/archive/shared-object appeared
/// as a link input, with no source ever seen compiled under this root: a
/// prebuilt vendored `.a`/`.so` checked into the repo is the central case,
/// and the reason the link scan exists: the compile scan alone can never mark such a component
/// used, because it never sees a source to compile.
std::string linked_input_detail(const ComponentUsage& usage)
{
  return "observed build: no source compiled, but " + std::to_string(usage.linked_input_count) +
         " link input(s) resolved under " + usage.root.generic_string() + " (e.g. " +
         usage.first_linked_input.generic_string() + ")";
}

}  // namespace

const fs::path& DirectoryResolver::canonical(const fs::path& directory)
{
  const auto cached = cache_.find(directory);
  if (cached != cache_.end())
  {
    return cached->second;
  }
  std::error_code error;
  fs::path resolved = fs::weakly_canonical(directory, error);
  if (error || resolved.empty())
  {
    resolved = fs::absolute(directory, error);
    if (error || resolved.empty())
    {
      resolved = directory;
    }
    resolved = resolved.lexically_normal();
  }
  return cache_.emplace(directory, std::move(resolved)).first->second;
}

fs::path absolute_argument_path(const fs::path& working_directory, std::string_view argument)
{
  fs::path candidate(argument);
  if (!candidate.is_absolute())
  {
    candidate = working_directory / candidate;
  }
  return candidate.lexically_normal();
}

fs::path resolve_directory_argument(DirectoryResolver& resolver, const fs::path& working_directory,
                                    std::string_view argument)
{
  return resolver.canonical(absolute_argument_path(working_directory, argument));
}

fs::path resolve_file_argument(DirectoryResolver& resolver, const fs::path& working_directory,
                               std::string_view argument)
{
  const fs::path candidate = absolute_argument_path(working_directory, argument);
  return resolver.canonical(candidate.parent_path()) / candidate.filename();
}

std::optional<fs::path> to_root_relative(const fs::path& absolute_path,
                                         const fs::path& canonical_root)
{
  const fs::path relative_path = absolute_path.lexically_relative(canonical_root);
  if (relative_path.empty())
  {
    return std::nullopt;
  }
  if (relative_path.begin() != relative_path.end() && *relative_path.begin() == "..")
  {
    return std::nullopt;
  }
  return relative_path;
}

const fs::path* enclosing_root(const fs::path& start_directory, const std::set<fs::path>& roots)
{
  fs::path candidate = start_directory;
  while (!candidate.empty())
  {
    const auto found = roots.find(candidate);
    if (found != roots.end())
    {
      return &*found;
    }
    // Termination is checked by comparing against the PREVIOUS value, not by
    // asking whether a parent exists: `parent_path()` is a fixed point at the
    // filesystem root (`/` has no relative path, so it is its own parent and
    // still reports `has_parent_path()`), and a walk that reached it would
    // spin forever. Callers pass root-relative paths today, so this is
    // hardening rather than a live bug: but a hang is a bad way to find out
    // that stopped being true.
    fs::path parent = candidate.parent_path();
    if (parent == candidate)
    {
      break;
    }
    candidate = std::move(parent);
  }
  return nullptr;
}

void keep_lowest(fs::path& kept, const fs::path& candidate)
{
  if (kept.empty() || candidate < kept)
  {
    kept = candidate;
  }
}

bool is_compiler_tool_name(std::string_view tool_name)
{
  return contains(kCompilerToolNames, tool_name);
}

bool is_link_mode_invocation(const TraceRecord& record)
{
  if (record.tool == kBareLinkerToolName)
  {
    return true;
  }
  if (!is_compiler_tool_name(record.tool))
  {
    return false;
  }
  for (std::size_t argument_index = 1; argument_index < record.arguments.size(); ++argument_index)
  {
    const std::string& argument = record.arguments[argument_index];
    // A response file's contents are never opened (rule 1's "never invent
    // evidence" cuts both ways: it can just as easily hide -c/-S/-E as it can
    // hide a source list), so its presence makes the compile-or-link question
    // unanswerable from argv alone. Defaulting to "not link-mode" keeps this
    // record on the compile-only path rather than guessing a classification
    // neither scan can back up.
    if (!argument.empty() && argument.front() == kResponseFilePrefix)
    {
      return false;
    }
    if (contains(kCompileOnlyOptions, std::string_view(argument)))
    {
      return false;
    }
  }
  return true;
}

CompileLine scan_compile_line(const TraceRecord& record)
{
  CompileLine line;
  // argv[0] is the tool itself, never an input.
  for (std::size_t argument_index = 1; argument_index < record.arguments.size(); ++argument_index)
  {
    const std::string& argument = record.arguments[argument_index];
    if (argument.empty() || argument == kStdinArgument)
    {
      continue;
    }
    if (argument.front() == kResponseFilePrefix)
    {
      ++line.response_file_count;
      continue;
    }
    if (argument.front() != '-')
    {
      if (has_source_file_extension(argument))
      {
        line.source_arguments.push_back(argument);
      }
      continue;
    }

    const std::string_view next_argument =
        argument_index + 1 < record.arguments.size()
            ? std::string_view(record.arguments[argument_index + 1])
            : std::string_view{};
    bool consumed_next = false;
    const std::string_view include_path =
        include_path_value(argument, next_argument, consumed_next);
    if (!include_path.empty())
    {
      line.include_path_arguments.emplace_back(include_path);
    }
    // Skip the value of any option that took one, whether that value was an
    // include directory (`-I dir`) or something to be ignored (`-o out.c`).
    // Skipping is the whole point: an unskipped value is read as a source file
    // on the next pass, which invents usage the build never had. The joined
    // spellings (`-Idir`, `-DNAME=1`) carry their value inside the argument
    // and so consume nothing, which is why neither branch fires for them.
    if (consumed_next || contains(kOptionsConsumingNextArgument, argument))
    {
      ++argument_index;
    }
  }
  return line;
}

std::set<fs::path> component_roots_of(const std::vector<core::Component>& components)
{
  std::set<fs::path> roots;
  for (const core::Component& component : components)
  {
    const fs::path normalized_root = core::normalized_subtree_path(component.root);
    if (!normalized_root.empty())
    {
      roots.insert(normalized_root);
    }
  }
  return roots;
}

core::Result<CompileMap> map_compiles_to_roots(const std::vector<TraceRecord>& records,
                                               const fs::path& scan_root,
                                               const std::set<fs::path>& component_roots)
{
  core::Result<CompileMap> outcome;
  for (const fs::path& root : component_roots)
  {
    outcome.value.usage_by_root[root].root = root;
  }

  DirectoryResolver resolver;
  const fs::path canonical_root = resolver.canonical(scan_root);

  // Sources are collected as SETS before counting so that a build compiling
  // the same file twice (a debug pass and a release pass) does not inflate a
  // count into something a reviewer cannot reconcile with the files in the
  // tree. The out-of-tree tally is a set for the same reason.
  std::map<fs::path, std::set<fs::path>> sources_by_root;
  std::set<fs::path> out_of_tree_sources;

  for (const TraceRecord& record : records)
  {
    if (!is_compiler_tool_name(record.tool))
    {
      continue;
    }
    // A link-mode record is never counted as a compile invocation (that
    // stays the link scan's evidence, not the compile scan's: see is_link_mode_invocation), but
    // its argv is still scanned below: a single-step "compile and link in one command" invocation
    // (`cc -o app main.c`, no `-c`) is classified link-mode by is_link_mode_invocation, yet still
    // names a real source or include path directly on the same line, and the link scan only
    // recognizes `.o`/`.a`/`.so`: skipping the scan entirely here would
    // silently drop that evidence rather than merely avoid double-counting.
    if (!is_link_mode_invocation(record))
    {
      ++outcome.value.compile_invocations;
    }

    const CompileLine line = scan_compile_line(record);
    outcome.value.unexpanded_response_files += line.response_file_count;
    const fs::path working_directory = resolver.canonical(fs::path(record.working_directory));

    for (const std::string& source_argument : line.source_arguments)
    {
      const fs::path absolute_source =
          resolve_file_argument(resolver, working_directory, source_argument);
      const std::optional<fs::path> relative_source =
          to_root_relative(absolute_source, canonical_root);
      if (!relative_source.has_value())
      {
        out_of_tree_sources.insert(absolute_source);
        continue;
      }
      outcome.value.compiled_sources.insert(*relative_source);
      const fs::path* root = enclosing_root(relative_source->parent_path(), component_roots);
      if (root != nullptr)
      {
        sources_by_root[*root].insert(*relative_source);
      }
    }

    for (const std::string& include_argument : line.include_path_arguments)
    {
      const fs::path absolute_include =
          resolve_directory_argument(resolver, working_directory, include_argument);
      const std::optional<fs::path> relative_include =
          to_root_relative(absolute_include, canonical_root);
      if (!relative_include.has_value())
      {
        continue;
      }
      const fs::path* root = enclosing_root(*relative_include, component_roots);
      if (root == nullptr)
      {
        continue;
      }
      ComponentUsage& usage = outcome.value.usage_by_root[*root];
      ++usage.include_path_count;
      keep_lowest(usage.first_include_path, *relative_include);
      usage.signal = std::max(usage.signal, UsageSignal::IncludePath);
    }
  }

  outcome.value.out_of_tree_sources = out_of_tree_sources.size();

  for (const auto& [root, sources] : sources_by_root)
  {
    ComponentUsage& usage = outcome.value.usage_by_root[root];
    usage.compiled_source_count = sources.size();
    if (!sources.empty())
    {
      usage.first_compiled_source = *sources.begin();
      usage.signal = std::max(usage.signal, UsageSignal::CompiledSource);
    }
  }

  // Gated on compiled_sources too, not just compile_invocations: a trace made
  // entirely of single-step compile-and-link records (`cc -o app main.c`, no
  // `-c`) has zero compile invocations by the compile scan's own count, yet the scan above
  // still finds a real source on each of them: the warning below must not
  // claim no evidence exists when some plainly does.
  if (outcome.value.compile_invocations == 0 && outcome.value.compiled_sources.empty())
  {
    outcome.warn(
        core::WarningCode::kObserveNoCompilerInvocations,
        "the trace holds no compiler invocations naming a source file, so no component's "
        "compiled-source or include-path evidence can be produced from it; link evidence, if "
        "any, is judged separately. Record the build with `bomwerk observe` first, and "
        "configure it under observe too if it is a CMake tree");
  }
  // The signature of a wrong scanned root: the build named source files, and
  // not one of them is inside the tree we were asked about. Without this the
  // run is indistinguishable from a real finding: every located component
  // reported unused, dropped from a trimmed SBOM, and an exit code of 0
  // saying the answer can be trusted. `--root` defaults to the current
  // directory, so getting this wrong takes nothing more than standing one
  // level up.
  if (outcome.value.compile_invocations > 0 && outcome.value.compiled_sources.empty() &&
      outcome.value.out_of_tree_sources > 0)
  {
    outcome.warn(core::WarningCode::kObserveEvidenceOutsideRoot,
                 "every compiled source lies outside " + scan_root.string() +
                     ", so no component there can be shown to be used. The trace was almost "
                     "certainly recorded against a different directory: point --root at the "
                     "repository this SBOM describes");
  }
  if (outcome.value.unexpanded_response_files > 0)
  {
    outcome.warn(core::WarningCode::kObserveResponseFilesUnexpanded,
                 std::to_string(outcome.value.unexpanded_response_files) +
                     " compile argument(s) were response files (@file), which bomwerk does not "
                     "open; a component whose sources appear only inside one may be reported "
                     "unused");
  }
  return outcome;
}

UsedSetSummary mark_used_in_build(std::vector<core::Component>& components, const CompileMap& map)
{
  UsedSetSummary summary;
  for (core::Component& component : components)
  {
    const fs::path normalized_root = core::normalized_subtree_path(component.root);
    if (normalized_root.empty())
    {
      ++summary.not_judgeable;
      continue;
    }
    ++summary.judged;

    const auto found = map.usage_by_root.find(normalized_root);
    const UsageSignal signal =
        found != map.usage_by_root.end() ? found->second.signal : UsageSignal::None;
    if (signal == UsageSignal::None)
    {
      component.used_in_build = false;
      ++summary.unused;
      continue;
    }

    component.used_in_build = true;
    ++summary.used;
    std::string detail;
    core::Confidence confidence = core::Confidence::Medium;
    if (signal == UsageSignal::CompiledSource)
    {
      detail = compiled_source_detail(found->second);
      confidence = core::Confidence::High;
    }
    else if (signal == UsageSignal::Linked)
    {
      detail = linked_input_detail(found->second);
      confidence = core::Confidence::High;
    }
    else  // UsageSignal::IncludePath -- the only possibility left once None was handled above
    {
      detail = include_path_detail(found->second);
    }
    component.evidence.push_back(core::Evidence{core::Source::ObservedBuild, detail, confidence});
  }
  return summary;
}

}  // namespace bomwerk::observe
