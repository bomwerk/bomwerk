#pragma once
#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "observe/trace_read.hpp"

namespace bomwerk::observe
{

/// What a trace proved about one component, weakest first so `std::max` picks
/// the strongest of several observations.
///
/// The three rungs are not the same claim, and flattening them would be wrong
/// in every direction. A COMPILED source under a component's root is the most
/// direct proof: the compiler read that file and emitted an object from it. A
/// LINKED input: a `.o`/`.a`/`.so` resolved on a link line, or `-lNAME`
/// resolved against `-L`: is also strong, and it is the ONLY signal a
/// prebuilt vendored archive can ever produce, since bomwerk never watches it
/// get compiled; it ranks below CompiledSource only because it names a path
/// consumed by the linker rather than a source read by the compiler. An
/// INCLUDE PATH is weaker still: a build may add `-Ithird_party/json/include`
/// to every compile line whether or not a single header there is ever
/// included: but it is the only signal a header-only library can ever
/// produce, and those are common enough in C/C++ that ignoring them would mark
/// most of them unused, which is the worse error for an SBOM to make.
enum class UsageSignal
{
  None,
  IncludePath,
  Linked,
  CompiledSource
};

/// What one compile command line named, before any of it is resolved against a
/// repository. Separated from the path work so the argv rules: which options
/// swallow the following word, which suffixes are source files: can be tested
/// on their own, without a filesystem.
struct CompileLine
{
  std::vector<std::string> source_arguments;        ///< argv entries naming a source file
  std::vector<std::string> include_path_arguments;  ///< -I/-isystem/-iquote/-idirafter values
  std::size_t response_file_count = 0;              ///< `@file` arguments, deliberately unexpanded
};

/// The evidence a trace carries for one component root.
struct ComponentUsage
{
  std::filesystem::path root;                   ///< root-relative, as the component carries it
  UsageSignal signal = UsageSignal::None;       ///< strongest signal seen
  std::size_t compiled_source_count = 0;        ///< distinct sources compiled under `root`
  std::size_t include_path_count = 0;           ///< compile lines adding an include path here
  std::size_t linked_input_count = 0;           ///< distinct link inputs resolved under `root`
  std::filesystem::path first_compiled_source;  ///< sorted-first, quoted in the evidence text
  std::filesystem::path first_include_path;     ///< sorted-first, quoted in the evidence text
  std::filesystem::path first_linked_input;     ///< sorted-first, quoted in the evidence text
};

/// Everything a trace says about one repository's component roots.
///
/// The counts that are not about components are the honest part: a build whose
/// compiles all live outside the scanned tree, or which hid them in response
/// files, has told us nothing, and the caller needs to be able to say so
/// instead of reporting every component unused.
struct CompileMap
{
  std::map<std::filesystem::path, ComponentUsage> usage_by_root;  ///< every root asked about
  std::set<std::filesystem::path> compiled_sources;               ///< root-relative, in-tree
  std::size_t compile_invocations = 0;        ///< trace records from a compiler driver
  std::size_t out_of_tree_sources = 0;        ///< /usr/include, a sibling checkout, a temp file
  std::size_t unexpanded_response_files = 0;  ///< `@file` arguments not followed
};

/// How a whole component list fared against a trace.
struct UsedSetSummary
{
  std::size_t judged = 0;         ///< components carrying a root, so a compile trace can speak
  std::size_t used = 0;           ///< of `judged`, those with any signal
  std::size_t unused = 0;         ///< of `judged`, those with none
  std::size_t not_judgeable = 0;  ///< rootless components; see `mark_used_in_build`
};

/// Whether `tool_name` is a compiler driver whose command line names source
/// files. `ld` and `ar` are deliberately absent: their arguments are objects
/// and archives, which is the link scan's evidence, not the compile scan's.
[[nodiscard]] bool is_compiler_tool_name(std::string_view tool_name);

/// Whether `record` is a LINK-MODE invocation: either the bare linker
/// (`tool == "ld"`), or a compiler-driver invocation (`is_compiler_tool_name`)
/// whose argv carries none of `-c`/`-S`/`-E`. A compiler-driver record naming
/// none of those always runs a link as its last phase: even one that also
/// names a `.c` source directly (`cc -o app main.c`): so this is the ONE
/// place the compile-line scan and the link-line scan agree on which half
/// of a cc/c++/... record's evidence applies. A record must never be
/// classified as both, or the two would double-count it, or disagree about
/// what a build step proves. `ar` needs no mention here: it is neither
/// `is_compiler_tool_name` nor `"ld"`, so it already falls through both
/// scans' tool checks without this predicate being consulted at all.
[[nodiscard]] bool is_link_mode_invocation(const TraceRecord& record);

/// Pull the source files and include directories out of one invocation's argv.
///
/// The option table this walks is the whole difficulty. `cc -o out.c foo.o`
/// must not report `out.c` as a compiled source, and `-include foo/prefix.h`
/// must not report a header as one: so every option known to swallow the
/// following word is skipped together with its value. An unknown `-flag` is
/// simply ignored, which is the safe direction: a missed source under-claims
/// usage, while a mis-read one invents it.
///
/// `@response-file` arguments are counted, never opened. Following one means
/// reading a path chosen by the scanned repository's own build system, and the
/// count lets the caller warn honestly instead of silently reporting the
/// components hidden inside it as unused.
[[nodiscard]] CompileLine scan_compile_line(const TraceRecord& record);

/// Resolve symlinks once per directory and remember the answer.
///
/// A build tree reached through a symlink is the normal case, not the exotic
/// one: `/tmp` is `/private/tmp` on macOS, and CI checkouts are routinely
/// symlinked: and a trace recorded under one spelling of a path shares no
/// prefix with a scan root spelled the other way. Doing this per ARGUMENT
/// would mean a stat per compile flag on a build with hundreds of thousands of
/// them; per directory it is a few thousand.
///
/// Exposed (not file-local) so `link_map.cpp` can reuse this exact cache
/// instead of duplicating its logic: there is nothing compile-specific
/// about it. `map_compiles_to_roots` and `map_links_to_roots` each still
/// build their own instance today, so a working directory shared by a
/// compile record and its sibling link record is canonicalized once per
/// scan, not once per trace; threading a single instance between the two
/// calls would remove that duplication but is a caller-side change, not
/// something this class does on its own.
class DirectoryResolver
{
 public:
  /// Canonical form of `directory`, or the best absolute form available when
  /// it does not exist (a build tree already deleted, a path only the build
  /// system ever saw). Never throws.
  ///
  /// `fs::absolute` is the middle fallback, and it matters: everything a trace
  /// carries is absolute, so a scan root left RELATIVE here shares a prefix
  /// with none of it and every component comes back unused: a confidently
  /// wrong answer rather than a degraded one. `lexically_normal` is the last
  /// resort only because something must be returned.
  [[nodiscard]] const std::filesystem::path& canonical(const std::filesystem::path& directory);

 private:
  std::map<std::filesystem::path, std::filesystem::path> cache_;
};

/// Absolute form of one argv path, before symlinks are resolved.
/// `working_directory` is already canonical; a relative argument is joined
/// onto it, an absolute one stands on its own.
[[nodiscard]] std::filesystem::path absolute_argument_path(
    const std::filesystem::path& working_directory, std::string_view argument);

/// Absolute, symlink-resolved form of an argv path naming a DIRECTORY.
[[nodiscard]] std::filesystem::path resolve_directory_argument(
    DirectoryResolver& resolver, const std::filesystem::path& working_directory,
    std::string_view argument);

/// Absolute, symlink-resolved form of an argv path naming a FILE. Only the
/// containing directory is resolved: a source file's own name is never a
/// symlink worth following, and resolving per file would defeat the cache
/// that makes this affordable at all.
[[nodiscard]] std::filesystem::path resolve_file_argument(
    DirectoryResolver& resolver, const std::filesystem::path& working_directory,
    std::string_view argument);

/// `absolute_path` expressed relative to `canonical_root`, or nothing when it
/// lies outside the scanned tree (a system header, a sibling checkout).
[[nodiscard]] std::optional<std::filesystem::path> to_root_relative(
    const std::filesystem::path& absolute_path, const std::filesystem::path& canonical_root);

/// The longest root in `roots` that contains `start_directory`, searching from
/// the directory itself upwards. Longest-first is what makes a source under
/// `third_party/zlib` attribute to zlib rather than to `third_party`.
[[nodiscard]] const std::filesystem::path* enclosing_root(
    const std::filesystem::path& start_directory, const std::set<std::filesystem::path>& roots);

/// Remember `candidate` when it sorts before what is already there, so the
/// example quoted in a component's evidence does not depend on trace order
/// (rule 3).
void keep_lowest(std::filesystem::path& kept, const std::filesystem::path& candidate);

/// The distinct, normalized roots `components` carry, which is exactly the set
/// `map_compiles_to_roots` must be given. Exposed so a caller cannot normalize
/// one side of the comparison and not the other: a mismatch there would look
/// like "nothing was used" rather than like a bug.
[[nodiscard]] std::set<std::filesystem::path> component_roots_of(
    const std::vector<core::Component>& components);

/// Map every compile in `records` onto `component_roots`, relative to
/// `scan_root` (the repository the trace was recorded against).
///
/// Paths in a trace are whatever the build system typed, so they are resolved
/// against each record's own working directory and then canonicalized: a
/// build tree reached through a symlink (`/tmp` on macOS is really
/// `/private/tmp`) would otherwise share no prefix with the scanned root and
/// every component would come back unused. Canonicalization is memoized per
/// directory: a large build has hundreds of thousands of arguments but only
/// thousands of directories.
///
/// The longest matching root wins, so a source under `third_party/zlib` is
/// attributed to zlib and not to a hypothetical `third_party` component.
///
/// Never throws (rule 1); a path that cannot be resolved is counted, not
/// raised. `complete` stays true throughout: a trace that proves nothing
/// still degrades the run rather than aborting it.
[[nodiscard]] core::Result<CompileMap> map_compiles_to_roots(
    const std::vector<TraceRecord>& records, const std::filesystem::path& scan_root,
    const std::set<std::filesystem::path>& component_roots);

/// Apply `map` to `components`: append `core::Source::ObservedBuild` evidence
/// to every rooted component the build touched, and set `used_in_build` to
/// false on every rooted component it did not.
///
/// A component with NO root is left exactly as it was, and counted separately.
/// This is the honest answer rather than a convenient one: only the submodule
/// and vendored-code producers record where a component lives in the tree, so
/// a compile trace has nothing to say about an npm or conan package, and
/// marking one unused because a C compiler never mentioned it would be a claim
/// the evidence does not support.
///
/// Call this AFTER `core::merge_all`. Merging is any-true-wins on
/// `used_in_build`, so a component marked unused here and merged afterwards
/// would silently flip back to used.
UsedSetSummary mark_used_in_build(std::vector<core::Component>& components, const CompileMap& map);

}  // namespace bomwerk::observe
