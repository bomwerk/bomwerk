#pragma once
#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "core/result.hpp"
#include "observe/compile_map.hpp"
#include "observe/trace_read.hpp"

namespace bomwerk::observe
{

/// One argv entry naming a `.o`/`.a`/`.so`(+versioned) link input directly, as
/// opposed to a `-lNAME` that must still be resolved against `-L`.
struct LinkInput
{
  std::string argument;               ///< the argv token itself, not yet resolved to a path
  bool inside_whole_archive = false;  ///< bracketed by --whole-archive at scan time

  /// Defaulted so a test can assert two scans produced the same result
  /// (e.g. `-Wl,`, `-Xlinker`, and bare `ld` spellings of one flag sequence)
  /// without comparing each field by hand.
  bool operator==(const LinkInput&) const = default;
};

/// One `-lNAME` argument, still unresolved.
struct LinkName
{
  std::string name;                   ///< NAME, without the `lib`/`.so`/`.a` bomwerk will try
  bool inside_whole_archive = false;  ///< bracketed by --whole-archive at scan time

  bool operator==(const LinkName&) const = default;
};

/// What one link-mode invocation's argv named, before any of it is resolved
/// against a repository. Mirrors `CompileLine`'s split between argv rules and
/// path arithmetic, for the same reason: the two fail differently and are
/// tested separately.
struct LinkLine
{
  std::vector<LinkInput> direct_inputs;         ///< `.o`/`.a`/`.so` arguments, in argv order
  std::vector<LinkName> named_libraries;        ///< `-l` arguments, in argv order
  std::vector<std::string> search_directories;  ///< `-L` arguments, in argv order
  std::size_t response_file_count = 0;          ///< `@file` arguments, deliberately unexpanded
  std::optional<std::filesystem::path>
      map_file;  ///< `-Map`/`-Wl,-Map` value, if any; metadata only
  std::optional<std::filesystem::path>
      output_path;  ///< `-o`/`--output` value, if any: what this link WROTE

  bool operator==(const LinkLine&) const = default;
};

/// Every path a trace proves the build wrote or consumed as a binary: the
/// input to the binary pass (`binscan`).
///
/// Separate from `LinkMap` on purpose. `LinkMap` answers "which components did
/// the build use", which is a question about the repository; this answers
/// "which files did the build produce", which is a question about the build
/// tree, and the two have different consumers. Keeping them apart is also what
/// lets `binscan` stay a producer that never learns a trace exists (module
/// dependency law, docs/CONTRIBUTING.md): it is handed paths, not records.
struct BuildArtifacts
{
  std::set<std::filesystem::path> link_outputs;     ///< `-o` of a link-mode record
  std::set<std::filesystem::path> archive_outputs;  ///< the archive an `ar` record wrote
  std::set<std::filesystem::path> linked_archives;  ///< `.a`/`.so` consumed on a link line
  std::size_t out_of_tree_artifacts = 0;            ///< resolved outside the scanned repository
  std::size_t unexpanded_response_files = 0;        ///< `@file` arguments that may hide outputs

  /// Every set flattened into one sorted list, which is the shape
  /// `binscan::map_binaries_to_roots` takes. Sorted and deduplicated so the
  /// pass over them cannot depend on trace order (rule 3).
  [[nodiscard]] std::vector<std::filesystem::path> all_paths() const;
};

/// Everything a trace says about one repository's component roots, from the
/// link side. Deliberately a separate type from `CompileMap`, not fields
/// bolted onto it: `link_invocations` means something structurally different
/// from `compile_invocations` (the complement, not an alternative reading of
/// it), and conflating them would invite exactly the double-counting
/// `is_link_mode_invocation` exists to prevent.
struct LinkMap
{
  std::map<std::filesystem::path, ComponentUsage> usage_by_root;  ///< every root asked about
  std::size_t link_invocations = 0;           ///< trace records classified link-mode
  std::size_t unresolved_library_names = 0;   ///< -lNAME matching no file in any -L
  std::size_t unexpanded_response_files = 0;  ///< `@file` arguments not followed
};

/// Reduce one trace record's argv to the flat list of bare linker-level
/// tokens a real linker would see, argv[0] excluded. `-Wl,a,b,c` splits on
/// `,` into three tokens (an empty segment from a stray `,,` is dropped);
/// `-Xlinker <token>` contributes its one following token, dropping the
/// wrapper. Every other argument passes through unchanged.
///
/// This runs the same way regardless of `record.tool`: a bare `ld` record
/// never carries `-Wl,`/`-Xlinker` in the first place: those are
/// compiler-driver spellings gcc/clang strip before re-exec'ing the real
/// linker: so the function is identity for `ld` by construction, needing no
/// branch on `record.tool`.
[[nodiscard]] std::vector<std::string> flatten_linker_tokens(const TraceRecord& record);

/// Walk one link-mode record's FLATTENED token list (see
/// `flatten_linker_tokens`) and classify every linker-level argument it
/// carries.
///
/// Stateful, unlike `scan_compile_line`'s per-argument table lookups:
/// `--whole-archive`/`--no-whole-archive` bracket a region, so a boolean is
/// tracked while walking. An unterminated `--whole-archive` simply leaves
/// every subsequent input tagged `true` through the end of the line: no
/// special handling needed, the loop just ends. `inside_whole_archive` is
/// captured and tested but does not yet affect attribution: nothing
/// downstream consults it in this PR, same as `map_file`.
[[nodiscard]] LinkLine scan_link_tokens(const std::vector<std::string>& tokens);

/// `flatten_linker_tokens` then `scan_link_tokens`, in one call: the shape
/// every real caller wants. Kept as two functions so the stateful walk is
/// testable against a hand-built token list directly, without needing a
/// `TraceRecord` or the flatten step.
[[nodiscard]] LinkLine scan_link_line(const TraceRecord& record);

/// Map every link in `records` onto `component_roots`, relative to
/// `scan_root` (the repository the trace was recorded against).
///
/// Two evidence pathways, resolved differently. A direct `.o`/`.a`/`.so`
/// argument already carries a real path: resolved via each record's own
/// working directory exactly like `map_compiles_to_roots` resolves a
/// compiled source, with no existence check, because the argument already
/// names a file the linker itself consumed. A `-lNAME` carries no path at
/// all: bomwerk must guess one by searching the `-L` directories seen on
/// the SAME record (order-independent, matching real linker behavior) for
/// `libNAME.so`/`libNAME.a`: and an unverified guess would be invented
/// evidence, so that guess is checked against the filesystem before being
/// trusted. A `-lNAME` with no `-L` at all on its record is skipped without
/// counting it: that shape is what a bare system library (`-lpthread`,
/// `-lm`, resolved through the linker's own default search paths bomwerk
/// never observes) looks like on essentially every real trace, and counting
/// it as "unresolved" would flag nearly all of them. A `-lNAME` that DOES
/// have a `-L` to search, and still isn't found there, is the actionable
/// case, and that one is counted, not silently dropped.
///
/// Never throws (rule 1); a path that cannot be resolved is counted (subject
/// to the paragraph above), never raised. `complete` stays true throughout :
/// a trace that proves nothing still degrades the run rather than aborting
/// it.
[[nodiscard]] core::Result<LinkMap> map_links_to_roots(
    const std::vector<TraceRecord>& records, const std::filesystem::path& scan_root,
    const std::set<std::filesystem::path>& component_roots);

/// The archive one `ar` invocation wrote, or nothing.
///
/// `ar` is neither a compiler driver nor `ld`, so neither existing scan looks
/// at it and it needs its own reading of argv. The operand order is the whole
/// difficulty and it is not positional in the simple sense: `ar` takes a
/// bundle of key letters (spelled `rcs` or `-rcs`), which may be preceded by
/// `--plugin <name>` (every GCC LTO build emits exactly that) and may THEMSELVES
/// pull operands ahead of the archive: `a`/`b`/`i` each take a relative-position
/// member name, `N` takes a count. Reading the archive as "argv[2]" gets a
/// plain `ar rcs lib.a a.o` right and every one of those wrong.
///
/// Deliberately conservative: an unrecognized key letter, or `M` (MRI script
/// mode, which names no archive on the command line at all), yields nothing
/// rather than a guess. A missed archive costs one artifact's evidence; a
/// mis-read one would attribute another file's contents to a component.
[[nodiscard]] std::optional<std::string> scan_archive_output(const TraceRecord& record);

/// Collect every binary `records` proves the build wrote or consumed, relative
/// to `scan_root`.
///
/// Paths come back ROOT-RELATIVE, and one that resolves outside `scan_root` is
/// counted rather than kept. Both halves of that matter: a build tree
/// elsewhere on disk is not something an SBOM about this repository can speak
/// to, and keeping absolute paths would put a machine-specific string into
/// binscan's sidecar, so two checkouts of one commit would produce different
/// bytes (rule 3).
///
/// Never throws (rule 1); a path that cannot be resolved is counted, never
/// raised, and `complete` stays true throughout: a trace that names no output
/// degrades the analysis rather than aborting the run.
[[nodiscard]] core::Result<BuildArtifacts> collect_build_artifacts(
    const std::vector<TraceRecord>& records, const std::filesystem::path& scan_root);

/// Fold `link_map`'s per-root evidence into `compile_map`: the stronger
/// `UsageSignal` wins at each root, same rule `map_compiles_to_roots` already
/// applies between `CompiledSource` and `IncludePath`.
///
/// Call this AFTER both `map_compiles_to_roots` and `map_links_to_roots`,
/// BEFORE `mark_used_in_build`: this is what lets `mark_used_in_build` stay
/// a single-map function while seeing every signal the trace produced, and
/// keeps `compile_map.cpp` unaware the link scan exists (it already documents `ld`/`ar`
/// as the link scan's evidence, not the compile scan's).
void merge_link_evidence(CompileMap& compile_map, const LinkMap& link_map);

}  // namespace bomwerk::observe
