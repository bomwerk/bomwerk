// ctest unit test for the compile mapping (observe/compile_map.hpp):
// trace -> source files compiled -> component roots -> used_in_build.
//
// Two halves are tested separately because they fail differently. The argv
// rules are pure string work and need no repository at all -- their failure
// mode is inventing a source file that was never compiled (`-o out.c`) or
// missing one that was. The path arithmetic needs a root to be relative to --
// its failure mode is a component wrongly reported unused because a build tree
// was reached through a symlink.
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "observe/compile_map.hpp"
#include "observe/trace_read.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::Evidence;
using bomwerk::core::Result;
using bomwerk::core::Source;
using bomwerk::observe::CompileLine;
using bomwerk::observe::CompileMap;
using bomwerk::observe::component_roots_of;
using bomwerk::observe::ComponentUsage;
using bomwerk::observe::is_compiler_tool_name;
using bomwerk::observe::is_link_mode_invocation;
using bomwerk::observe::map_compiles_to_roots;
using bomwerk::observe::mark_used_in_build;
using bomwerk::observe::scan_compile_line;
using bomwerk::observe::TraceRecord;
using bomwerk::observe::UsageSignal;
using bomwerk::observe::UsedSetSummary;
using bomwerk::test::TempTree;

namespace
{

/// The repository every path case below is relative to. Absolute and
/// deliberately not a real directory: `weakly_canonical` resolves what exists
/// and leaves the rest alone, so these cases stay hermetic and need no disk.
const std::string kRepositoryRootText = "/bomwerk-test-repo";
const fs::path kRepositoryRoot = kRepositoryRootText;

/// Where a CMake-style build actually runs its compiles from, which is what
/// makes every relative source argument below resolve the way a real trace's
/// would.
const std::string kBuildDirectoryText = kRepositoryRootText + "/build";

TraceRecord compile_record(const std::vector<std::string>& arguments,
                           const std::string& working_directory = kBuildDirectoryText)
{
  TraceRecord record;
  record.tool = arguments.empty() ? "cc" : arguments.front();
  record.arguments = arguments;
  record.working_directory = working_directory;
  record.process_id = 1;
  return record;
}

bool contains_path(const std::vector<std::string>& values, const std::string& wanted)
{
  return std::find(values.begin(), values.end(), wanted) != values.end();
}

Component rooted_component(const std::string& purl, const fs::path& root)
{
  Component component;
  component.purl = purl;
  component.name = purl;
  component.root = root;
  return component;
}

const Component* find_by_purl(const std::vector<Component>& components, const std::string& purl)
{
  for (const Component& component : components)
  {
    if (component.purl == purl)
    {
      return &component;
    }
  }
  return nullptr;
}

bool has_observed_build_evidence(const Component& component, Confidence confidence)
{
  for (const Evidence& evidence_entry : component.evidence)
  {
    if (evidence_entry.source == Source::ObservedBuild && evidence_entry.confidence == confidence)
    {
      return true;
    }
  }
  return false;
}

bool warnings_mention(const std::vector<bomwerk::core::Warning>& warnings,
                      const std::string& needle)
{
  for (const bomwerk::core::Warning& warning : warnings)
  {
    if (warning.message.find(needle) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

int main()
{
  // Given the tools bomwerk shims, when each is classified, then only the
  // compiler drivers count as compiles -- `ld` and `ar` carry link evidence,
  // which is the link scan's, and reading their object arguments as sources
  // here would invent
  // usage the compile trace never proved.
  {
    BOMWERK_TEST_CHECK(is_compiler_tool_name("cc"));
    BOMWERK_TEST_CHECK(is_compiler_tool_name("gcc"));
    BOMWERK_TEST_CHECK(is_compiler_tool_name("clang++"));
    BOMWERK_TEST_CHECK(is_compiler_tool_name("c++"));
    BOMWERK_TEST_CHECK(!is_compiler_tool_name("ld"));
    BOMWERK_TEST_CHECK(!is_compiler_tool_name("ar"));
    BOMWERK_TEST_CHECK(!is_compiler_tool_name("cmake"));
  }

  // Given a bare `ld` record, compiler-driver records with and without a
  // compile-only option, and a non-compiler tool, when each is classified,
  // then bare `ld` is always link-mode, a driver record carrying any of
  // `-c`/`-S`/`-E` is not, one carrying none of them is (this is the
  // evidence, the compile scan must never see it), and `ar`/an unrelated
  // tool are never link-mode either -- this is the ONE place both scans must
  // agree.
  {
    BOMWERK_TEST_CHECK(is_link_mode_invocation(compile_record({"ld", "-o", "app", "main.o"})));
    BOMWERK_TEST_CHECK(
        !is_link_mode_invocation(compile_record({"cc", "-c", "main.c", "-o", "main.o"})));
    BOMWERK_TEST_CHECK(!is_link_mode_invocation(compile_record({"cc", "-S", "main.c"})));
    BOMWERK_TEST_CHECK(!is_link_mode_invocation(compile_record({"cc", "-E", "main.c"})));
    BOMWERK_TEST_CHECK(
        is_link_mode_invocation(compile_record({"cc", "-o", "app", "main.o", "libx.a"})));
    // The classic case: a driver invocation that both names a source AND
    // links, with no -c/-S/-E anywhere -- still a link, by the rule's own
    // definition, even though the scanner would have found a source in it.
    BOMWERK_TEST_CHECK(is_link_mode_invocation(compile_record({"cc", "-o", "app", "main.c"})));
    BOMWERK_TEST_CHECK(!is_link_mode_invocation(compile_record({"ar", "rcs", "libx.a", "x.o"})));
    BOMWERK_TEST_CHECK(!is_link_mode_invocation(compile_record({"cmake", "--build", "."})));
  }

  // Given an ordinary compile line, when its argv is scanned, then the source
  // file is found and the output name is not mistaken for one.
  {
    const CompileLine line =
        scan_compile_line(compile_record({"cc", "-c", "src/main.c", "-o", "main.o"}));
    BOMWERK_TEST_CHECK(line.source_arguments.size() == 1);
    BOMWERK_TEST_CHECK(line.source_arguments[0] == "src/main.c");
  }

  // Given `-o` naming a file that LOOKS like a source, when the line is
  // scanned, then nothing is reported. This is the case the whole
  // options-consuming-their-value table exists for: without it, every compile
  // line would invent a source under whatever directory the build writes to.
  {
    const CompileLine line = scan_compile_line(compile_record({"cc", "-o", "out.c", "main.o"}));
    BOMWERK_TEST_CHECK(line.source_arguments.empty());
  }

  // Given every other option known to swallow the following word, when a line
  // scans them with source-looking values, then none of them is counted.
  {
    const CompileLine line = scan_compile_line(compile_record(
        {"cc", "-include", "prefix.c", "-imacros", "macros.c", "-MF", "dep.c", "-MT", "target.c",
         "-x", "c", "-Xpreprocessor", "opt.c", "-arch", "arm.c", "real.c"}));
    BOMWERK_TEST_CHECK(line.source_arguments.size() == 1);
    BOMWERK_TEST_CHECK(line.source_arguments[0] == "real.c");
  }

  // Given include options in both their separated and joined spellings, when
  // the line is scanned, then both yield the directory. gcc and clang accept
  // either, and a build system may emit either.
  {
    const CompileLine line = scan_compile_line(
        compile_record({"cc", "-I", "a/inc", "-Ib/inc", "-isystem", "c/inc", "-isystemd/inc",
                        "-iquote", "e/inc", "-idirafter", "f/inc", "-c", "main.c"}));
    BOMWERK_TEST_CHECK(line.include_path_arguments.size() == 6);
    BOMWERK_TEST_CHECK(contains_path(line.include_path_arguments, "a/inc"));
    BOMWERK_TEST_CHECK(contains_path(line.include_path_arguments, "b/inc"));
    BOMWERK_TEST_CHECK(contains_path(line.include_path_arguments, "c/inc"));
    BOMWERK_TEST_CHECK(contains_path(line.include_path_arguments, "d/inc"));
    BOMWERK_TEST_CHECK(contains_path(line.include_path_arguments, "e/inc"));
    BOMWERK_TEST_CHECK(contains_path(line.include_path_arguments, "f/inc"));
    BOMWERK_TEST_CHECK(line.source_arguments.size() == 1);
  }

  // Given every suffix a compiler driver treats as a translation unit, when a
  // line names one of each alongside files that are not sources, then exactly
  // the sources come back. `.C` and `.S` differ from `.c`/`.s` only in case,
  // which is why the comparison is case-folded.
  {
    const CompileLine line = scan_compile_line(
        compile_record({"cc", "a.c", "b.cc", "d.cpp", "e.cxx", "f.c++", "g.C", "h.m", "i.mm", "j.s",
                        "k.S", "l.h", "m.o", "n.a", "o.hpp", "README"}));
    BOMWERK_TEST_CHECK(line.source_arguments.size() == 10);
    BOMWERK_TEST_CHECK(!contains_path(line.source_arguments, "l.h"));
    BOMWERK_TEST_CHECK(!contains_path(line.source_arguments, "m.o"));
    BOMWERK_TEST_CHECK(contains_path(line.source_arguments, "g.C"));
    BOMWERK_TEST_CHECK(contains_path(line.source_arguments, "k.S"));
  }

  // Given a response file, when the line is scanned, then it is counted and
  // never opened. Following one means reading a path the scanned repository
  // chose; the count is what lets the caller warn instead of quietly reporting
  // the components hidden inside it as unused.
  {
    const CompileLine line = scan_compile_line(compile_record({"cc", "@objects.rsp", "-o", "x.o"}));
    BOMWERK_TEST_CHECK(line.response_file_count == 1);
    BOMWERK_TEST_CHECK(line.source_arguments.empty());
  }

  // Given argv[0] itself named like a source, a bare stdin `-`, and a
  // trailing `-I` with nothing after it, when the line is scanned, then none
  // of the three produces anything and none of them runs off the end of argv.
  {
    const CompileLine tool_only = scan_compile_line(compile_record({"cc"}));
    BOMWERK_TEST_CHECK(tool_only.source_arguments.empty());

    const CompileLine stdin_input = scan_compile_line(compile_record({"cc", "-x", "c", "-"}));
    BOMWERK_TEST_CHECK(stdin_input.source_arguments.empty());

    const CompileLine dangling = scan_compile_line(compile_record({"cc", "-c", "a.c", "-I"}));
    BOMWERK_TEST_CHECK(dangling.include_path_arguments.empty());
    BOMWERK_TEST_CHECK(dangling.source_arguments.size() == 1);
  }

  // Given components whose roots are spelled with and without a trailing
  // separator, when the root set is derived, then both name one root and a
  // rootless component contributes none. The two sides of the comparison have
  // to normalize identically or every component comes back unused.
  {
    std::vector<Component> components{rooted_component("pkg:generic/zlib", "third_party/zlib/"),
                                      rooted_component("pkg:generic/json", "third_party/json"),
                                      rooted_component("pkg:npm/left-pad", "")};
    components.push_back(rooted_component("pkg:generic/zlib-again", "third_party/./zlib"));
    const std::set<fs::path> roots = component_roots_of(components);
    BOMWERK_TEST_CHECK(roots.size() == 2);
    BOMWERK_TEST_CHECK(roots.count("third_party/zlib") == 1);
    BOMWERK_TEST_CHECK(roots.count("third_party/json") == 1);
  }

  // Given a build compiling from its own build directory with relative paths,
  // when the trace is mapped, then each source resolves through the record's
  // working directory back into the repository. This is the ordinary CMake
  // case: the compile runs in build/ and names ../third_party/....
  {
    const std::set<fs::path> roots{"third_party/zlib", "third_party/json"};
    const std::vector<TraceRecord> records{
        compile_record({"cc", "-c", "../third_party/zlib/adler32.c", "-o", "adler32.o"}),
        compile_record({"cc", "-c", "../third_party/zlib/inflate.c", "-o", "inflate.o"}),
        compile_record({"cc", "-c", "../src/main.c", "-o", "main.o"})};

    const Result<CompileMap> outcome = map_compiles_to_roots(records, kRepositoryRoot, roots);
    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(outcome.value.compile_invocations == 3);
    BOMWERK_TEST_CHECK(outcome.value.compiled_sources.size() == 3);
    BOMWERK_TEST_CHECK(outcome.value.compiled_sources.count("src/main.c") == 1);

    const auto zlib = outcome.value.usage_by_root.find("third_party/zlib");
    BOMWERK_TEST_CHECK(zlib != outcome.value.usage_by_root.end());
    BOMWERK_TEST_CHECK(zlib->second.signal == UsageSignal::CompiledSource);
    BOMWERK_TEST_CHECK(zlib->second.compiled_source_count == 2);
    BOMWERK_TEST_CHECK(zlib->second.first_compiled_source == "third_party/zlib/adler32.c");

    // A root nobody compiled is still PRESENT in the map, with no signal --
    // "asked about and not found" and "never asked about" must not look alike.
    const auto json = outcome.value.usage_by_root.find("third_party/json");
    BOMWERK_TEST_CHECK(json != outcome.value.usage_by_root.end());
    BOMWERK_TEST_CHECK(json->second.signal == UsageSignal::None);
  }

  // Given nested component roots, when a source under the deeper one is
  // mapped, then the LONGEST root wins. Attributing zlib's sources to a
  // `third_party` component would credit the wrong package.
  {
    const std::set<fs::path> roots{"third_party", "third_party/zlib"};
    const std::vector<TraceRecord> records{
        compile_record({"cc", "-c", "../third_party/zlib/adler32.c"})};

    const Result<CompileMap> outcome = map_compiles_to_roots(records, kRepositoryRoot, roots);
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/zlib").signal ==
                       UsageSignal::CompiledSource);
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party").signal == UsageSignal::None);
  }

  // Given a header-only library named only as an include directory, when the
  // trace is mapped, then it registers at the weaker rung. Without this every
  // header-only vendored library -- and C++ has many -- would be reported
  // unused, which is the worse direction for an SBOM to be wrong in.
  {
    const std::set<fs::path> roots{"third_party/json"};
    const std::vector<TraceRecord> records{
        compile_record({"cc", "-I../third_party/json/include", "-c", "../src/main.c"}),
        compile_record({"cc", "-I../third_party/json/include", "-c", "../src/other.c"})};

    const Result<CompileMap> outcome = map_compiles_to_roots(records, kRepositoryRoot, roots);
    const auto json = outcome.value.usage_by_root.at("third_party/json");
    BOMWERK_TEST_CHECK(json.signal == UsageSignal::IncludePath);
    BOMWERK_TEST_CHECK(json.include_path_count == 2);
    BOMWERK_TEST_CHECK(json.compiled_source_count == 0);
    BOMWERK_TEST_CHECK(json.first_include_path == "third_party/json/include");
  }

  // Given a component both compiled AND included, when the trace is mapped,
  // then the stronger signal stands. The rungs are ordered so this cannot
  // depend on which record happened to come first.
  {
    const std::set<fs::path> roots{"third_party/zlib"};
    const std::vector<TraceRecord> records{
        compile_record({"cc", "-I../third_party/zlib", "-c", "../src/main.c"}),
        compile_record({"cc", "-c", "../third_party/zlib/adler32.c"})};

    const Result<CompileMap> outcome = map_compiles_to_roots(records, kRepositoryRoot, roots);
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/zlib").signal ==
                       UsageSignal::CompiledSource);
  }

  // Given the same source compiled twice (a debug pass and a release pass),
  // when the trace is mapped, then it counts once. A count a reviewer cannot
  // reconcile with the files in the tree is worse than no count.
  {
    const std::set<fs::path> roots{"third_party/zlib"};
    const std::vector<TraceRecord> records{
        compile_record({"cc", "-c", "../third_party/zlib/adler32.c", "-o", "debug/adler32.o"}),
        compile_record({"cc", "-c", "../third_party/zlib/adler32.c", "-o", "release/adler32.o"})};

    const Result<CompileMap> outcome = map_compiles_to_roots(records, kRepositoryRoot, roots);
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/zlib").compiled_source_count ==
                       1);
    BOMWERK_TEST_CHECK(outcome.value.compile_invocations == 2);
  }

  // Given sources outside the scanned repository, when the trace is mapped,
  // then they are counted rather than forced into a component. A build that
  // also compiles a sibling checkout is normal, not an error.
  {
    const std::set<fs::path> roots{"third_party/zlib"};
    const std::vector<TraceRecord> records{
        compile_record({"cc", "-c", "/elsewhere/other-project/main.c"}),
        compile_record({"cc", "-c", "../../outside.c"})};

    const Result<CompileMap> outcome = map_compiles_to_roots(records, kRepositoryRoot, roots);
    BOMWERK_TEST_CHECK(outcome.value.out_of_tree_sources == 2);
    BOMWERK_TEST_CHECK(outcome.value.compiled_sources.empty());
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/zlib").signal ==
                       UsageSignal::None);
  }

  // Given a trace holding only link and archive steps, when it is mapped by
  // the compile scan alone, then nothing is attributed there and the
  // caller is told why -- compile_map.cpp never sees link evidence at all,
  // by design (see is_link_mode_invocation's own comment). This exact
  // fixture also produces no evidence in the link scan (test_link_map.cpp):
  // `ld -o app main.o` doesn't resolve under `third_party/zlib`, and the
  // `ar` record's archive is never subsequently named on a link line -- see
  // that file for cases where `ld`/`ar` records DO produce evidence.
  {
    // compile_record takes its tool name from argv[0], so these are `ld` and
    // `ar` invocations exactly as the shim would have recorded them.
    const TraceRecord link_record = compile_record({"ld", "-o", "app", "main.o"});
    const TraceRecord archive_record = compile_record({"ar", "rcs", "libx.a", "x.o"});

    const Result<CompileMap> outcome =
        map_compiles_to_roots({link_record, archive_record}, kRepositoryRoot, {"third_party/zlib"});
    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(outcome.value.compile_invocations == 0);
    BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "no compiler invocations"));
  }

  // Given a link-mode compiler-driver record (no -c/-S/-E) whose arguments
  // are only a `.o` and a `.a` (no recognized source extension), when it is
  // mapped, then it does NOT inflate compile_invocations and contributes no
  // source -- pinning the classification boundary from the link side.
  // Before, this exact record was silently absorbed as a no-op compile
  // line; it must no longer be counted as one.
  {
    const TraceRecord link_mode_record =
        compile_record({"cc", "-o", "app", "main.o", "libvendcrypto.a"});
    const Result<CompileMap> outcome =
        map_compiles_to_roots({link_mode_record}, kRepositoryRoot, {"third_party/zlib"});
    BOMWERK_TEST_CHECK(outcome.value.compile_invocations == 0);
    BOMWERK_TEST_CHECK(outcome.value.compiled_sources.empty());
    BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "no compiler invocations"));
  }

  // Given a link-mode compiler-driver record (no -c/-S/-E) that ALSO names a
  // real source directly on the same line -- the single-step "compile and
  // link in one command" shape (`cc -o app main.c`), common in small
  // Makefiles that skip a separate `-c` pass entirely -- when it is mapped,
  // then it still does NOT inflate compile_invocations (the classification
  // stands), but the source is still found and attributed with CompiledSource
  // evidence. Before this fix, is_link_mode_invocation's classification
  // caused the whole record to be skipped, and the link scan never
  // recognizes a `.c`/`.cpp` extension either -- so the component ended up
  // with NO evidence in either scan and was silently reported UNUSED.
  {
    const TraceRecord single_step_record =
        compile_record({"cc", "-o", "app", "../third_party/zlib/inflate.c"});
    const Result<CompileMap> outcome =
        map_compiles_to_roots({single_step_record}, kRepositoryRoot, {"third_party/zlib"});
    BOMWERK_TEST_CHECK(outcome.value.compile_invocations == 0);
    BOMWERK_TEST_CHECK(outcome.value.compiled_sources.count("third_party/zlib/inflate.c") == 1);
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/zlib").signal ==
                       UsageSignal::CompiledSource);
  }

  // Given compiles hidden behind response files, when the trace is mapped,
  // then they are counted and warned about. Silence here would read as "these
  // components were never compiled", which is exactly backwards.
  {
    const Result<CompileMap> outcome = map_compiles_to_roots(
        {compile_record({"cc", "@objects.rsp"}), compile_record({"cc", "@more.rsp"})},
        kRepositoryRoot, {"third_party/zlib"});
    BOMWERK_TEST_CHECK(outcome.value.unexpanded_response_files == 2);
    BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "response files"));
  }

  // Given the same records in a different order, when both are mapped, then
  // the results are identical -- including the example path quoted in the
  // evidence. A `-j8` build hands us its records in scheduling order, and two
  // runs of one build must still produce one answer (hard rule 3).
  {
    const std::set<fs::path> roots{"third_party/zlib"};
    std::vector<TraceRecord> records{
        compile_record({"cc", "-c", "../third_party/zlib/zutil.c"}),
        compile_record({"cc", "-c", "../third_party/zlib/adler32.c"}),
        compile_record({"cc", "-I../third_party/zlib", "-c", "../src/main.c"})};

    const Result<CompileMap> forward = map_compiles_to_roots(records, kRepositoryRoot, roots);
    std::reverse(records.begin(), records.end());
    const Result<CompileMap> reversed = map_compiles_to_roots(records, kRepositoryRoot, roots);

    const auto& forward_usage = forward.value.usage_by_root.at("third_party/zlib");
    const auto& reversed_usage = reversed.value.usage_by_root.at("third_party/zlib");
    BOMWERK_TEST_CHECK(forward_usage.signal == reversed_usage.signal);
    BOMWERK_TEST_CHECK(forward_usage.compiled_source_count == reversed_usage.compiled_source_count);
    BOMWERK_TEST_CHECK(forward_usage.first_compiled_source == reversed_usage.first_compiled_source);
    BOMWERK_TEST_CHECK(forward_usage.first_include_path == reversed_usage.first_include_path);
    BOMWERK_TEST_CHECK(forward.value.compiled_sources == reversed.value.compiled_sources);
  }

  // Given a build tree reached through a symlink, when the trace is mapped,
  // then the compiles still land inside the repository. A trace records
  // whatever spelling the build system used; without resolving it, the scanned
  // root and the traced path share no prefix and EVERY component comes back
  // unused. This is the one case that needs a real filesystem.
  {
    TempTree tree;
    const fs::path real_repository = tree.root() / "repository";
    tree.write("repository/third_party/zlib/adler32.c", "int adler(void) { return 0; }\n");
    const fs::path link_to_repository = tree.root() / "link-to-repository";
    std::error_code link_error;
    fs::create_directory_symlink(real_repository, link_to_repository, link_error);

    if (!link_error)
    {
      const std::vector<TraceRecord> records{
          compile_record({"cc", "-c", (link_to_repository / "third_party/zlib/adler32.c").string()},
                         (link_to_repository / "build").string())};

      const Result<CompileMap> outcome =
          map_compiles_to_roots(records, real_repository, {"third_party/zlib"});
      BOMWERK_TEST_CHECK(outcome.value.out_of_tree_sources == 0);
      BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/zlib").signal ==
                         UsageSignal::CompiledSource);
    }
  }

  // Given a component list spanning all three outcomes, when the map is
  // applied, then each is marked for the reason it deserves: compiled is High
  // evidence, include-only is Medium, nothing at all flips used_in_build to
  // false, and a component with no location in the repository is left exactly
  // as it was.
  {
    std::vector<Component> components{rooted_component("pkg:generic/zlib", "third_party/zlib"),
                                      rooted_component("pkg:generic/json", "third_party/json"),
                                      rooted_component("pkg:generic/unused", "third_party/unused"),
                                      rooted_component("pkg:npm/left-pad", "")};

    const std::vector<TraceRecord> records{
        compile_record({"cc", "-c", "../third_party/zlib/adler32.c"}),
        compile_record({"cc", "-I../third_party/json/include", "-c", "../src/main.c"})};
    const Result<CompileMap> map =
        map_compiles_to_roots(records, kRepositoryRoot, component_roots_of(components));

    const UsedSetSummary summary = mark_used_in_build(components, map.value);
    BOMWERK_TEST_CHECK(summary.judged == 3);
    BOMWERK_TEST_CHECK(summary.used == 2);
    BOMWERK_TEST_CHECK(summary.unused == 1);
    BOMWERK_TEST_CHECK(summary.not_judgeable == 1);

    const Component* zlib = find_by_purl(components, "pkg:generic/zlib");
    BOMWERK_TEST_CHECK(zlib != nullptr);
    BOMWERK_TEST_CHECK(zlib->used_in_build);
    BOMWERK_TEST_CHECK(has_observed_build_evidence(*zlib, Confidence::High));

    const Component* json = find_by_purl(components, "pkg:generic/json");
    BOMWERK_TEST_CHECK(json != nullptr);
    BOMWERK_TEST_CHECK(json->used_in_build);
    BOMWERK_TEST_CHECK(has_observed_build_evidence(*json, Confidence::Medium));
    BOMWERK_TEST_CHECK(json->evidence.back().detail.find("no source compiled") !=
                       std::string::npos);

    const Component* unused = find_by_purl(components, "pkg:generic/unused");
    BOMWERK_TEST_CHECK(unused != nullptr);
    BOMWERK_TEST_CHECK(!unused->used_in_build);
    BOMWERK_TEST_CHECK(unused->evidence.empty());

    // The rootless one is the whole point of the "not judgeable" count: a C
    // compiler trace has nothing to say about an npm package, so claiming it
    // unused would be a finding the evidence does not support.
    const Component* left_pad = find_by_purl(components, "pkg:npm/left-pad");
    BOMWERK_TEST_CHECK(left_pad != nullptr);
    BOMWERK_TEST_CHECK(left_pad->used_in_build);
    BOMWERK_TEST_CHECK(left_pad->evidence.empty());
  }

  // Given a component whose ONLY evidence is a link (no compiled source seen
  // under its root -- the prebuilt-vendored-archive case),
  // when mark_used_in_build is applied to a hand-built CompileMap carrying
  // that signal, then it is marked used at High confidence with detail text
  // naming link evidence rather than a compiled source. This unit-tests the
  // three-way dispatch in mark_used_in_build directly, independent of
  // map_links_to_roots's own path-resolution correctness (test_link_map.cpp
  // covers that).
  {
    std::vector<Component> components{
        rooted_component("pkg:generic/vendored-crypto", "third_party/vendored-crypto")};

    CompileMap map;
    ComponentUsage& usage = map.usage_by_root["third_party/vendored-crypto"];
    usage.root = "third_party/vendored-crypto";
    usage.signal = UsageSignal::Linked;
    usage.linked_input_count = 1;
    usage.first_linked_input = "third_party/vendored-crypto/libvendcrypto.a";

    const UsedSetSummary summary = mark_used_in_build(components, map);
    BOMWERK_TEST_CHECK(summary.judged == 1);
    BOMWERK_TEST_CHECK(summary.used == 1);

    const Component* vendored_crypto = find_by_purl(components, "pkg:generic/vendored-crypto");
    BOMWERK_TEST_CHECK(vendored_crypto != nullptr);
    BOMWERK_TEST_CHECK(vendored_crypto->used_in_build);
    BOMWERK_TEST_CHECK(has_observed_build_evidence(*vendored_crypto, Confidence::High));
    BOMWERK_TEST_CHECK(vendored_crypto->evidence.back().detail.find("no source compiled") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(vendored_crypto->evidence.back().detail.find("link input") !=
                       std::string::npos);
  }

  // Given the three non-None signals, when compared, then CompiledSource
  // outranks Linked outranks IncludePath -- guarding the decided enum order
  // (compile_map.hpp:34-40) against an accidental future reordering, since
  // mark_used_in_build's evidence-text choice depends on it.
  {
    BOMWERK_TEST_CHECK(std::max(UsageSignal::IncludePath, UsageSignal::Linked) ==
                       UsageSignal::Linked);
    BOMWERK_TEST_CHECK(std::max(UsageSignal::Linked, UsageSignal::CompiledSource) ==
                       UsageSignal::CompiledSource);
  }

  return 0;
}
