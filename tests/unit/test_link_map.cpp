// ctest unit test for the link mapping (observe/link_map.hpp):
// trace -> link/archive invocations -> component roots -> Linked evidence.
//
// Mirrors test_compile_map.cpp's own split: the argv/token rules (scan_link_
// line, flatten_linker_tokens) are pure string work tested without a
// repository, while path resolution (map_links_to_roots) needs a root to
// resolve against. A `-lNAME` resolution additionally needs a real file on
// disk to prove the existence check that pathway requires -- see the TempTree
// cases below -- while a direct `.o`/`.a`/`.so` argument never does, matching
// the established precedent that no `.a`/`.o`/`.so` fixture file is needed
// anywhere else in this codebase either.
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "core/result.hpp"
#include "observe/compile_map.hpp"
#include "observe/link_map.hpp"
#include "observe/trace_read.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Result;
using bomwerk::observe::BuildArtifacts;
using bomwerk::observe::collect_build_artifacts;
using bomwerk::observe::CompileMap;
using bomwerk::observe::ComponentUsage;
using bomwerk::observe::LinkInput;
using bomwerk::observe::LinkLine;
using bomwerk::observe::LinkMap;
using bomwerk::observe::LinkName;
using bomwerk::observe::map_links_to_roots;
using bomwerk::observe::merge_link_evidence;
using bomwerk::observe::scan_archive_output;
using bomwerk::observe::scan_link_line;
using bomwerk::observe::TraceRecord;
using bomwerk::observe::UsageSignal;
using bomwerk::test::TempTree;

namespace
{

/// The repository every path case below is relative to. Absolute and
/// deliberately not a real directory (see test_compile_map.cpp's identical
/// constant): `weakly_canonical` resolves what exists and leaves the rest
/// alone, so a case that never needs a real file stays hermetic.
const std::string kRepositoryRootText = "/bomwerk-test-repo";
const fs::path kRepositoryRoot = kRepositoryRootText;

/// Where a CMake-style build actually runs its link step from.
const std::string kBuildDirectoryText = kRepositoryRootText + "/build";

TraceRecord link_record(const std::vector<std::string>& arguments,
                        const std::string& working_directory = kBuildDirectoryText)
{
  TraceRecord record;
  record.tool = arguments.empty() ? "ld" : arguments.front();
  record.arguments = arguments;
  record.working_directory = working_directory;
  record.process_id = 1;
  return record;
}

bool contains_path(const std::vector<std::string>& values, const std::string& wanted)
{
  return std::find(values.begin(), values.end(), wanted) != values.end();
}

bool contains_input(const std::vector<LinkInput>& inputs, const std::string& wanted)
{
  for (const LinkInput& input : inputs)
  {
    if (input.argument == wanted)
    {
      return true;
    }
  }
  return false;
}

bool contains_name(const std::vector<LinkName>& names, const std::string& wanted)
{
  for (const LinkName& name : names)
  {
    if (name.name == wanted)
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
  // Given a trace mixing a compile-mode record with a link-mode one, when
  // mapped, then only the link-mode record counts as a link invocation --
  // the same classification boundary test_compile_map.cpp pins from the
  // side (is_link_mode_invocation is the one place both scans must agree),
  // exercised here through the actual map function.
  {
    const std::vector<TraceRecord> records{link_record({"cc", "-c", "main.c", "-o", "main.o"}),
                                           link_record({"cc", "-o", "app", "main.o"})};
    const Result<LinkMap> outcome =
        map_links_to_roots(records, kRepositoryRoot, {"third_party/zlib"});
    BOMWERK_TEST_CHECK(outcome.value.link_invocations == 1);
  }

  // Given .o/.a/.so (+ versioned) arguments alongside an output name and a
  // non-input file, when the line is scanned, then exactly the recognized
  // suffixes are captured and the output name (consumed by -o) is never
  // mistaken for one.
  {
    const LinkLine line = scan_link_line(link_record(
        {"cc", "-o", "app.a", "main.o", "libx.a", "liby.so", "libz.so.1.2.3", "README"}));
    BOMWERK_TEST_CHECK(line.direct_inputs.size() == 4);
    BOMWERK_TEST_CHECK(contains_input(line.direct_inputs, "main.o"));
    BOMWERK_TEST_CHECK(contains_input(line.direct_inputs, "libx.a"));
    BOMWERK_TEST_CHECK(contains_input(line.direct_inputs, "liby.so"));
    BOMWERK_TEST_CHECK(contains_input(line.direct_inputs, "libz.so.1.2.3"));
    BOMWERK_TEST_CHECK(!contains_input(line.direct_inputs, "app.a"));
    BOMWERK_TEST_CHECK(!contains_input(line.direct_inputs, "README"));
  }

  // Given -L/-l in both separated and joined spellings, when the line is
  // scanned, then both yield their value, mirroring compile_map.cpp's own
  // -I handling.
  {
    const LinkLine line = scan_link_line(
        link_record({"cc", "-L", "a/lib", "-Lb/lib", "-l", "foo", "-lbar", "-o", "app", "main.o"}));
    BOMWERK_TEST_CHECK(line.search_directories.size() == 2);
    BOMWERK_TEST_CHECK(contains_path(line.search_directories, "a/lib"));
    BOMWERK_TEST_CHECK(contains_path(line.search_directories, "b/lib"));
    BOMWERK_TEST_CHECK(line.named_libraries.size() == 2);
    BOMWERK_TEST_CHECK(contains_name(line.named_libraries, "foo"));
    BOMWERK_TEST_CHECK(contains_name(line.named_libraries, "bar"));
  }

  // Given a bare -lfoo resolved against a -L directory holding a real
  // libfoo.a, when the trace is mapped, then it resolves to Linked evidence;
  // given the same shape against a directory with nothing in it, then the
  // name is counted as unresolved and not attributed. Existence is checked
  // here -- unlike a direct .o/.a/.so argument -- because bomwerk itself
  // constructs this path as a guess, and an unverified guess would be
  // invented evidence.
  {
    TempTree tree;
    tree.write("repo/third_party/vendored/lib/libfoo.a", "placeholder\n");
    const fs::path repository_root = tree.root() / "repo";
    const std::string build_directory = (repository_root / "build").string();

    const std::vector<TraceRecord> records{
        link_record({"cc", "-L", "../third_party/vendored/lib", "-lfoo", "-o", "app", "main.o"},
                    build_directory),
        link_record({"cc", "-L", "../third_party/nowhere", "-lbaz", "-o", "app2", "main2.o"},
                    build_directory)};

    const Result<LinkMap> outcome =
        map_links_to_roots(records, repository_root, {"third_party/vendored"});
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/vendored").signal ==
                       UsageSignal::Linked);
    BOMWERK_TEST_CHECK(outcome.value.unresolved_library_names == 1);
  }

  // Given a bare -lNAME with NO -L at all anywhere on its record, when the
  // trace is mapped, then it is NOT counted as unresolved. That shape is
  // what an ordinary system library (-lpthread, -lm) looks like on nearly
  // every real trace -- resolved through the linker's own default search
  // paths bomwerk never observes -- so counting it would flag it on
  // virtually every real linked executable and degrade trim's exit code for
  // no actionable reason. A -lNAME with an explicit -L that still doesn't
  // hold the file (the case above) remains counted.
  {
    const std::vector<TraceRecord> records{link_record({"cc", "-lpthread", "-o", "app", "main.o"})};

    const Result<LinkMap> outcome =
        map_links_to_roots(records, kRepositoryRoot, {"third_party/zlib"});
    BOMWERK_TEST_CHECK(outcome.value.unresolved_library_names == 0);
  }

  // Given -L appearing AFTER the -l that uses it on the same line, when
  // mapped, then resolution still succeeds -- GNU ld applies every -L to
  // every -l on a line regardless of order, and so must bomwerk.
  {
    TempTree tree;
    tree.write("repo/third_party/vendored/lib/libfoo.a", "placeholder\n");
    const fs::path repository_root = tree.root() / "repo";

    const std::vector<TraceRecord> records{
        link_record({"cc", "-lfoo", "-L", "../third_party/vendored/lib", "-o", "app", "main.o"},
                    (repository_root / "build").string())};

    const Result<LinkMap> outcome =
        map_links_to_roots(records, repository_root, {"third_party/vendored"});
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/vendored").signal ==
                       UsageSignal::Linked);
  }

  // Given --whole-archive...--no-whole-archive bracketing one argument, when
  // scanned, then only the bracketed one is tagged; given an unterminated
  // --whole-archive, then everything after it stays tagged through the end
  // of the line -- no special handling needed, the loop just ends.
  {
    const LinkLine bracketed =
        scan_link_line(link_record({"ld", "-o", "app", "before.o", "--whole-archive", "libx.a",
                                    "--no-whole-archive", "after.o"}));
    BOMWERK_TEST_CHECK(bracketed.direct_inputs.size() == 3);
    for (const LinkInput& input : bracketed.direct_inputs)
    {
      BOMWERK_TEST_CHECK(input.inside_whole_archive == (input.argument == "libx.a"));
    }

    const LinkLine unterminated =
        scan_link_line(link_record({"ld", "-o", "app", "--whole-archive", "libx.a", "liby.a"}));
    BOMWERK_TEST_CHECK(unterminated.direct_inputs.size() == 2);
    for (const LinkInput& input : unterminated.direct_inputs)
    {
      BOMWERK_TEST_CHECK(input.inside_whole_archive);
    }
  }

  // Given the same --whole-archive/-lfoo/--no-whole-archive sequence spelled
  // three ways -- one -Wl, comma-joined argument, one -Xlinker per flag, and
  // bare ld tokens -- when each is scanned, then all three produce
  // byte-identical LinkLines. This is why flattening unifies for free: after
  // flatten_linker_tokens, all three reduce to the same bare token stream.
  {
    const LinkLine via_wl = scan_link_line(
        link_record({"cc", "-Wl,--whole-archive,-lfoo,--no-whole-archive", "-o", "app", "main.o"}));
    const LinkLine via_xlinker =
        scan_link_line(link_record({"cc", "-Xlinker", "--whole-archive", "-Xlinker", "-lfoo",
                                    "-Xlinker", "--no-whole-archive", "-o", "app", "main.o"}));
    const LinkLine via_bare_ld = scan_link_line(link_record(
        {"ld", "--whole-archive", "-lfoo", "--no-whole-archive", "-o", "app", "main.o"}));

    BOMWERK_TEST_CHECK(via_wl.named_libraries.size() == 1);
    BOMWERK_TEST_CHECK(via_wl.named_libraries[0].name == "foo");
    BOMWERK_TEST_CHECK(via_wl.named_libraries[0].inside_whole_archive);
    BOMWERK_TEST_CHECK(via_xlinker == via_wl);
    BOMWERK_TEST_CHECK(via_bare_ld == via_wl);
  }

  // Given -Map in its -Wl,-Map=file (joined) and -Wl,-Map,file (which
  // flattens to the separated bare form) spellings, and bare ld's own joined
  // and separated spellings, when each is scanned, then all four produce the
  // same map_file. Capture is metadata only -- "optional" per the ticket --
  // so nothing downstream consumes it yet.
  {
    const LinkLine via_wl_joined =
        scan_link_line(link_record({"cc", "-Wl,-Map=out.map", "-o", "app", "main.o"}));
    const LinkLine via_wl_separated =
        scan_link_line(link_record({"cc", "-Wl,-Map,out.map", "-o", "app", "main.o"}));
    const LinkLine via_bare_joined =
        scan_link_line(link_record({"ld", "-Map=out.map", "-o", "app", "main.o"}));
    const LinkLine via_bare_separated =
        scan_link_line(link_record({"ld", "-Map", "out.map", "-o", "app", "main.o"}));

    BOMWERK_TEST_CHECK(via_wl_joined.map_file.has_value());
    BOMWERK_TEST_CHECK(*via_wl_joined.map_file == fs::path("out.map"));
    BOMWERK_TEST_CHECK(via_wl_separated.map_file == via_wl_joined.map_file);
    BOMWERK_TEST_CHECK(via_bare_joined.map_file == via_wl_joined.map_file);
    BOMWERK_TEST_CHECK(via_bare_separated.map_file == via_wl_joined.map_file);
  }

  // Given a response-file argument on a link line, when scanned, then it is
  // counted and never opened; the map warns, the same reasoning
  // scan_compile_line's own @file handling uses.
  {
    const LinkLine line = scan_link_line(link_record({"ld", "@objects.rsp", "-o", "app"}));
    BOMWERK_TEST_CHECK(line.response_file_count == 1);

    const Result<LinkMap> outcome = map_links_to_roots(
        {link_record({"ld", "@objects.rsp", "-o", "app"})}, kRepositoryRoot, {"third_party/zlib"});
    BOMWERK_TEST_CHECK(outcome.value.unexpanded_response_files == 1);
    BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "response files"));
  }

  // Given a link-mode record directly naming a .a under a component root
  // (pathway 1 -- no fs::exists needed, the argument already carries a real
  // path the linker itself consumed), when mapped, then the component is
  // Linked with the right counts. This is the "static .a fixture attributed
  // correctly" scenario ("Done when") at unit level.
  {
    const std::vector<TraceRecord> records{link_record(
        {"c++", "-o", "app", "main.o", "../third_party/vendored-crypto/libvendcrypto.a"})};

    const Result<LinkMap> outcome =
        map_links_to_roots(records, kRepositoryRoot, {"third_party/vendored-crypto"});
    const ComponentUsage& usage = outcome.value.usage_by_root.at("third_party/vendored-crypto");
    BOMWERK_TEST_CHECK(usage.signal == UsageSignal::Linked);
    BOMWERK_TEST_CHECK(usage.linked_input_count == 1);
    BOMWERK_TEST_CHECK(usage.first_linked_input == "third_party/vendored-crypto/libvendcrypto.a");
    BOMWERK_TEST_CHECK(outcome.value.link_invocations == 1);
  }

  // Given a component both compiled (compile evidence) and separately linked
  // (link evidence), when the two maps are merged, then CompiledSource wins
  // over Linked in the final signal -- it names an exact source file watched
  // being compiled, marginally more specific than a path consumed on a link
  // line -- while the link counts are still carried over regardless of which
  // signal wins.
  {
    const std::set<fs::path> roots{"third_party/zlib"};
    CompileMap compile_map;
    compile_map.usage_by_root["third_party/zlib"].root = "third_party/zlib";
    compile_map.usage_by_root.at("third_party/zlib").signal = UsageSignal::CompiledSource;
    compile_map.usage_by_root.at("third_party/zlib").compiled_source_count = 1;

    const std::vector<TraceRecord> link_records{
        link_record({"c++", "-o", "app", "main.o", "../third_party/zlib/libzlib.a"})};
    const Result<LinkMap> link_outcome = map_links_to_roots(link_records, kRepositoryRoot, roots);

    merge_link_evidence(compile_map, link_outcome.value);
    BOMWERK_TEST_CHECK(compile_map.usage_by_root.at("third_party/zlib").signal ==
                       UsageSignal::CompiledSource);
    BOMWERK_TEST_CHECK(compile_map.usage_by_root.at("third_party/zlib").linked_input_count == 1);
  }

  // Given the same link records in a different order, when both are mapped,
  // then the results are identical -- including the example path quoted in
  // the evidence (hard rule 3).
  {
    const std::set<fs::path> roots{"third_party/zlib"};
    std::vector<TraceRecord> records{link_record({"c++", "-o", "app1", "../third_party/zlib/a.o"}),
                                     link_record({"c++", "-o", "app2", "../third_party/zlib/b.o"})};

    const Result<LinkMap> forward = map_links_to_roots(records, kRepositoryRoot, roots);
    std::reverse(records.begin(), records.end());
    const Result<LinkMap> reversed = map_links_to_roots(records, kRepositoryRoot, roots);

    const auto& forward_usage = forward.value.usage_by_root.at("third_party/zlib");
    const auto& reversed_usage = reversed.value.usage_by_root.at("third_party/zlib");
    BOMWERK_TEST_CHECK(forward_usage.signal == reversed_usage.signal);
    BOMWERK_TEST_CHECK(forward_usage.linked_input_count == reversed_usage.linked_input_count);
    BOMWERK_TEST_CHECK(forward_usage.first_linked_input == reversed_usage.first_linked_input);
  }

  // Given an ar record whose archive is never subsequently named on any link
  // line, when mapped, then it produces no evidence at all -- archiving
  // alone is never proof of use, only of having been built, matching the
  // own "compiled, not merely mentioned" philosophy. It also produces NO
  // warning despite link_invocations landing at 0: a trace with no link-mode
  // records at all is the normal state for plenty of valid builds (a
  // static-library-only target, exactly this fixture's shape), not the
  // anomaly zero *compiler* invocations belongs to the compile scan -- warning here would
  // degrade trim's exit code for an entirely healthy trace.
  {
    const std::vector<TraceRecord> records{link_record({"ar", "rcs", "libx.a", "x.o"})};
    const Result<LinkMap> outcome =
        map_links_to_roots(records, kRepositoryRoot, {"third_party/zlib"});
    BOMWERK_TEST_CHECK(outcome.value.link_invocations == 0);
    BOMWERK_TEST_CHECK(outcome.value.usage_by_root.at("third_party/zlib").signal ==
                       UsageSignal::None);
    BOMWERK_TEST_CHECK(outcome.warnings.empty());
  }

  // The binary pass reads what the build WROTE. Until now `-o` was consumed and discarded by
  // the option table, so nothing in the codebase knew what a link produced.

  // Given every spelling a real build system emits, when the line is scanned,
  // then the output name is captured -- and, critically, is NOT also recorded
  // as a link input. That second half is why `-o` stays in
  // kLinkOptionsConsumingNextArgument: `-o libfoo.so` looks exactly like a
  // versioned shared object to the input scanner.
  {
    const LinkLine separated = scan_link_line(link_record({"c++", "-o", "app", "main.o"}));
    BOMWERK_TEST_CHECK(separated.output_path.has_value());
    BOMWERK_TEST_CHECK(*separated.output_path == "app");

    const LinkLine joined = scan_link_line(link_record({"c++", "-oapp", "main.o"}));
    BOMWERK_TEST_CHECK(joined.output_path.has_value());
    BOMWERK_TEST_CHECK(*joined.output_path == "app");

    const LinkLine long_joined = scan_link_line(link_record({"ld", "--output=app", "main.o"}));
    BOMWERK_TEST_CHECK(long_joined.output_path.has_value());
    BOMWERK_TEST_CHECK(*long_joined.output_path == "app");

    const LinkLine forwarded = scan_link_line(link_record({"c++", "-Wl,-o,app", "main.o"}));
    BOMWERK_TEST_CHECK(forwarded.output_path.has_value());
    BOMWERK_TEST_CHECK(*forwarded.output_path == "app");

    const LinkLine shared =
        scan_link_line(link_record({"c++", "-shared", "-o", "libfoo.so.1", "foo.o"}));
    BOMWERK_TEST_CHECK(shared.output_path.has_value());
    BOMWERK_TEST_CHECK(*shared.output_path == "libfoo.so.1");
    BOMWERK_TEST_CHECK(!contains_input(shared.direct_inputs, "libfoo.so.1"));
  }

  // Given `-oformat=binary` -- ld's single-dash spelling of --oformat, the one
  // real collision with the joined `-o<value>` form -- when scanned, then it is
  // not mistaken for an output name.
  {
    const LinkLine line =
        scan_link_line(link_record({"ld", "-oformat=binary", "-o", "app", "main.o"}));
    BOMWERK_TEST_CHECK(line.output_path.has_value());
    BOMWERK_TEST_CHECK(*line.output_path == "app");
  }

  // Given a trailing bare `-o` with nothing after it, when scanned, then no
  // output is recorded -- the same convention `-Map` follows, so a malformed
  // line degrades to "unknown" rather than to an empty path.
  {
    const LinkLine line = scan_link_line(link_record({"c++", "main.o", "-o"}));
    BOMWERK_TEST_CHECK(!line.output_path.has_value());
  }

  // Given the ways `ar` can spell its operands, when scanned, then the archive
  // is found in each. Reading it as "argv[2]" gets the first case right and
  // every other one wrong: `--plugin` is what every GCC LTO build emits, and
  // the a/b/i modifiers each pull a position operand AHEAD of the archive.
  {
    BOMWERK_TEST_CHECK(scan_archive_output(link_record({"ar", "rcs", "libx.a", "x.o"})) ==
                       "libx.a");
    BOMWERK_TEST_CHECK(scan_archive_output(link_record({"ar", "qc", "libx.a", "x.o"})) == "libx.a");
    BOMWERK_TEST_CHECK(scan_archive_output(link_record({"ar", "-rcs", "libx.a", "x.o"})) ==
                       "libx.a");
    BOMWERK_TEST_CHECK(
        scan_archive_output(link_record(
            {"ar", "--plugin", "/usr/lib/liblto_plugin.so", "qc", "libx.a", "x.o"})) == "libx.a");
    BOMWERK_TEST_CHECK(scan_archive_output(
                           link_record({"ar", "rb", "existing.o", "libx.a", "new.o"})) == "libx.a");

    // Deliberately conservative: MRI script mode names no archive on the
    // command line, an unrecognized key bundle is not one bomwerk understands,
    // and a line that simply stops early has nothing to report. A missed
    // archive costs one artifact's evidence; a mis-read one would attribute
    // another file's contents to a component.
    BOMWERK_TEST_CHECK(!scan_archive_output(link_record({"ar", "-M"})).has_value());
    BOMWERK_TEST_CHECK(!scan_archive_output(link_record({"ar", "zzz", "libx.a"})).has_value());
    BOMWERK_TEST_CHECK(!scan_archive_output(link_record({"ar", "rcs"})).has_value());
    BOMWERK_TEST_CHECK(!scan_archive_output(link_record({"ar"})).has_value());
  }

  // Given a whole trace, when its artifacts are collected, then link outputs,
  // archive outputs and consumed libraries come back separately and
  // ROOT-RELATIVE. Relative is not cosmetic: an absolute path would put a
  // machine-specific string into binscan's sidecar, so two checkouts of one
  // commit would produce different bytes (rule 3).
  {
    const std::vector<TraceRecord> records{
        link_record({"cc", "-c", "../src/main.cpp", "-o", "main.o"}),
        link_record({"ar", "rcs", "libzlib.a", "adler32.o"}),
        link_record(
            {"c++", "-o", "app", "main.o", "../third_party/vendored-crypto/libvendcrypto.a"}),
    };
    const Result<BuildArtifacts> artifacts = collect_build_artifacts(records, kRepositoryRoot);

    BOMWERK_TEST_CHECK(artifacts.value.link_outputs.count("build/app") == 1);
    BOMWERK_TEST_CHECK(artifacts.value.archive_outputs.count("build/libzlib.a") == 1);
    BOMWERK_TEST_CHECK(
        artifacts.value.linked_archives.count("third_party/vendored-crypto/libvendcrypto.a") == 1);
    // A compile record is not a link, so its `-o main.o` is never an output
    // here -- `is_link_mode_invocation` is the one place the two scans agree,
    // and a `.o` has nothing the binary pass could read anyway.
    BOMWERK_TEST_CHECK(artifacts.value.link_outputs.count("build/main.o") == 0);
    BOMWERK_TEST_CHECK(artifacts.value.all_paths().size() == 3);
    BOMWERK_TEST_CHECK(artifacts.value.out_of_tree_artifacts == 0);
    BOMWERK_TEST_CHECK(artifacts.warnings.empty());
  }

  // Given a build whose tree lies outside the scanned repository, when its
  // artifacts are collected, then they are counted and dropped, not kept --
  // the same honesty rule CompileMap::out_of_tree_sources already applies.
  {
    const std::vector<TraceRecord> records{
        link_record({"c++", "-o", "app", "main.o"}, "/somewhere-else/build")};
    const Result<BuildArtifacts> artifacts = collect_build_artifacts(records, kRepositoryRoot);

    BOMWERK_TEST_CHECK(artifacts.value.link_outputs.empty());
    BOMWERK_TEST_CHECK(artifacts.value.out_of_tree_artifacts == 1);
    BOMWERK_TEST_CHECK(!artifacts.warnings.empty());
  }

  return 0;
}
