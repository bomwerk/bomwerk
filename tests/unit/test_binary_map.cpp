// ctest unit test for the binary attribution pass (binscan/binary_map.hpp):
// artifact paths -> what each holds -> Source::Binary evidence on components.
//
// The split mirrors compile_map/link_map exactly: the format readers are
// tested against bytes with no repository in sight (test_elf_read,
// test_archive_read), and this file tests the one thing that genuinely needs a
// tree on disk -- the existence check that stops a DT_NEEDED soname being
// attributed to a component on nothing more than a matching name.
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

#include "binscan/binary_map.hpp"
#include "binscan/sidecar.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "support/archive_builder.hpp"
#include "support/check.hpp"
#include "support/elf_builder.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::binscan::apply_binary_evidence;
using bomwerk::binscan::ArtifactKind;
using bomwerk::binscan::BinaryMap;
using bomwerk::binscan::ElfShape;
using bomwerk::binscan::map_binaries_to_roots;
using bomwerk::binscan::render_binscan_sidecar;
using bomwerk::core::Component;
using bomwerk::core::Result;
using bomwerk::core::Source;
using bomwerk::test::ArchiveBuildOptions;
using bomwerk::test::build_archive;
using bomwerk::test::build_elf;
using bomwerk::test::ElfBuildOptions;
using bomwerk::test::TempTree;

namespace
{

const fs::path kVendorRoot = "third_party/vendored-crypto";

/// A repository holding one vendored component: a real shared object, a real
/// archive, and a build directory with the outputs that name them.
void write_repository(const TempTree& tree)
{
  ElfBuildOptions vendored;
  vendored.needed = {"libc.so.6"};
  vendored.soname = "libvendcrypto.so.1";
  vendored.exported_symbols = {"AES_encrypt"};
  tree.write(kVendorRoot / "libvendcrypto.so.1", build_elf(vendored));

  ArchiveBuildOptions archive;
  archive.members = {{"aes.o", "aes"}, {"sha256.o", "sha"}};
  archive.indexed_symbols = {"AES_encrypt", "SHA256_Init"};
  tree.write(kVendorRoot / "libvendcrypto.a", build_archive(archive));

  ElfBuildOptions application;
  application.needed = {"libvendcrypto.so.1", "libc.so.6"};
  application.exported_symbols = {"main"};
  tree.write("build/app", build_elf(application));
}

std::size_t evidence_count(const Component& component, Source source)
{
  std::size_t total = 0;
  for (const auto& evidence : component.evidence)
  {
    if (evidence.source == source)
    {
      ++total;
    }
  }
  return total;
}

Component vendored_component()
{
  Component component;
  component.name = "vendcrypto";
  component.purl = "pkg:generic/vendcrypto@1.0";
  component.root = kVendorRoot;
  return component;
}

}  // namespace

int main()
{
  // Given a build output declaring a soname that RESOLVES to a real file
  // under a component root, when mapped, then that component gains Binary
  // evidence -- and a soname naming a library the repository does not contain
  // does not, landing in unmatched_sonames instead. That second half is the
  // rule the whole pass turns on: a soname carries no path, so matching it is
  // a guess, and an unverified guess would be invented evidence.
  {
    TempTree tree;
    write_repository(tree);

    const Result<BinaryMap> map = map_binaries_to_roots({"build/app"}, tree.root(), {kVendorRoot});

    BOMWERK_TEST_CHECK(map.value.counters.elf_artifacts == 1);
    BOMWERK_TEST_CHECK(map.value.counters.dynamic_artifacts == 1);
    BOMWERK_TEST_CHECK(map.value.evidence_by_root.count(kVendorRoot) == 1);
    BOMWERK_TEST_CHECK(map.value.evidence_by_root.at(kVendorRoot).needed_sonames ==
                       std::vector<std::string>{"libvendcrypto.so.1"});
    BOMWERK_TEST_CHECK(map.value.unmatched_sonames.count("libc.so.6") == 1);
    BOMWERK_TEST_CHECK(map.value.unmatched_sonames.count("libvendcrypto.so.1") == 0);

    // An unmatched soname is the NORMAL case for every product that links
    // anything at all, so it must never reach the warning channel -- warning
    // on libc would make warnings useless on the first real run.
    for (const bomwerk::core::Warning& warning : map.warnings)
    {
      BOMWERK_TEST_CHECK(warning.message.find("libc.so.6") == std::string::npos);
    }
  }

  // Given that evidence, when applied to components, then the vendored
  // component carries Source::Binary and `used_in_build` is UNTOUCHED. That
  // verdict belongs to observe::mark_used_in_build alone; two places deciding
  // one flag are two places that can disagree.
  {
    TempTree tree;
    write_repository(tree);
    const Result<BinaryMap> map = map_binaries_to_roots({"build/app"}, tree.root(), {kVendorRoot});

    std::vector<Component> components{vendored_component()};
    components.front().used_in_build = false;  // as if trim had already judged it
    const std::size_t marked = apply_binary_evidence(components, map.value);

    BOMWERK_TEST_CHECK(marked == 1);
    BOMWERK_TEST_CHECK(evidence_count(components.front(), Source::Binary) == 1);
    BOMWERK_TEST_CHECK(!components.front().used_in_build);
  }

  // Given a component with NO root, when evidence is applied, then it is left
  // exactly as it was -- a component read from a lockfile records no location,
  // so a binary pass has nothing to say about it, the same honest answer
  // mark_used_in_build gives.
  {
    TempTree tree;
    write_repository(tree);
    const Result<BinaryMap> map = map_binaries_to_roots({"build/app"}, tree.root(), {kVendorRoot});

    Component rootless;
    rootless.name = "left-pad";
    rootless.purl = "pkg:npm/left-pad@1.3.0";
    std::vector<Component> components{rootless};
    BOMWERK_TEST_CHECK(apply_binary_evidence(components, map.value) == 0);
    BOMWERK_TEST_CHECK(components.front().evidence.empty());
  }

  // Given a prebuilt archive sitting inside a component, when mapped, then the
  // component gains evidence from where the artifact LIVES rather than from
  // anything declaring it. This is the only view bomwerk has into a black-box
  // vendored `.a`.
  {
    TempTree tree;
    write_repository(tree);
    const Result<BinaryMap> map =
        map_binaries_to_roots({kVendorRoot / "libvendcrypto.a"}, tree.root(), {kVendorRoot});

    BOMWERK_TEST_CHECK(map.value.counters.archives == 1);
    BOMWERK_TEST_CHECK(map.value.evidence_by_root.at(kVendorRoot).archive_member_count == 2);

    std::vector<Component> components{vendored_component()};
    BOMWERK_TEST_CHECK(apply_binary_evidence(components, map.value) == 1);
    BOMWERK_TEST_CHECK(evidence_count(components.front(), Source::Binary) == 1);
  }

  // Given a prebuilt SHARED OBJECT sitting inside a component, when mapped,
  // then the component gains evidence from where the artifact lives -- exactly
  // as a prebuilt archive does. A vendored `.so` linked by path is the shape
  // The link scan can prove it was linked but never describe it, and it is the reason
  // `collect_build_artifacts` collects `.so` inputs at all; attributing only
  // archives would open the file, read its soname and symbols, and then throw
  // the answer away.
  {
    TempTree tree;
    write_repository(tree);
    const Result<BinaryMap> map =
        map_binaries_to_roots({kVendorRoot / "libvendcrypto.so.1"}, tree.root(), {kVendorRoot});

    BOMWERK_TEST_CHECK(map.value.counters.elf_artifacts == 1);
    BOMWERK_TEST_CHECK(map.value.evidence_by_root.at(kVendorRoot).shared_object_count == 1);

    std::vector<Component> components{vendored_component()};
    BOMWERK_TEST_CHECK(apply_binary_evidence(components, map.value) == 1);
    BOMWERK_TEST_CHECK(evidence_count(components.front(), Source::Binary) == 1);
  }

  // Given an archive under a root that sorts BEFORE the binary declaring a
  // soname resolving to that same root, when mapped, then the evidence names
  // the declaring binary -- never the archive. The archive declared nothing,
  // and quoting it as the declarer would write a false statement into the
  // SBOM.
  {
    TempTree tree;
    ElfBuildOptions vendored;
    vendored.soname = "libfoo.so.1";
    tree.write("3rdparty/foo/libfoo.so.1", build_elf(vendored));

    ArchiveBuildOptions archive;
    archive.members = {{"foo.o", "foo"}};
    archive.include_symbol_index = false;
    tree.write("3rdparty/foo/libfoo.a", build_archive(archive));

    ElfBuildOptions application;
    application.needed = {"libfoo.so.1"};
    tree.write("build/app", build_elf(application));

    const Result<BinaryMap> map = map_binaries_to_roots({"3rdparty/foo/libfoo.a", "build/app"},
                                                        tree.root(), {"3rdparty/foo"});

    BOMWERK_TEST_CHECK(map.value.evidence_by_root.at("3rdparty/foo").first_declaring_artifact ==
                       fs::path("build/app"));
  }

  // Given nested component roots, when an artifact under the deeper one is
  // mapped, then the LONGEST root wins -- a file under
  // third_party/vendored-crypto credits that component, never a `third_party`
  // component sitting above it. The compile and link scans already apply the same rule.
  {
    TempTree tree;
    write_repository(tree);
    const std::set<fs::path> roots{"third_party", kVendorRoot};
    const Result<BinaryMap> map =
        map_binaries_to_roots({kVendorRoot / "libvendcrypto.a"}, tree.root(), roots);

    BOMWERK_TEST_CHECK(map.value.evidence_by_root.count(kVendorRoot) == 1);
    BOMWERK_TEST_CHECK(map.value.evidence_by_root.count("third_party") == 0);
  }

  // Given a repository holding the UNVERSIONED `libfoo.so` while the binary
  // names `libfoo.so.1`, when mapped, then the two are matched. A build links
  // against the development name and records the soname, so a reader that
  // demanded an exact filename would miss the common case entirely.
  {
    TempTree tree;
    ElfBuildOptions vendored;
    tree.write("third_party/foo/libfoo.so", build_elf(vendored));

    ElfBuildOptions application;
    application.needed = {"libfoo.so.1"};
    tree.write("build/app", build_elf(application));

    const Result<BinaryMap> map =
        map_binaries_to_roots({"build/app"}, tree.root(), {"third_party/foo"});
    BOMWERK_TEST_CHECK(map.value.evidence_by_root.count("third_party/foo") == 1);
    BOMWERK_TEST_CHECK(map.value.unmatched_sonames.empty());
  }

  // Given a STATICALLY LINKED product, when mapped, then the static counter
  // records it and the run warns in those words. This is the case the whole
  // diagnostics design exists for: such a product legitimately has no dynamic
  // dependencies, and an operator must be able to tell that apart from
  // bomwerk having failed to find any.
  {
    TempTree tree;
    ElfBuildOptions options;
    options.file_type = 2;  // ET_EXEC
    options.include_dynamic = false;
    tree.write("build/static-app", build_elf(options));

    const Result<BinaryMap> map =
        map_binaries_to_roots({"build/static-app"}, tree.root(), {kVendorRoot});

    BOMWERK_TEST_CHECK(map.value.counters.static_artifacts == 1);
    BOMWERK_TEST_CHECK(map.value.counters.dynamic_artifacts == 0);
    bool said_statically_linked = false;
    for (const bomwerk::core::Warning& warning : map.warnings)
    {
      said_statically_linked =
          said_statically_linked || warning.message.find("statically linked") != std::string::npos;
    }
    BOMWERK_TEST_CHECK(said_statically_linked);
  }

  // Given each remaining shape from the diagnostics table, when mapped, then
  // each sets its OWN counter and no other. Folding these into one "skipped"
  // number is exactly what would lose the distinction the table exists to
  // preserve.
  {
    TempTree tree;
    ElfBuildOptions relocatable;
    relocatable.file_type = 1;  // ET_REL
    relocatable.include_dynamic = false;
    tree.write("build/adler32.o", build_elf(relocatable));

    ElfBuildOptions freestanding;
    freestanding.needed = {};
    tree.write("build/freestanding.so", build_elf(freestanding));

    tree.write("build/app.macho", std::string("\xCF\xFA\xED\xFE----", 8));

    // ELF magic followed by a class byte no ELF defines: bomwerk could not
    // read its structure, so it is MALFORMED. Folding it into
    // `static_artifacts` would claim the product has no dynamic dependencies
    // on the strength of a file that was never parsed.
    std::string corrupt = build_elf(freestanding);
    corrupt[4] = '\x09';
    tree.write("build/corrupt.so", corrupt);

    const Result<BinaryMap> map =
        map_binaries_to_roots({"build/adler32.o", "build/freestanding.so", "build/corrupt.so",
                               "build/app.macho", "build/never-written"},
                              tree.root(), {kVendorRoot});

    BOMWERK_TEST_CHECK(map.value.counters.artifacts_scanned == 5);
    BOMWERK_TEST_CHECK(map.value.counters.relocatable_artifacts == 1);
    BOMWERK_TEST_CHECK(map.value.counters.dynamic_without_needed == 1);
    BOMWERK_TEST_CHECK(map.value.counters.malformed_artifacts == 1);
    BOMWERK_TEST_CHECK(map.value.counters.unrecognized_artifacts == 1);
    BOMWERK_TEST_CHECK(map.value.counters.unreadable_artifacts == 1);
    BOMWERK_TEST_CHECK(map.value.counters.static_artifacts == 0);
    // The four per-shape counters partition `elf_artifacts` exactly, so a
    // reader of the summary can never be left with numbers that do not add up.
    BOMWERK_TEST_CHECK(map.value.counters.elf_artifacts ==
                       map.value.counters.dynamic_artifacts + map.value.counters.static_artifacts +
                           map.value.counters.relocatable_artifacts +
                           map.value.counters.malformed_artifacts);
    BOMWERK_TEST_CHECK(map.value.evidence_by_root.empty());
  }

  // Given the same artifacts in a different order, when mapped, then the map
  // and the sidecar are byte-identical. Trace order is an accident of how a
  // build was scheduled and must never reach the output (rule 3).
  {
    TempTree tree;
    write_repository(tree);
    const std::vector<fs::path> forward{"build/app", kVendorRoot / "libvendcrypto.a",
                                        kVendorRoot / "libvendcrypto.so.1"};
    std::vector<fs::path> reversed(forward.rbegin(), forward.rend());

    const Result<BinaryMap> first = map_binaries_to_roots(forward, tree.root(), {kVendorRoot});
    const Result<BinaryMap> second = map_binaries_to_roots(reversed, tree.root(), {kVendorRoot});

    BOMWERK_TEST_CHECK(first.value.artifacts.size() == second.value.artifacts.size());
    for (std::size_t index = 0; index < first.value.artifacts.size(); ++index)
    {
      BOMWERK_TEST_CHECK(first.value.artifacts[index].path == second.value.artifacts[index].path);
    }
    BOMWERK_TEST_CHECK(render_binscan_sidecar(first.value) == render_binscan_sidecar(second.value));
  }

  // Given no artifacts at all, when mapped, then nothing is claimed and
  // nothing is warned about -- an empty artifact list is the caller's problem
  // to report (it knows the trace path), not a degraded read here.
  {
    TempTree tree;
    const Result<BinaryMap> map = map_binaries_to_roots({}, tree.root(), {kVendorRoot});
    BOMWERK_TEST_CHECK(map.value.artifacts.empty());
    BOMWERK_TEST_CHECK(map.value.evidence_by_root.empty());
    BOMWERK_TEST_CHECK(map.warnings.empty());
  }

  return 0;
}
