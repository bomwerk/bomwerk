// ctest unit test for the fingerprint corpus loader and content matcher
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/file_index.hpp"
#include "core/file_io.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/sha256.hpp"
#include "heuristics/fingerprint.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;
namespace fingerprint = bomwerk::heuristics::fingerprint;

using bomwerk::core::Confidence;
using bomwerk::core::FileIndex;
using bomwerk::core::sha256;
using bomwerk::core::to_hex;
using bomwerk::core::WarningCode;
using bomwerk::test::TempTree;

namespace
{

/// Files have to clear `kMinHashableBytes` to vote, so every fixture body is
/// padded past it. That floor is deliberate (a 20-byte header is identical
/// across unrelated projects), and a test that ignored it would be testing
/// nothing.
std::string body(std::string_view marker)
{
  std::string content(marker);
  content += "\n";
  while (content.size() <= fingerprint::kMinHashableBytes + 8u)
  {
    content += "/* padding to clear the minimum hashable size */\n";
  }
  return content;
}

/// Builder for a corpus index document, so each test states only the shape it
/// cares about.
class IndexBuilder
{
 public:
  explicit IndexBuilder(std::string corpus_revision = "2026-11-02")
  {
    document_["schema_version"] = fingerprint::kIndexSchemaVersion;
    document_["corpus_revision"] = std::move(corpus_revision);
    document_["libraries"] = nlohmann::json::array();
    document_["releases"] = nlohmann::json::array();
    document_["files"] = nlohmann::json::object();
    document_["prefilter"] = nlohmann::json::array();
  }

  std::uint32_t add_library(const std::string& name, const std::string& license = "MIT")
  {
    nlohmann::json library;
    library["name"] = name;
    library["purl_type"] = "generic";
    library["purl_namespace"] = "";
    library["license"] = license;
    library["upstream"] = "https://example.invalid/" + name + ".git";
    document_["libraries"].push_back(std::move(library));
    return static_cast<std::uint32_t>(document_["libraries"].size() - 1);
  }

  std::uint32_t add_release(std::uint32_t library, const std::string& version,
                            std::uint32_t file_count)
  {
    nlohmann::json release;
    release["library"] = library;
    release["version"] = version;
    release["ref"] = "v" + version;
    release["commit"] = std::string(40, 'a');
    release["order"] = static_cast<std::uint32_t>(document_["releases"].size());
    release["file_count"] = file_count;
    document_["releases"].push_back(std::move(release));
    return static_cast<std::uint32_t>(document_["releases"].size() - 1);
  }

  /// Record `content` as belonging to each of `releases`. The prefilter is left
  /// empty on purpose in most tests: an index without one still has to match,
  /// it just pays for a SHA-256 per file.
  void add_file(std::string_view content, const std::vector<std::uint32_t>& releases)
  {
    document_["files"][to_hex(sha256(content))] = releases;
  }

  nlohmann::json& document() { return document_; }

  /// Write the document and load it back, asserting it was accepted.
  fingerprint::Index load(const TempTree& tree, const std::string& name = "index.json") const
  {
    tree.write(name, document_.dump());
    bomwerk::core::Result<fingerprint::Index> loaded = fingerprint::load_index(tree.root() / name);
    BOMWERK_TEST_CHECK(loaded.warnings.empty());
    BOMWERK_TEST_CHECK(!loaded.value.empty());
    return std::move(loaded.value);
  }

 private:
  nlohmann::json document_;
};

/// Build the shared FileIndex the way `run_scan` does, then match. Mirrors the
/// real call shape rather than a test-only convenience path.
bomwerk::core::Result<std::vector<fingerprint::RootMatch>> match_tree(
    const TempTree& tree, const fingerprint::Index& index)
{
  const bomwerk::core::Result<FileIndex> file_index =
      bomwerk::core::build_file_index(tree.root(), {}, {});
  BOMWERK_TEST_CHECK(file_index.complete);
  return fingerprint::match_vendored_files(file_index.value, tree.root(), index);
}

const fingerprint::RootMatch* match_for(const std::vector<fingerprint::RootMatch>& matches,
                                        const fs::path& vendor_root)
{
  const auto found = std::find_if(matches.begin(), matches.end(),
                                  [&vendor_root](const fingerprint::RootMatch& match)
                                  { return match.vendor_root == vendor_root; });
  return found == matches.end() ? nullptr : &*found;
}

bool has_warning(const std::vector<bomwerk::core::Warning>& warnings, WarningCode code)
{
  return std::any_of(warnings.begin(), warnings.end(), [code](const bomwerk::core::Warning& warning)
                     { return warning.code == code; });
}

// --- loader guards ---------------------------------------------------------

void a_missing_index_is_a_warning_not_a_failure()
{
  TempTree tree;
  const bomwerk::core::Result<fingerprint::Index> loaded =
      fingerprint::load_index(tree.root() / "absent.json");
  BOMWERK_TEST_CHECK(loaded.value.empty());
  BOMWERK_TEST_CHECK(loaded.complete);  // the SBOM is whole without a corpus
  BOMWERK_TEST_CHECK(has_warning(loaded.warnings, WarningCode::kFingerprintIndexUnreadable));
}

void a_document_that_is_not_json_is_refused()
{
  TempTree tree;
  tree.write("index.json", "this is not json at all");
  const bomwerk::core::Result<fingerprint::Index> loaded =
      fingerprint::load_index(tree.root() / "index.json");
  BOMWERK_TEST_CHECK(loaded.value.empty());
  BOMWERK_TEST_CHECK(has_warning(loaded.warnings, WarningCode::kFingerprintIndexUnreadable));
}

void an_unknown_schema_version_is_refused_whole()
{
  TempTree tree;
  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("zlib");
  const std::uint32_t release = builder.add_release(library, "1.2.11", 4);
  builder.add_file(body("zlib"), {release});
  // Everything else about the document is valid: only the version differs, and
  // that alone must be enough to decline it rather than read fields that may
  // have moved.
  builder.document()["schema_version"] = fingerprint::kIndexSchemaVersion + 1;
  tree.write("index.json", builder.document().dump());

  const bomwerk::core::Result<fingerprint::Index> loaded =
      fingerprint::load_index(tree.root() / "index.json");
  BOMWERK_TEST_CHECK(loaded.value.empty());
  BOMWERK_TEST_CHECK(has_warning(loaded.warnings, WarningCode::kFingerprintIndexSchemaUnsupported));
}

/// Libraries and releases are referenced BY POSITION, so a malformed entry
/// cannot be dropped: every later index would shift and files would be
/// reattributed to the wrong library. The whole document goes instead.
void a_malformed_positional_entry_refuses_the_whole_index()
{
  {
    TempTree tree;
    IndexBuilder builder;
    builder.add_library("zlib");
    builder.document()["libraries"].push_back(nlohmann::json::object());  // no name
    tree.write("index.json", builder.document().dump());
    const bomwerk::core::Result<fingerprint::Index> loaded =
        fingerprint::load_index(tree.root() / "index.json");
    BOMWERK_TEST_CHECK(loaded.value.empty());
    BOMWERK_TEST_CHECK(has_warning(loaded.warnings, WarningCode::kFingerprintIndexUnreadable));
  }
  {
    TempTree tree;
    IndexBuilder builder;
    const std::uint32_t library = builder.add_library("zlib");
    builder.add_release(library, "1.2.11", 4);
    // A release naming a library that does not exist.
    nlohmann::json dangling;
    dangling["library"] = 99;
    dangling["version"] = "9.9.9";
    dangling["file_count"] = 1;
    builder.document()["releases"].push_back(std::move(dangling));
    tree.write("index.json", builder.document().dump());
    const bomwerk::core::Result<fingerprint::Index> loaded =
        fingerprint::load_index(tree.root() / "index.json");
    BOMWERK_TEST_CHECK(loaded.value.empty());
  }
  {
    TempTree tree;
    IndexBuilder builder;
    const std::uint32_t library = builder.add_library("zlib");
    // file_count is release coverage's denominator; zero would make coverage
    // meaningless, so it is refused rather than defaulted.
    nlohmann::json release;
    release["library"] = library;
    release["version"] = "1.2.11";
    release["file_count"] = 0;
    builder.document()["releases"].push_back(std::move(release));
    tree.write("index.json", builder.document().dump());
    const bomwerk::core::Result<fingerprint::Index> loaded =
        fingerprint::load_index(tree.root() / "index.json");
    BOMWERK_TEST_CHECK(loaded.value.empty());
  }
}

/// A `files` entry is keyed by digest and referenced by nobody, so a bad one is
/// skipped and counted and the rest of the corpus keeps working.
void a_malformed_file_entry_is_skipped_and_counted()
{
  TempTree tree;
  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("zlib");
  const std::uint32_t release = builder.add_release(library, "1.2.11", 4);
  builder.add_file(body("zlib-good"), {release});
  builder.document()["files"]["not-a-digest"] = nlohmann::json::array({release});
  builder.document()["files"][std::string(64, 'A')] = nlohmann::json::array({release});
  builder.document()["files"][to_hex(sha256(body("dangling")))] =
      nlohmann::json::array({release + 50});
  tree.write("index.json", builder.document().dump());

  const bomwerk::core::Result<fingerprint::Index> loaded =
      fingerprint::load_index(tree.root() / "index.json");
  BOMWERK_TEST_CHECK(loaded.value.files.size() == 1);
  BOMWERK_TEST_CHECK(has_warning(loaded.warnings, WarningCode::kFingerprintIndexEntrySkipped));
}

void deep_nesting_is_rejected_before_the_json_parser_sees_it()
{
  TempTree tree;
  std::string nested = "{\"schema_version\":1,\"deep\":";
  const int depth = 64;
  for (int level = 0; level < depth; ++level)
  {
    nested += "[";
  }
  for (int level = 0; level < depth; ++level)
  {
    nested += "]";
  }
  nested += "}";
  tree.write("index.json", nested);

  const bomwerk::core::Result<fingerprint::Index> loaded =
      fingerprint::load_index(tree.root() / "index.json");
  BOMWERK_TEST_CHECK(loaded.value.empty());
  BOMWERK_TEST_CHECK(has_warning(loaded.warnings, WarningCode::kFingerprintIndexUnreadable));
}

void an_oversized_index_is_refused()
{
  TempTree tree;
  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("zlib");
  const std::uint32_t release = builder.add_release(library, "1.2.11", 4);
  builder.add_file(body("zlib"), {release});
  tree.write("index.json", builder.document().dump());

  fingerprint::LoadLimits limits;
  limits.max_index_bytes = 8;  // smaller than any real document
  const bomwerk::core::Result<fingerprint::Index> loaded =
      fingerprint::load_index(tree.root() / "index.json", limits);
  BOMWERK_TEST_CHECK(loaded.value.empty());
  BOMWERK_TEST_CHECK(has_warning(loaded.warnings, WarningCode::kFingerprintIndexUnreadable));
}

// --- matching --------------------------------------------------------------

/// The nightmare case that rules out any path-keyed scheme: the vendored copy
/// keeps `include/FreeRTOSConfig.h`, while upstream ships that file from
/// `examples/template_configuration/`. Only the bytes agree.
void a_match_is_content_addressed_and_path_independent()
{
  TempTree tree;
  const std::string config = body("FreeRTOSConfig");
  const std::string list_header = body("list.h");
  const std::string task_header = body("task.h");

  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("freertos");
  const std::uint32_t release = builder.add_release(library, "V11.1.0", 3);
  builder.add_file(config, {release});
  builder.add_file(list_header, {release});
  builder.add_file(task_header, {release});
  const fingerprint::Index index = builder.load(tree);

  // Vendored at paths that do not resemble the upstream layout at all.
  tree.write("third_party/freertos/include/FreeRTOSConfig.h", config);
  tree.write("third_party/freertos/include/list.h", list_header);
  tree.write("third_party/freertos/include/task.h", task_header);

  const auto matched = match_tree(tree, index);
  BOMWERK_TEST_CHECK(matched.value.size() == 1);
  const fingerprint::RootMatch& match = matched.value.front();
  BOMWERK_TEST_CHECK(match.vendor_root == fs::path("third_party/freertos"));
  BOMWERK_TEST_CHECK(match.library_name == "freertos");
  BOMWERK_TEST_CHECK(match.version == "V11.1.0");
  BOMWERK_TEST_CHECK(match.matched_files == 3);
  BOMWERK_TEST_CHECK(match.files_considered == 3);
  BOMWERK_TEST_CHECK(match.unmatched_files.empty());
}

/// The fork shape, which is the whole point of the ticket: most files agree
/// byte for byte and one does not. v1 reports the count and names the odd file
/// out, and draws no conclusion from it: that verdict is T93.
void a_partial_match_reports_the_count_and_names_the_unmatched_file()
{
  TempTree tree;
  std::vector<std::string> upstream_files;
  for (int file_number = 0; file_number < 6; ++file_number)
  {
    upstream_files.push_back(body("freertos-" + std::to_string(file_number)));
  }

  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("freertos");
  const std::uint32_t release = builder.add_release(library, "V11.1.0", 6);
  for (const std::string& content : upstream_files)
  {
    builder.add_file(content, {release});
  }
  const fingerprint::Index index = builder.load(tree, "corpus/index.json");

  for (std::size_t file_number = 0; file_number + 1 < upstream_files.size(); ++file_number)
  {
    tree.write("third_party/freertos/f" + std::to_string(file_number) + ".c",
               upstream_files[file_number]);
  }
  // The fork: upstream content plus a local addition.
  tree.write("third_party/freertos/list.c", upstream_files.back() + body("uxListInsertBounded"));

  const auto matched = match_tree(tree, index);
  const fingerprint::RootMatch* match = match_for(matched.value, fs::path("third_party/freertos"));
  BOMWERK_TEST_CHECK(match != nullptr);
  BOMWERK_TEST_CHECK(match->matched_files == 5);
  BOMWERK_TEST_CHECK(match->files_considered == 6);
  BOMWERK_TEST_CHECK(match->version == "V11.1.0");
  BOMWERK_TEST_CHECK(match->unmatched_files.size() == 1);
  BOMWERK_TEST_CHECK(match->unmatched_files.front() == fs::path("third_party/freertos/list.c"));

  const std::string detail = fingerprint::describe_match(*match);
  BOMWERK_TEST_CHECK(detail == "5 of 6 hashed files match freertos V11.1.0 (corpus 2026-11-02)");
}

/// Release coverage, criterion 2: both releases contain the shared header, so
/// the match counts tie. The release whose own file list is more completely
/// accounted for is the one on disk.
void a_shared_file_is_resolved_by_release_coverage()
{
  TempTree tree;
  const std::string shared_header = body("shared-header");

  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("zlib", "Zlib");
  const std::uint32_t small_release = builder.add_release(library, "1.2.11", 2);
  const std::uint32_t large_release = builder.add_release(library, "1.3.1", 40);
  builder.add_file(shared_header, {small_release, large_release});
  const fingerprint::Index index = builder.load(tree, "corpus/index.json");

  tree.write("third_party/zlib/zlib.h", shared_header);

  const auto matched = match_tree(tree, index);
  const fingerprint::RootMatch* match = match_for(matched.value, fs::path("third_party/zlib"));
  BOMWERK_TEST_CHECK(match != nullptr);
  BOMWERK_TEST_CHECK(match->version == "1.2.11");
  BOMWERK_TEST_CHECK(match->candidate_versions.empty());
  BOMWERK_TEST_CHECK(match->release_file_count == 2);
}

/// The assertion most worth reviewing. When the evidence genuinely cannot
/// separate two releases, no version is asserted. Picking the oldest would
/// overstate CVE exposure on a modern checkout and picking the newest would
/// understate it; both write a fabricated version into a document that drives
/// vulnerability matching.
void an_inseparable_tie_asserts_no_version()
{
  TempTree tree;
  const std::string shared_header = body("identical-in-both-releases");

  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("uthash");
  const std::uint32_t first = builder.add_release(library, "2.3.0", 5);
  const std::uint32_t second = builder.add_release(library, "2.4.0", 5);
  builder.add_file(shared_header, {first, second});
  const fingerprint::Index index = builder.load(tree, "corpus/index.json");

  tree.write("third_party/uthash/uthash.h", shared_header);

  const auto matched = match_tree(tree, index);
  const fingerprint::RootMatch* match = match_for(matched.value, fs::path("third_party/uthash"));
  BOMWERK_TEST_CHECK(match != nullptr);
  BOMWERK_TEST_CHECK(match->library_name == "uthash");
  BOMWERK_TEST_CHECK(match->version.empty());
  BOMWERK_TEST_CHECK(match->candidate_versions.size() == 2);
  BOMWERK_TEST_CHECK(match->candidate_versions[0] == "2.3.0");
  BOMWERK_TEST_CHECK(match->candidate_versions[1] == "2.4.0");
  BOMWERK_TEST_CHECK(match->confidence == Confidence::Low);

  const std::string detail = fingerprint::describe_match(*match);
  BOMWERK_TEST_CHECK(detail ==
                     "1 of 1 hashed file matches uthash, version undecided between 2.3.0, 2.4.0 "
                     "(corpus 2026-11-02)");
}

/// `High` needs several matched files, most of the root explained, and half the
/// release accounted for. A single matched header is real identity and nothing
/// more, so it stays `Medium`.
void confidence_separates_a_whole_copy_from_a_single_header()
{
  {
    TempTree tree;
    std::vector<std::string> files;
    for (int file_number = 0; file_number < 4; ++file_number)
    {
      files.push_back(body("whole-copy-" + std::to_string(file_number)));
    }
    IndexBuilder builder;
    const std::uint32_t library = builder.add_library("zlib", "Zlib");
    const std::uint32_t release = builder.add_release(library, "1.2.11", 4);
    for (const std::string& content : files)
    {
      builder.add_file(content, {release});
    }
    const fingerprint::Index index = builder.load(tree, "corpus/index.json");
    for (std::size_t file_number = 0; file_number < files.size(); ++file_number)
    {
      tree.write("third_party/zlib/f" + std::to_string(file_number) + ".c", files[file_number]);
    }
    const auto matched = match_tree(tree, index);
    const fingerprint::RootMatch* match = match_for(matched.value, fs::path("third_party/zlib"));
    BOMWERK_TEST_CHECK(match != nullptr);
    BOMWERK_TEST_CHECK(match->matched_files == 4);
    BOMWERK_TEST_CHECK(match->confidence == Confidence::High);
  }
  {
    TempTree tree;
    const std::string header = body("single-header");
    IndexBuilder builder;
    const std::uint32_t library = builder.add_library("cjson");
    const std::uint32_t release = builder.add_release(library, "1.7.15", 40);
    builder.add_file(header, {release});
    const fingerprint::Index index = builder.load(tree, "corpus/index.json");
    tree.write("third_party/cjson-prebuilt/include/cJSON.h", header);
    const auto matched = match_tree(tree, index);
    const fingerprint::RootMatch* match =
        match_for(matched.value, fs::path("third_party/cjson-prebuilt"));
    BOMWERK_TEST_CHECK(match != nullptr);
    BOMWERK_TEST_CHECK(match->version == "1.7.15");
    BOMWERK_TEST_CHECK(match->confidence == Confidence::Medium);
  }
}

/// Files below the minimum hashable size are not evidence either way: they are
/// never counted as matched and never counted as considered.
void tiny_files_never_vote()
{
  TempTree tree;
  const std::string tiny = "#pragma once\n";
  BOMWERK_TEST_CHECK(tiny.size() < fingerprint::kMinHashableBytes);
  const std::string real = body("real-file");

  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("zlib", "Zlib");
  const std::uint32_t release = builder.add_release(library, "1.2.11", 2);
  builder.add_file(tiny, {release});
  builder.add_file(real, {release});
  const fingerprint::Index index = builder.load(tree, "corpus/index.json");

  tree.write("third_party/zlib/tiny.h", tiny);
  tree.write("third_party/zlib/real.c", real);

  const auto matched = match_tree(tree, index);
  const fingerprint::RootMatch* match = match_for(matched.value, fs::path("third_party/zlib"));
  BOMWERK_TEST_CHECK(match != nullptr);
  BOMWERK_TEST_CHECK(match->matched_files == 1);
  BOMWERK_TEST_CHECK(match->files_considered == 1);
  BOMWERK_TEST_CHECK(match->unmatched_files.empty());
}

/// A prefilter is an optimisation, not an authority: an index without one must
/// produce exactly the same matches, and a prefilter that lists the right
/// values must not change them either.
void the_prefilter_does_not_change_the_answer()
{
  const std::string content = body("prefiltered");

  std::vector<fingerprint::RootMatch> without_prefilter;
  {
    TempTree tree;
    IndexBuilder builder;
    const std::uint32_t library = builder.add_library("zlib", "Zlib");
    const std::uint32_t release = builder.add_release(library, "1.2.11", 1);
    builder.add_file(content, {release});
    const fingerprint::Index index = builder.load(tree, "corpus/index.json");
    BOMWERK_TEST_CHECK(index.prefilter.empty());
    BOMWERK_TEST_CHECK(fingerprint::may_contain_fast_hash(index, 0));  // no prefilter, always maybe
    tree.write("third_party/zlib/z.c", content);
    without_prefilter = match_tree(tree, index).value;
  }

  BOMWERK_TEST_CHECK(without_prefilter.size() == 1);
  BOMWERK_TEST_CHECK(without_prefilter.front().matched_files == 1);
  BOMWERK_TEST_CHECK(without_prefilter.front().version == "1.2.11");

  // A prefilter that does NOT list the file's fast hash is an inconsistent
  // index; pass 1 then rejects the file. Asserted so the dependency between
  // the two halves of a built index is explicit rather than folklore.
  {
    TempTree tree;
    IndexBuilder builder;
    const std::uint32_t library = builder.add_library("zlib", "Zlib");
    const std::uint32_t release = builder.add_release(library, "1.2.11", 1);
    builder.add_file(content, {release});
    builder.document()["prefilter"].push_back(std::string(16, '0'));
    const fingerprint::Index index = builder.load(tree, "corpus/index.json");
    BOMWERK_TEST_CHECK(index.prefilter.size() == 1);
    tree.write("third_party/zlib/z.c", content);
    BOMWERK_TEST_CHECK(match_tree(tree, index).value.empty());
  }
}

/// Two runs over one tree, and a run over a reversed file order, must produce
/// identical results down to the evidence text (rule 3).
void matching_is_deterministic()
{
  TempTree tree;
  const std::string first = body("det-1");
  const std::string second = body("det-2");
  const std::string third = body("det-3");

  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("zlib", "Zlib");
  const std::uint32_t release = builder.add_release(library, "1.2.11", 3);
  builder.add_file(first, {release});
  builder.add_file(second, {release});
  builder.add_file(third, {release});
  const fingerprint::Index index = builder.load(tree, "corpus/index.json");

  tree.write("third_party/zlib/a.c", first);
  tree.write("third_party/zlib/b.c", second);
  tree.write("vendor/zlib/c.c", third);

  const bomwerk::core::Result<FileIndex> file_index =
      bomwerk::core::build_file_index(tree.root(), {}, {});
  const auto forward = fingerprint::match_vendored_files(file_index.value, tree.root(), index);
  const auto repeated = fingerprint::match_vendored_files(file_index.value, tree.root(), index);

  FileIndex reversed = file_index.value;
  std::reverse(reversed.files.begin(), reversed.files.end());
  const auto from_reversed = fingerprint::match_vendored_files(reversed, tree.root(), index);

  BOMWERK_TEST_CHECK(forward.value.size() == 2);  // third_party/zlib and vendor/zlib
  BOMWERK_TEST_CHECK(forward.value.size() == repeated.value.size());
  BOMWERK_TEST_CHECK(forward.value.size() == from_reversed.value.size());
  for (std::size_t position = 0; position < forward.value.size(); ++position)
  {
    BOMWERK_TEST_CHECK(forward.value[position].vendor_root == repeated.value[position].vendor_root);
    BOMWERK_TEST_CHECK(forward.value[position].vendor_root ==
                       from_reversed.value[position].vendor_root);
    BOMWERK_TEST_CHECK(fingerprint::describe_match(forward.value[position]) ==
                       fingerprint::describe_match(from_reversed.value[position]));
    BOMWERK_TEST_CHECK(forward.value[position].unmatched_files ==
                       from_reversed.value[position].unmatched_files);
  }
  BOMWERK_TEST_CHECK(forward.value[0].vendor_root == fs::path("third_party/zlib"));
  BOMWERK_TEST_CHECK(forward.value[1].vendor_root == fs::path("vendor/zlib"));
}

/// Nothing outside a vendor root is hashed at all, which is what keeps the cost
/// proportional to vendored code rather than to the repository.
void files_outside_a_vendor_root_are_never_matched()
{
  TempTree tree;
  const std::string content = body("first-party");

  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("zlib", "Zlib");
  const std::uint32_t release = builder.add_release(library, "1.2.11", 1);
  builder.add_file(content, {release});
  const fingerprint::Index index = builder.load(tree, "corpus/index.json");

  // Same bytes, but in src/ and in a test fixture directory: neither is a
  // vendored dependency the product ships.
  tree.write("src/main.c", content);
  tree.write("tests/third_party/zlib/z.c", content);

  BOMWERK_TEST_CHECK(match_tree(tree, index).value.empty());
}

/// An empty corpus short-circuits: no file is read, and no match is reported.
void an_empty_index_matches_nothing()
{
  TempTree tree;
  tree.write("third_party/zlib/z.c", body("anything"));
  const fingerprint::Index empty;
  BOMWERK_TEST_CHECK(empty.empty());
  BOMWERK_TEST_CHECK(match_tree(tree, empty).value.empty());
}

/// A root where only a sliver of the files match is a project that CONTAINS some
/// upstream files, not that library: a first-party directory that vendors one
/// copied header is not uthash. Reporting it would rename the directory and
/// assert a release's version into a document that drives CVE matching. The
/// threshold is pinned from both sides, because an off-by-one here silently
/// changes which directories get renamed.
void a_sliver_of_matching_files_is_not_a_match()
{
  const std::string header = body("copied-header");
  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("uthash", "BSD-1-Clause");
  const std::uint32_t release = builder.add_release(library, "2.4.0", 6);
  builder.add_file(header, {release});

  {
    // 1 matching file among 9 hashable ones is under one in eight: nothing.
    TempTree tree;
    const fingerprint::Index index = builder.load(tree, "corpus/index.json");
    tree.write("third_party/mylib/uthash.h", header);
    for (int other = 0; other < 8; ++other)
    {
      tree.write("third_party/mylib/own" + std::to_string(other) + ".c",
                 body("first-party-" + std::to_string(other)));
    }
    BOMWERK_TEST_CHECK(match_tree(tree, index).value.empty());
  }
  {
    // 1 of 8 is exactly one in eight, which is not a sliver: reported, Medium.
    TempTree tree;
    const fingerprint::Index index = builder.load(tree, "corpus/index.json");
    tree.write("third_party/mylib/uthash.h", header);
    for (int other = 0; other < 7; ++other)
    {
      tree.write("third_party/mylib/own" + std::to_string(other) + ".c",
                 body("first-party-" + std::to_string(other)));
    }
    const auto matched = match_tree(tree, index);
    BOMWERK_TEST_CHECK(matched.value.size() == 1);
    BOMWERK_TEST_CHECK(matched.value.front().confidence == Confidence::Medium);
  }
}

std::string fast_hash_hex(std::uint64_t value)
{
  char buffer[17];
  std::snprintf(buffer, sizeof(buffer), "%016llx", static_cast<unsigned long long>(value));
  return std::string(buffer);
}

/// The one path no other test reaches: an index whose prefilter holds the
/// file's REAL xxh3 value, formatted the way the builder writes it. Every
/// other test uses an empty prefilter (always "maybe") or a bogus one, so a
/// parse or byte-order mistake here would make every probe miss and matching
/// would quietly find nothing, with nothing red.
void a_correct_prefilter_entry_lets_the_file_through()
{
  const std::string content = body("prefilter-roundtrip");
  TempTree tree;
  tree.write("probe.bin", content);
  const bomwerk::core::BoundedFileFastHash fast =
      bomwerk::core::xxh3_file_bounded(tree.root() / "probe.bin", fingerprint::kMaxHashedFileBytes);
  BOMWERK_TEST_CHECK(fast.readable);

  IndexBuilder builder;
  const std::uint32_t library = builder.add_library("zlib", "Zlib");
  const std::uint32_t release = builder.add_release(library, "1.2.11", 1);
  builder.add_file(content, {release});
  builder.document()["prefilter"].push_back(fast_hash_hex(fast.hash));
  const fingerprint::Index index = builder.load(tree, "corpus/index.json");

  BOMWERK_TEST_CHECK(index.prefilter.size() == 1);
  BOMWERK_TEST_CHECK(fingerprint::may_contain_fast_hash(index, fast.hash));
  BOMWERK_TEST_CHECK(!fingerprint::may_contain_fast_hash(index, fast.hash ^ 1u));

  tree.write("third_party/zlib/z.c", content);
  const auto matched = match_tree(tree, index);
  BOMWERK_TEST_CHECK(matched.value.size() == 1);
  BOMWERK_TEST_CHECK(matched.value.front().matched_files == 1);
}

}  // namespace

int main()
{
  a_missing_index_is_a_warning_not_a_failure();
  a_document_that_is_not_json_is_refused();
  an_unknown_schema_version_is_refused_whole();
  a_malformed_positional_entry_refuses_the_whole_index();
  a_malformed_file_entry_is_skipped_and_counted();
  deep_nesting_is_rejected_before_the_json_parser_sees_it();
  an_oversized_index_is_refused();

  a_match_is_content_addressed_and_path_independent();
  a_partial_match_reports_the_count_and_names_the_unmatched_file();
  a_shared_file_is_resolved_by_release_coverage();
  an_inseparable_tie_asserts_no_version();
  confidence_separates_a_whole_copy_from_a_single_header();
  tiny_files_never_vote();
  the_prefilter_does_not_change_the_answer();
  matching_is_deterministic();
  files_outside_a_vendor_root_are_never_matched();
  an_empty_index_matches_nothing();
  a_sliver_of_matching_files_is_not_a_match();
  a_correct_prefilter_entry_lets_the_file_through();
  return 0;
}
