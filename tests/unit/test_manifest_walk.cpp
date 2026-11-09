// ctest unit test for the shared manifest read pipeline (core/manifest_walk).
#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/file_io.hpp"
#include "core/manifest_walk.hpp"
#include "core/warning_code.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::bound_in_memory_bytes;
using bomwerk::core::bound_manifest_bytes;
using bomwerk::core::FileIndex;
using bomwerk::core::for_each_manifest_file;
using bomwerk::core::ManifestMatch;
using bomwerk::core::ManifestWalkOptions;
using bomwerk::core::OversizedFilePolicy;
using bomwerk::core::prepare_manifest_file;
using bomwerk::core::walk_bounded_manifest_files;
using bomwerk::core::WalkedManifestFile;
using bomwerk::core::Warning;
using bomwerk::core::WarningCode;
using bomwerk::test::TempTree;

namespace
{

/// The options every `walk_bounded_manifest_files` case below starts from.
ManifestWalkOptions pub_walk_options(std::size_t max_scanned_files, std::size_t max_file_bytes)
{
  ManifestWalkOptions options;
  options.max_scanned_files = max_scanned_files;
  options.max_file_bytes = max_file_bytes;
  options.producer_name = "pub";
  options.file_label = "pubspec.lock";
  return options;
}

/// Two formats of one imaginary producer, for the multi-kind walk cases.
enum class TestKind
{
  kLock,
  kManifest,
};

/// Selects `x.lock` (skip when oversized) and `x.txt` (trim when oversized).
std::optional<ManifestMatch<TestKind>> select_test_kind(const fs::path& relative_path)
{
  if (relative_path.filename() == "x.lock")
  {
    return ManifestMatch<TestKind>{TestKind::kLock, OversizedFilePolicy::kSkip};
  }
  if (relative_path.filename() == "x.txt")
  {
    return ManifestMatch<TestKind>{TestKind::kManifest, OversizedFilePolicy::kTrimToLastNewline};
  }
  return std::nullopt;
}

}  // namespace

int main()
{
  // Given two matching files, when walked, then both are returned in index order.
  {
    TempTree tree;
    tree.write("a/pubspec.lock", "a\n");
    tree.write("b/pubspec.lock", "b\n");
    const FileIndex file_index{{"a/pubspec.lock", "b/pubspec.lock"}};
    const auto result = walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock",
                                                    pub_walk_options(2, 10));
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].label == "a/pubspec.lock");
    BOMWERK_TEST_CHECK(result.value[1].label == "b/pubspec.lock");
  }

  // Given a file budget of one, when walked, then the second match is skipped
  // with one file-limit warning naming the producer's files.
  {
    TempTree tree;
    tree.write("a/pubspec.lock", "a\n");
    tree.write("b/pubspec.lock", "b\n");
    const FileIndex file_index{{"a/pubspec.lock", "b/pubspec.lock"}};
    const auto result = walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock",
                                                    pub_walk_options(1, 10));
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].code == WarningCode::kFileLimitReached);
    BOMWERK_TEST_CHECK(result.warnings[0].message ==
                       "pub: file limit reached; remaining pubspec.lock files skipped");
    BOMWERK_TEST_CHECK(result.warnings[0].ecosystem == "pub");
  }

  // Given an oversized line-based file, when walked, then only complete lines remain.
  {
    TempTree tree;
    tree.write("pubspec.lock", "first\nsecond\npartial");
    const FileIndex file_index{{"pubspec.lock"}};
    const auto result = walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock",
                                                    pub_walk_options(1, 15));
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].bytes == "first\nsecond\n");
    BOMWERK_TEST_CHECK(result.value[0].truncated);
    BOMWERK_TEST_CHECK(result.warnings[0].code == WarningCode::kFileSizeLimitExceeded);
    BOMWERK_TEST_CHECK(result.warnings[0].message ==
                       "pub: file exceeds size limit, parsing first part only: pubspec.lock");
  }

  // Given an oversized whole-document file, when walked, then it is skipped.
  {
    TempTree tree;
    tree.write("pubspec.lock", "first\nsecond\npartial");
    const FileIndex file_index{{"pubspec.lock"}};
    ManifestWalkOptions options = pub_walk_options(1, 15);
    options.truncate_at_last_newline = false;
    const auto result =
        walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock", options);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings[0].code == WarningCode::kFileSizeLimitExceeded);
    BOMWERK_TEST_CHECK(result.warnings[0].message ==
                       "pub: file exceeds size limit, skipped: pubspec.lock");
  }

  // Given an unreadable path, when walked, then it warns and returns no file.
  {
    TempTree tree;
    const FileIndex file_index{{"pubspec.lock"}};
    const auto result = walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock",
                                                    pub_walk_options(1, 10));
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings[0].code == WarningCode::kUnreadableFile);
    BOMWERK_TEST_CHECK(result.warnings[0].message == "pub: unreadable file: pubspec.lock");
  }

  // Given no matching file, when walked, then it remains a complete no-op.
  {
    TempTree tree;
    tree.write("README.md", "nothing\n");
    const FileIndex file_index{{"README.md"}};
    const auto result = walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock",
                                                    pub_walk_options(1, 10));
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.complete);
  }

  // Given a file name that only ends like the wanted one, when walked, then it
  // is not selected (the match is on the whole last segment).
  {
    TempTree tree;
    tree.write("app/notpubspec.lock", "a\n");
    const FileIndex file_index{{"app/notpubspec.lock"}};
    const auto result = walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock",
                                                    pub_walk_options(1, 10));
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given an oversized trimmed file with no newline at all, when prepared,
  // then nothing of it survives but it is still handed on (empty, truncated).
  {
    std::vector<Warning> warnings;
    const std::optional<WalkedManifestFile> file =
        prepare_manifest_file("x.txt", bound_in_memory_bytes("abcdef", 3), "test",
                              OversizedFilePolicy::kTrimToLastNewline, warnings);
    BOMWERK_TEST_CHECK(file.has_value());
    BOMWERK_TEST_CHECK(file->bytes.empty());
    BOMWERK_TEST_CHECK(file->truncated);
    BOMWERK_TEST_CHECK(warnings.size() == 1);
  }

  // Given a file that starts with a UTF-8 byte-order mark, when prepared,
  // then the mark is gone and the first line reads as written.
  {
    std::vector<Warning> warnings;
    const std::optional<WalkedManifestFile> file =
        prepare_manifest_file("x.txt", bound_in_memory_bytes("\xEF\xBB\xBFkey: value\n", 64),
                              "test", OversizedFilePolicy::kSkip, warnings);
    BOMWERK_TEST_CHECK(file.has_value());
    BOMWERK_TEST_CHECK(file->bytes == "key: value\n");
    BOMWERK_TEST_CHECK(warnings.empty());
  }

  // Given in-memory bytes and the same bytes on disk, when bounded the same
  // way, then both paths yield the same file and the same warnings.
  {
    TempTree tree;
    tree.write("x.txt", "one\ntwo\nthr");
    std::vector<Warning> disk_warnings;
    const std::optional<WalkedManifestFile> from_disk = bomwerk::core::read_manifest_file(
        tree.root(), "x.txt", 9, "test", OversizedFilePolicy::kTrimToLastNewline, disk_warnings);
    std::vector<Warning> memory_warnings;
    const std::optional<WalkedManifestFile> from_memory =
        bound_manifest_bytes("x.txt", "one\ntwo\nthr", 9, "test",
                             OversizedFilePolicy::kTrimToLastNewline, memory_warnings);
    BOMWERK_TEST_CHECK(from_disk.has_value() && from_memory.has_value());
    BOMWERK_TEST_CHECK(from_disk->label == from_memory->label);
    BOMWERK_TEST_CHECK(from_disk->bytes == from_memory->bytes);
    BOMWERK_TEST_CHECK(from_disk->truncated == from_memory->truncated);
    BOMWERK_TEST_CHECK(disk_warnings.size() == 1 && memory_warnings.size() == 1);
    BOMWERK_TEST_CHECK(disk_warnings[0].message == memory_warnings[0].message);
  }

  // Given two kinds of one producer and a file budget of two, when streamed,
  // then the kinds share the budget, each keeps its own oversize policy, and
  // unselected files never count against it.
  {
    TempTree tree;
    tree.write("a/x.lock", "0123456789");
    tree.write("b/README.md", "ignored");
    tree.write("b/x.txt", "line\nmore");
    tree.write("c/x.lock", "{}");
    const FileIndex file_index{{"a/x.lock", "b/README.md", "b/x.txt", "c/x.lock"}};
    ManifestWalkOptions options;
    options.max_scanned_files = 2;
    options.max_file_bytes = 6;
    options.producer_name = "test";
    options.file_label = "test";
    std::vector<Warning> warnings;
    std::vector<std::pair<TestKind, std::string>> visited;
    for_each_manifest_file(
        file_index, tree.root(), options, warnings, select_test_kind, [] { return false; },
        [&](TestKind kind, WalkedManifestFile&& file)
        { visited.emplace_back(kind, std::move(file.bytes)); });
    // a/x.lock is oversized and skipped; b/x.txt is trimmed; c/x.lock is the
    // third selected file and hits the shared budget of two.
    BOMWERK_TEST_CHECK(visited.size() == 1);
    BOMWERK_TEST_CHECK(visited[0].first == TestKind::kManifest);
    BOMWERK_TEST_CHECK(visited[0].second == "line\n");
    BOMWERK_TEST_CHECK(warnings.size() == 3);
    BOMWERK_TEST_CHECK(warnings[0].message == "test: file exceeds size limit, skipped: a/x.lock");
    BOMWERK_TEST_CHECK(warnings[1].message ==
                       "test: file exceeds size limit, parsing first part only: b/x.txt");
    BOMWERK_TEST_CHECK(warnings[2].code == WarningCode::kFileLimitReached);
  }

  // Given a producer that asks to stop after its first file, when streamed,
  // then no further file is read and no file-limit warning is added.
  {
    TempTree tree;
    tree.write("a/x.lock", "{}");
    tree.write("b/x.lock", "{}");
    const FileIndex file_index{{"a/x.lock", "b/x.lock"}};
    ManifestWalkOptions options;
    options.max_scanned_files = 10;
    options.max_file_bytes = 10;
    options.producer_name = "test";
    options.file_label = "test";
    std::vector<Warning> warnings;
    std::vector<std::string> visited_labels;
    for_each_manifest_file(
        file_index, tree.root(), options, warnings, select_test_kind,
        [&] { return !visited_labels.empty(); },
        [&](TestKind, WalkedManifestFile&& file) { visited_labels.push_back(file.label); });
    BOMWERK_TEST_CHECK(visited_labels.size() == 1);
    BOMWERK_TEST_CHECK(visited_labels[0] == "a/x.lock");
    BOMWERK_TEST_CHECK(warnings.empty());
  }

  std::puts("test_manifest_walk: OK");
  return 0;
}
