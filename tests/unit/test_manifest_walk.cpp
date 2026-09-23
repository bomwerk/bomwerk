// ctest unit test for the bounded manifest walk helper.
#include <cassert>
#include <cstdio>

#include "core/manifest_walk.hpp"
#include "core/warning_code.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::FileIndex;
using bomwerk::core::ManifestWalkOptions;
using bomwerk::core::walk_bounded_manifest_files;
using bomwerk::core::WarningCode;
using bomwerk::test::TempTree;

int main()
{
  // Given two matching files, when walked, then both are returned in index order.
  {
    TempTree tree;
    tree.write("a/pubspec.lock", "a\n");
    tree.write("b/pubspec.lock", "b\n");
    FileIndex file_index{{"a/pubspec.lock", "b/pubspec.lock"}};
    ManifestWalkOptions options;
    options.max_scanned_files = 2;
    options.max_file_bytes = 10;
    options.producer_name = "pub";
    options.file_label = "pubspec.lock";
    const auto result =
        walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock", options);
    assert(result.value.size() == 2);
    assert(result.value[0].label == "a/pubspec.lock");
    assert(result.value[1].label == "b/pubspec.lock");
  }

  // Given a file budget of one, when walked, then the second match is skipped.
  {
    TempTree tree;
    tree.write("a/pubspec.lock", "a\n");
    tree.write("b/pubspec.lock", "b\n");
    FileIndex file_index{{"a/pubspec.lock", "b/pubspec.lock"}};
    ManifestWalkOptions options;
    options.max_scanned_files = 1;
    options.max_file_bytes = 10;
    options.producer_name = "pub";
    options.file_label = "pubspec.lock";
    const auto result =
        walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock", options);
    assert(result.value.size() == 1);
    assert(result.warnings.size() == 1);
    assert(result.warnings[0].code == WarningCode::kFileLimitReached);
  }

  // Given an oversized line-based file, when walked, then only complete lines remain.
  {
    TempTree tree;
    tree.write("pubspec.lock", "first\nsecond\npartial");
    FileIndex file_index{{"pubspec.lock"}};
    ManifestWalkOptions options;
    options.max_scanned_files = 1;
    options.max_file_bytes = 15;
    options.producer_name = "pub";
    options.file_label = "pubspec.lock";
    const auto result =
        walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock", options);
    assert(result.value.size() == 1);
    assert(result.value[0].bytes == "first\nsecond\n");
    assert(result.value[0].truncated);
    assert(result.warnings[0].code == WarningCode::kFileSizeLimitExceeded);
  }

  // Given an oversized whole-document file, when walked, then it is skipped.
  {
    TempTree tree;
    tree.write("pubspec.lock", "first\nsecond\npartial");
    FileIndex file_index{{"pubspec.lock"}};
    ManifestWalkOptions options;
    options.max_scanned_files = 1;
    options.max_file_bytes = 15;
    options.producer_name = "pub";
    options.file_label = "pubspec.lock";
    options.truncate_at_last_newline = false;
    const auto result =
        walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock", options);
    assert(result.value.empty());
    assert(result.warnings[0].code == WarningCode::kFileSizeLimitExceeded);
  }

  // Given an unreadable path, when walked, then it warns and returns no file.
  {
    TempTree tree;
    FileIndex file_index{{"pubspec.lock"}};
    ManifestWalkOptions options;
    options.max_scanned_files = 1;
    options.max_file_bytes = 10;
    options.producer_name = "pub";
    options.file_label = "pubspec.lock";
    const auto result =
        walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock", options);
    assert(result.value.empty());
    assert(result.warnings[0].code == WarningCode::kUnreadableFile);
  }

  // Given no matching file, when walked, then it remains a complete no-op.
  {
    TempTree tree;
    tree.write("README.md", "nothing\n");
    FileIndex file_index{{"README.md"}};
    ManifestWalkOptions options;
    options.max_scanned_files = 1;
    options.max_file_bytes = 10;
    options.producer_name = "pub";
    options.file_label = "pubspec.lock";
    const auto result =
        walk_bounded_manifest_files(file_index, tree.root(), "pubspec.lock", options);
    assert(result.value.empty());
    assert(result.warnings.empty());
    assert(result.complete);
  }

  std::puts("test_manifest_walk: OK");
  return 0;
}
