#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "support/check.hpp"
#include "support/temp_tree.hpp"
#include "vuln/cache.hpp"

namespace fs = std::filesystem;

using bomwerk::test::TempTree;
using bomwerk::vuln::AdvisoryRevision;
using bomwerk::vuln::FeedState;
using bomwerk::vuln::FeedTable;
using bomwerk::vuln::VulnCache;
using bomwerk::vuln::VulnCacheEntry;

namespace
{

constexpr const char* kZlibPurl = "pkg:conan/zlib@1.2.11";
constexpr const char* kZlibPayload = R"({"vulns":[{"id":"CVE-2022-37434"}]})";
constexpr std::int64_t kFetchedAt = 1'750'000'000;

constexpr const char* kFeedName = "example_feed";

/// Every table (and its one index) a freshly opened v2 cache must have :
/// v1's `vuln_cache` plus the five. Sorted, matching `sqlite_master`'s own
/// default row order for a name-ordered query. Kept as one list so adding a
/// table without updating BOTH the schema doc and this test fails loudly
/// here rather than drifting silently (docs/vuln-cache-schema.md).
const std::vector<std::string>& expected_schema_object_names()
{
  static const std::vector<std::string> names = {"feed_state", "osv_advisory_snapshot",
                                                 "vuln_cache"};
  return names;
}

/// Every table/index name `sqlite_master` reports for the file `database_path`
/// currently holds, sorted. A raw sqlite3 handle is opened directly (never
/// going through `VulnCache`) so this check is independent of whatever the
/// production accessor set happens to expose.
std::vector<std::string> actual_schema_object_names(const fs::path& database_path)
{
  sqlite3* database_handle = nullptr;
  sqlite3_open_v2(database_path.string().c_str(), &database_handle, SQLITE_OPEN_READONLY, nullptr);
  std::vector<std::string> names;
  sqlite3_stmt* statement = nullptr;
  const char* query_sql =
      "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') "
      "AND name NOT LIKE 'sqlite_%' ORDER BY name;";
  if (sqlite3_prepare_v2(database_handle, query_sql, -1, &statement, nullptr) == SQLITE_OK)
  {
    while (sqlite3_step(statement) == SQLITE_ROW)
    {
      names.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)));
    }
  }
  sqlite3_finalize(statement);
  sqlite3_close_v2(database_handle);
  std::sort(names.begin(), names.end());
  return names;
}

/// Build a v1-shaped file directly with sqlite3 (bypassing `VulnCache`
/// entirely, which today only ever writes v2): the only way to construct
/// the "existing warm cache from before this release" fixture the migration
/// tests need.
void write_v1_cache_file(const fs::path& database_path, const char* purl, const char* payload)
{
  sqlite3* database_handle = nullptr;
  sqlite3_open_v2(database_path.string().c_str(), &database_handle,
                  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
  sqlite3_exec(database_handle,
               "CREATE TABLE vuln_cache(purl TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL, "
               "payload TEXT NOT NULL);",
               nullptr, nullptr, nullptr);
  sqlite3_stmt* insert_statement = nullptr;
  sqlite3_prepare_v2(database_handle,
                     "INSERT INTO vuln_cache(purl, fetched_at, payload) VALUES(?1, ?2, ?3);", -1,
                     &insert_statement, nullptr);
  sqlite3_bind_text(insert_statement, 1, purl, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(insert_statement, 2, kFetchedAt);
  sqlite3_bind_text(insert_statement, 3, payload, -1, SQLITE_TRANSIENT);
  sqlite3_step(insert_statement);
  sqlite3_finalize(insert_statement);
  sqlite3_exec(database_handle, "PRAGMA user_version = 1;", nullptr, nullptr, nullptr);
  sqlite3_close_v2(database_handle);
}

}  // namespace

int main()
{
  // Given a database path whose parent directories do not exist yet, when
  // opened, then the cache creates them, opens cleanly, and starts empty.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "nested" / "dirs" / "vuln_cache.sqlite3";
    auto opened = VulnCache::open(database_path);
    BOMWERK_TEST_CHECK(opened.complete);
    BOMWERK_TEST_CHECK(opened.warnings.empty());
    BOMWERK_TEST_CHECK(opened.value.is_open());
    BOMWERK_TEST_CHECK(!opened.value.lookup(kZlibPurl).has_value());
  }

  // Given a stored entry, when looked up, then fetched_at and payload
  // round-trip byte-exactly.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;
    BOMWERK_TEST_CHECK(cache.store(kZlibPurl, kFetchedAt, kZlibPayload));
    const std::optional<VulnCacheEntry> entry = cache.lookup(kZlibPurl);
    BOMWERK_TEST_CHECK(entry.has_value());
    BOMWERK_TEST_CHECK(entry->fetched_at_epoch_seconds == kFetchedAt);
    BOMWERK_TEST_CHECK(entry->payload == kZlibPayload);
    BOMWERK_TEST_CHECK(cache.warnings().empty());
  }

  // Given a second store for the same purl, when looked up, then the newer
  // fetched_at and payload win: UPSERT keeps one row per purl.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;
    BOMWERK_TEST_CHECK(cache.store(kZlibPurl, kFetchedAt, "{}"));
    BOMWERK_TEST_CHECK(cache.store(kZlibPurl, kFetchedAt + 100, kZlibPayload));
    const std::optional<VulnCacheEntry> entry = cache.lookup(kZlibPurl);
    BOMWERK_TEST_CHECK(entry.has_value());
    BOMWERK_TEST_CHECK(entry->fetched_at_epoch_seconds == kFetchedAt + 100);
    BOMWERK_TEST_CHECK(entry->payload == kZlibPayload);
  }

  // Given a cache closed and reopened from the same file, when looked up,
  // then the stored entry survives: the cache is persistent, not in-memory.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "vuln_cache.sqlite3";
    {
      auto first_open = VulnCache::open(database_path);
      BOMWERK_TEST_CHECK(first_open.value.store(kZlibPurl, kFetchedAt, kZlibPayload));
    }
    auto second_open = VulnCache::open(database_path);
    BOMWERK_TEST_CHECK(second_open.warnings.empty());
    const std::optional<VulnCacheEntry> entry = second_open.value.lookup(kZlibPurl);
    BOMWERK_TEST_CHECK(entry.has_value());
    BOMWERK_TEST_CHECK(entry->payload == kZlibPayload);
  }

  // Given a purl that was never stored, when looked up, then a clean miss :
  // no value, no warnings.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    BOMWERK_TEST_CHECK(!opened.value.lookup("pkg:conan/never-stored@1.0").has_value());
    BOMWERK_TEST_CHECK(opened.value.warnings().empty());
  }

  // Given a default-constructed (closed) cache, when used, then lookups miss
  // and stores no-op: the graceful-degradation object never crashes.
  {
    VulnCache closed_cache;
    BOMWERK_TEST_CHECK(!closed_cache.is_open());
    BOMWERK_TEST_CHECK(!closed_cache.lookup(kZlibPurl).has_value());
    BOMWERK_TEST_CHECK(!closed_cache.store(kZlibPurl, kFetchedAt, "{}"));
    BOMWERK_TEST_CHECK(closed_cache.warnings().empty());
  }

  // Given a garbage file that is not SQLite at all, when opened, then a
  // warning and a closed cache: never a crash, and the user's file is not
  // destroyed (rule 1).
  {
    TempTree tree;
    tree.write("vuln_cache.sqlite3", "this is not a sqlite database at all");
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    BOMWERK_TEST_CHECK(opened.complete);
    BOMWERK_TEST_CHECK(!opened.warnings.empty());
    BOMWERK_TEST_CHECK(!opened.value.is_open());
  }

  // Given an open cache moved into another variable, when the destination is
  // used, then it owns the connection and works; a moved-from cache behaves
  // as closed.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    BOMWERK_TEST_CHECK(opened.value.store(kZlibPurl, kFetchedAt, kZlibPayload));
    VulnCache moved_cache = std::move(opened.value);
    BOMWERK_TEST_CHECK(moved_cache.is_open());
    BOMWERK_TEST_CHECK(moved_cache.lookup(kZlibPurl).has_value());
    BOMWERK_TEST_CHECK(!opened.value.is_open());
  }

  // Given a v1 file (built directly, bypassing VulnCache, to simulate a warm
  // cache from before this release) holding one payload, when opened by a v2
  // binary, then no warning, the payload round-trips byte-exactly, EVERY v2
  // table now exists, and PRAGMA user_version reads 2: the in-place
  // migration promised at cache.hpp's schema-version doc comment.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "vuln_cache.sqlite3";
    write_v1_cache_file(database_path, kZlibPurl, kZlibPayload);

    auto migrated = VulnCache::open(database_path);
    BOMWERK_TEST_CHECK(migrated.complete);
    BOMWERK_TEST_CHECK(migrated.warnings.empty());
    BOMWERK_TEST_CHECK(migrated.value.is_open());

    const std::optional<VulnCacheEntry> entry = migrated.value.lookup(kZlibPurl);
    BOMWERK_TEST_CHECK(entry.has_value());
    BOMWERK_TEST_CHECK(entry->fetched_at_epoch_seconds == kFetchedAt);
    BOMWERK_TEST_CHECK(entry->payload == kZlibPayload);

    BOMWERK_TEST_CHECK(actual_schema_object_names(database_path) == expected_schema_object_names());
    BOMWERK_TEST_CHECK(migrated.value.feed_record_count(FeedTable::OsvAdvisorySnapshot) == 0);
  }

  // Given a brand-new file, when opened, then it is created directly at v2 :
  // a fresh install takes the same migration loop as an upgrade, just
  // starting from schema version 0, and ends up with the identical table set.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "vuln_cache.sqlite3";
    auto opened = VulnCache::open(database_path);
    BOMWERK_TEST_CHECK(opened.complete);
    BOMWERK_TEST_CHECK(opened.warnings.empty());
    BOMWERK_TEST_CHECK(actual_schema_object_names(database_path) == expected_schema_object_names());
  }

  // Given an already-v2 file, when re-opened, then the migration is a no-op:
  // no warning, no row lost, and the table set is unchanged.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "vuln_cache.sqlite3";
    {
      auto first_open = VulnCache::open(database_path);
      BOMWERK_TEST_CHECK(first_open.value.store(kZlibPurl, kFetchedAt, kZlibPayload));
    }
    auto second_open = VulnCache::open(database_path);
    BOMWERK_TEST_CHECK(second_open.complete);
    BOMWERK_TEST_CHECK(second_open.warnings.empty());
    BOMWERK_TEST_CHECK(second_open.value.lookup(kZlibPurl).has_value());
    BOMWERK_TEST_CHECK(actual_schema_object_names(database_path) == expected_schema_object_names());
  }

  // Given a file stamped with a schema version newer than this binary
  // understands, when opened, then it is refused outright (unchanged from
  // v1) rather than the migration loop attempting to "catch up" backwards.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "vuln_cache.sqlite3";
    {
      sqlite3* database_handle = nullptr;
      sqlite3_open_v2(database_path.string().c_str(), &database_handle,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
      sqlite3_exec(database_handle, "PRAGMA user_version = 99;", nullptr, nullptr, nullptr);
      sqlite3_close_v2(database_handle);
    }
    auto opened = VulnCache::open(database_path);
    BOMWERK_TEST_CHECK(!opened.warnings.empty());
    BOMWERK_TEST_CHECK(!opened.value.is_open());
  }

  // Given one feed's state stored, when looked up, then every field
  // round-trips byte-exactly, including the empty-string defaults for
  // validators a feed never sent.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;

    FeedState state;
    state.feed_name = kFeedName;
    state.fetched_at_epoch_seconds = kFetchedAt;
    state.changed_at_epoch_seconds = kFetchedAt;
    state.etag = R"("186360-65992383975b8")";
    state.last_modified = "Fri, 21 Aug 2026 17:46:43 GMT";
    state.record_count = 1674;
    state.version_label = "2026.08.21";
    BOMWERK_TEST_CHECK(cache.store_feed_state(state));

    const std::optional<FeedState> looked_up = cache.lookup_feed_state(kFeedName);
    BOMWERK_TEST_CHECK(looked_up.has_value());
    BOMWERK_TEST_CHECK(looked_up->fetched_at_epoch_seconds == kFetchedAt);
    BOMWERK_TEST_CHECK(looked_up->changed_at_epoch_seconds == kFetchedAt);
    BOMWERK_TEST_CHECK(looked_up->etag == state.etag);
    BOMWERK_TEST_CHECK(looked_up->last_modified == state.last_modified);
    BOMWERK_TEST_CHECK(looked_up->content_digest.empty());
    BOMWERK_TEST_CHECK(looked_up->record_count == 1674);
    BOMWERK_TEST_CHECK(looked_up->version_label == state.version_label);
  }

  // Given a second store for the same feed, when looked up, then the newer
  // state wins: UPSERT keeps one row per feed, same contract as vuln_cache.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;

    FeedState first_state;
    first_state.feed_name = kFeedName;
    first_state.fetched_at_epoch_seconds = kFetchedAt;
    first_state.version_label = "2026.08.20";
    BOMWERK_TEST_CHECK(cache.store_feed_state(first_state));

    FeedState second_state = first_state;
    second_state.fetched_at_epoch_seconds = kFetchedAt + 86400;
    second_state.version_label = "2026.08.21";
    BOMWERK_TEST_CHECK(cache.store_feed_state(second_state));

    const std::optional<FeedState> looked_up = cache.lookup_feed_state(kFeedName);
    BOMWERK_TEST_CHECK(looked_up.has_value());
    BOMWERK_TEST_CHECK(looked_up->fetched_at_epoch_seconds == kFetchedAt + 86400);
    BOMWERK_TEST_CHECK(looked_up->version_label == "2026.08.21");
  }

  // Given a feed that was never stored, when looked up, then a clean miss :
  // same no-value-no-warning contract as the v1 purl lookup.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    BOMWERK_TEST_CHECK(!opened.value.lookup_feed_state("never-refreshed").has_value());
    BOMWERK_TEST_CHECK(opened.value.warnings().empty());
  }

  // Given a closed cache, when the new v2 accessors are used, then lookups
  // miss, stores return false, row counts read 0: every new accessor is as
  // inert as the v1 ones on a cache that never opened (rule 1).
  {
    VulnCache closed_cache;
    BOMWERK_TEST_CHECK(!closed_cache.lookup_feed_state(kFeedName).has_value());
    BOMWERK_TEST_CHECK(!closed_cache.store_feed_state(FeedState{}));
    BOMWERK_TEST_CHECK(closed_cache.feed_record_count(FeedTable::FeedState) == 0);
    BOMWERK_TEST_CHECK(closed_cache.warnings().empty());
  }

  // Given a fresh cache, when each v2 table's row count is read before
  // anything is written to it, then every one answers 0, not a warning :
  // an empty table and "never populated" are the same observable state.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;
    BOMWERK_TEST_CHECK(cache.feed_record_count(FeedTable::FeedState) == 0);
    BOMWERK_TEST_CHECK(cache.feed_record_count(FeedTable::OsvAdvisorySnapshot) == 0);
    BOMWERK_TEST_CHECK(cache.feed_record_count(FeedTable::VulnCacheEntries) == 0);
    BOMWERK_TEST_CHECK(cache.warnings().empty());
  }

  // Given a purl with no stored snapshot, when looked up, then an empty
  // (not a "problem") result: its first time being queried.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    BOMWERK_TEST_CHECK(opened.value.lookup_advisory_snapshot(kZlibPurl).empty());
    BOMWERK_TEST_CHECK(opened.value.warnings().empty());
  }

  // Given a snapshot stored for a purl, when looked up, then every advisory
  // round-trips (id + modified) and comes back ORDERED BY advisory_id: the
  // ordering `diff_advisory_revisions` depends on.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;
    const std::vector<AdvisoryRevision> current = {
        AdvisoryRevision{"GHSA-zzzz", "2026-01-01T00:00:00Z"},
        AdvisoryRevision{"CVE-2024-0001", "2026-01-01T00:00:00Z"}};
    BOMWERK_TEST_CHECK(cache.store_advisory_snapshot(kZlibPurl, current, {}, kFetchedAt));
    const std::vector<AdvisoryRevision> looked_up = cache.lookup_advisory_snapshot(kZlibPurl);
    BOMWERK_TEST_CHECK(looked_up.size() == 2);
    BOMWERK_TEST_CHECK(looked_up[0].advisory_id == "CVE-2024-0001");  // sorted, not insertion order
    BOMWERK_TEST_CHECK(looked_up[1].advisory_id == "GHSA-zzzz");
    BOMWERK_TEST_CHECK(looked_up[0].modified == "2026-01-01T00:00:00Z");
  }

  // Given a stored advisory, when its `modified` value changes on a LATER
  // store, then `modified`/`last_seen_at` update but `first_seen_at` is
  // PRESERVED: the field a finding-state machine's "how long has this been
  // known" question reads, which must survive routine re-confirmation.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;
    const std::vector<AdvisoryRevision> first_seen = {
        AdvisoryRevision{"CVE-2024-0001", "2026-01-01T00:00:00Z"}};
    BOMWERK_TEST_CHECK(cache.store_advisory_snapshot(kZlibPurl, first_seen, {}, kFetchedAt));

    const std::vector<AdvisoryRevision> updated = {
        AdvisoryRevision{"CVE-2024-0001", "2026-03-01T00:00:00Z"}};
    BOMWERK_TEST_CHECK(cache.store_advisory_snapshot(kZlibPurl, updated, {}, kFetchedAt + 86400));
    const std::vector<AdvisoryRevision> looked_up = cache.lookup_advisory_snapshot(kZlibPurl);
    BOMWERK_TEST_CHECK(looked_up.size() == 1);
    BOMWERK_TEST_CHECK(looked_up[0].modified == "2026-03-01T00:00:00Z");
    // first_seen_at is not exposed by lookup_advisory_snapshot (only id +
    // modified travel through the delta path); read it back directly to
    // confirm the UPSERT truly preserved it rather than overwriting.
    sqlite3* raw_handle = nullptr;
    sqlite3_open_v2((tree.root() / "vuln_cache.sqlite3").string().c_str(), &raw_handle,
                    SQLITE_OPEN_READONLY, nullptr);
    sqlite3_stmt* statement = nullptr;
    sqlite3_prepare_v2(raw_handle,
                       "SELECT first_seen_at, last_seen_at FROM osv_advisory_snapshot "
                       "WHERE purl = ?1 AND advisory_id = ?2;",
                       -1, &statement, nullptr);
    sqlite3_bind_text(statement, 1, kZlibPurl, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, "CVE-2024-0001", -1, SQLITE_TRANSIENT);
    BOMWERK_TEST_CHECK(sqlite3_step(statement) == SQLITE_ROW);
    BOMWERK_TEST_CHECK(sqlite3_column_int64(statement, 0) ==
                       kFetchedAt);  // first_seen_at: unchanged
    BOMWERK_TEST_CHECK(sqlite3_column_int64(statement, 1) ==
                       kFetchedAt + 86400);  // last_seen_at: moved
    sqlite3_finalize(statement);
    sqlite3_close_v2(raw_handle);
  }

  // Given a stored snapshot, when replaced with a call naming one of its ids
  // as REMOVED, then exactly that row is deleted and any other row survives.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;
    const std::vector<AdvisoryRevision> initial = {
        AdvisoryRevision{"CVE-2024-0001", "2026-01-01T00:00:00Z"},
        AdvisoryRevision{"GHSA-zzzz", "2026-01-01T00:00:00Z"}};
    BOMWERK_TEST_CHECK(cache.store_advisory_snapshot(kZlibPurl, initial, {}, kFetchedAt));

    const std::vector<AdvisoryRevision> surviving = {
        AdvisoryRevision{"CVE-2024-0001", "2026-01-01T00:00:00Z"}};
    BOMWERK_TEST_CHECK(
        cache.store_advisory_snapshot(kZlibPurl, surviving, {"GHSA-zzzz"}, kFetchedAt + 86400));
    const std::vector<AdvisoryRevision> looked_up = cache.lookup_advisory_snapshot(kZlibPurl);
    BOMWERK_TEST_CHECK(looked_up.size() == 1);
    BOMWERK_TEST_CHECK(looked_up[0].advisory_id == "CVE-2024-0001");
  }

  // Given both `current` and `removed_advisory_ids` empty, when stored, then
  // it is a true no-op: no row exists, no warning, no transaction overhead
  // for the common case of a purl with nothing to report.
  {
    TempTree tree;
    auto opened = VulnCache::open(tree.root() / "vuln_cache.sqlite3");
    VulnCache& cache = opened.value;
    BOMWERK_TEST_CHECK(cache.store_advisory_snapshot(kZlibPurl, {}, {}, kFetchedAt));
    BOMWERK_TEST_CHECK(cache.lookup_advisory_snapshot(kZlibPurl).empty());
    BOMWERK_TEST_CHECK(cache.warnings().empty());
  }

  // Given a closed cache, when the advisory-snapshot accessors are used, then
  // lookups are empty and stores return false: inert, never a crash.
  {
    VulnCache closed_cache;
    BOMWERK_TEST_CHECK(closed_cache.lookup_advisory_snapshot(kZlibPurl).empty());
    BOMWERK_TEST_CHECK(!closed_cache.store_advisory_snapshot(
        kZlibPurl, {AdvisoryRevision{"CVE-2024-0001", ""}}, {}, kFetchedAt));
  }

  return 0;
}
