#include "vuln/cache.hpp"

#include <sqlite3.h>

#include <cstddef>
#include <iterator>
#include <string>
#include <utility>

#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "vuln/sqlite_support.hpp"

namespace fs = std::filesystem;

namespace bomwerk::vuln
{
namespace
{

constexpr const char* kCacheFileName = "vuln_cache.sqlite3";
constexpr const char* kCacheSubdirectoryName = "bomwerk";

/// v1 schema.
constexpr const char* kSchemaV1Sql =
    "CREATE TABLE IF NOT EXISTS vuln_cache("
    "purl TEXT PRIMARY KEY, "
    "fetched_at INTEGER NOT NULL, "
    "payload TEXT NOT NULL);";

/// v2 schema: every statement is `CREATE ... IF NOT EXISTS`, so
/// applying this to a v1 file adds tables and touches not one existing row of
/// `vuln_cache`. `WITHOUT ROWID` on each: the declared PRIMARY KEY is the only
/// access pattern any of these tables ever needs, so it doubles as the
/// row: one B-tree, not a data B-tree plus a separate rowid index nothing
/// looks up by. Column meaning, expected row counts and the schema-version
/// history are documented in full in docs/vuln-cache-schema.md: keep that
/// file in sync with this string.
constexpr const char* kSchemaV2Sql =
    "CREATE TABLE IF NOT EXISTS feed_state("
    "feed_name TEXT PRIMARY KEY, "
    "fetched_at INTEGER NOT NULL, "
    "changed_at INTEGER NOT NULL, "
    "etag TEXT NOT NULL DEFAULT '', "
    "last_modified TEXT NOT NULL DEFAULT '', "
    "content_digest TEXT NOT NULL DEFAULT '', "
    "record_count INTEGER NOT NULL DEFAULT 0, "
    "version_label TEXT NOT NULL DEFAULT '') WITHOUT ROWID;"

    "CREATE TABLE IF NOT EXISTS osv_advisory_snapshot("
    "purl TEXT NOT NULL, "
    "advisory_id TEXT NOT NULL, "
    "modified TEXT NOT NULL, "
    "first_seen_at INTEGER NOT NULL, "
    "last_seen_at INTEGER NOT NULL, "
    "PRIMARY KEY(purl, advisory_id)) WITHOUT ROWID;";

/// Ordered, strictly ADDITIVE migration steps: index `i` brings a file at
/// schema version `i` to version `i + 1`. No step may DROP or ALTER an
/// existing table: a user's warm cache is months of avoided network traffic
/// and is never thrown away for our convenience (docs/CONTRIBUTING.md hard rule 5). Step
/// 0 is the original schema, so a brand-new file (`user_version` 0) and an
/// existing v1 file take exactly the same code path below, just starting at a
/// different index.
constexpr const char* kSchemaMigrations[] = {kSchemaV1Sql, kSchemaV2Sql};
static_assert(std::size(kSchemaMigrations) == kVulnCacheSchemaVersion,
              "every schema version needs exactly one migration step");

constexpr const char* kLookupSql = "SELECT fetched_at, payload FROM vuln_cache WHERE purl = ?1;";

constexpr const char* kStoreSql =
    "INSERT INTO vuln_cache(purl, fetched_at, payload) VALUES(?1, ?2, ?3) "
    "ON CONFLICT(purl) DO UPDATE SET "
    "fetched_at = excluded.fetched_at, payload = excluded.payload;";

constexpr const char* kLookupFeedStateSql =
    "SELECT fetched_at, changed_at, etag, last_modified, content_digest, record_count, "
    "version_label FROM feed_state WHERE feed_name = ?1;";

constexpr const char* kStoreFeedStateSql =
    "INSERT INTO feed_state(feed_name, fetched_at, changed_at, etag, last_modified, "
    "content_digest, record_count, version_label) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) "
    "ON CONFLICT(feed_name) DO UPDATE SET "
    "fetched_at = excluded.fetched_at, changed_at = excluded.changed_at, "
    "etag = excluded.etag, last_modified = excluded.last_modified, "
    "content_digest = excluded.content_digest, record_count = excluded.record_count, "
    "version_label = excluded.version_label;";

constexpr const char* kLookupAdvisorySnapshotSql =
    "SELECT advisory_id, modified FROM osv_advisory_snapshot WHERE purl = ?1 "
    "ORDER BY advisory_id;";

/// `first_seen_at` is deliberately NOT in the SET list: a surviving advisory
/// keeps the timestamp of when it was FIRST observed, even as `modified` and
/// `last_seen_at` move: see docs/vuln-cache-schema.md.
constexpr const char* kUpsertAdvisorySnapshotSql =
    "INSERT INTO osv_advisory_snapshot(purl, advisory_id, modified, first_seen_at, last_seen_at) "
    "VALUES(?1, ?2, ?3, ?4, ?4) "
    "ON CONFLICT(purl, advisory_id) DO UPDATE SET "
    "modified = excluded.modified, last_seen_at = excluded.last_seen_at;";

constexpr const char* kDeleteAdvisorySnapshotEntrySql =
    "DELETE FROM osv_advisory_snapshot WHERE purl = ?1 AND advisory_id = ?2;";

/// `FeedTable` -> its table name, via a fixed internal switch rather than a
/// caller-supplied string: `feed_record_count` can therefore never become a
/// SQL-injection point the way string-built DDL/DML could.
const char* table_name_for(FeedTable table)
{
  switch (table)
  {
    case FeedTable::VulnCacheEntries:
      return "vuln_cache";
    case FeedTable::FeedState:
      return "feed_state";
    case FeedTable::OsvAdvisorySnapshot:
      return "osv_advisory_snapshot";
  }
  return "vuln_cache";  // unreachable: all enumerators handled above
}

}  // namespace

VulnCache::VulnCache(sqlite_support::Sqlite3Handle database_handle)
    : database_handle_(std::move(database_handle))
{
}

core::Result<VulnCache> VulnCache::open(const fs::path& database_path)
{
  core::Result<VulnCache> result;  // default value = closed cache (degraded but usable)

  // A garbage file that is not SQLite at all fails on the FIRST real access
  // to its pages (SQLITE_NOTADB): whether that is `migrate_schema`'s own
  // BEGIN or the first migration step depends on libsqlite3's internals, but
  // either way this warns and runs cacheless rather than destroying the
  // user's file. Everything from "create the parent directory" through
  // "migrate to the current schema" is the identical sequence every
  // sqlite-backed store in this codebase needs: see
  // `sqlite_support::open_and_migrate`'s own doc comment for why it lives
  // there now rather than being hand-copied a fourth time.
  sqlite_support::OpenedDatabase opened = sqlite_support::open_and_migrate(
      database_path, "vuln cache", kVulnCacheSchemaVersion, kSchemaMigrations);
  if (opened.handle == nullptr)
  {
    result.warn(core::WarningCode::kVulnCacheOpenFailed, std::move(opened.warning));
    return result;
  }

  result.value = VulnCache(std::move(opened.handle));
  return result;
}

std::optional<VulnCacheEntry> VulnCache::lookup(const std::string& purl)
{
  if (!is_open())
  {
    return std::nullopt;
  }

  sqlite_support::PreparedStatement lookup_statement =
      sqlite_support::prepare(*database_handle_, kLookupSql);
  if (lookup_statement == nullptr)
  {
    // TODO: no WarningCode distinguishes a cache read/write/count
    // failure from an open failure; kVulnCacheOpenFailed is the closest existing
    // cause available, message text keeps the specific operation.
    warnings_.push_back(core::Warning{
        core::WarningCode::kVulnCacheOpenFailed,
        std::string("vuln cache lookup failed: ") + sqlite3_errmsg(database_handle_.get()),
        {},
        {}});
    return std::nullopt;
  }

  sqlite3_bind_text(lookup_statement.get(), 1, purl.c_str(), -1, SQLITE_TRANSIENT);

  const int step_status = sqlite3_step(lookup_statement.get());
  if (step_status == SQLITE_ROW)
  {
    VulnCacheEntry entry;
    entry.fetched_at_epoch_seconds = sqlite3_column_int64(lookup_statement.get(), 0);
    const unsigned char* payload_bytes = sqlite3_column_text(lookup_statement.get(), 1);
    const int payload_size = sqlite3_column_bytes(lookup_statement.get(), 1);
    if (payload_bytes != nullptr)
    {
      entry.payload.assign(reinterpret_cast<const char*>(payload_bytes),
                           static_cast<std::size_t>(payload_size));
    }
    return entry;
  }
  if (step_status != SQLITE_DONE)
  {
    warnings_.push_back(core::Warning{
        core::WarningCode::kVulnCacheOpenFailed,
        std::string("vuln cache lookup failed: ") + sqlite3_errmsg(database_handle_.get()),
        {},
        {}});
  }
  return std::nullopt;
}

bool VulnCache::store(const std::string& purl, std::int64_t fetched_at_epoch_seconds,
                      const std::string& payload)
{
  if (!is_open())
  {
    return false;
  }

  sqlite_support::PreparedStatement store_statement =
      sqlite_support::prepare(*database_handle_, kStoreSql);
  if (store_statement == nullptr)
  {
    warnings_.push_back(core::Warning{
        core::WarningCode::kVulnCacheOpenFailed,
        std::string("vuln cache store failed: ") + sqlite3_errmsg(database_handle_.get()),
        {},
        {}});
    return false;
  }

  sqlite3_bind_text(store_statement.get(), 1, purl.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(store_statement.get(), 2, fetched_at_epoch_seconds);
  sqlite3_bind_text(store_statement.get(), 3, payload.c_str(), static_cast<int>(payload.size()),
                    SQLITE_TRANSIENT);

  if (sqlite3_step(store_statement.get()) != SQLITE_DONE)
  {
    warnings_.push_back(core::Warning{
        core::WarningCode::kVulnCacheOpenFailed,
        std::string("vuln cache store failed: ") + sqlite3_errmsg(database_handle_.get()),
        {},
        {}});
    return false;
  }
  return true;
}

std::optional<FeedState> VulnCache::lookup_feed_state(const std::string& feed_name)
{
  if (!is_open())
  {
    return std::nullopt;
  }

  sqlite_support::PreparedStatement lookup_statement =
      sqlite_support::prepare(*database_handle_, kLookupFeedStateSql);
  if (lookup_statement == nullptr)
  {
    warnings_.push_back(core::Warning{core::WarningCode::kVulnCacheOpenFailed,
                                      std::string("vuln cache feed-state lookup failed: ") +
                                          sqlite3_errmsg(database_handle_.get()),
                                      {},
                                      {}});
    return std::nullopt;
  }

  sqlite3_bind_text(lookup_statement.get(), 1, feed_name.c_str(), -1, SQLITE_TRANSIENT);

  const int step_status = sqlite3_step(lookup_statement.get());
  if (step_status == SQLITE_ROW)
  {
    FeedState state;
    state.feed_name = feed_name;
    state.fetched_at_epoch_seconds = sqlite3_column_int64(lookup_statement.get(), 0);
    state.changed_at_epoch_seconds = sqlite3_column_int64(lookup_statement.get(), 1);
    state.etag = sqlite_support::read_text_column(*lookup_statement, 2);
    state.last_modified = sqlite_support::read_text_column(*lookup_statement, 3);
    state.content_digest = sqlite_support::read_text_column(*lookup_statement, 4);
    state.record_count = static_cast<std::size_t>(sqlite3_column_int64(lookup_statement.get(), 5));
    state.version_label = sqlite_support::read_text_column(*lookup_statement, 6);
    return state;
  }
  if (step_status != SQLITE_DONE)
  {
    warnings_.push_back(core::Warning{core::WarningCode::kVulnCacheOpenFailed,
                                      std::string("vuln cache feed-state lookup failed: ") +
                                          sqlite3_errmsg(database_handle_.get()),
                                      {},
                                      {}});
  }
  return std::nullopt;
}

bool VulnCache::store_feed_state(const FeedState& state)
{
  if (!is_open())
  {
    return false;
  }

  sqlite_support::PreparedStatement store_statement =
      sqlite_support::prepare(*database_handle_, kStoreFeedStateSql);
  if (store_statement == nullptr)
  {
    warnings_.push_back(core::Warning{core::WarningCode::kVulnCacheOpenFailed,
                                      std::string("vuln cache feed-state store failed: ") +
                                          sqlite3_errmsg(database_handle_.get()),
                                      {},
                                      {}});
    return false;
  }

  sqlite3_bind_text(store_statement.get(), 1, state.feed_name.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(store_statement.get(), 2, state.fetched_at_epoch_seconds);
  sqlite3_bind_int64(store_statement.get(), 3, state.changed_at_epoch_seconds);
  sqlite3_bind_text(store_statement.get(), 4, state.etag.c_str(),
                    static_cast<int>(state.etag.size()), SQLITE_TRANSIENT);
  sqlite3_bind_text(store_statement.get(), 5, state.last_modified.c_str(),
                    static_cast<int>(state.last_modified.size()), SQLITE_TRANSIENT);
  sqlite3_bind_text(store_statement.get(), 6, state.content_digest.c_str(),
                    static_cast<int>(state.content_digest.size()), SQLITE_TRANSIENT);
  sqlite3_bind_int64(store_statement.get(), 7, static_cast<std::int64_t>(state.record_count));
  sqlite3_bind_text(store_statement.get(), 8, state.version_label.c_str(),
                    static_cast<int>(state.version_label.size()), SQLITE_TRANSIENT);

  if (sqlite3_step(store_statement.get()) != SQLITE_DONE)
  {
    warnings_.push_back(core::Warning{core::WarningCode::kVulnCacheOpenFailed,
                                      std::string("vuln cache feed-state store failed: ") +
                                          sqlite3_errmsg(database_handle_.get()),
                                      {},
                                      {}});
    return false;
  }
  return true;
}

std::vector<AdvisoryRevision> VulnCache::lookup_advisory_snapshot(const std::string& purl)
{
  std::vector<AdvisoryRevision> revisions;
  if (!is_open())
  {
    return revisions;
  }

  sqlite_support::PreparedStatement lookup_statement =
      sqlite_support::prepare(*database_handle_, kLookupAdvisorySnapshotSql);
  if (lookup_statement == nullptr)
  {
    warnings_.push_back(core::Warning{core::WarningCode::kVulnCacheOpenFailed,
                                      std::string("vuln cache advisory-snapshot lookup failed: ") +
                                          sqlite3_errmsg(database_handle_.get()),
                                      {},
                                      {}});
    return revisions;
  }

  sqlite3_bind_text(lookup_statement.get(), 1, purl.c_str(), -1, SQLITE_TRANSIENT);
  while (sqlite3_step(lookup_statement.get()) == SQLITE_ROW)
  {
    AdvisoryRevision revision;
    revision.advisory_id = sqlite_support::read_text_column(*lookup_statement, 0);
    revision.modified = sqlite_support::read_text_column(*lookup_statement, 1);
    revisions.push_back(std::move(revision));
  }
  return revisions;
}

bool VulnCache::store_advisory_snapshot(const std::string& purl,
                                        const std::vector<AdvisoryRevision>& current,
                                        const std::vector<std::string>& removed_advisory_ids,
                                        std::int64_t observed_at_epoch_seconds)
{
  if (!is_open())
  {
    return false;
  }
  if (current.empty() && removed_advisory_ids.empty())
  {
    return true;  // nothing to write; not worth a transaction (the common case
                  // for a purl with no advisories before or after this refresh)
  }

  if (const std::string begin_error =
          sqlite_support::execute_simple_sql(*database_handle_, "BEGIN IMMEDIATE;");
      !begin_error.empty())
  {
    warnings_.push_back(core::Warning{core::WarningCode::kVulnCacheOpenFailed,
                                      "vuln cache advisory-snapshot store failed: " + begin_error,
                                      {},
                                      {}});
    return false;
  }

  bool step_failed = false;

  if (!current.empty())
  {
    sqlite_support::PreparedStatement upsert_statement =
        sqlite_support::prepare(*database_handle_, kUpsertAdvisorySnapshotSql);
    step_failed = upsert_statement == nullptr;
    for (std::size_t revision_index = 0; !step_failed && revision_index < current.size();
         ++revision_index)
    {
      const AdvisoryRevision& revision = current[revision_index];
      sqlite3_reset(upsert_statement.get());
      // Explicit byte lengths, not -1 (NUL-terminated): `advisory_id` and
      // `modified` originate from untrusted, parsed OSV JSON, which can carry
      // an embedded NUL byte via a ` ` escape: sqlite3_bind_text's -1
      // form would silently truncate at that byte, letting two distinct ids
      // collide at the same (purl, advisory_id) primary key (rule 1).
      sqlite3_bind_text(upsert_statement.get(), 1, purl.c_str(), static_cast<int>(purl.size()),
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(upsert_statement.get(), 2, revision.advisory_id.c_str(),
                        static_cast<int>(revision.advisory_id.size()), SQLITE_TRANSIENT);
      sqlite3_bind_text(upsert_statement.get(), 3, revision.modified.c_str(),
                        static_cast<int>(revision.modified.size()), SQLITE_TRANSIENT);
      sqlite3_bind_int64(upsert_statement.get(), 4, observed_at_epoch_seconds);
      step_failed = sqlite3_step(upsert_statement.get()) != SQLITE_DONE;
    }
  }

  if (!step_failed && !removed_advisory_ids.empty())
  {
    sqlite_support::PreparedStatement delete_statement =
        sqlite_support::prepare(*database_handle_, kDeleteAdvisorySnapshotEntrySql);
    step_failed = delete_statement == nullptr;
    for (std::size_t removed_index = 0; !step_failed && removed_index < removed_advisory_ids.size();
         ++removed_index)
    {
      sqlite3_reset(delete_statement.get());
      sqlite3_bind_text(delete_statement.get(), 1, purl.c_str(), static_cast<int>(purl.size()),
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(delete_statement.get(), 2, removed_advisory_ids[removed_index].c_str(),
                        static_cast<int>(removed_advisory_ids[removed_index].size()),
                        SQLITE_TRANSIENT);
      step_failed = sqlite3_step(delete_statement.get()) != SQLITE_DONE;
    }
  }

  if (step_failed)
  {
    warnings_.push_back(core::Warning{core::WarningCode::kVulnCacheOpenFailed,
                                      std::string("vuln cache advisory-snapshot store failed: ") +
                                          sqlite3_errmsg(database_handle_.get()),
                                      {},
                                      {}});
    (void)sqlite_support::execute_simple_sql(*database_handle_, "ROLLBACK;");
    return false;
  }

  if (const std::string commit_error =
          sqlite_support::execute_simple_sql(*database_handle_, "COMMIT;");
      !commit_error.empty())
  {
    warnings_.push_back(core::Warning{core::WarningCode::kVulnCacheOpenFailed,
                                      "vuln cache advisory-snapshot store failed: " + commit_error,
                                      {},
                                      {}});
    (void)sqlite_support::execute_simple_sql(*database_handle_, "ROLLBACK;");
    return false;
  }
  return true;
}

std::size_t VulnCache::feed_record_count(FeedTable table)
{
  if (!is_open())
  {
    return 0;
  }

  const std::string count_sql = std::string("SELECT COUNT(*) FROM ") + table_name_for(table) + ";";
  sqlite_support::PreparedStatement count_statement =
      sqlite_support::prepare(*database_handle_, count_sql.c_str());
  if (count_statement == nullptr || sqlite3_step(count_statement.get()) != SQLITE_ROW)
  {
    warnings_.push_back(core::Warning{
        core::WarningCode::kVulnCacheOpenFailed,
        std::string("vuln cache row count failed: ") + sqlite3_errmsg(database_handle_.get()),
        {},
        {}});
    return 0;
  }
  return static_cast<std::size_t>(sqlite3_column_int64(count_statement.get(), 0));
}

fs::path default_cache_database_path()
{
  return sqlite_support::resolve_xdg_database_path("XDG_CACHE_HOME", ".cache",
                                                   kCacheSubdirectoryName, kCacheFileName);
}

}  // namespace bomwerk::vuln
