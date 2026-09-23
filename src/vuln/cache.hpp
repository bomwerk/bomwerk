#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "core/result.hpp"
#include "core/warning.hpp"
#include "vuln/delta.hpp"
#include "vuln/sqlite_support.hpp"

namespace bomwerk::vuln
{
namespace detail
{
class CacheExtension;
}
/// On-disk schema version stamped into `PRAGMA user_version`.
///
/// v1: `vuln_cache` alone.
/// v2: adds `feed_state` and `osv_advisory_snapshot`: see
/// docs/vuln-cache-schema.md for
/// every column. The migration from v1 is STRICTLY ADDITIVE (`CREATE TABLE IF
/// NOT EXISTS`, `vuln_cache` itself untouched) and runs in `open()`, so an
/// existing v1 file gains the new tables in place rather than losing its warm
/// `vuln_cache` rows. A file stamped newer than this binary understands is
/// still refused outright (unchanged from v1).
inline constexpr int kVulnCacheSchemaVersion = 2;

/// One cached OSV answer for a purl: `payload` is the per-purl response
/// object exactly as the API returned it (so metadata we do not extract yet
/// stays recoverable), `fetched_at_epoch_seconds` is wall-clock seconds since
/// the Unix epoch (1970-01-01 UTC: a timestamp format, not an OS
/// requirement) deciding the 24 h refresh.
struct VulnCacheEntry
{
  std::int64_t fetched_at_epoch_seconds = 0;
  std::string payload;
};

/// One of the v2 bulk-feed tables, named by a fixed internal enum
/// rather than a caller-supplied string: `feed_record_count` below turns
/// this into a table name via an internal switch, so it can never become a
/// SQL-injection point the way string-built DDL/DML could.
enum class FeedTable
{
  VulnCacheEntries,  ///< the v1 `vuln_cache` table, included so one accessor answers for all
  FeedState,
  OsvAdvisorySnapshot,  ///< populated starting the OSV-deltas commit
};

/// A bulk feed's persisted refresh state: everything `refresh_feeds` needs to
/// decide whether the next call must transfer anything at all. One row per
/// feed (`feed_name` is a fixed feed-specific constant owned by its caller),
/// not per purl; per-purl freshness stays exactly what
/// `VulnCacheEntry::fetched_at_epoch_seconds` already answers.
struct FeedState
{
  std::string feed_name;
  std::int64_t fetched_at_epoch_seconds = 0;  ///< when this feed was last ASKED about
  std::int64_t changed_at_epoch_seconds = 0;  ///< when its content last actually MOVED
  std::string etag;            ///< response validator, empty when the server sent none
  std::string last_modified;   ///< response validator, empty when the server sent none
  std::string content_digest;  ///< change detector for a feed serving neither (EUVD)
  std::size_t record_count = 0;
  std::string version_label;  ///< a feed's own catalogue version, or its content digest
};

/// SQLite-backed response cache, table `vuln_cache(purl TEXT PRIMARY KEY,
/// fetched_at INTEGER NOT NULL, payload TEXT NOT NULL)`,
/// plus the v2 bulk-feed tables documented in
/// docs/vuln-cache-schema.md. The PRIMARY KEY is the only per-purl lookup
/// pattern and gives SQLite its index; the v2 tables are `WITHOUT ROWID` for
/// the same reason (the primary key IS the row, so there is exactly one
/// B-tree per table, never a second rowid index nothing looks up by).
///
/// Never throws (rule 1): every sqlite problem is collected into
/// `warnings()` and degrades the operation: a failed `open` yields a closed
/// cache, a failed lookup a miss, a failed store returns false: so the
/// caller always proceeds, merely without persistence.
class VulnCache
{
 public:
  /// A default-constructed cache is closed and inert: every lookup always
  /// misses, every store is a no-op: the graceful-degradation object callers
  /// fall back to when the real cache cannot open.
  VulnCache() = default;
  ~VulnCache() = default;

  /// Defaulted: `sqlite_support::Sqlite3Handle` (a `unique_ptr`) already
  /// closes the old handle before taking on the new one, so there is no
  /// hand-written close-then-steal logic left to get wrong here.
  VulnCache(VulnCache&&) noexcept = default;
  VulnCache& operator=(VulnCache&&) noexcept = default;
  VulnCache(const VulnCache&) = delete;
  VulnCache& operator=(const VulnCache&) = delete;

  /// Open (creating parent directories, the file, and the schema as needed;
  /// migrating an existing v1 file to v2 in place). Any failure: unwritable
  /// path, corrupt/garbage file, schema stamped by a newer bomwerk, a failed
  /// migration step: returns a closed cache plus a warning, never an error;
  /// a failed migration leaves the file exactly as it was (rolled back), so a
  /// warm v1 cache is never partially rewritten.
  [[nodiscard]] static core::Result<VulnCache> open(const std::filesystem::path& database_path);

  bool is_open() const { return database_handle_ != nullptr; }

  /// The cached entry for `purl`, or nullopt on miss (and on any sqlite
  /// problem, which also appends to `warnings()`).
  [[nodiscard]] std::optional<VulnCacheEntry> lookup(const std::string& purl);

  /// UPSERT one purl's payload. Returns false (plus a warning) on failure.
  bool store(const std::string& purl, std::int64_t fetched_at_epoch_seconds,
             const std::string& payload);

  // ----: v2 bulk-feed state ----

  /// The stored state for one bulk feed, or nullopt when it was never
  /// fetched (and on any sqlite problem, which also appends to `warnings()`).
  [[nodiscard]] std::optional<FeedState> lookup_feed_state(const std::string& feed_name);

  /// UPSERT one feed's state. Returns false (plus a warning) on failure.
  bool store_feed_state(const FeedState& state);

  /// `purl`'s stored `(advisory_id, modified)` pairs, ORDERED BY advisory_id.
  /// The ordering is part of the contract, not incidental:
  /// `diff_advisory_revisions` (delta.hpp) walks two already-sorted ranges
  /// with a two-pointer merge. Empty: not a "problem": for a purl with no
  /// stored snapshot yet (its first time being queried).
  [[nodiscard]] std::vector<AdvisoryRevision> lookup_advisory_snapshot(const std::string& purl);

  /// Replace `purl`'s snapshot with `current`: UPSERTing each one (preserving
  /// `first_seen_at` for a surviving id: see docs/vuln-cache-schema.md) :
  /// and DELETE exactly `removed_advisory_ids`. Both loops run inside ONE
  /// transaction reusing ONE prepared statement each, so a purl with several
  /// advisories costs one fsync total rather than one per row, and a purl's
  /// snapshot is never left half-written. A no-op (returns true immediately,
  /// opens no transaction) when both `current` and `removed_advisory_ids` are
  /// empty. Returns false (plus a warning) on failure, leaving the previous
  /// snapshot for `purl` untouched (the transaction rolls back).
  bool store_advisory_snapshot(const std::string& purl,
                               const std::vector<AdvisoryRevision>& current,
                               const std::vector<std::string>& removed_advisory_ids,
                               std::int64_t observed_at_epoch_seconds);

  /// `SELECT COUNT(*)` on one v2 table, or `vuln_cache` itself: what
  /// `bomwerk feeds --status` and the idempotency tests read to confirm a
  /// refresh wrote (or did not write) rows. Returns 0 on any sqlite problem,
  /// which also appends to `warnings()`; a genuinely empty table and a
  /// failed count are otherwise indistinguishable from the caller's side,
  /// same posture as `lookup`'s miss-or-failure fold.
  [[nodiscard]] std::size_t feed_record_count(FeedTable table);

  /// sqlite problems collected since `open` (rule 1: they warn, never throw).
  const std::vector<core::Warning>& warnings() const { return warnings_; }

 private:
  explicit VulnCache(sqlite_support::Sqlite3Handle database_handle);

  sqlite_support::Sqlite3Handle database_handle_;
  std::vector<core::Warning> warnings_;

  friend class detail::CacheExtension;
};

/// Where the cache lives when the caller does not choose: honors
/// `$XDG_CACHE_HOME`, falls back to `$HOME/.cache`, then the system temp
/// directory: always under a `bomwerk/` subdirectory.
[[nodiscard]] std::filesystem::path default_cache_database_path();

}  // namespace bomwerk::vuln
