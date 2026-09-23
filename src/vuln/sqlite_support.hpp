#pragma once
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

struct sqlite3;       ///< forward declaration: <sqlite3.h> stays private to
struct sqlite3_stmt;  ///< the .cpp of whichever module opens a database

namespace bomwerk::vuln::sqlite_support
{

/// The vuln cache and the separate finding-state file (a long-running
/// vs. another short-lived run, or a scan sharing the vuln cache)
/// may see concurrent access; sqlite retries a busy lock for this long before
/// reporting SQLITE_BUSY.
inline constexpr int kBusyTimeoutMilliseconds = 5000;

/// Stateless deleters, so `unique_ptr` costs exactly what the raw pointer
/// cost: an empty deleter is empty-base-optimized away, `sizeof(Sqlite3Handle)
/// == sizeof(sqlite3*)`, and the call inlines to a direct `sqlite3_close_v2`/
/// `sqlite3_finalize`. No control block, no atomic refcount: `shared_ptr`
/// would pay for both, and no database handle or prepared statement in this
/// codebase is ever shared between owners. Bodies live in sqlite_support.cpp
/// (which includes <sqlite3.h>), not here: this header is included from
/// cache.hpp/finding_state.hpp for the type aliases below, and must never
/// pull `<sqlite3.h>` itself into either of those public headers.
struct Sqlite3Close
{
  void operator()(sqlite3* database_handle) const noexcept;
};

struct Sqlite3Finalize
{
  void operator()(sqlite3_stmt* statement) const noexcept;
};

/// Owns one open database connection; closes it (harmless no-op on null) on
/// destruction, move-from, or reassignment. `VulnCache`/
/// every sqlite-backed store holds this instead of a raw `sqlite3*`: it
/// replaces the hand-written destructor + move constructor + move assignment
/// those classes used to need, and cannot forget to close the old handle on
/// move-assignment the way a hand-written one can.
using Sqlite3Handle = std::unique_ptr<sqlite3, Sqlite3Close>;

/// Owns one prepared statement for its scope; finalizes on destruction. Null
/// (`get() == nullptr`, or compare directly against `nullptr`) when
/// `prepare()` failed.
using PreparedStatement = std::unique_ptr<sqlite3_stmt, Sqlite3Finalize>;

/// Prepare `statement_sql` against `database`, or a null handle when sqlite
/// refuses it (the caller reads `sqlite3_errmsg` itself for the message).
[[nodiscard]] PreparedStatement prepare(sqlite3& database, const char* statement_sql);

/// Run one self-contained SQL statement (or several, semicolon-separated);
/// returns the error message from the first failing statement, an empty
/// string on success.
[[nodiscard]] std::string execute_simple_sql(sqlite3& database, const std::string& statement_sql);

/// Bind `value` to `?<column_index>` of `statement` as TEXT, with an explicit
/// byte length rather than `-1` (NUL-terminated): every string bound through
/// this can originate from untrusted, parsed input (a purl, an advisory id, a
/// component identity, a filesystem path segment), and `-1` would silently
/// truncate the bound value at its first embedded NUL rather than binding it
/// in full. `SQLITE_TRANSIENT` so sqlite copies the bytes immediately: the
/// caller's `std::string` is free to go out of scope, be reused, or be moved
/// from right after this call returns.
void bind_text(sqlite3_stmt* statement, int column_index, const std::string& value);

/// Read column `column_index` of `statement` as TEXT, or an empty string when
/// the column is NULL. `sqlite3_column_text` returns nullptr for a NULL
/// column even when the schema declares `NOT NULL DEFAULT ''`: every text
/// column read in this codebase goes through this rather than trusting the
/// schema default alone.
[[nodiscard]] std::string read_text_column(sqlite3_stmt& statement, int column_index);

/// Create `file_path`'s parent directory (and any missing ancestors) if it
/// does not already exist, or do nothing when `file_path` names a bare
/// filename with no directory component. Every `open()` in this codebase's
/// every sqlite-backed store in the product needs exactly this before calling
/// `sqlite3_open_v2` with `SQLITE_OPEN_CREATE`, and shares it here rather than
/// each repeating it: `fs::create_directories("")` fails outright (EINVAL)
/// for an empty path rather than being the harmless no-op a bare relative
/// config value (`state_db = "state.sqlite3"`, say) needs it to be: a guard
/// only one store's `open` had; the others never carried it at all, each hitting
/// the bug independently rather than one having a copy that slipped.
///
/// Returns an empty `std::error_code` on success (including the
/// nothing-to-do case); the caller's own `directory_error.message()` names
/// what went wrong otherwise, exactly as if it had called
/// `fs::create_directories` itself.
[[nodiscard]] std::error_code create_parent_directories_if_needed(
    const std::filesystem::path& file_path);

/// `database`'s `PRAGMA user_version`, or -1 when it cannot be read (which a
/// garbage/corrupt file typically causes: the caller's first migration step
/// then produces the actionable error instead).
[[nodiscard]] int read_schema_version(sqlite3& database);

/// Bring `database` from `current_version` to `target_version` by applying
/// `migrations[current_version..target_version)` in order, all inside ONE
/// transaction this function opens and commits itself (`BEGIN IMMEDIATE`
/// through `COMMIT`, stamping `PRAGMA user_version = target_version` before
/// the commit): a step failing partway, or a crash, leaves the file exactly
/// as it was: this function issues the `ROLLBACK` itself before returning.
/// `current_version` is only a hint for the cheap already-current fast path
/// below: once the write lock is actually held, the schema version is
/// re-read from `database` itself and THAT value, not `current_version`,
/// decides everything else: including refusing outright, same as the
/// caller's own pre-lock check, if the locked-in-place read finds the file
/// already at a version newer than `target_version` (a second writer having
/// raced ahead while this call waited for the lock) or unreadable at all
/// (never treated as "brand new", which would replay every migration step,
/// destructively so for one like finding_state's v1->v2, against a file that
/// may already hold real evidence). A brand-new file's `PRAGMA user_version`
/// of exactly `0` IS still treated as "start from `migrations[0]`".
/// Returns an empty string on success, the failing step's message otherwise.
[[nodiscard]] std::string migrate_schema(sqlite3& database, int current_version, int target_version,
                                         std::span<const char* const> migrations);

/// Outcome of `open_and_migrate` below: exactly one of `handle`/`warning` is
/// set. `handle == nullptr` is the single thing every caller needs to check :
/// a `warning` is always present in that case, and never present otherwise.
struct OpenedDatabase
{
  Sqlite3Handle handle;  ///< null on any failure below
  std::string warning;   ///< non-empty exactly when `handle` is null
};

/// The complete "open a sqlite-backed store" sequence every one of this
/// codebase's sqlite-backed stores need, byte-for-byte
/// identical apart from the store's own name (for warning text) and its own
/// schema version/migrations: create parent directories as needed
/// (`create_parent_directories_if_needed`), `sqlite3_open_v2` with
/// `SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE` (wrapping the handle
/// immediately so any failure below still closes it automatically), set the
/// busy timeout, refuse a file a NEWER bomwerk stamped
/// (`read_schema_version(*handle) > target_schema_version`), then
/// `migrate_schema` to bring it current.
///
/// Extracted after TWO of these three stores were found still missing a fix
/// (`create_parent_directories_if_needed`'s own doc comment) that only the
/// third ever had: sharing just the directory guard would still have left
/// this same class of drift free to recur somewhere else in this identical
/// sequence: this shares the whole
/// sequence instead, so a future change to any part of it (a new pragma, a
/// different busy timeout, WAL mode) lands here once rather than needing to
/// be found and re-applied at three call sites again.
///
/// `store_name` (e.g. `"vuln cache"`, or whatever a composed store calls
/// itself) appears verbatim as the subject of every warning this produces :
/// each caller's own `"<name> disabled: ..."` phrasing lives here now, not
/// three times over.
[[nodiscard]] OpenedDatabase open_and_migrate(const std::filesystem::path& database_path,
                                              std::string_view store_name,
                                              int target_schema_version,
                                              std::span<const char* const> migrations);

/// Open an existing SQLite store without creating directories, creating the
/// database, or migrating/stamping its schema. The handle is returned only
/// when the file opens read-only and its schema version exactly matches
/// `expected_schema_version`; every other outcome is a warning plus a null
/// handle. This is for evidence/reporting consumers that must never mutate the
/// operational store merely by reading it.
[[nodiscard]] OpenedDatabase open_read_only(const std::filesystem::path& database_path,
                                            std::string_view store_name,
                                            int expected_schema_version);

/// Resolve `subdirectory/file_name` via the standard XDG fallback chain a
/// database file's "where does this live when the caller does not choose"
/// default follows: `$env_var` (when set and non-empty) -> `$HOME /
/// home_fallback` -> the system temp directory -> the current directory as
/// a last resort. `home_fallback` is a path relative to `$HOME` (e.g.
/// `.cache`, or `.local/state` for `$XDG_STATE_HOME`'s own fallback) rather
/// than a single directory name, since not every XDG variable's fallback is
/// one path segment. Shared by `vuln::default_cache_database_path` and
/// a store's own default path helper: the two are otherwise the same
/// fallback chain over a different env var, home path, and file name.
[[nodiscard]] std::filesystem::path resolve_xdg_database_path(
    const char* env_var, const std::filesystem::path& home_fallback,
    const std::filesystem::path& subdirectory, const std::filesystem::path& file_name);

}  // namespace bomwerk::vuln::sqlite_support
