// ctest unit test for the shared sqlite3 open/migrate plumbing every
// sqlite-backed store is built on. Hermetic: a throwaway directory tree
// under a TempTree for every case; `open_and_migrate`'s own tests use a
// tiny throwaway schema of their own rather than any real store's, since the
// function itself does not care what schema it is migrating.
#include <sqlite3.h>

#include <cstddef>
#include <filesystem>
#include <string>

#include "support/check.hpp"
#include "support/temp_tree.hpp"
#include "vuln/sqlite_support.hpp"

namespace fs = std::filesystem;
namespace sqlite_support = bomwerk::vuln::sqlite_support;

using bomwerk::test::TempTree;

namespace
{

constexpr const char* kThrowawaySchemaV1Sql =
    "CREATE TABLE IF NOT EXISTS widgets(name TEXT NOT NULL PRIMARY KEY) WITHOUT ROWID;";
constexpr const char* kThrowawaySchemaMigrations[] = {kThrowawaySchemaV1Sql};
constexpr int kThrowawaySchemaVersion = 1;
constexpr int kNewerThanSupportedSchemaVersion = 99;

// A second, DESTRUCTIVE step (drop-then-recreate, the same shape as
// `finding_state`'s real v1->v2 migration): needed only by the
// stale-current-version race test below, which must be able to tell whether
// a step actually re-ran rather than merely whether the final schema version
// matches.
constexpr const char* kDestructiveSchemaV2Sql =
    "DROP TABLE IF EXISTS widgets; CREATE TABLE widgets(name TEXT NOT NULL PRIMARY KEY) WITHOUT "
    "ROWID;";
constexpr const char* kDestructiveSchemaMigrations[] = {kThrowawaySchemaV1Sql,
                                                        kDestructiveSchemaV2Sql};
constexpr int kDestructiveSchemaVersion = 2;

/// `PRAGMA user_version` of the file at `database_path`, read with a fresh,
/// independent connection: never through the handle `open_and_migrate`
/// itself returned: so this is a check on what actually landed on disk, not
/// a check on the function's own bookkeeping.
int read_stamped_schema_version(const fs::path& database_path)
{
  sqlite3* database_handle = nullptr;
  sqlite3_open_v2(database_path.string().c_str(), &database_handle, SQLITE_OPEN_READONLY, nullptr);
  sqlite3_stmt* statement = nullptr;
  int version = -1;
  if (sqlite3_prepare_v2(database_handle, "PRAGMA user_version;", -1, &statement, nullptr) ==
      SQLITE_OK)
  {
    if (sqlite3_step(statement) == SQLITE_ROW)
    {
      version = sqlite3_column_int(statement, 0);
    }
  }
  sqlite3_finalize(statement);
  sqlite3_close_v2(database_handle);
  return version;
}

}  // namespace

int main()
{
  // Given a database path whose parent directory does not exist yet, when
  // create_parent_directories_if_needed runs, then the parent (and any
  // missing ancestors) are created and no error is reported.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "nested" / "deeper" / "state.sqlite3";
    BOMWERK_TEST_CHECK(!fs::is_directory(database_path.parent_path()));

    const std::error_code error =
        bomwerk::vuln::sqlite_support::create_parent_directories_if_needed(database_path);
    BOMWERK_TEST_CHECK(!error);
    BOMWERK_TEST_CHECK(fs::is_directory(database_path.parent_path()));
  }

  // Given a database path whose parent directory already exists, then
  // nothing breaks and no error is reported: the common case every store's
  // own tests already exercise via TempTree's own root.
  {
    TempTree tree;
    const std::error_code error =
        bomwerk::vuln::sqlite_support::create_parent_directories_if_needed(tree.root() /
                                                                           "state.sqlite3");
    BOMWERK_TEST_CHECK(!error);
  }

  // Given a BARE RELATIVE FILENAME: `parent_path()` is empty, the exact
  // shape a `state_db = "state.sqlite3"` config value takes: then this is treated as
  // "nothing to create" rather than the `fs::create_directories("")` EINVAL
  // failure that used to silently disable whichever store hit it. This is
  // the regression this function exists to fix; each of the three stores'
  // own `open()` now delegates here instead of repeating the guard by hand.
  {
    const fs::path bare_relative_filename("state.sqlite3");
    BOMWERK_TEST_CHECK(bare_relative_filename.parent_path().empty());

    const std::error_code error =
        bomwerk::vuln::sqlite_support::create_parent_directories_if_needed(bare_relative_filename);
    BOMWERK_TEST_CHECK(!error);
  }

  // Given a fresh path with no file there yet, when open_and_migrate runs,
  // then it creates the parent directory, opens the file, stamps it at the
  // target schema version, and returns a non-null handle with no warning :
  // the shared sequence every one of the three real stores' own open() now
  // delegates to instead of hand-copying it a fourth time.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "nested" / "widgets.sqlite3";

    sqlite_support::OpenedDatabase opened = sqlite_support::open_and_migrate(
        database_path, "test widgets store", kThrowawaySchemaVersion, kThrowawaySchemaMigrations);
    BOMWERK_TEST_CHECK(opened.handle != nullptr);
    BOMWERK_TEST_CHECK(opened.warning.empty());
    BOMWERK_TEST_CHECK(fs::is_regular_file(database_path));
    BOMWERK_TEST_CHECK(read_stamped_schema_version(database_path) == kThrowawaySchemaVersion);
  }

  // Given a BARE RELATIVE FILENAME as the database path: the regression
  // `create_parent_directories_if_needed` exists to fix: then
  // open_and_migrate succeeds end to end rather than failing at the
  // directory-creation step. Uses the current working directory (whatever
  // ctest runs from) rather than TempTree, so the file is removed
  // immediately after rather than left behind for a real run to trip over.
  {
    const fs::path bare_relative_filename("bomwerk_test_bare_relative.sqlite3");
    // Removed up front, not just at the end: BOMWERK_TEST_CHECK aborts on
    // failure, which skips the cleanup below entirely: this guards against
    // a stale, already-migrated file left over from a prior aborted run
    // silently taking `migrate_schema`'s no-op fast path instead of actually
    // re-exercising create-and-migrate.
    {
      std::error_code stale_removal_error;
      fs::remove(bare_relative_filename, stale_removal_error);
    }
    sqlite_support::OpenedDatabase opened =
        sqlite_support::open_and_migrate(bare_relative_filename, "test widgets store",
                                         kThrowawaySchemaVersion, kThrowawaySchemaMigrations);
    BOMWERK_TEST_CHECK(opened.handle != nullptr);
    BOMWERK_TEST_CHECK(opened.warning.empty());
    opened.handle.reset();  // close before removing, harmless on every platform this targets
    std::error_code removal_error;
    fs::remove(bare_relative_filename, removal_error);
  }

  // Given a file already stamped with a schema version NEWER than the target
  // (a file a future bomwerk wrote), when open_and_migrate runs, then it
  // refuses outright: a null handle and a warning naming the store and the
  // path, never touching the file's contents.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "widgets.sqlite3";
    {
      sqlite3* database_handle = nullptr;
      sqlite3_open_v2(database_path.string().c_str(), &database_handle,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
      const std::string set_newer_version_sql =
          "PRAGMA user_version = " + std::to_string(kNewerThanSupportedSchemaVersion) + ";";
      sqlite3_exec(database_handle, set_newer_version_sql.c_str(), nullptr, nullptr, nullptr);
      sqlite3_close_v2(database_handle);
    }

    sqlite_support::OpenedDatabase opened = sqlite_support::open_and_migrate(
        database_path, "test widgets store", kThrowawaySchemaVersion, kThrowawaySchemaMigrations);
    BOMWERK_TEST_CHECK(opened.handle == nullptr);
    BOMWERK_TEST_CHECK(!opened.warning.empty());
    BOMWERK_TEST_CHECK(opened.warning.find("test widgets store") != std::string::npos);
    BOMWERK_TEST_CHECK(read_stamped_schema_version(database_path) ==
                       kNewerThanSupportedSchemaVersion);  // untouched
  }

  // Given a path that cannot be opened as a database at all (a directory
  // sitting where the file should be), then open_and_migrate degrades to a
  // null handle plus a warning rather than crashing or throwing.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "widgets.sqlite3";
    fs::create_directories(database_path);

    sqlite_support::OpenedDatabase opened = sqlite_support::open_and_migrate(
        database_path, "test widgets store", kThrowawaySchemaVersion, kThrowawaySchemaMigrations);
    BOMWERK_TEST_CHECK(opened.handle == nullptr);
    BOMWERK_TEST_CHECK(!opened.warning.empty());
  }

  // Given a file ALREADY at `target_version` (as if a racing process just
  // migrated and committed while this call's `current_version` snapshot was
  // taken before that: the TOCTOU `migrate_schema` guards against by
  // re-reading under its own write lock), when `migrate_schema` is called
  // directly with that now-stale, lower `current_version`, then it detects
  // the file is already current and returns success WITHOUT replaying any
  // step: critically, without re-running the destructive second step
  // (`DROP TABLE` then `CREATE TABLE`, the same shape as `finding_state`'s
  // real v1->v2 migration), which would otherwise silently discard a row
  // the "winning" racer already inserted after its own migration committed.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "widgets.sqlite3";
    sqlite_support::OpenedDatabase opened =
        sqlite_support::open_and_migrate(database_path, "test widgets store",
                                         kDestructiveSchemaVersion, kDestructiveSchemaMigrations);
    BOMWERK_TEST_CHECK(opened.handle != nullptr);
    BOMWERK_TEST_CHECK(opened.warning.empty());

    // Stand-in for data a concurrent process inserted after its own
    // migration committed but before this (stale) call below runs.
    BOMWERK_TEST_CHECK(sqlite_support::execute_simple_sql(*opened.handle,
                                                          "INSERT INTO widgets(name) VALUES "
                                                          "('sentinel');")
                           .empty());

    const std::string migration_error =
        sqlite_support::migrate_schema(*opened.handle, /*current_version=*/kThrowawaySchemaVersion,
                                       kDestructiveSchemaVersion, kDestructiveSchemaMigrations);
    BOMWERK_TEST_CHECK(migration_error.empty());

    sqlite_support::PreparedStatement row_count_statement = sqlite_support::prepare(
        *opened.handle, "SELECT COUNT(*) FROM widgets WHERE name = 'sentinel';");
    BOMWERK_TEST_CHECK(row_count_statement != nullptr);
    BOMWERK_TEST_CHECK(sqlite3_step(row_count_statement.get()) == SQLITE_ROW);
    BOMWERK_TEST_CHECK(sqlite3_column_int(row_count_statement.get(), 0) == 1);  // survived
  }

  // Given a file ALREADY NEWER than `target_version` (the mirror-image race
  //: a newer bomwerk migrated further while this call's stale
  // `current_version` snapshot still names an older target, e.g. a rolling
  // upgrade), when `migrate_schema` is called directly, then it refuses
  // rather than silently stamping `PRAGMA user_version` back down to the
  // stale target over a file whose actual schema is already newer.
  {
    TempTree tree;
    const fs::path database_path = tree.root() / "widgets.sqlite3";
    sqlite_support::OpenedDatabase opened =
        sqlite_support::open_and_migrate(database_path, "test widgets store",
                                         kDestructiveSchemaVersion, kDestructiveSchemaMigrations);
    BOMWERK_TEST_CHECK(opened.handle != nullptr);

    // current_version=0 (stale: this caller's own pre-lock read predates the
    // other binary's migration) and target=1 (its own, older understanding
    // of the schema): deliberately NOT equal, so the fast no-op path above
    // is not taken and the lock-time re-check actually runs.
    const std::string migration_error = sqlite_support::migrate_schema(
        *opened.handle, /*current_version=*/0, kThrowawaySchemaVersion, kThrowawaySchemaMigrations);
    BOMWERK_TEST_CHECK(!migration_error.empty());
    BOMWERK_TEST_CHECK(read_stamped_schema_version(database_path) ==
                       kDestructiveSchemaVersion);  // untouched, not stamped back down
  }

  return 0;
}
