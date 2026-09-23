#include "vuln/sqlite_support.hpp"

#include <sqlite3.h>

#include <cstddef>
#include <cstdlib>
#include <string_view>
#include <system_error>
#include <utility>

namespace bomwerk::vuln::sqlite_support
{

void Sqlite3Close::operator()(sqlite3* database_handle) const noexcept
{
  sqlite3_close_v2(database_handle);  // harmless no-op on nullptr
}

void Sqlite3Finalize::operator()(sqlite3_stmt* statement) const noexcept
{
  sqlite3_finalize(statement);  // harmless no-op on nullptr
}

PreparedStatement prepare(sqlite3& database, const char* statement_sql)
{
  sqlite3_stmt* statement_handle = nullptr;
  if (sqlite3_prepare_v2(&database, statement_sql, -1, &statement_handle, nullptr) != SQLITE_OK)
  {
    return nullptr;
  }
  return PreparedStatement(statement_handle);
}

std::string execute_simple_sql(sqlite3& database, const std::string& statement_sql)
{
  char* error_message = nullptr;
  if (sqlite3_exec(&database, statement_sql.c_str(), nullptr, nullptr, &error_message) != SQLITE_OK)
  {
    std::string message = error_message != nullptr ? error_message : "unknown sqlite error";
    sqlite3_free(error_message);
    return message;
  }
  return {};
}

void bind_text(sqlite3_stmt* statement, int column_index, const std::string& value)
{
  sqlite3_bind_text(statement, column_index, value.c_str(), static_cast<int>(value.size()),
                    SQLITE_TRANSIENT);
}

std::error_code create_parent_directories_if_needed(const std::filesystem::path& file_path)
{
  std::error_code directory_error;
  if (file_path.has_parent_path())
  {
    std::filesystem::create_directories(file_path.parent_path(), directory_error);
  }
  return directory_error;
}

std::string read_text_column(sqlite3_stmt& statement, int column_index)
{
  const unsigned char* text_bytes = sqlite3_column_text(&statement, column_index);
  if (text_bytes == nullptr)
  {
    return {};
  }
  const int text_size = sqlite3_column_bytes(&statement, column_index);
  return std::string(reinterpret_cast<const char*>(text_bytes),
                     static_cast<std::size_t>(text_size));
}

int read_schema_version(sqlite3& database)
{
  PreparedStatement version_statement = prepare(database, "PRAGMA user_version;");
  if (version_statement == nullptr || sqlite3_step(version_statement.get()) != SQLITE_ROW)
  {
    return -1;
  }
  return sqlite3_column_int(version_statement.get(), 0);
}

std::string migrate_schema(sqlite3& database, int current_version, int target_version,
                           std::span<const char* const> migrations)
{
  // Already current: skip the write transaction entirely rather than
  // paying a write-lock acquisition, a `PRAGMA user_version` write and a
  // COMMIT to re-stamp a version number that has not changed: the common
  // case for every `open()` of an already-migrated file, now including a
  // short-lived invocation opening the store fresh on
  // every call (not just a long-lived process, which only pays
  // this once per process lifetime).
  if (current_version == target_version)
  {
    return {};
  }

  // Belt-and-suspenders ROLLBACK on every failure branch below, including
  // this first one where BEGIN itself failed (so no transaction is actually
  // open): a ROLLBACK with nothing to roll back simply fails too, and that
  // failure is discarded here: the caller only ever sees the ORIGINAL
  // error, never a rollback's.
  if (const std::string begin_error = execute_simple_sql(database, "BEGIN IMMEDIATE;");
      !begin_error.empty())
  {
    (void)execute_simple_sql(database, "ROLLBACK;");
    return begin_error;
  }

  // Re-read now that the write lock is actually held, rather than trusting
  // the caller-supplied `current_version` (read before any lock was
  // acquired): a second process racing to open this same fresh/pre-migration
  // file could have been blocked here while a first process migrated and
  // committed, in which case that snapshot is stale and replaying migration
  // steps against it would re-run them: destructively so for a step like
  // finding_state's v1->v2 (`DROP TABLE` then `CREATE TABLE`), which is the
  // one schema in this codebase migrating EVIDENCE rather than a derived
  // index. If another writer already brought the file to `target_version`
  // while this connection waited for the lock, there is nothing left to do.
  const int locked_version = read_schema_version(database);
  if (locked_version == target_version)
  {
    (void)execute_simple_sql(database, "ROLLBACK;");
    return {};
  }
  // The mirror image of the same race: a NEWER binary could have migrated
  // past `target_version` while this connection waited for the lock (a
  // rolling upgrade where an older and a newer bomwerk briefly overlap).
  // `open_and_migrate`'s own pre-lock refusal only ever saw the stale
  // snapshot, so it must be re-checked here too: falling through would
  // otherwise stamp `PRAGMA user_version = target_version` back over a file
  // already at a later schema, lying about its own shape to every future
  // opener without ever touching a single table.
  if (locked_version > target_version)
  {
    (void)execute_simple_sql(database, "ROLLBACK;");
    return "has schema version " + std::to_string(locked_version) +
           " (newer than this bomwerk understands, target " + std::to_string(target_version) + ")";
  }
  // `read_schema_version` returns -1 for BOTH "brand-new, never-stamped file"
  // (PRAGMA user_version defaults to 0, never -1, so this can't be that) and
  // "cannot be read at all" (a transient I/O error on this very read, or a
  // corrupt/tampered header): collapsing that into `starting_version = 0`
  // below, as the caller-supplied `current_version` always has, would treat
  // "I don't know what's on disk" as "there is nothing on disk yet" and
  // replay every migration step from scratch, including a destructive one
  // like finding_state's v1->v2 `DROP TABLE`+`CREATE TABLE`, against a file
  // that may already hold real evidence. Refusing here, now that the write
  // lock is held and a fresh read was just attempted, is strictly safer than
  // guessing.
  if (locked_version < 0)
  {
    (void)execute_simple_sql(database, "ROLLBACK;");
    return "cannot read schema version while holding the write lock";
  }

  const int starting_version = locked_version;
  for (int version = starting_version; version < target_version; ++version)
  {
    if (const std::string step_error =
            execute_simple_sql(database, migrations[static_cast<std::size_t>(version)]);
        !step_error.empty())
    {
      (void)execute_simple_sql(database, "ROLLBACK;");
      return "migration to schema version " + std::to_string(version + 1) +
             " failed: " + step_error;
    }
  }

  if (const std::string version_error = execute_simple_sql(
          database, "PRAGMA user_version = " + std::to_string(target_version) + ";");
      !version_error.empty())
  {
    (void)execute_simple_sql(database, "ROLLBACK;");
    return version_error;
  }

  if (const std::string commit_error = execute_simple_sql(database, "COMMIT;");
      !commit_error.empty())
  {
    (void)execute_simple_sql(database, "ROLLBACK;");
    return commit_error;
  }
  return {};
}

OpenedDatabase open_and_migrate(const std::filesystem::path& database_path,
                                std::string_view store_name, int target_schema_version,
                                std::span<const char* const> migrations)
{
  OpenedDatabase opened;  // default value = null handle, empty warning (never both empty)
  const std::string store_name_text(store_name);

  if (const std::error_code directory_error = create_parent_directories_if_needed(database_path);
      directory_error)
  {
    opened.warning = store_name_text + " disabled: cannot create " +
                     database_path.parent_path().string() + ": " + directory_error.message();
    return opened;
  }

  sqlite3* raw_database_handle = nullptr;
  const int open_status = sqlite3_open_v2(database_path.string().c_str(), &raw_database_handle,
                                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
  // Wrapped immediately: whatever sqlite3_open_v2 allocated (even on
  // failure: it can still hand back a handle solely to report the error via
  // sqlite3_errmsg) is closed automatically the moment this function returns,
  // with no explicit close call needed on any failure branch below.
  Sqlite3Handle database_handle(raw_database_handle);
  if (open_status != SQLITE_OK)
  {
    const char* error_message = database_handle != nullptr ? sqlite3_errmsg(database_handle.get())
                                                           : sqlite3_errstr(open_status);
    opened.warning =
        store_name_text + " disabled: cannot open " + database_path.string() + ": " + error_message;
    return opened;
  }

  sqlite3_busy_timeout(database_handle.get(), kBusyTimeoutMilliseconds);

  // Forward-compatibility guard: never touch a file a NEWER bomwerk wrote :
  // its schema may not be what the caller's own prepared statements expect.
  // `read_schema_version` returns -1 for a garbage/corrupt file, which the
  // migration step below turns into the actionable error instead.
  const int schema_version = read_schema_version(*database_handle);
  if (schema_version > target_schema_version)
  {
    opened.warning = store_name_text + " disabled: " + database_path.string() +
                     " has schema version " + std::to_string(schema_version) +
                     " (newer than this bomwerk understands)";
    return opened;
  }

  // Every migration step, and the version stamp itself, runs inside ONE
  // transaction (see migrate_schema's own doc comment): a step failing
  // partway, or a crash, leaves the file exactly as it was, never a
  // half-migrated schema whose `user_version` lies about its shape.
  if (const std::string migration_error =
          migrate_schema(*database_handle, schema_version, target_schema_version, migrations);
      !migration_error.empty())
  {
    opened.warning =
        store_name_text + " disabled: " + database_path.string() + ": " + migration_error;
    return opened;
  }

  opened.handle = std::move(database_handle);
  return opened;
}

OpenedDatabase open_read_only(const std::filesystem::path& database_path,
                              std::string_view store_name, int expected_schema_version)
{
  OpenedDatabase opened;
  const std::string store_name_text(store_name);
  sqlite3* raw_database_handle = nullptr;
  const int open_status = sqlite3_open_v2(database_path.string().c_str(), &raw_database_handle,
                                          SQLITE_OPEN_READONLY, nullptr);
  Sqlite3Handle database_handle(raw_database_handle);
  if (open_status != SQLITE_OK)
  {
    const char* error_message = database_handle != nullptr ? sqlite3_errmsg(database_handle.get())
                                                           : sqlite3_errstr(open_status);
    opened.warning = store_name_text + " disabled: cannot open " + database_path.string() +
                     " read-only: " + error_message;
    return opened;
  }

  sqlite3_busy_timeout(database_handle.get(), kBusyTimeoutMilliseconds);
  const int schema_version = read_schema_version(*database_handle);
  if (schema_version != expected_schema_version)
  {
    opened.warning = store_name_text + " disabled: " + database_path.string() +
                     " has schema version " + std::to_string(schema_version) +
                     " (read-only consumer requires " + std::to_string(expected_schema_version) +
                     ")";
    return opened;
  }

  opened.handle = std::move(database_handle);
  return opened;
}

std::filesystem::path resolve_xdg_database_path(const char* env_var,
                                                const std::filesystem::path& home_fallback,
                                                const std::filesystem::path& subdirectory,
                                                const std::filesystem::path& file_name)
{
  if (const char* env_value = std::getenv(env_var); env_value != nullptr && *env_value != '\0')
  {
    return std::filesystem::path(env_value) / subdirectory / file_name;
  }
  if (const char* home_directory = std::getenv("HOME");
      home_directory != nullptr && *home_directory != '\0')
  {
    return std::filesystem::path(home_directory) / home_fallback / subdirectory / file_name;
  }
  std::error_code temp_error;
  const std::filesystem::path temp_directory = std::filesystem::temp_directory_path(temp_error);
  if (!temp_error)
  {
    return temp_directory / subdirectory / file_name;
  }
  return file_name;  // last resort: current directory
}

}  // namespace bomwerk::vuln::sqlite_support
