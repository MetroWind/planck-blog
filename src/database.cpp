#include <string_view>
#include <memory>
#include <vector>
#include <expected>
#include <tuple>
#include <optional>

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include "database.hpp"
#include "error.hpp"
#include "utils.hpp"

SQLiteStatement::SQLiteStatement(SQLiteStatement&& rhs)
{
    std::swap(sql, rhs.sql);
}

SQLiteStatement& SQLiteStatement::operator=(SQLiteStatement&& rhs)
{
    std::swap(sql, rhs.sql);
    return *this;
}

SQLiteStatement::~SQLiteStatement()
{
    if(sql != nullptr)
    {
        sqlite3_finalize(sql);
    }
}

E<SQLiteStatement> SQLiteStatement::fromStr(sqlite3* db, std::string_view expr)
{
    SQLiteStatement s;
    int code = sqlite3_prepare_v2(db, expr.data(), expr.size(), &s.sql, nullptr);
    if(code != SQLITE_OK)
    {
        return std::unexpected(runtimeError(std::format(
            "Invalid statement '{}': {}", expr, sqlite3_errstr(code))));
    }
    return E<SQLiteStatement>{std::in_place, std::move(s)};
}

void SQLite::clear()
{
    if(db != nullptr)
    {
        sqlite3_close(db);
        db = nullptr;
    }
}

E<std::unique_ptr<SQLite>>
SQLite::connectFile(const std::string& db_file)
{
    auto data = std::make_unique<SQLite>();
    if(int code = sqlite3_open(db_file.c_str(), &data->db);
       code != SQLITE_OK)
    {
        data->clear();
        return std::unexpected(runtimeError(std::string(
            "Failed to create DB connection: ") + sqlite3_errstr(code)));
    }
    // Enable WAL.
    DO_OR_RETURN(data->execute("PRAGMA journal_mode = WAL;"));
    // Enable foreign key support.
    DO_OR_RETURN(data->execute("PRAGMA foreign_keys = ON;"));
    return data;
}

E<std::unique_ptr<SQLite>> SQLite::connectMemory()
{
    return connectFile(":memory:");
}

E<SQLiteStatement> SQLite::statementFromStr(std::string_view s)
{
    return SQLiteStatement::fromStr(db, s);
}

E<void> SQLite::execute(SQLiteStatement sql_code) const
{
    auto result = eval<int>(std::move(sql_code));
    if(result.has_value())
    {
        return {};
    }
    else
    {
        return std::unexpected(result.error());
    }
}

E<void> SQLite::execute(const char* sql_code) const
{
    ASSIGN_OR_RETURN(auto sql, SQLiteStatement::fromStr(db, sql_code));
    return execute(std::move(sql));
}

SQLite::~SQLite()
{
    clear();
}

int64_t SQLite::lastInsertRowID() const
{
    return sqlite3_last_insert_rowid(db);
}

int64_t SQLite::changedRowsCount() const
{
    return sqlite3_changes64(db);
}
