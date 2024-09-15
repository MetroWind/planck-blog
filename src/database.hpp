#pragma once

#include <exception>
#include <memory>
#include <tuple>
#include <type_traits>
#include <vector>
#include <string>
#include <string_view>
#include <utility>
#include <iostream>

#include <sqlite3.h>

#include "error.hpp"
#include "utils.hpp"

// A simple RAII wrapper of sqlite3_stmt*.
class SQLiteStatement
{
public:
    SQLiteStatement(const SQLiteStatement&) = delete;
    SQLiteStatement& operator=(const SQLiteStatement&) = delete;
    SQLiteStatement(SQLiteStatement&& rhs);
    SQLiteStatement& operator=(SQLiteStatement&& rhs);
    ~SQLiteStatement();

    static E<SQLiteStatement> fromStr(sqlite3* db, std::string_view expr);

    sqlite3_stmt* data() const { return sql; }

    template<typename... Types>
    E<void> bind(Types... args) const;

    // Do not use.
    SQLiteStatement() = default;
private:
    sqlite3_stmt* sql = nullptr;
};

// This should be thread-safe. Multiple threads should be able to use
// the same SQLite object at the same time. This is because SQLite 3
// uses serialized threading model by default. See
// https://www.sqlite.org/threadsafe.html.
class SQLite
{
public:
    SQLite() = default;
    ~SQLite();
    SQLite(const SQLite&) = delete;
    SQLite& operator=(const SQLite&) = delete;

    static E<std::unique_ptr<SQLite>>
    connectFile(const std::string& db_file);
    static E<std::unique_ptr<SQLite>> connectMemory();

    E<SQLiteStatement> statementFromStr(std::string_view expr);

    // Evaluate a SQL statement, and retrieve the result. In the
    // return value, each element is a row, which is modeled as a
    // tuple. The type of the tuple depends on the template arguments
    // you pass when calling this function. Example:
    //
    //   eval<int, std::string>(...);
    //
    // You are responsible to make sure that the template arguments
    // matche the expected result of the SQL statement. Otherwise it
    // could seg fault.
    template<typename... Types>
    E<std::vector<std::tuple<Types...>>> eval(SQLiteStatement sql_code) const;
    template<typename... Types>
    E<std::vector<std::tuple<Types...>>> eval(const char* sql_code) const;
    template<typename... Types>
    E<std::vector<std::tuple<Types...>>> eval(const std::string& sql_code) const
    {
        return eval<Types...>(sql_code.c_str());
    }

    // Evaluate a SQL statement that is not supposed to return data.
    E<void> execute(SQLiteStatement sql_code) const;
    E<void> execute(const char* sql_code) const;
    E<void> execute(const std::string& sql_code) const
    {
        return execute(sql_code.c_str());
    }

    // Evaluate a SQL statement that is supposed to return a single
    // value. Return that value.
    template<typename T>
    E<T> evalToValue(SQLiteStatement sql_code) const;
    template<typename T>
    E<T> evalToValue(const char* sql_code) const;
    template<typename T>
    E<T> evalToValue(const std::string& sql_code) const
    {
        return evalToValue<T>(sql_code.c_str());
    }

    int64_t lastInsertRowID() const;
    // Count the number of affected rows in the most recently finished
    // INSERT, UPDATE or DELETE.
    int64_t changedRowsCount() const;

private:
    sqlite3* db = nullptr;
    void clear();
};

// ========== Template implementations ==============================>

namespace internal
{

template<typename T>
inline void getValue(SQLiteStatement&, int, T&)
{
    static_assert(false, "Invalid type of sqlite column");
}

template<>
inline void getValue(SQLiteStatement& sql, int i, int64_t& x)
{
    x = sqlite3_column_int64(sql.data(), i);
}

template<>
inline void getValue(SQLiteStatement& sql, int i, int& x)
{
    x = sqlite3_column_int(sql.data(), i);
}

template<>
inline void getValue(SQLiteStatement& sql, int i, double& x)
{
    x = sqlite3_column_double(sql.data(), i);
}

template<>
inline void getValue(SQLiteStatement& sql, int i, std::string& s)
{
    const unsigned char* raw = sqlite3_column_text(sql.data(), i);
    if(raw == nullptr)
    {
        // The column value is NULL. Do nothing.
        return;
    }
    s = reinterpret_cast<const char*>(raw);
}

// template<typename T, typename T1, typename... Types>
// inline std::tuple<T, T1, Types...> getRowInternal(SQLiteStatement& sql, int i)
// {
//     std::tuple<T> result;
//     getValue(sql, i, std::get<0>(result));
//     return std::tuple_cat(result, getRowInternal<T1, Types...>(sql, i+1));
// }

template<typename T, typename... Types>
inline std::tuple<T, Types...> getRowInternal(SQLiteStatement& sql, int i)
{
    std::tuple<T> result;
    getValue(sql, i, std::get<0>(result));
    if constexpr(sizeof...(Types) == 0)
    {
        return result;
    }
    else
    {
        return std::tuple_cat(result, getRowInternal<Types...>(sql, i+1));
    }
}

template<typename T, typename... Types>
inline std::tuple<T, Types...> getRow(SQLiteStatement& sql)
{
    return getRowInternal<T, Types...>(sql, 0);
}

inline E<void> sqlMaybe(int code, const char* msg)
{
    if(code != SQLITE_OK)
    {
        return std::unexpected(runtimeError(std::format(
            "{}: {}", msg, sqlite3_errstr(code))));
    }
    return {};
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, int x)
{
    return sqlMaybe(sqlite3_bind_int(sql.data(), i, x),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, int64_t x)
{
    return sqlMaybe(sqlite3_bind_int64(sql.data(), i, x),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, double x)
{
    return sqlMaybe(sqlite3_bind_double(sql.data(), i, x),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, const std::string& x)
{
    return sqlMaybe(sqlite3_bind_text(sql.data(), i, x.data(), x.size(),
                                      SQLITE_TRANSIENT),
                    "Failed to bind parameter");
}

inline E<void> bindOne(const SQLiteStatement& sql, int i, const char* x)
{
    return sqlMaybe(sqlite3_bind_text(sql.data(), i, x, -1,
                                      SQLITE_STATIC),
                    "Failed to bind parameter");
}

template<typename T>
inline E<void> bindInternal(const SQLiteStatement& sql, int i, T x)
{
    return bindOne(sql, i, x);
}

template<typename T, typename...Types>
inline E<void> bindInternal(const SQLiteStatement& sql, int i, T x,
                            Types... args)
{
    auto e = bindOne(sql, i, x);
    if(!e.has_value())
    {
        return std::unexpected(e.error());
    }
    return bindInternal(sql, i+1, args...);
}

} // namespace internal

template<typename... Types>
E<void> SQLiteStatement::bind(Types... args) const
{
    return internal::bindInternal(*this, 1, args...);
}

template<typename... Types>
E<std::vector<std::tuple<Types...>>> SQLite::eval(SQLiteStatement sql) const
{
    std::vector<std::tuple<Types...>> result;
    while(true)
    {
        int code = sqlite3_step(sql.data());
        switch(code)
        {
        case SQLITE_DONE:
            return result;
        case SQLITE_ROW:
            result.push_back(internal::getRow<Types...>(sql));
            break;
        case SQLITE_BUSY:
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return std::unexpected(runtimeError(sqlite3_errstr(code)));
        case SQLITE_ERROR:
        case SQLITE_MISUSE:
            return std::unexpected(runtimeError(std::string(
                "Failed to evaluate SQL: ") + sqlite3_errstr(code)));
        default:
            return std::unexpected(runtimeError(std::string(
                "Unexpected return code when evaluating SQL: ") +
                sqlite3_errstr(code)));
        }
    }
    return result;
}

template<typename... Types>
E<std::vector<std::tuple<Types...>>> SQLite::eval(const char* sql_code) const
{
    ASSIGN_OR_RETURN(auto sql, SQLiteStatement::fromStr(db, sql_code));
    return eval<Types...>(std::move(sql));
}

template<typename T>
E<T> SQLite::evalToValue(SQLiteStatement sql_code) const
{
    ASSIGN_OR_RETURN(std::vector<std::tuple<T>> result,
                     eval<T>(std::move(sql_code)));
    if(result.empty())
    {
        return std::unexpected(runtimeError(
            "evalToValue() expects a return value from SQL evaluation, "
            "but no value is returned"));
    }
    return std::get<0>(std::move(result)[0]);
}

template<typename T>
E<T> SQLite::evalToValue(const char* sql_code) const
{
    ASSIGN_OR_RETURN(auto sql, SQLiteStatement::fromStr(db, sql_code));
    return evalToValue<T>(std::move(sql));
}
