# Design Document: Migrating Utility Libraries to `libmw`

## 1. Overview

This document outlines the detailed plan for migrating the internal utility libraries of the `nsblog` project to the external `libmw` library.

**What is `libmw`?**
`libmw` (available at [MetroWind/libmw](https://github.com/MetroWind/libmw)) is a shared C++ library that consolidates common utility functions and wrappers. Over time, `nsblog` accumulated its own custom-built wrappers for SQLite, URL parsing, HTTP client requests, process execution, cryptography (hashing), and error handling. Because these tools are useful across multiple projects (such as `shrt`), they were extracted into `libmw`.

**Why migrate?**
Migrating to `libmw` reduces code duplication. By using a shared library, bug fixes and feature additions to `libmw` will automatically benefit `nsblog` without needing to copy-paste code. This ensures `nsblog` remains maintainable, clean, and focused solely on blog-specific business logic.

---

## 2. Current Architecture vs. Target Architecture

### 2.1 Current Architecture
Currently, `nsblog` contains a directory `src/` housing various utility files:
- `database.hpp` / `database.cpp`: A lightweight RAII (Resource Acquisition Is Initialization) wrapper around the `sqlite3` C API.
- `url.hpp` / `url.cpp`: A wrapper around `libcurl` for parsing and formatting URLs.
- `http_client.hpp` / `http_client.cpp`: A wrapper around `libcurl` for making HTTP requests.
- `exec.hpp` / `exec.cpp`: A wrapper around POSIX pipes and the `fork`/`exec` system calls to spawn child processes.
- `hash.hpp` / `hash.cpp`: A custom hashing utility utilizing cryptographic libraries.
- `error.hpp`: A custom error handling mechanism based on C++23's `std::expected`.
- `utils.hpp`: Assorted utility functions (like URL encoding) and macros (`ASSIGN_OR_RETURN`).

In the current architecture, all these classes and functions live in the **global namespace** (meaning they are not scoped inside a `namespace {}` block).

### 2.2 Target Architecture
In the target architecture, these files will be entirely removed from the `nsblog` repository. Instead, `nsblog` will depend on `libmw` as an external dependency via CMake.

**The `mw::` Namespace**
The most significant architectural shift is that `libmw` encapsulates all its components within the `mw` namespace. This prevents name collisions with other libraries. For example, the `SQLite` class becomes `mw::SQLite`.

---

## 3. CMake Integration

CMake is our build system generator. It reads `CMakeLists.txt` to understand how to compile the project and what dependencies to download.

### 3.1 FetchContent for `libmw`
We will use CMake's `FetchContent` module. `FetchContent` allows CMake to download source code from a Git repository during the configuration phase and compile it alongside our project.

**Step-by-step CMake changes:**
1. **Declare the library:** Tell CMake where to find `libmw`.
   ```cmake
   include(FetchContent)
   FetchContent_Declare(
     libmw
     GIT_REPOSITORY https://github.com/MetroWind/libmw.git
   )
   ```
2. **Set Build Options:** `libmw` is modular. We only want to build the parts we need. We must set specific CMake variables *before* making the library available.
   ```cmake
   set(LIBMW_BUILD_URL ON)
   set(LIBMW_BUILD_SQLITE ON)
   set(LIBMW_BUILD_HTTP_SERVER ON)
   set(LIBMW_BUILD_CRYPTO ON)
   FetchContent_MakeAvailable(libmw)
   ```
   *Explanation of Options:* Setting these to `ON` tells `libmw`'s `CMakeLists.txt` to compile those specific subdirectories.
3. **Link the Libraries:** We need to tell the `nsblog` executable to link against `libmw`'s compiled targets.
   ```cmake
   set(LIBS
     # ... existing libs ...
     mw::mw
     mw::url
     mw::sqlite
     mw::http-server
     mw::crypto
   )
   ```
4. **Include Directories:** Tell the compiler where to find the header files for `libmw`.
   ```cmake
   set(INCLUDES
     # ... existing includes ...
     ${libmw_SOURCE_DIR}/includes
   )
   ```

---

## 4. Component-by-Component Migration Guide

This section details exactly what an programmer needs to change in the C++ source code.

### 4.1 Error Handling (`error.hpp`)
- **What it is:** A header defining `Error` (a `std::variant` of `RuntimeError` and `HTTPError`) and `E<T>` (an alias for `std::expected<T, Error>`). `std::expected` is a C++23 feature that holds either a successful return value or an error, forcing the programmer to handle errors explicitly.
- **Migration Action:** Change `#include "error.hpp"` to `#include <mw/error.hpp>`.
- **Code Changes:** Update all usages of `E<T>`, `Error`, `runtimeError`, and `httpError` to `mw::E<T>`, `mw::Error`, `mw::runtimeError`, and `mw::httpError`.

### 4.2 Database (`database.hpp` -> `<mw/database.hpp>`)
- **What it is:** The SQLite wrapper. SQLite is a C library, which means it uses raw pointers (`sqlite3*`) and requires manual memory management (calling `sqlite3_close`). The wrapper uses RAII to automatically close the database when the object goes out of scope.
- **Migration Action:**
  - Prefix `SQLite` and `SQLiteStatement` with `mw::`.
  - `libmw` introduced `std::optional` support for binding and retrieving null values. This means if a database column can be NULL, `libmw` can directly map it to a `std::optional<T>`. This might require minor adjustments if `nsblog` previously handled NULLs manually.

### 4.3 Utilities (`utils.hpp` -> `<mw/utils.hpp>`)
- **What it is:** Contains macros like `ASSIGN_OR_RETURN` (which propagates errors automatically if a function returning `std::expected` fails) and functions like `urlEncode`.
- **Migration Action:**
  - Prefix `urlEncode`, `strip`, `split`, etc., with `mw::`.
  - **CRITICAL DIFFERENCE:** `nsblog`'s `utils.hpp` contains a `parseJSON` function that relies on the external `nlohmann::json` library. `libmw` removed this function to avoid forcing a JSON dependency on all its users.
  - **Action Required:** We must recreate `parseJSON` directly inside `nsblog`. We should create a new file `src/local_utils.hpp` (or place it in an appropriate existing file) with the following code:
    ```cpp
    #include <nlohmann/json.hpp>
    template <typename Bytes>
    nlohmann::json parseJSON(Bytes&& bs)
    {
        return nlohmann::json::parse(bs, nullptr, false);
    }
    ```

### 4.4 URL and HTTP Client (`url.hpp`, `http_client.hpp`)
- **What they are:** Wrappers around `libcurl`, a C library for making network requests.
- **Migration Action:** Prefix `URL`, `HTTPRequest`, `HTTPResponse`, and `HTTPSession` with `mw::`.
- **Note:** `libmw`'s `HTTPSession` includes a new constructor `explicit HTTPSession(std::string_view socket_path);` which supports Unix domain sockets. Existing `nsblog` code using the default constructor will work without changes.

### 4.5 Exec (`exec.hpp`)
- **What it is:** A wrapper for spawning child processes. It uses `fork()` (which clones the current process) and `execvp()` (which replaces the cloned process with a new program). It uses POSIX `pipe()` to capture the standard input/output of the child process.
- **Migration Action:** Prefix `Process`, `Pipe`, `Input`, and `Output` with `mw::`.

### 4.6 Hashing/Crypto (`hash.hpp` -> `<mw/crypto.hpp>`)
- **What it is:** Previously, `nsblog` had a simple `Sha256HalfHasher`. `libmw` replaces this with a robust cryptography suite wrapping OpenSSL (`EVP_MD_CTX`), supporting SHA256, SHA512, AES-GCM encryption, and Argon2id key derivation.
- **Migration Action:**
  - Replace `#include "hash.hpp"` with `#include <mw/crypto.hpp>`.
  - Change `Sha256HalfHasher` to `mw::SHA256HalfHasher` (Note the capitalization difference: `Sha` vs `SHA`).
  - Update `CMakeLists.txt` to link against OpenSSL if `mw::crypto` requires it implicitly, though `libmw`'s CMake should handle the OpenSSL dependency internally via `find_package(OpenSSL)`. We may need to ensure OpenSSL is installed on the build machine.

---

## 5. Execution Workflow

Follow these steps strictly to implement the design:

### Step 1: Clean up `CMakeLists.txt`
1. Open `CMakeLists.txt`.
2. Add the `FetchContent_Declare` block for `libmw` as described in Section 3.1.
3. Add the `set(LIBMW_BUILD_...)` flags and `FetchContent_MakeAvailable(libmw)`.
4. Remove the `nsblog` local files from the `SOURCE_FILES` and `TEST_FILES` lists (e.g., remove `src/database.cpp`, `src/url.cpp`, `src/http_client.cpp`, `src/exec.cpp`, `src/hash.cpp`, `src/utils_test.cpp`, etc.).
5. Add the `mw::` libraries to the `LIBS` list.
6. Add `${libmw_SOURCE_DIR}/includes` to the `INCLUDES` list.

### Step 2: Delete Old Files
Delete the following files from the `src/` directory:
- `database.hpp`, `database.cpp`, `database_test.cpp`
- `url.hpp`, `url.cpp`, `url_test.cpp`
- `http_client.hpp`, `http_client.cpp`, `http_client_test.cpp`, `http_client_mock.hpp`
- `exec.hpp`, `exec.cpp`, `exec_test.cpp`
- `hash.hpp`, `hash.cpp`, `hash_test.cpp`, `hash_mock.hpp`
- `error.hpp`
- `utils.hpp`, `utils_test.cpp`
- `test_utils.hpp`

### Step 3: Implement `parseJSON` Locally
Create a new file `src/json_utils.hpp` (or similar) and implement the `parseJSON` template function as shown in Section 4.3. Include this new header wherever `parseJSON` is used (e.g., `main.cpp`, `auth.cpp`, `app.cpp`, `data.cpp`).

### Step 4: Refactoring Includes and Namespaces
This is the most time-consuming step. You must use a search-and-replace tool or manually go through the remaining `.cpp` and `.hpp` files:
1. Change includes from `"error.hpp"` to `<mw/error.hpp>`, `"database.hpp"` to `<mw/database.hpp>`, etc.
2. Search for usages of the migrated classes (e.g., `SQLite`, `URL`, `HTTPSession`, `Process`, `E<`, `Error`, `runtimeError`).
3. Prepend them with `mw::` (e.g., `mw::SQLite`, `mw::URL`, `mw::HTTPSession`, `mw::Process`, `mw::E<`, `mw::Error`, `mw::runtimeError`).
4. Rename `Sha256HalfHasher` to `mw::SHA256HalfHasher`.

### Step 5: Compilation and Testing
1. Configure the project: `cmake -B build .`
   - *Explanation:* This reads `CMakeLists.txt`, downloads `libmw`, and prepares the `build` directory.
2. Build the project: `cmake --build build -j`
   - *Explanation:* This compiles the C++ code. If you missed any `mw::` prefixes, the compiler will throw "identifier not found" errors. Fix them and recompile.
3. Run the tests: `ctest --test-dir build`
   - *Explanation:* This runs the automated tests. All tests must pass to confirm that the migration did not break the blog's functionality.
