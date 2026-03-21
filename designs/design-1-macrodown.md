# Design: Replace cmark with MacroDown

## Overview
The goal is to replace the current Markdown parser (`cmark`) with `MacroDown` (`https://git.xeno.darksair.org/macrodown.git`) in the `nsblog` project. `MacroDown` provides an extensible Markdown-like parsing system with built-in macro support.

## Required Changes

### 1. Build System (`CMakeLists.txt`)
The project currently fetches `cmark` via `FetchContent`. This needs to be replaced with `MacroDown`:
* Remove `FetchContent_Declare` for `cmark`.
* Add `FetchContent_Declare` for `macrodown` pointing to the git repository `https://git.xeno.darksair.org/macrodown.git`.
* Update `FetchContent_MakeAvailable` to use `macrodown` instead of `cmark`.
* Create a symlink in the build directory to allow headers to be included as `<macrodown/header.h>`:
  ```cmake
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated_includes)
  file(CREATE_LINK 
      ${macrodown_SOURCE_DIR}/include 
      ${CMAKE_CURRENT_BINARY_DIR}/generated_includes/macrodown 
      SYMBOLIC
  )
  ```
* Update `target_include_directories` for the main target (`planck-blog`) and test targets to include `${CMAKE_CURRENT_BINARY_DIR}/generated_includes`.
* Update `target_link_libraries` for the main target (`planck-blog`) and test targets to link against `MacroDown::MacroDown` (the alias provided by `MacroDown`'s `CMakeLists.txt`) instead of `cmark`.

### 2. Package Configuration (`packages/arch/PKGBUILD`)
The Arch Linux PKGBUILD currently lists `cmark` as a dependency.
* Remove `cmark` from the `depends` array since it is being replaced. `MacroDown` is not currently packaged for Arch, so it will be built from source via CMake's `FetchContent` along with the rest of the project.

### 3. Rendering Implementation (`src/post_rendering.cpp`)
The `renderMarkdown` function is responsible for converting Markdown to HTML using `cmark_markdown_to_html`. This logic needs to be rewritten to use `MacroDown`'s C++ API.

* Replace `#include <cmark.h>` with the required `MacroDown` headers using the namespaced path:
  ```cpp
  #include <macrodown/macrodown.h>
  #include <macrodown/standard_library.h>
  ```
* Rewrite `renderMarkdown(const std::string& src)`:
  * Instantiate the `macrodown::MacroDown` engine.
  * Optionally, register the standard library macros if desired:
    ```cpp
    macrodown::StandardLibrary::registerMacros(md.evaluator());
    ```
  * Parse the input string into a syntax tree:
    ```cpp
    auto ast = md.parse(src);
    if (!ast) {
        return std::unexpected(mw::runtimeError("Failed to parse Markdown with MacroDown."));
    }
    ```
  * Render the resulting syntax tree to HTML:
    ```cpp
    std::string html = md.render(*ast);
    return html;
    ```

### 4. Testing
* Ensure the project builds successfully with `MacroDown` linked statically.
* Run the existing test suite (specifically tests involving Markdown rendering, like `post_rendering_test.cpp` if it covers Markdown) to verify that the conversion to HTML produces the expected structures and doesn't break existing layout styling.
* Verify memory safety (no leaks) since we are moving from a C-based API (`cmark_markdown_to_html` returned an allocated C-string we had to `free()`) to a modern C++ memory management style (`std::string` and `std::unique_ptr`).

## Considerations
* **C++23 Compatibility**: Both `nsblog` and `MacroDown` are written in C++23. Toolchain compatibility shouldn't be an issue.
* **Feature Parity**: Ensure that `MacroDown` supports all standard Markdown elements previously used by `nsblog` posts that were rendered by `cmark`.
* **Sub-dependencies**: `MacroDown` fetches `uni-algo`. This is handled transparently by CMake `FetchContent`, but might increase initial configuration time.