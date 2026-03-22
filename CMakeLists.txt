# cmake -B build . && cmake --build build -j
cmake_minimum_required(VERSION 3.24)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

project(Blog)

include(FetchContent)
FetchContent_Declare(
  libmw
  GIT_REPOSITORY https://github.com/MetroWind/libmw.git
)

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
)
FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.1.1
)
FetchContent_Declare(
  ryml
  GIT_REPOSITORY https://github.com/biojppm/rapidyaml.git
  GIT_TAG
  GIT_SHALLOW FALSE  # ensure submodules are checked out
)
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_Declare(
  inja
  GIT_REPOSITORY https://github.com/pantor/inja.git
  GIT_TAG main
)
include_directories(${json_SOURCE_DIR}/single_include)
set(INJA_USE_EMBEDDED_JSON FALSE)
set(INJA_BUILD_TESTS FALSE)
set(BUILD_BENCHMARK FALSE)

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.12.0
)

FetchContent_Declare(
  macrodown
  GIT_REPOSITORY https://git.xeno.darksair.org/macrodown.git
)

set(LIBMW_BUILD_URL ON)
set(LIBMW_BUILD_SQLITE ON)
set(LIBMW_BUILD_HTTP_SERVER ON)
set(LIBMW_BUILD_CRYPTO ON)

set(SPDLOG_USE_STD_FORMAT ON)
FetchContent_MakeAvailable(libmw json inja cxxopts googletest ryml spdlog macrodown)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated_includes)
file(CREATE_LINK 
    ${macrodown_SOURCE_DIR}/include 
    ${CMAKE_CURRENT_BINARY_DIR}/generated_includes/macrodown 
    SYMBOLIC
)
unset(BUILD_BENCHMARK)

find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
# find_package(cmark REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libmagic REQUIRED libmagic)

set(SOURCE_FILES
  src/app.cpp
  src/app.hpp
  src/attachment.cpp
  src/attachment.hpp
  src/config.cpp
  src/config.hpp
  src/data.cpp
  src/data.hpp
  src/post.cpp
  src/post.hpp
  src/post_rendering.cpp
  src/post_rendering.hpp
  src/attachment.hpp
  src/legacy-migration.hpp
  src/theme.cpp
  src/theme.hpp
)

set(LIBS
  mw::mw
  mw::url
  mw::sqlite
  mw::http-server
  mw::crypto
  cxxopts
  spdlog::spdlog
  ryml::ryml
  ${CURL_LIBRARIES}
  ${SQLite3_LIBRARIES}
  ${libmagic_LIBRARIES}
  MacroDown::MacroDown
)

set(INCLUDES
  ${libmw_SOURCE_DIR}/includes
  ${CURL_INCLUDE_DIR}
  ${json_SOURCE_DIR}/single_include
  ${inja_SOURCE_DIR}/single_include/inja
  ${SQLite3_INCLUDE_DIRS}
  ${libmagic_INCLUDE_DIRS}
  ${CMAKE_CURRENT_BINARY_DIR}/generated_includes
)

add_executable(planck-blog ${SOURCE_FILES} src/main.cpp)
set_property(TARGET planck-blog PROPERTY CXX_STANDARD 23)

set_property(TARGET planck-blog PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
target_compile_options(planck-blog PRIVATE -Wall -Wextra -Wpedantic -Wno-deprecated-literal-operator)
target_include_directories(planck-blog PRIVATE ${INCLUDES})
target_link_libraries(planck-blog PRIVATE ${LIBS})

set(TEST_FILES
  src/app_test.cpp
  src/attachment_test.cpp
  src/data_test.cpp
  src/post_rendering_test.cpp
)

# ctest --test-dir build
add_executable(planck-blog_test ${SOURCE_FILES} ${TEST_FILES})
set_property(TARGET planck-blog_test PROPERTY CXX_STANDARD 23)

set_property(TARGET planck-blog_test PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
target_compile_options(planck-blog_test PRIVATE -Wall -Wextra -Wpedantic -Wno-deprecated-literal-operator)
target_include_directories(planck-blog_test PRIVATE
  ${INCLUDES}
  ${googletest_SOURCE_DIR}/googletest/include
  ${googletest_SOURCE_DIR}/googlemock/include
)

target_link_libraries(planck-blog_test PRIVATE
  ${LIBS}
  GTest::gtest_main
  GTest::gmock_main
)

enable_testing()
include(GoogleTest)
gtest_discover_tests(planck-blog_test
  # Need this so that the unit tests can find the templates.
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})