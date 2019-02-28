
include(ExternalProject)

ExternalProject_Add(
  fmt
  URL https://github.com/fmtlib/fmt/releases/download/5.3.0/fmt-5.3.0.zip
  URL_HASH SHA256=4c0741e10183f75d7d6f730b8708a99b329b2f942dad5a9da3385ab92bb4a15c
  DOWNLOAD_NO_PROGRESS ON
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/deps/third_party/fmt
  CMAKE_ARGS "-DCMAKE_BUILD_TYPE=Release;-DFMT_DOC=OFF;-DFMT_INSTALL=OFF;-DFMT_TEST=OFF"
  INSTALL_COMMAND "")

ExternalProject_Get_Property(fmt source_dir binary_dir)

add_library(libfmt IMPORTED STATIC GLOBAL)

add_dependencies(libfmt fmt)

set_target_properties(libfmt PROPERTIES "IMPORTED_LOCATION" "${binary_dir}/libfmt.a")

include_directories("${source_dir}/include/")
