
include(ExternalProject)

add_custom_target(3party)
set(THIRD_PARTY_LIBRARIES)
############################################################

#
# third-party project: fmtlib
# from:    https://github.com/fmtlib/fmt/
# desc:    A modern formatting library http://fmtlib.net
# ver:     5.3.0
# license: BSD-2c
ExternalProject_Add(
  fmt
  URL https://github.com/fmtlib/fmt/releases/download/5.3.0/fmt-5.3.0.zip
  URL_HASH SHA256=4c0741e10183f75d7d6f730b8708a99b329b2f942dad5a9da3385ab92bb4a15c
  DOWNLOAD_NO_PROGRESS ON
  PREFIX ${THIRD_PARTY_DIR}/fmt
  CMAKE_ARGS "-DCMAKE_BUILD_TYPE=Release;-DFMT_DOC=OFF;-DFMT_INSTALL=OFF;-DFMT_TEST=OFF"
  INSTALL_COMMAND "")

ExternalProject_Get_Property(fmt source_dir binary_dir)

set(FMT_BINARY_DIR ${binary_dir})

add_library(libfmt IMPORTED STATIC GLOBAL)

add_dependencies(libfmt fmt)

set_target_properties(libfmt PROPERTIES
  IMPORTED_LOCATION ${binary_dir}/libfmt.a)

include_directories(${source_dir}/include/)

add_dependencies(3party libfmt)

list(APPEND THIRD_PARTY_LIBRARIES libfmt)

#
# third-party project: http-parser
# from:    https://github.com/nodejs/http-parser
# desc:    http request/response parser for c
# ver:     2.9.0
# license: MIT
#
find_program(MAKE_EXE NAMES make gmake nmake)

ExternalProject_Add(
  http-parser
  URL https://github.com/nodejs/http-parser/archive/v2.9.0.zip
  URL_HASH SHA256=dbace2021bb531f5b3275c3bcdbef586a61b8fea07876520ddfd5f58878400ee
  DOWNLOAD_NO_PROGRESS ON
  PREFIX ${THIRD_PARTY_DIR}/http-parser
  BUILD_IN_SOURCE ON
  INSTALL_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${MAKE_EXE} package)

ExternalProject_Get_Property(http-parser source_dir)

set(HTTP_PARSER_BUILD_DIR ${source_dir})

include_directories(${source_dir})

add_library(libhttp-parser IMPORTED STATIC GLOBAL)

add_dependencies(libhttp-parser http-parser)

set_target_properties(libhttp-parser PROPERTIES
  IMPORTED_LOCATION ${HTTP_PARSER_BUILD_DIR}/libhttp_parser.a)

add_dependencies(3party libhttp-parser)

list(APPEND THIRD_PARTY_LIBRARIES libhttp-parser)
