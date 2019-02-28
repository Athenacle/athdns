
find_package(Threads REQUIRED)

include(ExternalProject)

ExternalProject_Add(
  gtest
  URL https://github.com/google/googletest/archive/release-1.8.1.zip
  URL_HASH SHA256=927827c183d01734cc5cfef85e0ff3f5a92ffe6188e0d18e909c5efebf28a0c7
  DOWNLOAD_NO_PROGRESS ON
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/deps/third_party/gtest
  INSTALL_COMMAND "")

enable_testing()

ExternalProject_Get_Property(gtest source_dir binary_dir)

if(${COMPILER_SUPPORT_NO_ZERO_AS_NULL})
  add_compile_options(-Wno-zero-as-null-pointer-constant)
endif()

add_library(libgtest IMPORTED STATIC GLOBAL)
add_dependencies(libgtest gtest)

set_target_properties(libgtest PROPERTIES
  "IMPORTED_LOCATION" "${binary_dir}/googlemock/gtest/libgtest.a"
  "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}")

add_library(libgmock IMPORTED STATIC GLOBAL)
add_dependencies(libgmock gtest)

set_target_properties(libgmock PROPERTIES
  "IMPORTED_LOCATION" "${binary_dir}/googlemock/libgmock.a"
  "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}")

include_directories("${source_dir}/googletest/include"
  "${source_dir}/googlemock/include")
