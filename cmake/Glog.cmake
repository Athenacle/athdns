
FIND_PACKAGE(Threads REQUIRED)

# Enable ExternalProject CMake module
INCLUDE(ExternalProject)

# Download and install GoogleTest
ExternalProject_Add(
    glog
    URL https://github.com/google/glog/archive/master.zip
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/glog
    # Disable install step
    INSTALL_COMMAND ""
)
ENABLE_TESTING()

ExternalProject_Get_Property(glog source_dir binary_dir)

IF(${COMPILER_SUPPORT_NO_ZERO_AS_NULL})
  ADD_COMPILE_OPTIONS(-Wno-zero-as-null-pointer-constant)
ENDIF()

ADD_LIBRARY(libglog IMPORTED STATIC GLOBAL)

SET_TARGET_PROPERTIES(libglog PROPERTIES
    "IMPORTED_LOCATION" "${binary_dir}/libglog.a"
    "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
)


# I couldn't make it work with INTERFACE_INCLUDE_DIRECTORIES
INCLUDE_DIRECTORIES("${binary_dir}/glog/")
