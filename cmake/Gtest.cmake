
FIND_PACKAGE(Threads REQUIRED)

# Enable ExternalProject CMake module
INCLUDE(ExternalProject)

# Download and install GoogleTest
ExternalProject_Add(
    gtest
    URL https://github.com/google/googletest/archive/master.zip
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/gtest
    # Disable install step
    INSTALL_COMMAND ""
)
ENABLE_TESTING()

# Get GTest source and binary directories from CMake project
ExternalProject_Get_Property(gtest source_dir binary_dir)

    IF(${COMPILER_SUPPORT_NO_ZERO_AS_NULL})
        ADD_COMPILE_OPTIONS(-Wno-zero-as-null-pointer-constant)
    ENDIF() 

# Create a libgtest target to be used as a dependency by test programs
ADD_LIBRARY(libgtest IMPORTED STATIC GLOBAL)
ADD_DEPENDENCIES(libgtest gtest)

# Set libgtest properties
SET_TARGET_PROPERTIES(libgtest PROPERTIES
    "IMPORTED_LOCATION" "${binary_dir}/lib/libgtest.a"
    "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
)

# Create a libgmock target to be used as a dependency by test programs
ADD_LIBRARY(libgmock IMPORTED STATIC GLOBAL)
ADD_DEPENDENCIES(libgmock gtest)

# Set libgmock properties
SET_TARGET_PROPERTIES(libgmock PROPERTIES
    "IMPORTED_LOCATION" "${binary_dir}/lib/libgmock.a"
    "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"

)

# I couldn't make it work with INTERFACE_INCLUDE_DIRECTORIES
INCLUDE_DIRECTORIES("${source_dir}/googletest/include"
                    "${source_dir}/googlemock/include")


