# https://gist.github.com/Lewiscowles1986/225a10154637d18d6187147015c8d0f7
#
# Find the JEMALLOC client includes and library
#

# This module defines
# JEMALLOC_INCLUDE_DIR, where to find jemalloc.h
# JEMALLOC_LIBRARIES, the libraries to link against
# JEMALLOC_FOUND, if false, you cannot build anything that requires JEMALLOC

# also defined, but not for general use are
# JEMALLOC_LIBRARY, where to find the JEMALLOC library.

set( JEMALLOC_FOUND 0 )

if ( UNIX )
  find_path( JEMALLOC_INCLUDE_DIR
    NAMES
      jemalloc/jemalloc.h
    PATHS
      /usr/include
      /usr/include/jemalloc
      /usr/local/include
      /usr/local/include/jemalloc
      $ENV{JEMALLOC_ROOT}
      $ENV{JEMALLOC_ROOT}/include
      ${CMAKE_SOURCE_DIR}/externals/jemalloc
  DOC
    "Specify include-directories that might contain jemalloc.h here."
  )
  find_library( JEMALLOC_LIBRARY
    NAMES
      jemalloc libjemalloc JEMALLOC
    PATHS
      /usr/lib
      /usr/lib/jemalloc
      /usr/local/lib
      /usr/local/lib/jemalloc
      /usr/local/jemalloc/lib
      $ENV{JEMALLOC_ROOT}/lib
      $ENV{JEMALLOC_ROOT}
    DOC "Specify library-locations that might contain the jemalloc library here."
  )

  find_package_handle_standard_args(JEMALLOC DEFAULT_MSG JEMALLOC_LIBRARY JEMALLOC_INCLUDE_DIR)
endif (UNIX)
