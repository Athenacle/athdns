
include(CheckCXXCompilerFlag)


if ((${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang") OR
    ${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")

  check_cxx_compiler_flag(-fno-permissive COMPILER_SUPPORT_FNOPERMISSIVE)
  check_cxx_compiler_flag(-ggdb3 COMPILER_SUPPORT_GGDB3)
  check_cxx_compiler_flag(-Wall COMPILER_SUPPORT_WALL)
  check_cxx_compiler_flag(-Weverything COMPILER_SUPPORT_WEVERYTHING)
  check_cxx_compiler_flag(-Wno-undef COMPILER_SUPPORT_NO_UNDEF)
  check_cxx_compiler_flag(-Wno-write-strings COMPILER_SUPPORT_NO_WRITE_STRINGS)
  check_cxx_compiler_flag(-Wno-deprecated COMPILER_SUPPORT_NO_DEPRECATED)
  check_cxx_compiler_flag(-Wno-padded COMPILER_SUPPORT_NO_PADDED)
  check_cxx_compiler_flag(-Wextra COMPILER_SUPPORT_WEXTRA)
  check_cxx_compiler_flag(-Wno-format-nonliteral COMPILER_SUPPORT_NO_FORMAT_NONLITERAL)
  check_cxx_compiler_flag(-fsanitize=address COMPILER_SUPPORT_FSANITIZE_ADDRESS)
  check_cxx_compiler_flag(-Wno-zero-as-null-pointer-constant COMPILER_SUPPORT_NO_ZERO_AS_NULL)
  check_cxx_compiler_flag(-Wno-unused-command-line-argument COMPILER_SUPPORT_UNUSED_COMMAND_LINE_ARG)

  if (${COMPILER_SUPPORT_UNUSED_COMMAND_LINE_ARG})
    add_compile_options(-Wno-unused-command-line-argument)
  endif()
  if (${COMPILER_SUPPORT_WEVERYTHING})
  else()
    if (${COMPILER_SUPPORT_WALL})
      add_compile_options(-Wall)
    endif()

    if (${COMPILER_SUPPORT_WEXTRA})
      add_compile_options(-Wextra)
    endif()

    if (${COMPILER_SUPPORT_WALL})
      add_compile_options(-Wall)
    endif()

    if (${COMPILER_SUPPORT_NO_WRITE_STRINGS})
      add_compile_options(-Wno-write-strings)
    endif()
  endif()

  if (${COMPILER_SUPPOER_NO_UNDEF})
    add_compile_options(-Wno-undef)
  endif()

  if (${COMPILER_SUPPORT_NO_FORMAT_NONLITERAL})
    add_compile_options(-Wno-format-nonliteral)
  endif()

  if (${COMPILER_SUPPORT_NO_PADDED})
    add_compile_options(-Wno-padded)
  endif()

  if (${COMPILER_SUPPORT_GGDB3})
    set(${CMAKE_C_FLAGS_DEBUG} "-ggdb3 ${CMAKE_C_FLAGS_DEBUG}")
    set(${CMAKE_CXX_FLAGS_DEBUG} "-ggdb3 ${CMAKE_CXX_FLAGS_DEBUG}")
  else()
    set(${CMAKE_C_FLAGS_DEBUG} "-g ${CMAKE_C_FLAGS_DEBUG}")
    set(${CMAKE_CXX_FLAGS_DEBUG} "-g ${CMAKE_CXX_FLAGS_DEBUG}")
  endif()

  if (${COMPILER_SUPPORT_FNOPERMISSIVE})
    set(CMAKE_CXX_FLAGS "-fno-permissive ${CMAKE_CXX_FLAGS}")
  endif()

  if (${COMPILER_SUPPORT_NO_DEPRECATED})
    add_compile_options(-Wno-deprecated)
  endif()

endif()
