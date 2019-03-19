include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckIncludeFileCXX)

check_include_file_cxx(unistd.h UNIX_HAVE_UNISTD)
check_include_file_cxx(sys/stat.h UNIX_HAVE_SYS_STAT)
check_include_file_cxx(sys/time.h UNIX_HAVE_SYS_TIME)
check_include_file_cxx(fcntl.h UNIX_HAVE_FCNTL)

check_function_exists(read UNIX_HAVE_READ)
check_function_exists(write UNIX_HAVE_WRITE)
check_function_exists(stat UNIX_HAVE_STAT)
check_function_exists(getopt_long UNIX_HAVE_GETOPTLONG)
check_function_exists(strerror UNIX_HAVE_STRERROR)
check_function_exists(open UNIX_HAVE_OPEN)
check_function_exists(gettimeofday UNIX_HAVE_GETTIMEOFDAY)

include(CheckStructHasMember)

check_struct_has_member("struct timespec" tv_sec "time.h" HAVE_TIMESPEC_TV_SEC)
check_struct_has_member("struct timespec" tv_nsec "time.h" HAVE_TIMESPEC_TV_NSEC)

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
int main() {
  return __builtin_expect(0, 1);
}" HAVE_BUILTIN_EXPECT)
