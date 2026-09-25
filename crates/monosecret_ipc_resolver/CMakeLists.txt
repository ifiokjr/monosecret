cmake_minimum_required(VERSION 3.20)
project(libmonosecret_resolver VERSION 1.0.0 LANGUAGES C)

option(MONOSECRET_RESOLVER_BUILD_TESTS "Build C client tests" ON)

include(GNUInstallDirs)
include(CheckLinkerFlag)
find_package(Threads REQUIRED)
find_package(yyjson CONFIG REQUIRED)

# yyjson arrives as a static archive whose symbols carry default visibility, so
# linking it into the shared library would re-export roughly fifty yyjson
# symbols and let an application's own copy of yyjson interpose on the one this
# library calls. Keep them local, matching what the previously vendored build
# achieved by compiling yyjson with hidden visibility. Windows needs nothing:
# there only MONOSECRET_RESOLVER_API marks a symbol dllexport.
check_linker_flag(C "LINKER:--exclude-libs,ALL" MONOSECRET_RESOLVER_HAS_EXCLUDE_LIBS)
if(MONOSECRET_RESOLVER_HAS_EXCLUDE_LIBS)
  set(MONOSECRET_RESOLVER_HIDE_YYJSON "LINKER:--exclude-libs,ALL")
else()
  check_linker_flag(C "LINKER:-unexported_symbol,_yyjson*"
      MONOSECRET_RESOLVER_HAS_UNEXPORTED_SYMBOL)
  if(MONOSECRET_RESOLVER_HAS_UNEXPORTED_SYMBOL)
    set(MONOSECRET_RESOLVER_HIDE_YYJSON "LINKER:-unexported_symbol,_yyjson*")
  else()
    set(MONOSECRET_RESOLVER_HIDE_YYJSON "")
  endif()
endif()

set(MONOSECRET_RESOLVER_SOURCES
    src/frame.c
    src/json.c
    src/secure_memory.c
    src/session.c)

if(WIN32)
  list(APPEND MONOSECRET_RESOLVER_SOURCES src/process_windows.c)
else()
  list(APPEND MONOSECRET_RESOLVER_SOURCES src/process_posix.c)
endif()

add_library(monosecret_resolver_objects OBJECT ${MONOSECRET_RESOLVER_SOURCES})
set_target_properties(monosecret_resolver_objects PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    POSITION_INDEPENDENT_CODE YES
    C_VISIBILITY_PRESET hidden)
target_include_directories(monosecret_resolver_objects PRIVATE include src)
target_link_libraries(monosecret_resolver_objects PRIVATE yyjson::yyjson)
target_compile_definitions(monosecret_resolver_objects PRIVATE MONOSECRET_RESOLVER_BUILDING)
if(MSVC)
  target_compile_options(monosecret_resolver_objects PRIVATE /W4 /WX /experimental:c11atomics)
else()
  target_compile_options(monosecret_resolver_objects PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# A Windows DLL must compile the public definitions with dllexport, while the
# static archive must not carry DLL export directives. Other platforms can
# safely share the hidden-visibility object set.
if(WIN32)
  add_library(monosecret_resolver_shared_objects OBJECT ${MONOSECRET_RESOLVER_SOURCES})
  set_target_properties(monosecret_resolver_shared_objects PROPERTIES
      C_STANDARD 11
      C_STANDARD_REQUIRED YES
      C_EXTENSIONS NO
      POSITION_INDEPENDENT_CODE YES
      C_VISIBILITY_PRESET hidden)
  target_include_directories(monosecret_resolver_shared_objects PRIVATE include src)
  target_link_libraries(monosecret_resolver_shared_objects PRIVATE yyjson::yyjson)
  target_compile_definitions(monosecret_resolver_shared_objects PRIVATE
      MONOSECRET_RESOLVER_BUILDING MONOSECRET_RESOLVER_SHARED)
  if(MSVC)
    target_compile_options(monosecret_resolver_shared_objects PRIVATE /W4 /WX /experimental:c11atomics)
  else()
    target_compile_options(monosecret_resolver_shared_objects PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
  endif()
  set(MONOSECRET_RESOLVER_SHARED_OBJECTS $<TARGET_OBJECTS:monosecret_resolver_shared_objects>)
else()
  set(MONOSECRET_RESOLVER_SHARED_OBJECTS $<TARGET_OBJECTS:monosecret_resolver_objects>)
endif()

add_library(monosecret_resolver_static STATIC
    $<TARGET_OBJECTS:monosecret_resolver_objects>)
add_library(monosecret_resolver_shared SHARED
    ${MONOSECRET_RESOLVER_SHARED_OBJECTS})
# MSVC names both the static archive and the DLL import library
# monosecret-resolver.lib, so one would overwrite the other in the build and
# install directories. Other toolchains give them distinct suffixes.
if(MSVC)
  set_target_properties(monosecret_resolver_static PROPERTIES OUTPUT_NAME monosecret-resolver-static)
else()
  set_target_properties(monosecret_resolver_static PROPERTIES OUTPUT_NAME monosecret-resolver)
endif()
set_target_properties(monosecret_resolver_shared PROPERTIES
    OUTPUT_NAME monosecret-resolver
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
target_link_libraries(monosecret_resolver_static PUBLIC Threads::Threads)
target_link_libraries(monosecret_resolver_static PRIVATE yyjson::yyjson)
target_link_libraries(monosecret_resolver_shared PUBLIC Threads::Threads)
target_link_libraries(monosecret_resolver_shared PRIVATE yyjson::yyjson)
target_compile_definitions(monosecret_resolver_shared PUBLIC MONOSECRET_RESOLVER_SHARED)
target_link_options(monosecret_resolver_shared PRIVATE ${MONOSECRET_RESOLVER_HIDE_YYJSON})
target_include_directories(monosecret_resolver_static PUBLIC include)
target_include_directories(monosecret_resolver_shared PUBLIC include)

install(TARGETS monosecret_resolver_static monosecret_resolver_shared
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/monosecret_resolver.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(monosecret-resolver.pc.in monosecret-resolver.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/monosecret-resolver.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(MONOSECRET_RESOLVER_BUILD_TESTS)
  enable_testing()
  add_executable(monosecret_resolver_smoke tests/smoke.c)
  target_link_libraries(monosecret_resolver_smoke PRIVATE monosecret_resolver_static)
  add_test(NAME monosecret_resolver_smoke COMMAND monosecret_resolver_smoke)
  add_executable(monosecret_resolver_smoke_shared tests/smoke.c)
  target_link_libraries(monosecret_resolver_smoke_shared PRIVATE monosecret_resolver_shared)
  add_test(NAME monosecret_resolver_smoke_shared COMMAND monosecret_resolver_smoke_shared)
  add_executable(monosecret_resolver_fake_peer tests/fake_peer.c)
  target_link_libraries(monosecret_resolver_fake_peer PRIVATE yyjson::yyjson)
  add_executable(monosecret_resolver_session tests/session.c)
  target_link_libraries(monosecret_resolver_session PRIVATE monosecret_resolver_static)
  add_test(NAME monosecret_resolver_session
           COMMAND monosecret_resolver_session $<TARGET_FILE:monosecret_resolver_fake_peer>)
  add_executable(monosecret_resolver_backpressure tests/backpressure.c)
  target_link_libraries(monosecret_resolver_backpressure PRIVATE monosecret_resolver_static)
  add_test(NAME monosecret_resolver_backpressure
           COMMAND monosecret_resolver_backpressure $<TARGET_FILE:monosecret_resolver_fake_peer>)
  add_executable(monosecret_resolver_regressions tests/regressions.c)
  target_link_libraries(monosecret_resolver_regressions PRIVATE monosecret_resolver_static)
  add_test(NAME monosecret_resolver_regressions
           COMMAND monosecret_resolver_regressions $<TARGET_FILE:monosecret_resolver_fake_peer>)
  # Links its own copy of the sources built with the test-only open hook, so
  # the installed library never carries it.
  add_executable(monosecret_resolver_open_order
                 tests/open_order.c ${MONOSECRET_RESOLVER_SOURCES})
  target_include_directories(monosecret_resolver_open_order PRIVATE include src)
  target_link_libraries(monosecret_resolver_open_order PRIVATE Threads::Threads yyjson::yyjson)
  target_compile_definitions(monosecret_resolver_open_order PRIVATE
      MONOSECRET_RESOLVER_BUILDING MONOSECRET_RESOLVER_TESTING)
  add_test(NAME monosecret_resolver_open_order
           COMMAND monosecret_resolver_open_order $<TARGET_FILE:monosecret_resolver_fake_peer>)

  foreach(test_target IN ITEMS
      monosecret_resolver_smoke
      monosecret_resolver_smoke_shared
      monosecret_resolver_fake_peer
      monosecret_resolver_session
      monosecret_resolver_backpressure
      monosecret_resolver_regressions
      monosecret_resolver_open_order)
    set_target_properties(${test_target} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    if(MSVC)
      target_compile_options(${test_target} PRIVATE /W4 /WX /experimental:c11atomics)
    else()
      target_compile_options(${test_target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
  endforeach()
endif()
