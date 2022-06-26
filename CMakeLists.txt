cmake_minimum_required(VERSION 3.13)

project(rlbox_nacl
        VERSION 0.1
        DESCRIPTION "RLBox integration with WASM modules compiled with nacl")

# Project Settings ###################

# set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DEV "Use settings suitable for dev contributions to rlbox" OFF)
option(BUILD32 "Build 32-bit binaries" OFF)

if (BUILD32)
  add_compile_options(-m32)
  add_link_options(-m32)
endif()

file(GLOB_RECURSE
     ALL_CXX_SOURCE_FILES
     ${CMAKE_SOURCE_DIR}/include/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/include/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/include/*.cc
     ${CMAKE_SOURCE_DIR}/include/*.hh
     ${CMAKE_SOURCE_DIR}/include/*.ii
     ${CMAKE_SOURCE_DIR}/include/*.[CHI]
     ${CMAKE_SOURCE_DIR}/test/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/test/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/test/*.cc
     ${CMAKE_SOURCE_DIR}/test/*.hh
     ${CMAKE_SOURCE_DIR}/test/*.ii
     ${CMAKE_SOURCE_DIR}/test/*.[CHI]
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/c_src/*.cc
     ${CMAKE_SOURCE_DIR}/c_src/*.hh
     ${CMAKE_SOURCE_DIR}/c_src/*.ii
     ${CMAKE_SOURCE_DIR}/c_src/*.[CHI])

# Dev Tools ###################

if(DEV)
  find_program(CLANG_TIDY "clang-tidy")
  if(CLANG_TIDY)
    # Config in .clang-tidy
    set(CMAKE_CXX_CLANG_TIDY clang-tidy)
  endif()

  find_program(CLANG_FORMAT "clang-format")
  if(CLANG_FORMAT)
    # Config in .clang-format
    add_custom_target(format-source
                      COMMAND clang-format
                              -i
                              -style=file
                              ${ALL_CXX_SOURCE_FILES})
  endif()

endif()

# Dependencies ###################

find_program(CARGO "cargo")
if(!CARGO)
  message(
    FATAL_ERROR
      "Could not find cargo. Please install cargo as it is needed to build rust libraries."
    )
endif()

include(FetchContent)

FetchContent_Declare(
  rlbox
  GIT_REPOSITORY https://github.com/PLSysSec/rlbox_api_cpp17.git)
FetchContent_GetProperties(rlbox)
if(NOT rlbox_POPULATED)
  FetchContent_Populate(rlbox)
endif()

FetchContent_Declare(catch2
                     GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                     GIT_TAG v2.13.7)
FetchContent_GetProperties(catch2)
if(NOT catch2_POPULATED)
  FetchContent_Populate(catch2)
endif()

add_subdirectory("${catch2_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/contrib")

if (EXISTS "${CMAKE_SOURCE_DIR}/../nacl_rlbox")
  set(modnacl_SOURCE_DIR "${CMAKE_SOURCE_DIR}/../nacl_rlbox")
else()
message(
  FATAL_ERROR
    "Use gclient sync to create folder ${CMAKE_SOURCE_DIR}/../nacl_rlbox"
  )
endif()

# Nacl compiler and runtime ###################

if (BUILD32)
  set(NACL_PLATFORM_PARAM "x86-32")
  set(NACL_PLATFORM_PARAM_ALT "i686")
  set(NACL_PLATFORM_PARAM_ALT2 "x86_32")
else()
  set(NACL_PLATFORM_PARAM "x86-64")
  set(NACL_PLATFORM_PARAM_ALT "x86_64")
  set(NACL_PLATFORM_PARAM_ALT2 "x86_64")
endif()
if (${CMAKE_BUILD_TYPE} STREQUAL "Release")
  set(NACL_BUILD_TYPE "opt")
else()
  set(NACL_BUILD_TYPE "dbg")
endif()
set(NACL_BUILD_OUTPUT_FOLDER "scons-out")
set(NACL_BUILD_OUTPUT_PATH "${modnacl_SOURCE_DIR}/native_client/${NACL_BUILD_OUTPUT_FOLDER}")
set(NACL_RUNTIME_DIR "${NACL_BUILD_OUTPUT_PATH}/${NACL_BUILD_TYPE}-linux-${NACL_PLATFORM_PARAM}/lib/")
set(NACL_LIBRARY_SANDBOX_RUNTIME
  "${NACL_RUNTIME_DIR}/libdyn_ldr.a"
  "${NACL_RUNTIME_DIR}/libsel.a"
  "${NACL_RUNTIME_DIR}/libnacl_error_code.a"
  "${NACL_RUNTIME_DIR}/libenv_cleanser.a"
  "${NACL_RUNTIME_DIR}/libnrd_xfer.a"
  "${NACL_RUNTIME_DIR}/libnacl_perf_counter.a"
  "${NACL_RUNTIME_DIR}/libnacl_base.a"
  "${NACL_RUNTIME_DIR}/libimc.a"
  "${NACL_RUNTIME_DIR}/libnacl_fault_inject.a"
  "${NACL_RUNTIME_DIR}/libnacl_interval.a"
  "${NACL_RUNTIME_DIR}/libplatform_qual_lib.a"
  "${NACL_RUNTIME_DIR}/libvalidators.a"
  "${NACL_RUNTIME_DIR}/libdfa_validate_caller_${NACL_PLATFORM_PARAM_ALT2}.a"
  "${NACL_RUNTIME_DIR}/libcpu_features.a"
  "${NACL_RUNTIME_DIR}/libvalidation_cache.a"
  "${NACL_RUNTIME_DIR}/libplatform.a"
  "${NACL_RUNTIME_DIR}/libgio.a"
  "${NACL_RUNTIME_DIR}/libnccopy_${NACL_PLATFORM_PARAM_ALT2}.a"
)
set (NACL_LIBRARY_SANDBOX_PROJECTS
  "dyn_ldr"
  "sel"
  "nacl_error_code"
  "env_cleanser"
  "nrd_xfer"
  "nacl_perf_counter"
  "nacl_base"
  "imc"
  "nacl_fault_inject"
  "nacl_interval"
  "platform_qual_lib"
  "validators"
  "dfa_validate_caller_${NACL_PLATFORM_PARAM_ALT2}"
  "cpu_features"
  "validation_cache"
  "platform"
  "gio"
  "nccopy_${NACL_PLATFORM_PARAM_ALT2}"
  "${NACL_BUILD_OUTPUT_FOLDER}/nacl_irt-${NACL_PLATFORM_PARAM}/staging/irt_core.nexe"
  "ncval_new"
  "sel_ldr"
)
set(NACL_COMPILER_DIR "${modnacl_SOURCE_DIR}/native_client/toolchain/linux_x86")
set(NACL_C_COMPILER "${NACL_COMPILER_DIR}/pnacl_newlib/bin/${NACL_PLATFORM_PARAM_ALT}-nacl-clang")
set(NACL_CXX_COMPILER "${NACL_COMPILER_DIR}/pnacl_newlib/bin/${NACL_PLATFORM_PARAM_ALT}-nacl-clang++")
set(NACL_C_COMPILER_GCC "${NACL_COMPILER_DIR}/nacl_x86_glibc/bin/${NACL_PLATFORM_PARAM_ALT}-nacl-gcc")
set(NACL_CXX_COMPILER_GCC "${NACL_COMPILER_DIR}/nacl_x86_glibc/bin/${NACL_PLATFORM_PARAM_ALT}-nacl-g++")
set(NACL_LIBC_PATH "${NACL_BUILD_OUTPUT_PATH}/nacl_irt-${NACL_PLATFORM_PARAM}/staging/irt_core.nexe")

add_custom_command(OUTPUT ${NACL_LIBRARY_SANDBOX_RUNTIME}
                   WORKING_DIRECTORY "${modnacl_SOURCE_DIR}/native_client"
                   COMMAND ./scons
                           MODE=${NACL_BUILD_TYPE}-linux,nacl
                           platform=${NACL_PLATFORM_PARAM}
                           werror=0
                           DESTINATION_ROOT="${NACL_BUILD_OUTPUT_PATH}"
                           ${NACL_LIBRARY_SANDBOX_PROJECTS}
                   COMMENT "Building NaCl runtime")

add_custom_target(nacl_runtime ALL DEPENDS ${NACL_LIBRARY_SANDBOX_RUNTIME})

# Tests ###################

if(DEV)
  if(MSVC)
    add_compile_options(/W4) # warnings
    add_compile_options(/WX) # warnings as errors
  else()
    add_compile_options(-Wall -Wextra -pedantic) # warnings
    add_compile_options(-Werror) # warnings as errors
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
  endif()
endif()

include(CTest)
include(Catch)

set(GLUE_LIB_SO "${CMAKE_BINARY_DIR}/nacl/glue_lib_nacl.nexe")
set(GLUE_LIB_GCC_SO "${CMAKE_BINARY_DIR}/nacl_gcc/glue_lib_nacl.nexe")

add_custom_command(OUTPUT ${GLUE_LIB_SO} ${GLUE_LIB_GCC_SO}
                   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/c_src
                   COMMAND rlbox_SOURCE_DIR=${rlbox_SOURCE_DIR}
                           NACL_C_COMPILER=${NACL_C_COMPILER}
                           NACL_CXX_COMPILER=${NACL_CXX_COMPILER}
                           modnacl_SOURCE_DIR=${modnacl_SOURCE_DIR}
                           ${CMAKE_COMMAND}
                           -S .
                           -B ${CMAKE_BINARY_DIR}/nacl
                           -DCMAKE_BUILD_TYPE=Release
                   COMMAND VERBOSE=1
                           ${CMAKE_COMMAND}
                           --build ${CMAKE_BINARY_DIR}/nacl
                           --target all
                   COMMAND rlbox_SOURCE_DIR=${rlbox_SOURCE_DIR}
                           NACL_C_COMPILER=${NACL_C_COMPILER_GCC}
                           NACL_CXX_COMPILER=${NACL_CXX_COMPILER_GCC}
                           modnacl_SOURCE_DIR=${modnacl_SOURCE_DIR}
                           ${CMAKE_COMMAND}
                           -S .
                           -B ${CMAKE_BINARY_DIR}/nacl_gcc
                           -DCMAKE_BUILD_TYPE=Release
                   COMMAND VERBOSE=1
                           ${CMAKE_COMMAND}
                           --build ${CMAKE_BINARY_DIR}/nacl_gcc
                           --target all
                   COMMENT "Building nacl library")

add_custom_target(glue_lib_nacl ALL DEPENDS nacl_runtime ${GLUE_LIB_SO} ${GLUE_LIB_GCC_SO})

find_package(Threads REQUIRED)

# Tests executables ###################

add_executable(test_rlbox_glue test/test_nacl_sandbox_glue_main.cpp
                               test/test_nacl_sandbox_glue.cpp)
target_include_directories(test_rlbox_glue PUBLIC include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)
target_include_directories(test_rlbox_glue
                           PUBLIC ${modnacl_SOURCE_DIR}/native_client/src/trusted/dyn_ldr)

target_compile_definitions(test_rlbox_glue PUBLIC
                           GLUE_LIB_NACL_PATH="${GLUE_LIB_SO}"
                           NACL_LIBC_PATH="${NACL_LIBC_PATH}")

target_link_libraries(test_rlbox_glue
                      Catch2::Catch2
                      ${NACL_LIBRARY_SANDBOX_RUNTIME}
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      )

add_dependencies(test_rlbox_glue nacl_runtime)

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue rt)
endif()
catch_discover_tests(test_rlbox_glue)

###################

add_executable(test_rlbox_glue_gcc test/test_nacl_sandbox_glue_main.cpp
                               test/test_nacl_sandbox_glue.cpp)
target_include_directories(test_rlbox_glue_gcc PUBLIC include)
target_include_directories(test_rlbox_glue_gcc
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue_gcc
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue_gcc
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)
target_include_directories(test_rlbox_glue_gcc
                           PUBLIC ${modnacl_SOURCE_DIR}/native_client/src/trusted/dyn_ldr)

target_compile_definitions(test_rlbox_glue_gcc PUBLIC
                           GLUE_LIB_NACL_PATH="${GLUE_LIB_GCC_SO}"
                           NACL_LIBC_PATH="${NACL_LIBC_PATH}")

target_link_libraries(test_rlbox_glue_gcc
                      Catch2::Catch2
                      ${NACL_LIBRARY_SANDBOX_RUNTIME}
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      )

add_dependencies(test_rlbox_glue_gcc nacl_runtime)

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue_gcc rt)
endif()
catch_discover_tests(test_rlbox_glue_gcc)

####

add_executable(test_rlbox_glue_embed test/test_nacl_sandbox_glue_main.cpp
                                     test/test_nacl_sandbox_glue_embedder_vars.cpp)
target_include_directories(test_rlbox_glue_embed PUBLIC include)
target_include_directories(test_rlbox_glue_embed
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue_embed
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue_embed
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)
target_include_directories(test_rlbox_glue_embed
                           PUBLIC ${modnacl_SOURCE_DIR}/native_client/src/trusted/dyn_ldr)

target_compile_definitions(test_rlbox_glue_embed PUBLIC
                           GLUE_LIB_NACL_PATH="${GLUE_LIB_SO}"
                           NACL_LIBC_PATH="${NACL_LIBC_PATH}")

target_link_libraries(test_rlbox_glue_embed
                      Catch2::Catch2
                      ${NACL_LIBRARY_SANDBOX_RUNTIME}
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      )

add_dependencies(test_rlbox_glue_embed nacl_runtime)

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue_embed rt)
endif()
catch_discover_tests(test_rlbox_glue_embed)

# Shortcuts ###################

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -V)
add_dependencies(check test_rlbox_glue test_rlbox_glue_embed glue_lib_nacl)
