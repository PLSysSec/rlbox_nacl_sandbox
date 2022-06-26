cmake_minimum_required(VERSION 3.13)

set(ASM_OPTIONS "-x assembler-with-cpp")
enable_language(C CXX ASM)

# Mac adds extra flags
set(HAVE_FLAG_SEARCH_PATHS_FIRST 0)

project(rlbox_nacl_testlib
        VERSION 0.1
        DESCRIPTION "RLBox integration with WASM modules compiled with nacl")

if(NOT DEFINED ENV{rlbox_SOURCE_DIR})
  message(FATAL_ERROR "Set rlbox_SOURCE_DIR environment variable")
endif()

if(NOT DEFINED ENV{NACL_C_COMPILER})
  message(FATAL_ERROR "Set NACL_C_COMPILER environment variable")
endif()

if(NOT DEFINED ENV{NACL_CXX_COMPILER})
  message(FATAL_ERROR "Set NACL_CXX_COMPILER environment variable")
endif()

if(NOT DEFINED ENV{modnacl_SOURCE_DIR})
  message(FATAL_ERROR "Set modnacl_SOURCE_DIR environment variable")
endif()

if(NOT DEFINED ENV{OUTPUT_SUFFIX})
  set(OUTPUT_SUFFIX "")
else()
  set(OUTPUT_SUFFIX $ENV{OUTPUT_SUFFIX})
endif()

set(rlbox_SOURCE_DIR $ENV{rlbox_SOURCE_DIR})
set(NACL_C_COMPILER $ENV{NACL_C_COMPILER})
set(NACL_CXX_COMPILER $ENV{NACL_CXX_COMPILER})
set(modnacl_SOURCE_DIR $ENV{modnacl_SOURCE_DIR})

set(CMAKE_C_COMPILER ${NACL_C_COMPILER})
set(CMAKE_CXX_COMPILER ${NACL_CXX_COMPILER})
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)


add_executable(glue_lib_nacl${OUTPUT_SUFFIX}.nexe
               ${modnacl_SOURCE_DIR}/native_client/src/trusted/dyn_ldr/dyn_ldr_sandbox_init.c
               ${modnacl_SOURCE_DIR}/native_client/src/trusted/dyn_ldr/dyn_ldr_sandbox_init_asm.S
               ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c)
target_include_directories(glue_lib_nacl.nexe PUBLIC ${modnacl_SOURCE_DIR})

# add_executable(syscall_bench_nacl${OUTPUT_SUFFIX}.nexe
#               ${CMAKE_SOURCE_DIR}/syscall_bench.cpp)
