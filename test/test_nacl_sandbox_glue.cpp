#define RLBOX_USE_EXCEPTIONS
#define RLBOX_ENABLE_DEBUG_ASSERTIONS
#define RLBOX_SINGLE_THREADED_INVOCATIONS
#include "rlbox_nacl_sandbox.hpp"

// NOLINTNEXTLINE
#define TestName "rlbox_nacl_sandbox"
// NOLINTNEXTLINE
#define TestType rlbox::rlbox_nacl_sandbox

#ifndef GLUE_LIB_NACL_PATH
#  error "Missing definition for GLUE_LIB_NACL_PATH"
#endif

#ifndef NACL_LIBC_PATH
#  error "Missing definition for NACL_LIBC_PATH"
#endif

// NOLINTNEXTLINE
#define CreateSandbox(sandbox) sandbox.create_sandbox(GLUE_LIB_NACL_PATH, NACL_LIBC_PATH)
// NOLINTNEXTLINE
#include "test_sandbox_glue.inc.cpp"
