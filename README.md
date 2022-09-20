# RLBOX NaCl Sandbox Integration

**This is a prototype. Not yet ready for production use.**

Integration with RLBox sandboxing API to leverage the sandboxing in Native Client (NaCl) modules compiled with NaCl clang or NaCl gcc compilers.

For details about the RLBox sandboxing APIs, see [here](https://github.com/PLSysSec/rlbox_api_cpp17).

This code has been tested on 32-bit and 64-bit versions of Ubuntu.

## Building/Running the tests

You can build and run the tests using cmake with the following commands.

```bash
cmake -S . -B ./build
cmake --build ./build --target all
cmake --build ./build --target test
```

## Using this library

First, build the rlbox_nacl_sandbox repo with

```bash
cmake -S . -B ./build
cmake --build ./build --target all
```

This NaCl integration with RLBox depends on 2 external tools/libraries that are pulled in **automatically** to run the tests included in this repo.

1. [The **modified** NaCl compiler and runtime for library sandboxing](https://github.com/shravanrn/Sandboxing_NaCl/) that compiles your code to NaCl modules and provides the runtime to execute this
3.  [The RLBox APIs]((https://github.com/PLSysSec/rlbox_api_cpp17)) - A set of APIs that allow easy use of sandboxed libraries.

In the below steps, you can either use the automatically pulled in versions as described below, or download the tools yourself.

In order to sandbox a library of your choice.

- Build the sources of your library along with the file `native_client/src/trusted/dyn_ldr/dyn_ldr_sandbox_init.c` using the clang compiler available in `native_client/toolchain/linux_x86/pnacl_newlib_raw/bin/<arch>-nacl-clang`. This will produce a NaCl module.
- Finally you can write sandboxed code, just as you would with any other RLBox sandbox, such as in the short example below. For more detailed examples, please refer to the tutorial in the [RLBox Repo]((https://github.com/PLSysSec/rlbox_api_cpp17)).


```c++
#include "rlbox_nacl_sandbox.hpp"
#include "rlbox.hpp"

int main()
{
    rlbox_sandbox<rlbox_nacl_sandbox> sandbox;
    sandbox.create_sandbox("libFoo.nexe");
    // Invoke function bar with parameter 1
    sandbox.invoke_sandbox_function(bar, 1);
    sandbox.destroy_sandbox();
    return 0;
}
```

- To compile the above example, you must include the rlbox header files in `build/_deps/rlbox-src/code/include`, the integration header files in `include/` and the nacl_sandbox library in `build/cargo/{debug or release}/librlbox_nacl_sandbox.a` (make sure to use the whole archive and the rdynamic linker options). For instance, you can compile the above with

```bash
g++ -std=c++17 example.cpp -o example -I build/_deps/rlbox-src/code/include -I include -Wl,--whole-archive -l:build/cargo/debug/librlbox_nacl_sandbox.a -Wl,--no-whole-archive -Wl,-rdynamic
```

## Contributing Code

1. To contribute code, it is recommended you install clang-tidy which the build
uses if available. Install using:

   On Ubuntu:
```bash
sudo apt install clang-tidy
```
   On Arch Linux:
```bash
sudo pacman -S clang-tidy
```

2. It is recommended you use the dev mode for building during development. This
treat warnings as errors, enables clang-tidy checks, runs address sanitizer etc.
Also, you probably want to use the debug build. To do this, adjust your build
settings as shown below

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -DDEV=ON -S . -B ./build
```

3. After making changes to the source, add any new required tests and run all
tests as described earlier.

4. To make sure all code/docs are formatted with, we use clang-format.
Install using:

   On Ubuntu:
```bash
sudo apt install clang-format
```
   On Arch Linux:
```bash
sudo pacman -S clang-format
```

5. Format code with the format-source target:
```bash
cmake --build ./build --target format-source
```

6. Submit the pull request.
