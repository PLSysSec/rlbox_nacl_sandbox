// NaCl support direct invocation of syscalls so testing perf of this

#include <chrono>
#include <iostream>

#include <sys/time.h>
#include <unistd.h>

using namespace std::chrono;

int main(int argc, char** argv)
{
  const int test_iterations = 1000000;

  auto enter_time = high_resolution_clock::now();
  auto exit_time = enter_time;

  // perform the test twice. first one is warmup
  for (int j = 0; j < 2; j++) {
    enter_time = high_resolution_clock::now();
    int acc = 0;
    struct timeval tv;
    for (int i = 0; i < test_iterations; i++) {
      acc += gettimeofday((struct timeval*) &tv, nullptr);
    }
    exit_time = high_resolution_clock::now();
    sleep(1);
  }

  int64_t ns = duration_cast<nanoseconds>(exit_time - enter_time).count();
  std::cout << "NaCl syscall invocation time: "
            << (ns / test_iterations) << "\n";
}
