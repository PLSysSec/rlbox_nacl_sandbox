#pragma once

#include "dyn_ldr_lib.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
// RLBox allows applications to provide a custom shared lock implementation
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  include <shared_mutex>
#endif
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#define RLBOX_NACL_UNUSED(...) (void)__VA_ARGS__

// Use the same convention as rlbox to allow applications to customize the
// shared lock
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  define RLBOX_SHARED_LOCK(name) std::shared_timed_mutex name
#  define RLBOX_ACQUIRE_SHARED_GUARD(name, ...)                                \
    std::shared_lock<std::shared_timed_mutex> name(__VA_ARGS__)
#  define RLBOX_ACQUIRE_UNIQUE_GUARD(name, ...)                                \
    std::unique_lock<std::shared_timed_mutex> name(__VA_ARGS__)
#else
#  if !defined(RLBOX_SHARED_LOCK) || !defined(RLBOX_ACQUIRE_SHARED_GUARD) ||   \
    !defined(RLBOX_ACQUIRE_UNIQUE_GUARD)
#    error                                                                     \
      "RLBOX_USE_CUSTOM_SHARED_LOCK defined but missing definitions for RLBOX_SHARED_LOCK, RLBOX_ACQUIRE_SHARED_GUARD, RLBOX_ACQUIRE_UNIQUE_GUARD"
#  endif
#endif

namespace rlbox {

namespace detail {
  // relying on the dynamic check settings (exception vs abort) in the rlbox lib
  inline void dynamic_check(bool check, const char* const msg);
}

namespace nacl_detail {

  template<typename T>
  constexpr bool false_v = false;

  // https://stackoverflow.com/questions/6512019/can-we-get-the-type-of-a-lambda-argument
  namespace return_argument_detail {
    template<typename Ret, typename... Rest>
    Ret helper(Ret (*)(Rest...));

    template<typename Ret, typename F, typename... Rest>
    Ret helper(Ret (F::*)(Rest...));

    template<typename Ret, typename F, typename... Rest>
    Ret helper(Ret (F::*)(Rest...) const);

    template<typename F>
    decltype(helper(&F::operator())) helper(F);
  } // namespace return_argument_detail

  template<typename T>
  using return_argument =
    decltype(return_argument_detail::helper(std::declval<T>()));

  ///////////////////////////////////////////////////////////////

  // https://stackoverflow.com/questions/37602057/why-isnt-a-for-loop-a-compile-time-expression
  namespace compile_time_for_detail {
    template<std::size_t N>
    struct num
    {
      static const constexpr auto value = N;
    };

    template<class F, std::size_t... Is>
    inline void compile_time_for_helper(F func, std::index_sequence<Is...>)
    {
      (func(num<Is>{}), ...);
    }
  } // namespace compile_time_for_detail

  template<std::size_t N, typename F>
  inline void compile_time_for(F func)
  {
    compile_time_for_detail::compile_time_for_helper(
      func, std::make_index_sequence<N>());
  }

  ///////////////////////////////////////////////////////////////

  template<typename T, typename = void>
  struct convert_type_to_nacl_type
  {
    static_assert(std::is_void_v<T>, "Missing specialization");
    using type = void;
  };

  template<typename T>
  struct convert_type_to_nacl_type<
    T,
    std::enable_if_t<(std::is_integral_v<T> || std::is_enum_v<T>)&&sizeof(T) <=
                     sizeof(uint32_t)>>
  {
    using type = uint32_t;
  };

  template<typename T>
  struct convert_type_to_nacl_type<
    T,
    std::enable_if_t<(std::is_integral_v<T> ||
                      std::is_enum_v<T>)&&sizeof(uint32_t) < sizeof(T) &&
                     sizeof(T) <= sizeof(uint64_t)>>
  {
    using type = uint64_t;
  };

  template<typename T>
  struct convert_type_to_nacl_type<T,
                                   std::enable_if_t<std::is_same_v<T, float>>>
  {
    using type = T;
  };

  template<typename T>
  struct convert_type_to_nacl_type<T,
                                   std::enable_if_t<std::is_same_v<T, double>>>
  {
    using type = T;
  };

  template<typename T>
  struct convert_type_to_nacl_type<
    T,
    std::enable_if_t<std::is_pointer_v<T> || std::is_class_v<T>>>
  {
    // pointers are 32 bit indexes in nacl
    // but the modified nacl uses pointer sizes according to the host
    using type = uintptr_t;
  };

  ///////////////////////////////////////////////////////////////

  namespace prepend_arg_type_detail {
    template<typename T, typename T_ArgNew>
    struct helper;

    template<typename T_ArgNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_ArgNew>
    {
      using type = T_Ret(T_ArgNew, T_Args...);
    };
  }

  template<typename T_Func, typename T_ArgNew>
  using prepend_arg_type =
    typename prepend_arg_type_detail::helper<T_Func, T_ArgNew>::type;

  ///////////////////////////////////////////////////////////////

  namespace change_return_type_detail {
    template<typename T, typename T_RetNew>
    struct helper;

    template<typename T_RetNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_RetNew>
    {
      using type = T_RetNew(T_Args...);
    };
  }

  template<typename T_Func, typename T_RetNew>
  using change_return_type =
    typename change_return_type_detail::helper<T_Func, T_RetNew>::type;

  ///////////////////////////////////////////////////////////////

  namespace change_class_arg_types_detail {
    template<typename T, typename T_ArgNew>
    struct helper;

    template<typename T_ArgNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_ArgNew>
    {
      using type =
        T_Ret(std::conditional_t<std::is_class_v<T_Args>, T_ArgNew, T_Args>...);
    };
  }

  template<typename T_Func, typename T_ArgNew>
  using change_class_arg_types =
    typename change_class_arg_types_detail::helper<T_Func, T_ArgNew>::type;

} // namespace nacl_detail

class rlbox_nacl_sandbox;

struct rlbox_nacl_sandbox_thread_data
{
  rlbox_nacl_sandbox* sandbox;
  uint32_t last_callback_invoked;
};

#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES

rlbox_nacl_sandbox_thread_data* get_rlbox_nacl_sandbox_thread_data();
#  define RLBOX_NACL_SANDBOX_STATIC_VARIABLES()                                \
    thread_local rlbox::rlbox_nacl_sandbox_thread_data                         \
      rlbox_nacl_sandbox_thread_info{ 0, 0 };                                  \
    namespace rlbox {                                                          \
      rlbox_nacl_sandbox_thread_data* get_rlbox_nacl_sandbox_thread_data()     \
      {                                                                        \
        return &rlbox_nacl_sandbox_thread_info;                                \
      }                                                                        \
    }                                                                          \
    static_assert(true, "Enforce semi-colon")

#endif

class rlbox_nacl_sandbox
{
public:
  using T_LongLongType = long long;
  using T_LongType = long;
  using T_IntType = int;
  using T_PointerType = uintptr_t;
  using T_ShortType = short;

private:
  std::once_flag nacl_init_flag;
  NaClSandbox* sandbox = nullptr;
  uintptr_t heap_base;
  void* malloc_index = 0;
  void* free_index = 0;
  size_t return_slot_size = 0;
  T_PointerType return_slot = 0;

  static const size_t MAX_CALLBACKS = 8;
  mutable RLBOX_SHARED_LOCK(callback_mutex);
  void* callback_unique_keys[MAX_CALLBACKS]{ 0 };
  void* callbacks[MAX_CALLBACKS]{ 0 };
  uint32_t callback_slot_assignment[MAX_CALLBACKS]{ 0 };
  mutable std::map<const void*, uint32_t> internal_callbacks;
  mutable std::map<uint32_t, const void*> slot_assignments;

#ifndef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
  thread_local static inline rlbox_nacl_sandbox_thread_data thread_data{ 0, 0 };
#endif

  template<typename T_FormalRet, typename T_ActualRet>
  inline auto serialize_to_sandbox(T_ActualRet arg)
  {
    if constexpr (std::is_class_v<T_FormalRet>) {
      // structs returned as pointers into wasm memory/wasm stack
      auto ptr = reinterpret_cast<T_FormalRet*>(
        impl_get_unsandboxed_pointer<T_FormalRet*>(arg));
      T_FormalRet ret = *ptr;
      return ret;
    } else {
      return arg;
    }
  }

  template<uint32_t N, typename T_Ret, typename... T_Args>
  static T_Ret callback_interceptor(
    void* /* vmContext */,
    rlbox_nacl_sandbox* /* curr_sbx */)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_nacl_sandbox_thread_data();
#endif
    thread_data.last_callback_invoked = N;
    using T_Func = T_Ret (*)(T_Args...);
    T_Func func;
    {
      RLBOX_ACQUIRE_SHARED_GUARD(lock, thread_data.sandbox->callback_mutex);
      func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
    }

  	NaClSandbox_Thread* naclThreadData = callbackParamsBegin(thread_data.sandbox->sandbox);
    std::tuple<T_Args...> args { COMPLETELY_UNTRUSTED_CALLBACK_STACK_PARAM(naclThreadData, T_Args)... };
    return std::apply(func, args);
  }

  template<uint32_t N, typename T_Ret, typename... T_Args>
  static void callback_interceptor_promoted(
    void* /* vmContext */,
    rlbox_nacl_sandbox* /* curr_sbx */)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_nacl_sandbox_thread_data();
#endif

    auto ret_val = callback_interceptor<N, T_Ret, T_Args...>(nullptr, nullptr);
    // Copy the return value back
    auto ret_ptr = reinterpret_cast<T_Ret*>(
      thread_data.sandbox->template impl_get_unsandboxed_pointer<T_Ret*>(ret_val));
    *ret_ptr = ret_val;
  }

  template<typename T_Ret, typename... T_Args>
  static inline constexpr unsigned int get_param_count(
    // dummy for template inference
    T_Ret (*)(T_Args...) = nullptr)
  {
    // Class return types as promoted to args
    constexpr bool promoted = std::is_class_v<T_Ret>;
    if constexpr (promoted) {
      return sizeof...(T_Args) + 1;
    } else {
      return sizeof...(T_Args);
    }
  }

  void ensure_return_slot_size(size_t size)
  {
    if (size > return_slot_size) {
      if (return_slot_size) {
        impl_free_in_sandbox(return_slot);
      }
      return_slot = impl_malloc_in_sandbox(size);
      detail::dynamic_check(
        return_slot != 0,
        "Error initializing return slot. Sandbox may be out of memory!");
      return_slot_size = size;
    }
  }

template <typename T>
inline void sandbox_handleNaClArg(NaClSandbox_Thread* naclThreadData, T arg)
{
  if constexpr (std::is_floating_point_v<T>) {
    PUSH_FLOAT_TO_STACK(naclThreadData, T, arg);
  } else {
    PUSH_VAL_TO_STACK(naclThreadData, T, arg);
  }
}

template<typename T_Ret>
inline void sandbox_handleNaClArgs(NaClSandbox_Thread* naclThreadData, T_Ret(*dummy_func_ptr)())
{
  RLBOX_NACL_UNUSED(naclThreadData);
  RLBOX_NACL_UNUSED(dummy_func_ptr);
}

template<typename T_Ret,
  typename T_FormalArg, typename... T_FormalArgs,
  typename T_ActualArg, typename... T_ActualArgs>
inline void sandbox_handleNaClArgs
(
  NaClSandbox_Thread* naclThreadData,
  T_Ret(*dummy_func_ptr)(T_FormalArg, T_FormalArgs...),
  T_ActualArg param, T_ActualArgs... params
)
{
  RLBOX_NACL_UNUSED(dummy_func_ptr);
  T_FormalArg param_conv = param;
  sandbox_handleNaClArg(naclThreadData, param_conv);
  sandbox_handleNaClArgs(naclThreadData, reinterpret_cast<T_Ret(*)(T_FormalArgs...)>(0), params...);
}


protected:
  // Set external_loads_exist to true, if the host application loads the
  // library nacl_module_path outside of rlbox_nacl_sandbox such as via dlopen
  // or the Windows equivalent
  inline void impl_create_sandbox(const char* nacl_module_path, const char* libc_path)
  {
    std::call_once(nacl_init_flag, [](){
      initializeDlSandboxCreator(0 /* no logging */ );
    });

    detail::dynamic_check(sandbox == nullptr, "Sandbox already initialized");
    sandbox = createDlSandbox(libc_path, nacl_module_path);
    detail::dynamic_check(sandbox != nullptr, "Sandbox could not be created");

    heap_base = reinterpret_cast<uintptr_t>(impl_get_memory_location());

    #if defined(__x86_64__)
      // Check that the heap is aligned to the pointer size i.e. 32-bit pointer =>
      // aligned to 4GB. The implementations of
      // impl_get_unsandboxed_pointer_no_ctx and impl_get_sandboxed_pointer_no_ctx
      // below rely on this.
      uintptr_t heap_offset_mask = std::numeric_limits<T_PointerType>::max();
      detail::dynamic_check((heap_base & heap_offset_mask) == 0,
                            "Sandbox heap not aligned to 4GB");
    #endif

    // cache these for performance
    malloc_index = impl_lookup_symbol("malloc");
    free_index = impl_lookup_symbol("free");
  }

  inline void impl_destroy_sandbox()
  {
    if (return_slot_size) {
      impl_free_in_sandbox(return_slot);
    }
    destroyDlSandbox(sandbox);
  }

  template<typename T>
  inline void* impl_get_unsandboxed_pointer(T_PointerType p) const
  {
    return (void*) getUnsandboxedAddress(sandbox, (uintptr_t) p);
  }

  template<typename T>
  inline T_PointerType impl_get_sandboxed_pointer(const void* p) const
  {
    return (T_PointerType) getSandboxedAddress(sandbox, (uintptr_t) p);
  }

  template<typename T>
  static inline void* impl_get_unsandboxed_pointer_no_ctx(
    T_PointerType p,
    const void* example_unsandboxed_ptr,
    rlbox_nacl_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    #if defined(__x86_64__)
      // grab the memory base from the example_unsandboxed_ptr
      uintptr_t heap_base_mask =
        std::numeric_limits<uintptr_t>::max() &
        ~(static_cast<uintptr_t>(std::numeric_limits<T_PointerType>::max()));
      uintptr_t computed_heap_base =
        reinterpret_cast<uintptr_t>(example_unsandboxed_ptr) & heap_base_mask;
      uintptr_t ret = computed_heap_base | p;
      return reinterpret_cast<void*>(ret);
    #else
      auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
      return sandbox->impl_get_unsandboxed_pointer<T>(p);
    #endif
  }

  template<typename T>
  static inline T_PointerType impl_get_sandboxed_pointer_no_ctx(
    const void* p,
    const void* example_unsandboxed_ptr,
    rlbox_nacl_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    #if defined(__x86_64__)
      // Just clear the memory base to leave the offset
      RLBOX_LUCET_UNUSED(example_unsandboxed_ptr);
      uintptr_t ret = reinterpret_cast<uintptr_t>(p) &
                      std::numeric_limits<T_PointerType>::max();
      return static_cast<T_PointerType>(ret);
    #else
      auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
      return sandbox->impl_get_sandboxed_pointer<T>(p);
    #endif
  }

  static inline bool impl_is_in_same_sandbox(
    const void* p1,
    const void* p2,
    rlbox_nacl_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    if (p1 == nullptr || p2 == nullptr) {
      return true;
    }

    // returns the sandbox the pointer belongs to
    // returns null if this belongs to the app
    void* p1_sbx = expensive_sandbox_finder(p1);
    void* p2_sbx = expensive_sandbox_finder(p2);

    return p1_sbx == p2_sbx;
  }

  inline bool impl_is_pointer_in_sandbox_memory(const void* p)
  {
    return isAddressInSandboxMemoryOrNull(sandbox, (uintptr_t) p);
  }

  inline bool impl_is_pointer_in_app_memory(const void* p)
  {
    return isAddressInNonSandboxMemoryOrNull(sandbox, (uintptr_t) p);
  }

  inline size_t impl_get_total_memory() {
    #if defined(__i386__)
      return ((size_t)1) << ((size_t)30);
    #elif defined(__x86_64__)
      return ((size_t)1) << ((size_t)32);
    #else
      #error Unsupported architecture
    #endif
  }

  inline void* impl_get_memory_location()
  {
    return (void*) getSandboxMemoryBase(sandbox);
  }

  void* impl_lookup_symbol(const char* func_name)
  {
    return symbolTableLookupInSandbox(sandbox, func_name);
  }

  template<typename T, typename T_Converted, typename... T_Args>
  auto impl_invoke_with_func_ptr(T_Converted* func_ptr, T_Args&&... params)
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_nacl_sandbox_thread_data();
#endif
    thread_data.sandbox = this;

    //  Returned class are returned as an out parameter before the actual
    // function parameters. Handle this.
    using T_Ret = nacl_detail::return_argument<T_Converted>;
    if constexpr (std::is_class_v<T_Ret>) {
      using T_Conv1 = nacl_detail::change_return_type<T_Converted, void>;
      using T_Conv2 = nacl_detail::prepend_arg_type<T_Conv1, T_PointerType>;
      auto func_ptr_conv =
        reinterpret_cast<T_Conv2*>(reinterpret_cast<uintptr_t>(func_ptr));
      ensure_return_slot_size(sizeof(T_Ret));
      impl_invoke_with_func_ptr<T>(func_ptr_conv, return_slot, params...);

      auto ptr = reinterpret_cast<T_Ret*>(
        impl_get_unsandboxed_pointer<T_Ret*>(return_slot));
      T_Ret ret = *ptr;
      return ret;
    } else {
      constexpr auto max_param_size = (sizeof(params) + ... + 0);
      NaClSandbox_Thread* naclThreadData = preFunctionCall(sandbox, max_param_size, 0 /* stack array size */);
      sandbox_handleNaClArgs(naclThreadData, func_ptr, params...);
      invokeFunctionCall(naclThreadData, (void*) func_ptr);

      if constexpr (std::is_floating_point_v<T_Ret>) {
        return (T_Ret) functionCallReturnDouble(naclThreadData);
      } else if constexpr (!std::is_same_v<T_Ret, void>) {
        return (T_Ret) functionCallReturnRawPrimitiveInt(naclThreadData);
      }
    }
  }

  inline T_PointerType impl_malloc_in_sandbox(size_t size)
  {
    detail::dynamic_check(size <= std::numeric_limits<uint32_t>::max(),
                          "Attempting to malloc more than the heap size");
    using T_Func = void*(size_t);
    using T_Converted = T_PointerType(uint32_t);
    T_PointerType ret = impl_invoke_with_func_ptr<T_Func, T_Converted>(
      reinterpret_cast<T_Converted*>(malloc_index),
      static_cast<uint32_t>(size));
    return ret;
  }

  inline void impl_free_in_sandbox(T_PointerType p)
  {
    using T_Func = void(void*);
    using T_Converted = void(T_PointerType);
    impl_invoke_with_func_ptr<T_Func, T_Converted>(
      reinterpret_cast<T_Converted*>(free_index), p);
  }

  template<typename T_Ret, typename... T_Args>
  inline T_PointerType impl_register_callback(void* key, void* callback)
  {
    bool found = false;
    uint32_t found_loc = 0;
    void* chosen_interceptor = nullptr;

    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);

    // need a compile time for loop as we we need I to be a compile time value
    // this is because we are setting the I'th callback ineterceptor
    nacl_detail::compile_time_for<MAX_CALLBACKS>([&](auto I) {
      constexpr auto i = I.value;
      if (!found && callbacks[i] == nullptr) {
        found = true;
        found_loc = i;

        if constexpr (std::is_class_v<T_Ret>) {
          chosen_interceptor = reinterpret_cast<void*>(
            callback_interceptor_promoted<i, T_Ret, T_Args...>);
        } else {
          chosen_interceptor =
            reinterpret_cast<void*>(callback_interceptor<i, T_Ret, T_Args...>);
        }
      }
    });

    detail::dynamic_check(
      found,
      "Could not find an empty slot in sandbox function table. This would "
      "happen if you have registered too many callbacks, or unsandboxed "
      "too many function pointers. You can file a bug if you want to "
      "increase the maximum allowed callbacks or unsadnboxed functions "
      "pointers");

    uintptr_t result =
      registerSandboxCallbackWithState(sandbox, found_loc, (uintptr_t) chosen_interceptor, this);

    callback_unique_keys[found_loc] = key;
    callbacks[found_loc] = callback;
    callback_slot_assignment[found_loc] = result;
    slot_assignments[result] = callback;

    return static_cast<T_PointerType>(result);
  }

  static inline std::pair<rlbox_nacl_sandbox*, void*>
  impl_get_executed_callback_sandbox_and_key()
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_nacl_sandbox_thread_data();
#endif
    auto sandbox = thread_data.sandbox;
    auto callback_num = thread_data.last_callback_invoked;
    void* key = sandbox->callback_unique_keys[callback_num];
    return std::make_pair(sandbox, key);
  }

  template<typename T_Ret, typename... T_Args>
  inline void impl_unregister_callback(void* key)
  {
    bool found = false;
    uint32_t i = 0;
    {
      RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
      for (; i < MAX_CALLBACKS; i++) {
        if (callback_unique_keys[i] == key) {
          unregisterSandboxCallback(sandbox, i);
          callback_unique_keys[i] = nullptr;
          callbacks[i] = nullptr;
          callback_slot_assignment[i] = 0;
          found = true;
          break;
        }
      }
    }

    detail::dynamic_check(
      found, "Internal error: Could not find callback to unregister");

    return;
  }
};

} // namespace rlbox