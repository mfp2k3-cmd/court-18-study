cmake_minimum_required(VERSION 3.20)
project(nba18_port VERSION 0.1.0 LANGUAGES CXX ASM)

option(NBA16_BUILD_SHADPS4_RUNTIME
    "Build the pinned GPL shadPS4 runtime from third_party/shadPS4" OFF)
option(NBA16_BUILD_SHADPS4_CORE
    "Also build reusable shadPS4 core components for in-process NBA integration" OFF)
set(NBA16_SHADPS4_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/shadPS4-prerelease-3eecea9" CACHE PATH
    "Source tree for the pinned shadPS4 core")
set(NBA16_SHADPS4_CORE_PATCH "${CMAKE_CURRENT_SOURCE_DIR}/patches/shadps4/nba16-reusable-core-prerelease.patch" CACHE FILEPATH
    "Local runtime integration patch used by the NBA LIVE 18 migration base")
set(NBA16_PROTOC_EXECUTABLE "" CACHE FILEPATH
    "Optional prebuilt protoc executable to avoid building libprotoc")

set(ZLIB_USE_STATIC_LIBS TRUE)
find_package(ZLIB REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL3 REQUIRED sdl3)
pkg_check_modules(VULKAN REQUIRED vulkan)

set(NBA16_GRAPHICS_PKG_CFLAGS ${SDL3_CFLAGS} ${VULKAN_CFLAGS})
set(NBA16_GRAPHICS_PKG_LDFLAGS ${SDL3_LDFLAGS} ${VULKAN_LDFLAGS})
# pkg-config for SDL3 on MinGW adds -mwindows globally. These binaries are
# diagnostic/console tools, so do not hide their logs behind a GUI subsystem.
list(REMOVE_ITEM NBA16_GRAPHICS_PKG_LDFLAGS -mwindows)

add_library(nba16-graphics-host STATIC
    src/vulkan_presenter.cpp
    src/native_window_host.cpp
)
target_include_directories(nba16-graphics-host PUBLIC src)
target_compile_options(nba16-graphics-host PRIVATE ${NBA16_GRAPHICS_PKG_CFLAGS})
target_link_options(nba16-graphics-host PUBLIC ${NBA16_GRAPHICS_PKG_LDFLAGS})
target_link_libraries(nba16-graphics-host PUBLIC ${SDL3_LIBRARIES} ${VULKAN_LIBRARIES})
target_compile_features(nba16-graphics-host PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(nba16-graphics-host PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-graphics-host PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

# Native Windows host shell. It exercises the application/window lifecycle
# independently from the diagnostic inspector and does not start the game.
add_executable(nba16-native-shell
    src/native_shell_main.cpp
)
target_link_libraries(nba16-native-shell PRIVATE nba16-graphics-host)
target_compile_features(nba16-native-shell PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(nba16-native-shell PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-native-shell PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_executable(nba16-inspect
    src/main.cpp
    src/elf64_inspector.cpp
    src/self_program_image.cpp
    src/guest_image_map.cpp
    src/guest_image_memory.cpp
    src/guest_execution_stack.cpp
    src/ps4_dynamic_link.cpp
    src/import_resolver.cpp
    src/module_exports.cpp
    src/ps4_module_loader.cpp
    src/ps4_module_set.cpp
    src/fiber_runtime.cpp
    src/libc_runtime.cpp
    src/guest_libc_allocator.cpp
    src/kernel_runtime.cpp
    src/guest_process_context.cpp
    src/aio_runtime.cpp
    src/posix_aio_imports.cpp
    src/posix_fs_imports.cpp
    src/sanitizer_fiber_imports.cpp
    src/unsupported_posix_imports.cpp
    src/guest_tls_runtime.cpp
    src/guest_tcb_runtime.cpp
    src/guest_fiber_switch.S
    src/guest_call_stack.S
    src/syscall_return_flags.S
)
target_include_directories(nba16-inspect PRIVATE src)
target_compile_features(nba16-inspect PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(nba16-inspect PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-inspect PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_executable(nba16-big-inspect
    src/big_inventory.cpp
)
target_compile_features(nba16-big-inspect PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(nba16-big-inspect PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-big-inspect PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_library(nba16-big-reader STATIC
    src/big_archive.cpp
)
target_include_directories(nba16-big-reader PUBLIC src)
target_link_libraries(nba16-big-reader PUBLIC ${ZLIB_LIBRARY})
if(MSVC)
    target_include_directories(nba16-big-reader SYSTEM PRIVATE ${ZLIB_INCLUDE_DIRS})
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(nba16-big-reader PRIVATE -idirafter ${ZLIB_INCLUDE_DIRS})
else()
    target_include_directories(nba16-big-reader SYSTEM PRIVATE ${ZLIB_INCLUDE_DIRS})
endif()
target_compile_features(nba16-big-reader PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(nba16-big-reader PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-big-reader PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_executable(nba16-big-read
    src/big_member_cli.cpp
)
target_link_libraries(nba16-big-read PRIVATE nba16-big-reader)
target_compile_features(nba16-big-read PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(nba16-big-read PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-big-read PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_library(nba16-vfs STATIC
    src/vfs.cpp
)
target_include_directories(nba16-vfs PUBLIC src)
target_link_libraries(nba16-vfs PUBLIC nba16-big-reader)
target_compile_features(nba16-vfs PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(nba16-vfs PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-vfs PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_library(nba16-guest-syscalls STATIC
    src/guest_syscalls.cpp
)
target_include_directories(nba16-guest-syscalls PUBLIC src)
target_link_libraries(nba16-guest-syscalls PUBLIC nba16-vfs)
target_compile_features(nba16-guest-syscalls PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(nba16-guest-syscalls PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-guest-syscalls PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()
target_link_libraries(nba16-inspect PRIVATE nba16-guest-syscalls)

# The shadPS4 upstream source is kept as a pinned GPL submodule. For the
# independent NBA host, an optional local patch exposes its runtime as a static
# core and links it into the NBA-named executable in the same process.
if(NBA16_BUILD_SHADPS4_RUNTIME)
    include(ExternalProject)
    add_custom_target(nba16-prepare-shadps4
        COMMAND powershell -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_CURRENT_SOURCE_DIR}/apply-shadps4-local-patches.ps1"
            -ShadPS4Root "${NBA16_SHADPS4_SOURCE_DIR}"
            -CorePatch "${NBA16_SHADPS4_CORE_PATCH}"
        COMMENT "Applying pinned local patches to shadPS4"
        VERBATIM)
    if(CMAKE_C_COMPILER)
        set(NBA16_SHADPS4_C_COMPILER "${CMAKE_C_COMPILER}")
    else()
        find_program(NBA16_SHADPS4_C_COMPILER NAMES clang clang.exe REQUIRED)
    endif()
    # LibreSSL's endian compatibility helpers are hidden by strict feature
    # macros in the MinGW/Clang headers unless the default API set is enabled.
    if(MSVC)
        set(NBA16_SHADPS4_C_FLAGS "/D_DEFAULT_SOURCE")
    else()
        set(NBA16_SHADPS4_C_FLAGS "-D_DEFAULT_SOURCE")
    endif()

    set(NBA16_SHADPS4_TARGETS)
    set(NBA16_SHADPS4_BYPRODUCTS)
    if(NBA16_BUILD_SHADPS4_CORE)
        list(APPEND NBA16_SHADPS4_TARGETS nba16-shadps4-core)
        if(WIN32)
            list(APPEND NBA16_SHADPS4_TARGETS nba16-port)
            list(APPEND NBA16_SHADPS4_BYPRODUCTS
                "${CMAKE_BINARY_DIR}/shadPS4-runtime/NBA LIVE 18.exe")
        endif()
        list(APPEND NBA16_SHADPS4_BYPRODUCTS
            "${CMAKE_BINARY_DIR}/shadPS4-runtime/libnba16-shadps4-core.a")
    else()
        list(APPEND NBA16_SHADPS4_TARGETS shadps4)
        list(APPEND NBA16_SHADPS4_BYPRODUCTS
            "${CMAKE_BINARY_DIR}/shadPS4-runtime/shadps4.exe")
    endif()

    ExternalProject_Add(nba16-shadps4-runtime
        DEPENDS nba16-prepare-shadps4
        SOURCE_DIR "${NBA16_SHADPS4_SOURCE_DIR}"
        BINARY_DIR "${CMAKE_BINARY_DIR}/shadPS4-runtime"
        CMAKE_GENERATOR "${CMAKE_GENERATOR}"
        CMAKE_ARGS
            "-DCMAKE_BUILD_TYPE=Release"
            "-DCMAKE_C_COMPILER=${NBA16_SHADPS4_C_COMPILER}"
            "-DCMAKE_C_FLAGS=${NBA16_SHADPS4_C_FLAGS}"
            "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
            "-DCMAKE_ASM_COMPILER=${CMAKE_ASM_COMPILER}"
            "-DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
            "-DCMAKE_PROJECT_shadPS4_INCLUDE=${CMAKE_CURRENT_SOURCE_DIR}/cmake/shadps4_find_openssl.cmake"
            "-DENABLE_DISCORD_RPC=OFF"
            "-DENABLE_UPDATER=OFF"
            "-DENABLE_TESTS=OFF"
            "-DENABLE_SYSTEM_LIBRARIES=OFF"
            "-DNBA16_BUILD_REUSABLE_CORE=${NBA16_BUILD_SHADPS4_CORE}"
            "-DNBA16_HOST_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DNBA16_PROTOC_EXECUTABLE=${NBA16_PROTOC_EXECUTABLE}"
        BUILD_COMMAND
            "${CMAKE_COMMAND}" --build <BINARY_DIR> --target ${NBA16_SHADPS4_TARGETS} --config Release
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS ${NBA16_SHADPS4_BYPRODUCTS}
        USES_TERMINAL_CONFIGURE TRUE
        USES_TERMINAL_BUILD TRUE
    )

    add_custom_target(nba16-build-shadps4 DEPENDS nba16-shadps4-runtime)

    if(WIN32 AND NBA16_BUILD_SHADPS4_CORE)
        add_executable(nba16-launcher WIN32 src/nba16_launcher.cpp)
        target_compile_features(nba16-launcher PRIVATE cxx_std_20)
        target_link_libraries(nba16-launcher PRIVATE comctl32 gdiplus ole32 shell32 uuid)
        set_target_properties(nba16-launcher PROPERTIES
            OUTPUT_NAME "COURT 18 Launcher"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/shadPS4-runtime"
        )
        add_dependencies(nba16-launcher nba16-shadps4-runtime)
        add_custom_command(TARGET nba16-launcher POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:nba16-launcher>/assets"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/assets/nba-live16-background-wide.png"
                "$<TARGET_FILE_DIR:nba16-launcher>/assets/nba-live16-background-wide.png"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/assets/nba-live16-background-arena.png"
                "$<TARGET_FILE_DIR:nba16-launcher>/assets/nba-live16-background-arena.png"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/assets/nba-live16-background-with-ball.jpg"
                "$<TARGET_FILE_DIR:nba16-launcher>/assets/nba-live16-background-with-ball.jpg"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/assets/nba-live16-background.jpg"
                "$<TARGET_FILE_DIR:nba16-launcher>/assets/nba-live16-background.jpg"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/assets/court18-play-ball.png"
                "$<TARGET_FILE_DIR:nba16-launcher>/assets/court18-play-ball.png"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/assets/nba-live16-button-leather.png"
                "$<TARGET_FILE_DIR:nba16-launcher>/assets/nba-live16-button-leather.png"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/assets/court18.ico"
                "$<TARGET_FILE_DIR:nba16-launcher>/assets/court18.ico"
            VERBATIM
        )
    endif()
endif()

add_executable(nba16-module-inspect
    src/module_inspect.cpp
    src/module_exports.cpp
    src/ps4_module_loader.cpp
    src/ps4_module_set.cpp
    src/import_resolver.cpp
    src/guest_image_map.cpp
    src/guest_image_memory.cpp
    src/guest_tcb_runtime.cpp
    src/ps4_dynamic_link.cpp
    src/self_program_image.cpp
    src/elf64_inspector.cpp
)
target_include_directories(nba16-module-inspect PRIVATE src)
target_link_libraries(nba16-module-inspect PRIVATE nba16-big-reader)
target_compile_features(nba16-module-inspect PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(nba16-module-inspect PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-module-inspect PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_executable(nba16-module-set-inspect
    src/module_set_inspect.cpp
    src/netctl_runtime.cpp
    src/graphics_call_trace.cpp
    src/gnm_import_traps.cpp
    src/gnm_hardware_init.cpp
    src/gnm_submission_runtime.cpp
    src/elf64_inspector.cpp
    src/self_program_image.cpp
    src/guest_image_map.cpp
    src/guest_image_memory.cpp
    src/guest_execution_stack.cpp
    src/ps4_dynamic_link.cpp
    src/import_resolver.cpp
    src/module_exports.cpp
    src/ps4_module_loader.cpp
    src/ps4_module_set.cpp
    src/fiber_runtime.cpp
    src/libc_runtime.cpp
    src/guest_libc_allocator.cpp
    src/kernel_runtime.cpp
    src/app_content_runtime.cpp
    src/playgo_runtime.cpp
    src/user_service_runtime.cpp
    src/pad_runtime.cpp
    src/video_out_runtime.cpp
    src/native_runtime_paths.cpp
    src/native_runtime_services.cpp
    src/native_process_image.cpp
    src/native_guest_process.cpp
    src/sysmodule_runtime.cpp
    src/guest_process_context.cpp
    src/aio_runtime.cpp
    src/posix_aio_imports.cpp
    src/posix_fs_imports.cpp
    src/sanitizer_fiber_imports.cpp
    src/unsupported_posix_imports.cpp
    src/guest_tls_runtime.cpp
    src/guest_tcb_runtime.cpp
    src/guest_fiber_switch.S
    src/guest_call_stack.S
    src/syscall_return_flags.S
)
target_include_directories(nba16-module-set-inspect PRIVATE src)
target_compile_definitions(nba16-module-set-inspect PRIVATE NBA16_ENABLE_FS_EOF_INSTRUCTION_TRACE=1)
target_link_libraries(nba16-module-set-inspect PRIVATE nba16-guest-syscalls nba16-vfs
    nba16-graphics-host)
target_compile_features(nba16-module-set-inspect PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(nba16-module-set-inspect PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-module-set-inspect PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_executable(nba16-nid-match
    src/nid_name_cli.cpp
)
target_compile_features(nba16-nid-match PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(nba16-nid-match PRIVATE /W4 /permissive-)
else()
    target_compile_options(nba16-nid-match PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()
