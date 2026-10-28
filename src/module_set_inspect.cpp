#include "fiber_runtime.h"
#include "guest_tls_runtime.h"
#include "guest_tcb_runtime.h"
#include "guest_call_bridge.h"
#include "kernel_runtime.h"
#include "libc_runtime.h"
#include "ps4_dynamic_link.h"
#include "ps4_module_set.h"
#include "guest_image_memory.h"
#include "guest_execution_stack.h"
#include "guest_libc_allocator.h"
#include "guest_process_context.h"
#include "graphics_call_trace.h"
#include "gnm_import_traps.h"
#include "video_out_runtime.h"
#include "native_runtime_paths.h"
#include "native_runtime_services.h"
#include "native_process_image.h"
#include "native_guest_process.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <iomanip>
#include <limits>
#include <set>
#include <string_view>
#include <vector>
#include <cstdio>
#include <cstdarg>
#include <atomic>
#include <chrono>
#include <thread>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#endif

#ifdef _WIN32
namespace {
void write_atomic_diagnostic(const char* format, ...) {
    std::array<char, 768> line{};
    va_list args;
    va_start(args, format);
    const int count = std::vsnprintf(line.data(), line.size(), format, args);
    va_end(args);
    if (count <= 0) return;
    const auto length = static_cast<DWORD>(std::min<int>(count,
        static_cast<int>(line.size() - 1)));
    DWORD written{};
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), line.data(), length, &written, nullptr);
}

struct GuestEntryParams {
    std::int32_t argc{};
    std::uint32_t padding{};
    const char* argv[33]{};
    std::uint64_t entry_address{};
};

#ifdef _WIN32
void NBA16_GUEST_SYSV_ABI guest_entrypoint_exit_probe() {
    std::fputs("Guest entry point chamou a função de saída do probe.\n", stderr);
    nba16::nba16_guest_return_to_caller_fiber();
}

void NBA16_GUEST_SYSV_ABI guest_process_exit_probe(int status) {
    std::fprintf(stderr, "Guest chamou _exit(%d), caller=0x%llx\n", status,
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(
            __builtin_return_address(0))));
    auto frame = reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0));
    for (unsigned index = 0; index < 6 && frame != 0; ++index) {
        std::array<std::uintptr_t, 2> pair{};
        SIZE_T copied{};
        if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(frame),
                pair.data(), sizeof(pair), &copied) == 0 || copied != sizeof(pair)) break;
        std::fprintf(stderr, "Guest _exit frame[%u]=0x%llx return=0x%llx\n", index,
            static_cast<unsigned long long>(frame),
            static_cast<unsigned long long>(pair[1]));
        frame = pair[0];
    }
    const auto stack_base = reinterpret_cast<std::uintptr_t>(__builtin_frame_address(0));
    std::array<std::uintptr_t, 40> stack_words{};
    SIZE_T stack_bytes{};
    if (ReadProcessMemory(GetCurrentProcess(),
            reinterpret_cast<const void*>(stack_base - 0x40), stack_words.data(),
            sizeof(stack_words), &stack_bytes) != 0) {
        for (std::size_t index = 0; index < stack_bytes / sizeof(std::uintptr_t); ++index) {
            const auto value = stack_words[index];
            if (value > 0x100000000ULL)
                std::fprintf(stderr, "Guest _exit stack[%zu]=0x%llx\n", index,
                    static_cast<unsigned long long>(value));
        }
    }
    nba16::nba16_guest_return_to_caller_fiber();
}
#endif

struct ProbeRegion {
    std::string name;
    std::uint64_t load_bias{};
    std::uint64_t begin{};
    std::uint64_t end{};
    std::uint32_t flags{};
};
std::vector<ProbeRegion> probe_regions;
std::uintptr_t diagnostic_fopen_target{};
std::uintptr_t diagnostic_fread_target{};
std::uintptr_t diagnostic_fclose_target{};

void find_rip_relative_references(const nba16::GuestImageMap& map,
        const nba16::GuestImageMemory& memory, std::uint64_t target_rva,
        std::string_view image_name) {
    std::vector<std::uint64_t> references;
    std::string error;
    for (const auto& region : map.regions) {
        if ((region.flags & 1U) == 0 || region.memory_size < 8) continue;
        const auto* bytes = static_cast<const std::byte*>(memory.translate(
            map, memory.load_bias() + region.virtual_address,
            static_cast<std::size_t>(region.memory_size), false, error));
        if (bytes == nullptr) {
            std::cerr << "Não foi possível varrer o segmento executável em 0x"
                      << std::hex << region.virtual_address << std::dec << ": "
                      << error << '\n';
            error.clear();
            continue;
        }
        const auto size = static_cast<std::size_t>(region.memory_size);
        for (std::size_t start = 0; start + 8 <= size; ++start) {
            std::size_t opcode = start;
            bool operand16 = false;
            for (unsigned prefix_count = 0; prefix_count < 4 && opcode < size; ++prefix_count) {
                const auto value = std::to_integer<std::uint8_t>(bytes[opcode]);
                if ((value >= 0x40 && value <= 0x4f) || value == 0xf2 || value == 0xf3) {
                    ++opcode;
                    continue;
                }
                if (value == 0x66) {
                    operand16 = true;
                    ++opcode;
                    continue;
                }
                break;
            }
            if (opcode >= size) continue;
            const auto first_opcode = std::to_integer<std::uint8_t>(bytes[opcode]);
            const auto modrm_index = opcode + (first_opcode == 0x0f ? 2U : 1U);
            if (modrm_index + 5 > size) continue;
            if (first_opcode == 0x0f && modrm_index == opcode + 2 &&
                std::to_integer<std::uint8_t>(bytes[opcode + 1]) == 0x38) continue;
            const auto modrm = std::to_integer<std::uint8_t>(bytes[modrm_index]);
            if ((modrm & 0xc7U) != 0x05U) continue;
            std::size_t immediate_size = 0;
            if (first_opcode == 0xc6 || first_opcode == 0x80 || first_opcode == 0x82 ||
                first_opcode == 0x83) immediate_size = 1;
            else if (first_opcode == 0xc7 || first_opcode == 0x81)
                immediate_size = operand16 ? 2 : 4;
            else if (first_opcode == 0x0f &&
                std::to_integer<std::uint8_t>(bytes[opcode + 1]) == 0xba)
                immediate_size = 1;
            const auto displacement_index = modrm_index + 1;
            const auto instruction_end = displacement_index + 4 + immediate_size;
            if (instruction_end > size) continue;
            std::int32_t displacement{};
            std::memcpy(&displacement, bytes + displacement_index, sizeof(displacement));
            const auto next_rva = region.virtual_address + instruction_end;
            const auto resolved = static_cast<std::int64_t>(next_rva) + displacement;
            if (resolved >= 0 && static_cast<std::uint64_t>(resolved) == target_rva)
                references.push_back(region.virtual_address + start);
        }
    }
    std::sort(references.begin(), references.end());
    references.erase(std::unique(references.begin(), references.end()), references.end());
    std::cout << "Referências RIP-relativas candidatas para " << image_name << "+0x" << std::hex
              << target_rva << std::dec << ": " << references.size() << '\n';
    for (const auto address : references)
        std::cout << "  " << image_name << "+0x" << std::hex << address << std::dec << '\n';
}

void find_relative_call_references(const nba16::GuestImageMap& map,
        const nba16::GuestImageMemory& memory, std::uint64_t target_rva) {
    std::vector<std::uint64_t> references;
    std::string error;
    for (const auto& region : map.regions) {
        if ((region.flags & 1U) == 0 || region.memory_size < 5) continue;
        const auto* bytes = static_cast<const std::byte*>(memory.translate(
            map, memory.load_bias() + region.virtual_address,
            static_cast<std::size_t>(region.memory_size), false, error));
        if (bytes == nullptr) {
            error.clear();
            continue;
        }
        const auto size = static_cast<std::size_t>(region.memory_size);
        for (std::size_t offset = 0; offset + 5 <= size; ++offset) {
            if (std::to_integer<std::uint8_t>(bytes[offset]) != 0xe8) continue;
            std::int32_t displacement{};
            std::memcpy(&displacement, bytes + offset + 1, sizeof(displacement));
            const auto next_rva = region.virtual_address + offset + 5;
            const auto resolved = static_cast<std::int64_t>(next_rva) + displacement;
            if (resolved >= 0 && static_cast<std::uint64_t>(resolved) == target_rva)
                references.push_back(region.virtual_address + offset);
        }
    }
    std::sort(references.begin(), references.end());
    references.erase(std::unique(references.begin(), references.end()), references.end());
    std::cout << "Referências CALL rel32 candidatas para eboot+0x" << std::hex
              << target_rva << std::dec << ": " << references.size() << '\n';
    for (const auto address : references)
        std::cout << "  eboot+0x" << std::hex << address << std::dec << '\n';
}

void find_relative_branch_references(const nba16::GuestImageMap& map,
        const nba16::GuestImageMemory& memory, std::uint64_t target_rva,
        std::string_view image_name = "eboot") {
    std::vector<std::uint64_t> references;
    std::string error;
    for (const auto& region : map.regions) {
        if ((region.flags & 1U) == 0 || region.memory_size < 2) continue;
        const auto* bytes = static_cast<const std::uint8_t*>(memory.translate(
            map, memory.load_bias() + region.virtual_address,
            static_cast<std::size_t>(region.memory_size), false, error));
        if (bytes == nullptr) { error.clear(); continue; }
        const auto size = static_cast<std::size_t>(region.memory_size);
        for (std::size_t offset = 0; offset + 2 <= size; ++offset) {
            const auto opcode = bytes[offset];
            std::size_t instruction_size{};
            std::int64_t displacement{};
            if (opcode == 0xe9 || opcode == 0xe8) {
                if (offset + 5 > size) continue;
                std::int32_t relative{};
                std::memcpy(&relative, bytes + offset + 1, sizeof(relative));
                instruction_size = 5;
                displacement = relative;
            } else if (opcode == 0x0f && offset + 6 <= size &&
                       bytes[offset + 1] >= 0x80 && bytes[offset + 1] <= 0x8f) {
                std::int32_t relative{};
                std::memcpy(&relative, bytes + offset + 2, sizeof(relative));
                instruction_size = 6;
                displacement = relative;
            } else if (opcode == 0xeb || (opcode >= 0x70 && opcode <= 0x7f)) {
                instruction_size = 2;
                displacement = static_cast<std::int8_t>(bytes[offset + 1]);
            } else {
                continue;
            }
            const auto next_rva = region.virtual_address + offset + instruction_size;
            const auto resolved = static_cast<std::int64_t>(next_rva) + displacement;
            if (resolved >= 0 && static_cast<std::uint64_t>(resolved) == target_rva)
                references.push_back(region.virtual_address + offset);
        }
    }
    std::sort(references.begin(), references.end());
    references.erase(std::unique(references.begin(), references.end()), references.end());
    std::cout << "Candidatos de salto relativo para " << image_name << "+0x" << std::hex
              << target_rva << std::dec << ": " << references.size() << '\n';
    for (const auto address : references)
        std::cout << "  " << image_name << "+0x" << std::hex << address << std::dec << '\n';
}

void find_member_field_write_candidates(const nba16::GuestImageMap& map,
        const nba16::GuestImageMemory& memory, std::uint8_t member_offset) {
    struct Candidate { std::uint64_t rva; std::uint8_t base; std::uint8_t opcode; };
    std::vector<Candidate> candidates;
    std::string error;
    for (const auto& region : map.regions) {
        if ((region.flags & 1U) == 0 || region.memory_size < 8) continue;
        const auto* bytes = static_cast<const std::uint8_t*>(memory.translate(
            map, memory.load_bias() + region.virtual_address,
            static_cast<std::size_t>(region.memory_size), false, error));
        if (bytes == nullptr) { error.clear(); continue; }
        const auto size = static_cast<std::size_t>(region.memory_size);
        for (std::size_t start = 0; start + 4 < size; ++start) {
            auto opcode_index = start;
            while (opcode_index < size && opcode_index - start < 4) {
                const auto prefix = bytes[opcode_index];
                if (prefix == 0xf0 || prefix == 0xf2 || prefix == 0xf3 ||
                    prefix == 0x66 || (prefix >= 0x40 && prefix <= 0x4f)) {
                    ++opcode_index;
                    continue;
                }
                break;
            }
            if (opcode_index >= size) continue;
            std::uint8_t rex = 0;
            for (auto index = start; index < opcode_index; ++index)
                if (bytes[index] >= 0x40 && bytes[index] <= 0x4f) rex = bytes[index];
            const auto opcode = bytes[opcode_index++];
            std::uint8_t second_opcode = 0;
            bool has_modrm = false;
            bool writes_memory = false;
            if (opcode == 0x88 || opcode == 0x89 || opcode == 0x86 || opcode == 0x87) {
                has_modrm = true; writes_memory = true;
            } else if (opcode == 0xc6 || opcode == 0xc7) {
                has_modrm = true; writes_memory = true;
            } else if (opcode == 0x0f && opcode_index < size) {
                second_opcode = bytes[opcode_index++];
                has_modrm = second_opcode == 0xb0 || second_opcode == 0xb1 ||
                    second_opcode == 0xc0 || second_opcode == 0xc1 ||
                    second_opcode == 0xab || second_opcode == 0xb3 ||
                    second_opcode == 0xbb || second_opcode == 0xba;
                writes_memory = has_modrm;
            }
            if (!has_modrm || !writes_memory || opcode_index >= size) continue;
            const auto modrm = bytes[opcode_index++];
            const auto mod = static_cast<std::uint8_t>(modrm >> 6U);
            const auto rm = static_cast<std::uint8_t>(modrm & 7U);
            if (mod == 0 || mod == 3) continue;
            std::uint8_t base = static_cast<std::uint8_t>(rm | ((rex & 1U) ? 8U : 0U));
            if (rm == 4) {
                if (opcode_index >= size) continue;
                const auto sib = bytes[opcode_index++];
                const auto sib_base = static_cast<std::uint8_t>(sib & 7U);
                if (mod == 0 && sib_base == 5) continue;
                base = static_cast<std::uint8_t>(sib_base | ((rex & 1U) ? 8U : 0U));
            }
            std::int64_t displacement{};
            if (mod == 1) {
                if (opcode_index >= size) continue;
                displacement = static_cast<std::int8_t>(bytes[opcode_index]);
            } else {
                if (opcode_index + 4 > size) continue;
                std::int32_t value{};
                std::memcpy(&value, bytes + opcode_index, sizeof(value));
                displacement = value;
            }
            if (displacement != member_offset) continue;
            if (opcode == 0xc6 || opcode == 0xc7) {
                const auto operation = static_cast<std::uint8_t>((modrm >> 3U) & 7U);
                if (operation != 0) continue;
            }
            if (opcode == 0x0f && second_opcode == 0xba) {
                const auto operation = static_cast<std::uint8_t>((modrm >> 3U) & 7U);
                if (operation < 5) continue;
            }
            candidates.push_back({region.virtual_address + start, base, opcode});
        }
    }
    std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
        return left.rva < right.rva;
    });
    candidates.erase(std::unique(candidates.begin(), candidates.end(),
        [](const auto& left, const auto& right) { return left.rva == right.rva; }),
        candidates.end());
    std::cout << "Candidatos de escrita/atualização em [reg+0x" << std::hex
              << static_cast<unsigned>(member_offset) << std::dec << "]: "
              << candidates.size() << '\n';
    for (const auto& candidate : candidates) {
        static constexpr std::array<const char*, 16> registers{
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
        std::cout << "  eboot+0x" << std::hex << candidate.rva << std::dec
                  << " base=%" << registers[candidate.base]
                  << " opcode=0x" << std::hex << static_cast<unsigned>(candidate.opcode)
                  << std::dec << '\n';
    }
}
std::uintptr_t diagnostic_fios_open_target{};
std::uintptr_t diagnostic_fios_close_target{};

#ifdef _WIN32
std::atomic<bool> active_rip_sampler_stop{};
std::atomic<std::uintptr_t> active_scheduler_state_address{};
std::atomic<bool> scheduler_state_watchpoint_hit{};
std::atomic<std::uint32_t> scheduler_state_write_count{};

std::string host_module_path(HMODULE module) {
    std::array<wchar_t, 1024> wide_path{};
    const auto length = GetModuleFileNameW(module, wide_path.data(),
        static_cast<DWORD>(wide_path.size()));
    if (length == 0 || length >= wide_path.size()) return "<module-path-unavailable>";
    const auto bytes = WideCharToMultiByte(CP_UTF8, 0, wide_path.data(),
        static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return "<module-path-conversion-failed>";
    std::string path(static_cast<std::size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide_path.data(), static_cast<int>(length),
        path.data(), bytes, nullptr, nullptr);
    return path;
}

void sample_active_guest_rips(DWORD target_thread_id) {
    const auto thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
        THREAD_QUERY_INFORMATION, FALSE, target_thread_id);
    if (thread == nullptr) {
        std::fprintf(stderr, "ACTIVE-GUEST-RIP: OpenThread failed error=%lu\n",
                     static_cast<unsigned long>(GetLastError()));
        return;
    }
    std::uint32_t samples = 0;
    std::uint32_t guest_samples = 0;
    std::uintptr_t last_guest_rip = 0;
    bool host_stack_dumped = false;
    std::fputs("ACTIVE-GUEST-RIP sampling process-entry thread.\n", stderr);
    while (!active_rip_sampler_stop.load(std::memory_order_acquire) && samples < 2000) {
        const auto suspended = SuspendThread(thread);
        if (suspended != static_cast<DWORD>(-1)) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (GetThreadContext(thread, &context)) {
                ++samples;
                const auto rip = static_cast<std::uintptr_t>(context.Rip);
                const auto owner = std::find_if(probe_regions.begin(), probe_regions.end(),
                    [rip](const ProbeRegion& region) {
                        return rip >= region.begin && rip < region.end;
                    });
                if (owner != probe_regions.end()) {
                    ++guest_samples;
                    if (rip != last_guest_rip) {
                        last_guest_rip = rip;
                        std::fprintf(stderr,
                            "ACTIVE-GUEST-RIP module=%s offset=0x%llx rip=0x%llx "
                            "rsp=0x%llx rbp=0x%llx rax=0x%llx rbx=0x%llx "
                            "rcx=0x%llx rdx=0x%llx\n",
                            owner->name.c_str(),
                            static_cast<unsigned long long>(rip - owner->load_bias),
                            static_cast<unsigned long long>(rip),
                            static_cast<unsigned long long>(context.Rsp),
                            static_cast<unsigned long long>(context.Rbp),
                            static_cast<unsigned long long>(context.Rax),
                            static_cast<unsigned long long>(context.Rbx),
                            static_cast<unsigned long long>(context.Rcx),
                            static_cast<unsigned long long>(context.Rdx));
                        if (owner->name == "eboot.bin" &&
                            rip - owner->load_bias == 0x4c10U) {
                            std::array<unsigned char, 32> code{};
                            SIZE_T code_bytes{};
                            (void)ReadProcessMemory(GetCurrentProcess(),
                                reinterpret_cast<const void*>(rip), code.data(),
                                code.size(), &code_bytes);
                            std::fputs("ACTIVE-GUEST-CODE eboot+0x4c10 bytes=", stderr);
                            for (SIZE_T index = 0; index < code_bytes; ++index)
                                std::fprintf(stderr, "%02x", code[index]);
                            std::fputc('\n', stderr);
                            std::uintptr_t vtable{};
                            std::uintptr_t dispatch_target{};
                            std::uint64_t scheduler_state{};
                            SIZE_T object_bytes{};
                            SIZE_T target_bytes{};
                            SIZE_T state_bytes{};
                            (void)ReadProcessMemory(GetCurrentProcess(),
                                reinterpret_cast<const void*>(context.Rdi), &vtable,
                                sizeof(vtable), &object_bytes);
                            if (object_bytes == sizeof(vtable)) {
                                (void)ReadProcessMemory(GetCurrentProcess(),
                                    reinterpret_cast<const void*>(vtable + 0x30),
                                    &dispatch_target, sizeof(dispatch_target), &target_bytes);
                            }
                            if (context.R12 <= UINTPTR_MAX - 0x38U) {
                                (void)ReadProcessMemory(GetCurrentProcess(),
                                    reinterpret_cast<const void*>(context.R12 + 0x38U),
                                    &scheduler_state, sizeof(scheduler_state), &state_bytes);
                            }
                            const auto target_owner = std::find_if(probe_regions.begin(),
                                probe_regions.end(), [dispatch_target](const ProbeRegion& region) {
                                    return dispatch_target >= region.begin &&
                                        dispatch_target < region.end;
                                });
                            if (object_bytes == sizeof(vtable) &&
                                target_bytes == sizeof(dispatch_target)) {
                                std::array<std::uint64_t, 8> receiver_words{};
                                SIZE_T receiver_word_bytes{};
                                (void)ReadProcessMemory(GetCurrentProcess(),
                                    reinterpret_cast<const void*>(context.Rdi),
                                    receiver_words.data(), sizeof(receiver_words),
                                    &receiver_word_bytes);
                                std::array<std::uint64_t, 8> scheduler_words{};
                                SIZE_T scheduler_word_bytes{};
                                if (context.R12 != 0)
                                    (void)ReadProcessMemory(GetCurrentProcess(),
                                        reinterpret_cast<const void*>(context.R12),
                                        scheduler_words.data(), sizeof(scheduler_words),
                                        &scheduler_word_bytes);
                                std::array<std::uint64_t, 8> state_owner_words{};
                                SIZE_T state_owner_word_bytes{};
                                if (scheduler_word_bytes == sizeof(scheduler_words) &&
                                    scheduler_words[3] != 0)
                                    (void)ReadProcessMemory(GetCurrentProcess(),
                                        reinterpret_cast<const void*>(scheduler_words[3]),
                                        state_owner_words.data(), sizeof(state_owner_words),
                                        &state_owner_word_bytes);
                                if (target_owner != probe_regions.end()) {
                                    std::fprintf(stderr,
                                        "ACTIVE-GUEST-DISPATCH object=0x%llx vtable=0x%llx "
                                        "method30=%s+0x%llx target=0x%llx r12=0x%llx "
                                        "state=%s0x%llx r14=0x%llx\n",
                                        static_cast<unsigned long long>(context.Rdi),
                                        static_cast<unsigned long long>(vtable),
                                        target_owner->name.c_str(),
                                        static_cast<unsigned long long>(dispatch_target -
                                            target_owner->load_bias),
                                        static_cast<unsigned long long>(dispatch_target),
                                        static_cast<unsigned long long>(context.R12),
                                        state_bytes == sizeof(scheduler_state) ? "" : "unreadable/",
                                        static_cast<unsigned long long>(scheduler_state),
                                        static_cast<unsigned long long>(context.R14));
                                } else {
                                    std::fprintf(stderr,
                                        "ACTIVE-GUEST-DISPATCH object=0x%llx vtable=0x%llx "
                                        "method30=host/unknown:0x%llx r12=0x%llx "
                                        "state=%s0x%llx r14=0x%llx\n",
                                        static_cast<unsigned long long>(context.Rdi),
                                        static_cast<unsigned long long>(vtable),
                                        static_cast<unsigned long long>(dispatch_target),
                                        static_cast<unsigned long long>(context.R12),
                                        state_bytes == sizeof(scheduler_state) ? "" : "unreadable/",
                                        static_cast<unsigned long long>(scheduler_state),
                                        static_cast<unsigned long long>(context.R14));
                                }
                                if (scheduler_word_bytes == sizeof(scheduler_words)) {
                                    std::fprintf(stderr,
                                        "ACTIVE-GUEST-DISPATCH-OBJECT address=0x%llx "
                                        "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                                        static_cast<unsigned long long>(context.R12),
                                        static_cast<unsigned long long>(scheduler_words[0]),
                                        static_cast<unsigned long long>(scheduler_words[1]),
                                        static_cast<unsigned long long>(scheduler_words[2]),
                                        static_cast<unsigned long long>(scheduler_words[3]),
                                        static_cast<unsigned long long>(scheduler_words[4]),
                                        static_cast<unsigned long long>(scheduler_words[5]),
                                        static_cast<unsigned long long>(scheduler_words[6]),
                                        static_cast<unsigned long long>(scheduler_words[7]));
                                }
                                if (receiver_word_bytes == sizeof(receiver_words)) {
                                    std::fprintf(stderr,
                                        "ACTIVE-GUEST-DISPATCH-RECEIVER address=0x%llx "
                                        "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                                        static_cast<unsigned long long>(context.Rdi),
                                        static_cast<unsigned long long>(receiver_words[0]),
                                        static_cast<unsigned long long>(receiver_words[1]),
                                        static_cast<unsigned long long>(receiver_words[2]),
                                        static_cast<unsigned long long>(receiver_words[3]),
                                        static_cast<unsigned long long>(receiver_words[4]),
                                        static_cast<unsigned long long>(receiver_words[5]),
                                        static_cast<unsigned long long>(receiver_words[6]),
                                        static_cast<unsigned long long>(receiver_words[7]));
                                }
                                if (state_owner_word_bytes == sizeof(state_owner_words)) {
                                    std::fprintf(stderr,
                                        "ACTIVE-GUEST-STATE-OWNER address=0x%llx "
                                        "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                                        static_cast<unsigned long long>(scheduler_words[3]),
                                        static_cast<unsigned long long>(state_owner_words[0]),
                                        static_cast<unsigned long long>(state_owner_words[1]),
                                        static_cast<unsigned long long>(state_owner_words[2]),
                                        static_cast<unsigned long long>(state_owner_words[3]),
                                        static_cast<unsigned long long>(state_owner_words[4]),
                                        static_cast<unsigned long long>(state_owner_words[5]),
                                        static_cast<unsigned long long>(state_owner_words[6]),
                                        static_cast<unsigned long long>(state_owner_words[7]));
                                }
                            }
                        }
                        std::array<std::uintptr_t, 16> stack{};
                        SIZE_T copied{};
                        if (ReadProcessMemory(GetCurrentProcess(),
                                reinterpret_cast<const void*>(context.Rsp),
                                stack.data(), sizeof(stack), &copied) != 0) {
                            for (std::size_t index = 0;
                                 index < copied / sizeof(std::uintptr_t); ++index) {
                                const auto value = stack[index];
                                const auto frame_owner = std::find_if(probe_regions.begin(),
                                    probe_regions.end(), [value](const ProbeRegion& region) {
                                        return (region.flags & 1U) != 0 &&
                                            value >= region.begin && value < region.end;
                                    });
                                if (frame_owner != probe_regions.end()) {
                                    std::fprintf(stderr,
                                        "ACTIVE-GUEST-STACK index=%zu module=%s offset=0x%llx\n",
                                        index, frame_owner->name.c_str(),
                                        static_cast<unsigned long long>(
                                            value - frame_owner->load_bias));
                                }
                            }
                        }
                    }
                    if (owner->name == "eboot.bin" &&
                        rip - owner->load_bias == 0x4c10U &&
                        (samples % 50U) == 0 && context.R12 <= UINTPTR_MAX - 0x38U) {
                        std::uint64_t scheduler_state{};
                        SIZE_T state_bytes{};
                        (void)ReadProcessMemory(GetCurrentProcess(),
                            reinterpret_cast<const void*>(context.R12 + 0x38U),
                            &scheduler_state, sizeof(scheduler_state), &state_bytes);
                        std::fprintf(stderr,
                            "ACTIVE-GUEST-DISPATCH-SAMPLE sample=%u status=%s0x%llx "
                            "object=0x%llx counter=0x%llx\n",
                            samples, state_bytes == sizeof(scheduler_state) ? "" : "unreadable/",
                            static_cast<unsigned long long>(scheduler_state),
                            static_cast<unsigned long long>(context.R12),
                            static_cast<unsigned long long>(context.R14));
                    }
                    if (owner->name == "eboot.bin" &&
                        rip - owner->load_bias == 0x4c10U &&
                        context.R12 <= UINTPTR_MAX - 0x38U) {
                        active_scheduler_state_address.store(context.R12 + 0x38U,
                            std::memory_order_release);
                    }
                } else if ((samples % 50U) == 0) {
                    std::fprintf(stderr,
                        "ACTIVE-HOST-RIP samples=%u guest=%u rip=0x%llx rsp=0x%llx "
                        "rbp=0x%llx rax=0x%llx rdx=0x%llx r10=0x%llx\n",
                        samples, guest_samples, static_cast<unsigned long long>(rip),
                        static_cast<unsigned long long>(context.Rsp),
                        static_cast<unsigned long long>(context.Rbp),
                        static_cast<unsigned long long>(context.Rax),
                        static_cast<unsigned long long>(context.Rdx),
                        static_cast<unsigned long long>(context.R10));
                    const auto wait_owner = std::find_if(probe_regions.begin(),
                        probe_regions.end(), [&context](const ProbeRegion& region) {
                            return context.R10 >= region.begin && context.R10 < region.end;
                        });
                    if (wait_owner != probe_regions.end()) {
                        std::fprintf(stderr,
                            "ACTIVE-HOST-WAIT-ADDRESS guest=%s+0x%llx flags=%x\n",
                            wait_owner->name.c_str(),
                            static_cast<unsigned long long>(context.R10 -
                                wait_owner->load_bias), wait_owner->flags);
                    }
                    if (!host_stack_dumped) {
                        host_stack_dumped = true;
                        std::array<std::uintptr_t, 24> stack{};
                        SIZE_T copied{};
                        if (ReadProcessMemory(GetCurrentProcess(),
                                reinterpret_cast<const void*>(context.Rsp), stack.data(),
                                sizeof(stack), &copied) != 0) {
                            for (std::size_t index = 0;
                                 index < copied / sizeof(std::uintptr_t); ++index) {
                                const auto value = stack[index];
                                const auto guest_owner = std::find_if(probe_regions.begin(),
                                    probe_regions.end(), [value](const ProbeRegion& region) {
                                        return (region.flags & 1U) != 0 &&
                                            value >= region.begin && value < region.end;
                                    });
                                if (guest_owner != probe_regions.end()) {
                                    std::fprintf(stderr,
                                        "ACTIVE-HOST-STACK index=%zu guest=%s+0x%llx\n",
                                        index, guest_owner->name.c_str(),
                                        static_cast<unsigned long long>(
                                            value - guest_owner->load_bias));
                                    continue;
                                }
                                HMODULE owner_module{};
                                if (value != 0 && GetModuleHandleExW(
                                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        reinterpret_cast<LPCWSTR>(value), &owner_module)) {
                                    std::fprintf(stderr,
                                        "ACTIVE-HOST-STACK index=%zu module=%s base=0x%llx "
                                        "offset=0x%llx\n", index,
                                        host_module_path(owner_module).c_str(),
                                        static_cast<unsigned long long>(
                                            reinterpret_cast<std::uintptr_t>(owner_module)),
                                        static_cast<unsigned long long>(value -
                                            reinterpret_cast<std::uintptr_t>(owner_module)));
                                }
                            }
                        }
                        auto frame = static_cast<std::uintptr_t>(context.Rbp);
                        for (std::size_t index = 0; index < 16 && frame != 0; ++index) {
                            std::array<std::uintptr_t, 2> pair{};
                            SIZE_T frame_bytes{};
                            if (ReadProcessMemory(GetCurrentProcess(),
                                    reinterpret_cast<const void*>(frame), pair.data(),
                                    sizeof(pair), &frame_bytes) == 0 ||
                                frame_bytes != sizeof(pair)) break;
                            const auto owner = std::find_if(probe_regions.begin(),
                                probe_regions.end(), [address = pair[1]](
                                    const ProbeRegion& region) {
                                    return (region.flags & 1U) != 0 &&
                                        address >= region.begin && address < region.end;
                                });
                            if (owner != probe_regions.end()) {
                                std::fprintf(stderr,
                                    "ACTIVE-HOST-FRAME index=%zu guest=%s+0x%llx\n",
                                    index, owner->name.c_str(),
                                    static_cast<unsigned long long>(pair[1] - owner->load_bias));
                            } else {
                                HMODULE frame_module{};
                                if (pair[1] != 0 && GetModuleHandleExW(
                                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        reinterpret_cast<LPCWSTR>(pair[1]), &frame_module)) {
                                    std::fprintf(stderr,
                                        "ACTIVE-HOST-FRAME index=%zu module=%s base=0x%llx "
                                        "offset=0x%llx\n", index,
                                        host_module_path(frame_module).c_str(),
                                        static_cast<unsigned long long>(
                                            reinterpret_cast<std::uintptr_t>(frame_module)),
                                        static_cast<unsigned long long>(pair[1] -
                                            reinterpret_cast<std::uintptr_t>(frame_module)));
                                }
                            }
                            if (pair[0] <= frame || pair[0] - frame > 0x100000U) break;
                            frame = pair[0];
                        }
                        auto unwind_context = context;
                        for (std::size_t index = 0; index < 24 && unwind_context.Rip != 0;
                             ++index) {
                            const auto pc = static_cast<std::uintptr_t>(unwind_context.Rip);
                            const auto guest_owner = std::find_if(probe_regions.begin(),
                                probe_regions.end(), [pc](const ProbeRegion& region) {
                                    return (region.flags & 1U) != 0 &&
                                        pc >= region.begin && pc < region.end;
                                });
                            if (guest_owner != probe_regions.end()) {
                                std::fprintf(stderr,
                                    "ACTIVE-HOST-UNWIND index=%zu guest=%s+0x%llx\n",
                                    index, guest_owner->name.c_str(),
                                    static_cast<unsigned long long>(pc -
                                        guest_owner->load_bias));
                                break;
                            }
                            HMODULE pc_module{};
                            if (GetModuleHandleExW(
                                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(pc), &pc_module)) {
                                std::fprintf(stderr,
                                    "ACTIVE-HOST-UNWIND index=%zu module=%s offset=0x%llx\n",
                                    index, host_module_path(pc_module).c_str(),
                                    static_cast<unsigned long long>(pc -
                                        reinterpret_cast<std::uintptr_t>(pc_module)));
                            } else {
                                std::fprintf(stderr,
                                    "ACTIVE-HOST-UNWIND index=%zu pc=0x%llx\n", index,
                                    static_cast<unsigned long long>(pc));
                            }
                            DWORD64 image_base{};
                            const auto function = RtlLookupFunctionEntry(
                                unwind_context.Rip, &image_base, nullptr);
                            if (function == nullptr) {
                                std::uintptr_t return_address{};
                                SIZE_T return_bytes{};
                                if (ReadProcessMemory(GetCurrentProcess(),
                                        reinterpret_cast<const void*>(unwind_context.Rsp),
                                        &return_address, sizeof(return_address),
                                        &return_bytes) == 0 ||
                                    return_bytes != sizeof(return_address) ||
                                    return_address == 0) break;
                                unwind_context.Rip = return_address;
                                unwind_context.Rsp += sizeof(return_address);
                                continue;
                            }
                            PVOID handler_data{};
                            DWORD64 establisher_frame{};
                            KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
                            if (RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base,
                                    unwind_context.Rip, function, &unwind_context,
                                    &handler_data, &establisher_frame, &nonvolatile) == nullptr) {
                                break;
                            }
                        }
                    }
                }
                if ((samples % 50U) == 0) {
                    const auto state_address = active_scheduler_state_address.load(
                        std::memory_order_acquire);
                    if (state_address != 0) {
                        std::uint64_t scheduler_state{};
                        SIZE_T state_bytes{};
                        (void)ReadProcessMemory(GetCurrentProcess(),
                            reinterpret_cast<const void*>(state_address),
                            &scheduler_state, sizeof(scheduler_state), &state_bytes);
                        std::fprintf(stderr,
                            "ACTIVE-GUEST-DISPATCH-POLL sample=%u status=%s0x%llx address=0x%llx\n",
                            samples, state_bytes == sizeof(scheduler_state) ? "" : "unreadable/",
                            static_cast<unsigned long long>(scheduler_state),
                            static_cast<unsigned long long>(state_address));
                    }
                }
            }
            ResumeThread(thread);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::fprintf(stderr, "ACTIVE-GUEST-RIP finished samples=%u guest=%u\n",
                 samples, guest_samples);
    CloseHandle(thread);
}

void sample_active_process_threads(DWORD process_id, DWORD process_entry_thread_id) {
    struct ThreadRipSample {
        DWORD thread_id{};
        std::uintptr_t rip{};
        std::uint32_t last_emitted_cycle{};
    };
    std::vector<ThreadRipSample> last_rips;
    std::uint32_t cycles = 0;
    std::uint32_t records = 0;
    std::uint32_t process_entry_host_stack_dumps = 0;
    std::fprintf(stderr,
        "ACTIVE-THREAD sampling process guest/host threads entry_tid=%lu\n",
        process_entry_thread_id);
    while (!active_rip_sampler_stop.load(std::memory_order_acquire) &&
           cycles < 300 && records < 512) {
        ++cycles;
        const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 item{};
            item.dwSize = sizeof(item);
            if (Thread32First(snapshot, &item)) {
                do {
                    if (item.th32OwnerProcessID != process_id ||
                        item.th32ThreadID == GetCurrentThreadId()) continue;
                    const auto thread = OpenThread(THREAD_GET_CONTEXT |
                        THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE,
                        item.th32ThreadID);
                    if (thread == nullptr) continue;
                    const auto suspended = SuspendThread(thread);
                    if (suspended != static_cast<DWORD>(-1)) {
                        CONTEXT context{};
                        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                        if (GetThreadContext(thread, &context)) {
                            const auto rip = static_cast<std::uintptr_t>(context.Rip);
                            const auto owner = std::find_if(probe_regions.begin(),
                                probe_regions.end(), [rip](const ProbeRegion& region) {
                                    return rip >= region.begin && rip < region.end;
                                });
                            const auto previous = std::find_if(last_rips.begin(), last_rips.end(),
                                [&item](const auto& entry) {
                                    return entry.thread_id == item.th32ThreadID;
                                });
                            const auto guest_offset = owner == probe_regions.end()
                                ? 0U : rip - owner->load_bias;
                            const bool target_memory_loop = owner != probe_regions.end() &&
                                owner->name == "eboot.bin" && guest_offset >= 0x2410000U &&
                                guest_offset < 0x2420000U;
                            const bool periodic_sample = previous != last_rips.end() &&
                                cycles - previous->last_emitted_cycle >=
                                    (target_memory_loop ? 25U : 100U) &&
                                (target_memory_loop || owner == probe_regions.end());
                            const bool changed = previous == last_rips.end() ||
                                (previous->rip != rip &&
                                 (owner != probe_regions.end() ||
                                  cycles - previous->last_emitted_cycle >= 100U)) ||
                                periodic_sample;
                            if (previous == last_rips.end())
                                last_rips.push_back({item.th32ThreadID, rip, cycles});
                            else if (changed) {
                                previous->rip = rip;
                                previous->last_emitted_cycle = cycles;
                            }
                            if (changed && records < 512) {
                                if (owner != probe_regions.end()) {
                                    std::fprintf(stderr,
                                        "ACTIVE-THREAD tid=%lu module=%s+0x%llx rip=0x%llx "
                                        "rsp=0x%llx rax=0x%llx rbx=0x%llx rcx=0x%llx "
                                        "rdx=0x%llx r14=0x%llx r15=0x%llx r10=0x%llx\n",
                                        item.th32ThreadID, owner->name.c_str(),
                                        static_cast<unsigned long long>(rip - owner->load_bias),
                                        static_cast<unsigned long long>(rip),
                                        static_cast<unsigned long long>(context.Rsp),
                                        static_cast<unsigned long long>(context.Rax),
                                        static_cast<unsigned long long>(context.Rbx),
                                        static_cast<unsigned long long>(context.Rcx),
                                        static_cast<unsigned long long>(context.Rdx),
                                        static_cast<unsigned long long>(context.R14),
                                        static_cast<unsigned long long>(context.R15),
                                        static_cast<unsigned long long>(context.R10));
                                } else {
                                    HMODULE module{};
                                    const auto module_offset = GetModuleHandleExW(
                                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        reinterpret_cast<LPCWSTR>(rip), &module) != 0
                                        ? rip - reinterpret_cast<std::uintptr_t>(module)
                                        : 0;
                                    std::string wait_location = "none";
                                    if (context.R10 != 0) {
                                        std::array<std::uint64_t, 2> wait_words{};
                                        SIZE_T wait_bytes{};
                                        const bool wait_read = ReadProcessMemory(
                                            GetCurrentProcess(),
                                            reinterpret_cast<const void*>(context.R10),
                                            wait_words.data(), sizeof(wait_words),
                                            &wait_bytes) != 0 &&
                                            wait_bytes == sizeof(wait_words);
                                        const auto wait_owner = std::find_if(probe_regions.begin(),
                                            probe_regions.end(), [&context](
                                                const ProbeRegion& region) {
                                                    return context.R10 >= region.begin &&
                                                           context.R10 < region.end;
                                                });
                                        char wait_text[192]{};
                                        if (wait_owner != probe_regions.end()) {
                                            std::snprintf(wait_text, sizeof(wait_text),
                                                "%s+0x%llx", wait_owner->name.c_str(),
                                                static_cast<unsigned long long>(context.R10 -
                                                    wait_owner->load_bias));
                                        } else {
                                            std::snprintf(wait_text, sizeof(wait_text),
                                                "0x%llx", static_cast<unsigned long long>(
                                                    context.R10));
                                        }
                                        wait_location = wait_text;
                                        if (wait_read) {
                                            char value_text[64]{};
                                            std::snprintf(value_text, sizeof(value_text),
                                                "[0x%llx,0x%llx]",
                                                static_cast<unsigned long long>(wait_words[0]),
                                                static_cast<unsigned long long>(wait_words[1]));
                                            wait_location += value_text;
                                        }
                                    }
                                    std::fprintf(stderr,
                                        "ACTIVE-THREAD tid=%lu host=%s+0x%llx rip=0x%llx "
                                        "rsp=0x%llx rax=0x%llx rdx=0x%llx r10=%s\n",
                                        item.th32ThreadID,
                                        module != nullptr ? host_module_path(module).c_str()
                                                          : "<unknown>",
                                        static_cast<unsigned long long>(module_offset),
                                        static_cast<unsigned long long>(rip),
                                        static_cast<unsigned long long>(context.Rsp),
                                        static_cast<unsigned long long>(context.Rax),
                                        static_cast<unsigned long long>(context.Rdx),
                                        wait_location.c_str());
                                    if (item.th32ThreadID == process_entry_thread_id &&
                                        process_entry_host_stack_dumps < 3) {
                                        std::array<std::uintptr_t, 16> host_stack{};
                                        SIZE_T host_stack_bytes{};
                                        if (ReadProcessMemory(GetCurrentProcess(),
                                                reinterpret_cast<const void*>(context.Rsp),
                                                host_stack.data(), sizeof(host_stack),
                                                &host_stack_bytes) != 0) {
                                            for (std::size_t stack_index = 0;
                                                 stack_index < host_stack_bytes /
                                                     sizeof(std::uintptr_t); ++stack_index) {
                                                const auto address = host_stack[stack_index];
                                                const auto frame_owner = std::find_if(
                                                    probe_regions.begin(), probe_regions.end(),
                                                    [address](const ProbeRegion& region) {
                                                        return address >= region.begin &&
                                                               address < region.end;
                                                    });
                                                if (frame_owner != probe_regions.end()) {
                                                    std::fprintf(stderr,
                                                        "ACTIVE-MAIN-HOSTSTACK tid=%lu index=%zu "
                                                        "guest=%s+0x%llx\n",
                                                        item.th32ThreadID, stack_index,
                                                        frame_owner->name.c_str(),
                                                        static_cast<unsigned long long>(address -
                                                            frame_owner->load_bias));
                                                } else {
                                                    HMODULE frame_module{};
                                                    if (address != 0 && GetModuleHandleExW(
                                                            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                                            reinterpret_cast<LPCWSTR>(address),
                                                            &frame_module)) {
                                                        std::fprintf(stderr,
                                                            "ACTIVE-MAIN-HOSTSTACK tid=%lu index=%zu "
                                                            "module=%s+0x%llx\n",
                                                            item.th32ThreadID, stack_index,
                                                            host_module_path(frame_module).c_str(),
                                                            static_cast<unsigned long long>(address -
                                                                reinterpret_cast<std::uintptr_t>(
                                                                    frame_module)));
                                                    }
                                                }
                                            }
                                            auto unwind = context;
                                            // NtWaitForAlertByThreadId is a leaf syscall stub.
                                            // Start unwinding at its caller's return PC so the
                                            // unwind metadata for RtlSleepConditionVariableSRW
                                            // sees a context at the call site, not mid-syscall.
                                            if (unwind.Rip >= reinterpret_cast<std::uintptr_t>(
                                                    GetModuleHandleW(L"ntdll.dll")) &&
                                                unwind.Rip < reinterpret_cast<std::uintptr_t>(
                                                    GetModuleHandleW(L"ntdll.dll")) + 0x200000U) {
                                                std::uintptr_t syscall_return{};
                                                SIZE_T return_bytes{};
                                                if (ReadProcessMemory(GetCurrentProcess(),
                                                        reinterpret_cast<const void*>(unwind.Rsp),
                                                        &syscall_return, sizeof(syscall_return),
                                                        &return_bytes) != 0 &&
                                                    return_bytes == sizeof(syscall_return) &&
                                                    syscall_return != 0) {
                                                    HMODULE ntdll{};
                                                    if (GetModuleHandleExW(
                                                            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                                            reinterpret_cast<LPCWSTR>(syscall_return),
                                                            &ntdll) && ntdll == GetModuleHandleW(L"ntdll.dll")) {
                                                        unwind.Rip = syscall_return;
                                                        unwind.Rsp += sizeof(syscall_return);
                                                        std::fprintf(stderr,
                                                            "ACTIVE-MAIN-UNWIND-START tid=%lu "
                                                            "module=ntdll+0x%llx rsp=0x%llx\n",
                                                            item.th32ThreadID,
                                                            static_cast<unsigned long long>(
                                                                syscall_return - reinterpret_cast<std::uintptr_t>(ntdll)),
                                                            static_cast<unsigned long long>(unwind.Rsp));
                                                    }
                                                }
                                            }
                                            for (std::size_t frame_index = 0;
                                                 frame_index < 12 && unwind.Rip != 0;
                                                 ++frame_index) {
                                                const auto pc = static_cast<std::uintptr_t>(
                                                    unwind.Rip);
                                                const auto guest_frame = std::find_if(
                                                    probe_regions.begin(), probe_regions.end(),
                                                    [pc](const ProbeRegion& region) {
                                                        return pc >= region.begin &&
                                                               pc < region.end;
                                                    });
                                                if (guest_frame != probe_regions.end()) {
                                                    std::fprintf(stderr,
                                                        "ACTIVE-MAIN-UNWIND tid=%lu index=%zu "
                                                        "guest=%s+0x%llx\n",
                                                        item.th32ThreadID, frame_index,
                                                        guest_frame->name.c_str(),
                                                        static_cast<unsigned long long>(pc -
                                                            guest_frame->load_bias));
                                                } else {
                                                    HMODULE frame_module{};
                                                    if (GetModuleHandleExW(
                                                            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                                            reinterpret_cast<LPCWSTR>(pc),
                                                            &frame_module)) {
                                                        std::fprintf(stderr,
                                                            "ACTIVE-MAIN-UNWIND tid=%lu index=%zu "
                                                            "module=%s+0x%llx\n",
                                                            item.th32ThreadID, frame_index,
                                                            host_module_path(frame_module).c_str(),
                                                            static_cast<unsigned long long>(pc -
                                                                reinterpret_cast<std::uintptr_t>(
                                                                    frame_module)));
                                                    }
                                                }
                                                DWORD64 image_base{};
                                                const auto function = RtlLookupFunctionEntry(
                                                    unwind.Rip, &image_base, nullptr);
                                                if (function == nullptr) {
                                                    std::uintptr_t return_address{};
                                                    SIZE_T return_bytes{};
                                                    if (ReadProcessMemory(GetCurrentProcess(),
                                                            reinterpret_cast<const void*>(
                                                                unwind.Rsp), &return_address,
                                                            sizeof(return_address),
                                                            &return_bytes) == 0 ||
                                                        return_bytes != sizeof(return_address) ||
                                                        return_address == 0) break;
                                                    unwind.Rip = return_address;
                                                    unwind.Rsp += sizeof(return_address);
                                                    continue;
                                                }
                                                PVOID handler_data{};
                                                DWORD64 establisher_frame{};
                                                KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
                                                // A null return means "no exception handler";
                                                // it does not indicate an unwind failure.
                                                RtlVirtualUnwind(UNW_FLAG_NHANDLER,
                                                    image_base, unwind.Rip, function,
                                                    &unwind, &handler_data,
                                                    &establisher_frame,
                                                    &nonvolatile);
                                            }
                                            ++process_entry_host_stack_dumps;
                                        }
                                    }
                                }
                                ++records;
                            }
                        }
                        ResumeThread(thread);
                    }
                    CloseHandle(thread);
                } while (Thread32Next(snapshot, &item));
            }
            CloseHandle(snapshot);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::fprintf(stderr, "ACTIVE-THREAD finished cycles=%u records=%u\n",
                 cycles, records);
}

void watch_scheduler_state_writes(DWORD process_id) {
    constexpr std::uint64_t watchpoint_mask = 0xF0003ULL;
    constexpr std::uint64_t write_dword_watchpoint = 0xD0001ULL;
    const auto watcher_thread_id = GetCurrentThreadId();
    std::uint32_t cycles = 0;
    std::size_t armed_threads = 0;
    std::set<DWORD> armed_thread_ids;
    std::fprintf(stderr, "%s watchpoint monitoring started\n",
        std::getenv("NBA16_TRACE_SHADER_BOUND_WRITES") != nullptr
            ? "SHADER-BOUND" : "SCHED-STATE");
    while (!active_rip_sampler_stop.load(std::memory_order_acquire) &&
           !scheduler_state_watchpoint_hit.load(std::memory_order_acquire) &&
           cycles < 150) {
        ++cycles;
        const auto target = active_scheduler_state_address.load(std::memory_order_acquire);
        if (target != 0) {
            const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 item{};
                item.dwSize = sizeof(item);
                if (Thread32First(snapshot, &item)) {
                    do {
                        if (item.th32OwnerProcessID != process_id ||
                            item.th32ThreadID == watcher_thread_id ||
                            armed_thread_ids.contains(item.th32ThreadID)) continue;
                        const auto thread = OpenThread(THREAD_GET_CONTEXT |
                            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
                            THREAD_QUERY_INFORMATION, FALSE, item.th32ThreadID);
                        if (thread == nullptr) continue;
                        const auto suspended = SuspendThread(thread);
                        if (suspended != static_cast<DWORD>(-1)) {
                            CONTEXT context{};
                            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                            if (GetThreadContext(thread, &context)) {
                                const bool already_armed = context.Dr0 == target &&
                                    (context.Dr7 & 1ULL) != 0 &&
                                    (context.Dr7 & watchpoint_mask) ==
                                        write_dword_watchpoint;
                                if (!already_armed) {
                                    context.Dr0 = target;
                                    context.Dr6 = 0;
                                    context.Dr7 = (context.Dr7 & ~watchpoint_mask) |
                                        write_dword_watchpoint;
                                    if (SetThreadContext(thread, &context)) {
                                        armed_thread_ids.insert(item.th32ThreadID);
                                        ++armed_threads;
                                        if (armed_threads <= 16)
                                            std::fprintf(stderr,
                                                "%s armed tid=%lu address=0x%llx\n",
                                                std::getenv("NBA16_TRACE_SHADER_BOUND_WRITES") != nullptr
                                                    ? "SHADER-BOUND" : "SCHED-STATE",
                                                item.th32ThreadID,
                                                static_cast<unsigned long long>(target));
                                    }
                                }
                            }
                            ResumeThread(thread);
                        }
                        CloseHandle(thread);
                    } while (Thread32Next(snapshot, &item));
                }
                CloseHandle(snapshot);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    const bool hit = scheduler_state_watchpoint_hit.load(std::memory_order_acquire);
    std::size_t disarmed_threads = 0;
    for (const auto thread_id : armed_thread_ids) {
        const auto thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
            THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, thread_id);
        if (thread == nullptr) continue;
        const auto suspended = SuspendThread(thread);
        if (suspended != static_cast<DWORD>(-1)) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(thread, &context) &&
                context.Dr0 == active_scheduler_state_address.load(
                    std::memory_order_acquire)) {
                context.Dr0 = 0;
                context.Dr6 = 0;
                context.Dr7 &= ~watchpoint_mask;
                if (SetThreadContext(thread, &context)) ++disarmed_threads;
            }
            ResumeThread(thread);
        }
        CloseHandle(thread);
    }
    std::fprintf(stderr,
        "%s watchpoint monitoring %s writes=%u cycles=%u armed=%zu disarmed=%zu\n",
        std::getenv("NBA16_TRACE_SHADER_BOUND_WRITES") != nullptr
            ? "SHADER-BOUND" : "SCHED-STATE",
        hit ? "captured writes" : "ended before write limit",
        scheduler_state_write_count.load(std::memory_order_acquire),
        cycles, armed_threads, disarmed_threads);
}
#endif

struct FopenTraceSite {
    std::uint64_t offset;
    std::array<std::uint8_t, 4> signature;
    const char* label;
    std::uintptr_t address{};
    std::uint8_t original{};
    bool armed{};
    std::uint32_t hit_count{};
    std::uint32_t max_hits{};
};
std::array<FopenTraceSite, 256> fopen_trace_sites{{
    {0xeaea, {0x48, 0x85, 0xc0, 0x74}, "allocator-return"},
    {0xeb04, {0x5b, 0x41, 0x5e, 0x5d}, "stream-ready"},
    {0xec55, {0x48, 0xc7, 0x83, 0x80}, "file-template"},
    {0xec8c, {0x41, 0x0f, 0xb6, 0x0c}, "mode-parse"},
    {0xed3d, {0x48, 0x85, 0xff, 0x74}, "path-check"},
    {0xed54, {0x89, 0xc1, 0x89, 0x4b}, "open-return"},
}};
thread_local int fopen_trace_step_site = -1;
thread_local bool jm_worker_instruction_trace_active = false;
thread_local std::uint32_t jm_worker_instruction_trace_remaining = 0;
thread_local bool fs_eof_instruction_trace_active = false;
thread_local std::uint32_t fs_eof_instruction_trace_remaining = 0;
thread_local std::uint32_t fs_eof_instruction_trace_guest_steps = 0;
thread_local std::uint32_t fs_eof_instruction_trace_host_steps = 0;
thread_local bool fs_eof_instruction_trace_follow_wait = false;
thread_local std::uintptr_t fs_eof_wait_return_breakpoint{};
thread_local std::uint8_t fs_eof_wait_return_original{};
thread_local bool fs_eof_wait_return_armed{};
thread_local bool shader_state_instruction_trace_active{};
thread_local std::uint32_t shader_state_instruction_trace_steps{};
thread_local std::uint32_t shader_state_instruction_trace_host_steps{};
thread_local std::uintptr_t shader_state_update_object{};
std::atomic_bool shader_state_instruction_trace_started{};
bool arm_fclose_trace_site(std::uintptr_t address, const char* label,
                           std::array<std::uint8_t, 4> signature,
                           std::uint64_t display_offset,
                           std::uint32_t max_hits);

void start_guest_instruction_trace(const char* trigger, bool follow_wait) {
    fs_eof_instruction_trace_active = true;
    fs_eof_instruction_trace_remaining = 20000;
    fs_eof_instruction_trace_guest_steps = 0;
    fs_eof_instruction_trace_host_steps = 0;
    fs_eof_instruction_trace_follow_wait = follow_wait;
    std::fprintf(stderr, "GUEST-INST tracing begins after %s\n", trigger);
    __asm__ volatile("pushfq\n\torq $0x100, (%%rsp)\n\tpopfq" ::: "memory", "cc");
}

void start_fs_eof_instruction_trace() {
    if (std::getenv("NBA16_TRACE_FS_AFTER_EOF") != nullptr)
        start_guest_instruction_trace("shader EOF", true);
}

void start_gnm_submitdone_instruction_trace() {
    if (std::getenv("NBA16_TRACE_GNM_AFTER_SUBMIT_DONE") != nullptr)
        start_guest_instruction_trace("sceGnmSubmitDone", false);
}

void start_shader_state_instruction_trace() {
    if (std::getenv("NBA16_TRACE_SHADER_STATE_FLOW") == nullptr) return;
    if (shader_state_instruction_trace_started.exchange(true,
            std::memory_order_acq_rel)) return;
    const auto eboot = std::find_if(probe_regions.begin(), probe_regions.end(),
        [](const auto& region) { return region.name == "eboot.bin"; });
    if (eboot == probe_regions.end()) {
        std::fputs("SHADER-STATE trace: eboot.bin region unavailable\n", stderr);
        return;
    }
    std::size_t armed{};
    for (const auto& [offset, label] : std::array{
            std::pair<std::uint64_t, const char*>{0x7950, "shader-state-poll"},
            std::pair<std::uint64_t, const char*>{0x4bdf, "shader-main-state-getter-call"},
            std::pair<std::uint64_t, const char*>{0x4be2, "shader-main-state-getter-return"},
            std::pair<std::uint64_t, const char*>{0x4c16, "shader-main-state-getter-call-2"},
            std::pair<std::uint64_t, const char*>{0x4c19, "shader-main-state-getter-return-2"},
            std::pair<std::uint64_t, const char*>{0x7bf7, "shader-state-update-call"},
            std::pair<std::uint64_t, const char*>{0x7bfc, "shader-state-update-return"},
            std::pair<std::uint64_t, const char*>{0x79d6, "shader-reader-bound-arg"},
            std::pair<std::uint64_t, const char*>{0x72f1, "shader-bound-source-vcall"},
            std::pair<std::uint64_t, const char*>{0x72f4, "shader-bound-source-vcall-return"},
            std::pair<std::uint64_t, const char*>{0x7496, "shader-bound-store-stack-value"},
            std::pair<std::uint64_t, const char*>{0x685e80, "shader-bound-getter-entry"},
            std::pair<std::uint64_t, const char*>{0x685ea1, "shader-bound-getter-dispatch"},
            std::pair<std::uint64_t, const char*>{0x692260, "shader-bound-query-method-entry"},
            std::pair<std::uint64_t, const char*>{0x69228e, "shader-bound-query-helper-return"},
            std::pair<std::uint64_t, const char*>{0x692296, "shader-bound-query-result"},
            std::pair<std::uint64_t, const char*>{0x297d540, "shader-bound-query-helper-dispatch"},
            std::pair<std::uint64_t, const char*>{0x685ea4, "shader-bound-getter-method-entry"},
            std::pair<std::uint64_t, const char*>{0x685ea7, "shader-bound-getter-method-return"},
            std::pair<std::uint64_t, const char*>{0x8bb2, "shader-state-poll-return"},
            std::pair<std::uint64_t, const char*>{0x3950, "shader-state-update"},
            std::pair<std::uint64_t, const char*>{0x7bf7, "shader-state-update-call"},
            std::pair<std::uint64_t, const char*>{0x7bfc, "shader-state-update-return"},
            std::pair<std::uint64_t, const char*>{0x225f3aa, "shader-queue-callback-cleanup-begin"},
            std::pair<std::uint64_t, const char*>{0x225f3b1, "shader-queue-recursive-call"},
            std::pair<std::uint64_t, const char*>{0x225f3b6, "shader-queue-recursive-return"},
            std::pair<std::uint64_t, const char*>{0x225f3c2, "shader-queue-state-check"},
            std::pair<std::uint64_t, const char*>{0x225f3c8, "shader-queue-state-complete"},
            std::pair<std::uint64_t, const char*>{0x225f4a0, "shader-stream-reader-ctor"},
            std::pair<std::uint64_t, const char*>{0x225f1a0, "shader-queue-process-entry"},
            std::pair<std::uint64_t, const char*>{0x225f1f0, "shader-queue-drain-method-entry"},
            std::pair<std::uint64_t, const char*>{0x225f020, "shader-stream-read-entry"},
            std::pair<std::uint64_t, const char*>{0x225f30a, "shader-queue-item-call-entry"},
            std::pair<std::uint64_t, const char*>{0x225f30d, "shader-queue-item-call-return"},
            std::pair<std::uint64_t, const char*>{0x225f040, "shader-queue-cleanup-entry"},
            std::pair<std::uint64_t, const char*>{0x225f111, "shader-queue-cleanup-dispatch"},
            std::pair<std::uint64_t, const char*>{0x225f116, "shader-queue-cleanup-dispatch-return"},
            std::pair<std::uint64_t, const char*>{0x225f18f, "shader-queue-tail-dispatch"},
            std::pair<std::uint64_t, const char*>{0x41aaf0, "shader-queue-method-entry"},
            std::pair<std::uint64_t, const char*>{0x41ab59, "shader-queue-method-listener-call"},
            std::pair<std::uint64_t, const char*>{0x41abca, "shader-queue-method-filter-call"},
            std::pair<std::uint64_t, const char*>{0x41ac30, "shader-queue-method-tail-jump"},
            std::pair<std::uint64_t, const char*>{0xc90400, "shader-state-query"},
            std::pair<std::uint64_t, const char*>{0xc904c0, "shader-state-source-operation-call"},
            std::pair<std::uint64_t, const char*>{0xc904c3, "shader-state-source-operation-return"},
            std::pair<std::uint64_t, const char*>{0x7abb, "shader-state-query-return"},
            std::pair<std::uint64_t, const char*>{0x7b1c, "shader-state-query-dispatch-return"},
            std::pair<std::uint64_t, const char*>{0x7b1f, "shader-state-query-dispatch-skip"}}) {
        std::array<std::uint8_t, 4> signature{};
        SIZE_T copied{};
        const auto address = static_cast<std::uintptr_t>(eboot->load_bias + offset);
        if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                signature.data(), signature.size(), &copied) == 0 || copied != signature.size())
            continue;
        if (arm_fclose_trace_site(address, label, signature, offset, 24)) ++armed;
    }
    std::fprintf(stderr,
        "SHADER-STATE trace armed shared eboot breakpoints=%zu; "
        "FS_AFTER_EOF=%d\n", armed,
        std::getenv("NBA16_TRACE_FS_AFTER_EOF") != nullptr ? 1 : 0);
}

void arm_eboot_memory_allocation_trace() {
    if (std::getenv("NBA16_TRACE_EBOOT_MEMORY_ALLOC") == nullptr) return;
    const auto eboot = std::find_if(probe_regions.begin(), probe_regions.end(),
        [](const auto& region) { return region.name == "eboot.bin"; });
    if (eboot == probe_regions.end()) return;
    std::size_t armed{};
    for (const auto& [offset, label] : std::array{
            std::pair<std::uint64_t, const char*>{0xb56525, "memory-pool-map-entry"},
            std::pair<std::uint64_t, const char*>{0xb5652a, "memory-pool-map-return"},
            std::pair<std::uint64_t, const char*>{0x41fb90, "memory-pool-create-entry"},
            std::pair<std::uint64_t, const char*>{0x41fc03, "memory-pool-create-call"},
            std::pair<std::uint64_t, const char*>{0x41fc08, "memory-pool-create-return"},
            std::pair<std::uint64_t, const char*>{0x41fc15, "memory-pool-register-call"},
            std::pair<std::uint64_t, const char*>{0x41fc1a, "memory-pool-register-return"},
            std::pair<std::uint64_t, const char*>{0x41fc1d, "memory-pool-commit-call"},
            std::pair<std::uint64_t, const char*>{0x41fc22, "memory-pool-commit-return"},
            std::pair<std::uint64_t, const char*>{0x41fc38, "memory-pool-create-return-final"}}) {
        std::array<std::uint8_t, 4> signature{};
        SIZE_T copied{};
        const auto address = static_cast<std::uintptr_t>(eboot->load_bias + offset);
        if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                signature.data(), signature.size(), &copied) == 0 || copied != signature.size())
            continue;
        if (arm_fclose_trace_site(address, label, signature, offset, 8)) ++armed;
    }
    std::fprintf(stderr, "EBOOT-MEM-TRACE shared breakpoints armed=%zu\n", armed);
}

void arm_eboot_exception_guard_trace() {
    if (std::getenv("NBA16_TRACE_EXCEPTION_GUARD") == nullptr) return;
    const auto eboot = std::find_if(probe_regions.begin(), probe_regions.end(),
        [](const auto& region) { return region.name == "eboot.bin"; });
    if (eboot == probe_regions.end()) return;
    for (const auto& [rva, label, signature] : std::array{
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x2040ab, "exception-init-helper-call", {0xe8, 0xc0, 0x52, 0xb5}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d59370, "exception-init-helper-entry", {0x55, 0x48, 0x89, 0xe5}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d593b8, "exception-init-first-subcall", {0xe8, 0x13, 0x5a, 0x35}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d593c8, "exception-init-second-subcall", {0xe8, 0xf3, 0xf1, 0xff}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d593cd, "exception-init-second-result-test", {0x84, 0xc0, 0x0f, 0x84}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d593cf, "exception-init-second-result-branch", {0x0f, 0x84, 0xce, 0x00}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d585c0, "exception-init-setup-helper-entry", {0x55, 0x48, 0x89, 0xe5}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d58602, "exception-init-setup-inner-call", {0xe8, 0x59, 0x58, 0xfe}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d59492, "netctl-register-callback-call", {0xe8, 0x69, 0x45, 0xc2}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x1d59497, "netctl-register-callback-result", {0x85, 0xc0, 0x74, 0x10}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0xbde24f, "netctl-init-call", {0xe8, 0xdc, 0x08, 0xda}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0xbde254, "netctl-init-result-test", {0x85, 0xc0, 0x0f, 0x94}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x2040b0, "exception-init-result-test", {0x84, 0xc0, 0x0f, 0x84}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x2040b2, "exception-init-result-branch", {0x0f, 0x84, 0x2e, 0x01}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x2041cb, "exception-guard-compare", {0x48, 0x3b, 0x45, 0xd8}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x2041cf, "exception-guard-branch", {0x75, 0x0f, 0xb0, 0x01}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x2041e0, "exception-guard-fail-call", {0xe8, 0x6b, 0x92, 0x77}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x2041e6, "exception-guard-ud2", {0x0f, 0x0b, 0x0f, 0x1f}}}) {
        if (!arm_fclose_trace_site(static_cast<std::uintptr_t>(eboot->load_bias + rva),
                label, signature, rva, 1)) continue;
        std::array<std::uint8_t, 4> armed_bytes{};
        SIZE_T copied{};
        (void)ReadProcessMemory(GetCurrentProcess(),
            reinterpret_cast<const void*>(eboot->load_bias + rva),
            armed_bytes.data(), armed_bytes.size(), &copied);
        std::fprintf(stderr,
            "EXCEPTION-GUARD trace armed eboot+0x%llx address=0x%llx bytes=%02x %02x %02x %02x read=%llu\n",
            static_cast<unsigned long long>(rva),
            static_cast<unsigned long long>(eboot->load_bias + rva),
            armed_bytes[0], armed_bytes[1], armed_bytes[2], armed_bytes[3],
            static_cast<unsigned long long>(copied));
    }
    const auto netctl = std::find_if(probe_regions.begin(), probe_regions.end(),
        [](const auto& region) { return region.name == "libSceNetCtl.prx"; });
    if (netctl != probe_regions.end()) {
        for (const auto& [rva, label, signature] : std::array{
                std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                    0x1a10, "netctl-init-entry", {0x55, 0x48, 0x89, 0xe5}},
                std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                    0x1df0, "netctl-register-callback-entry", {0x55, 0x48, 0x89, 0xe5}}}) {
            if (arm_fclose_trace_site(static_cast<std::uintptr_t>(netctl->load_bias + rva),
                    label, signature, rva, 4)) {
                std::fprintf(stderr,
                    "EXCEPTION-GUARD trace armed %s+0x%llx address=0x%llx\n",
                    netctl->name.c_str(), static_cast<unsigned long long>(rva),
                    static_cast<unsigned long long>(netctl->load_bias + rva));
            }
        }
    }
}

void arm_libkernel_usrstack_panic_trace() {
    if (std::getenv("NBA16_TRACE_USRSTACK_PANIC") == nullptr) return;
    const auto kernel = std::find_if(probe_regions.begin(), probe_regions.end(),
        [](const auto& region) { return region.name == "libkernel.prx"; });
    if (kernel == probe_regions.end()) {
        std::fputs("USRSTACK-TRACE: libkernel.prx region unavailable\n", stderr);
        return;
    }
    std::size_t armed{};
    for (const auto& [offset, label, signature] : std::array{
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x33536, "libkernel-usrstack-helper-call", {0x31, 0xff, 0xe8, 0xd3}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x3353d, "libkernel-usrstack-helper-result", {0x48, 0x85, 0xc0, 0x0f}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x33c10, "libkernel-usrstack-helper-entry", {0x55, 0x48, 0x89, 0xe5}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x33c71, "libkernel-usrstack-helper-null-return", {0x48, 0x85, 0xdb, 0x74}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x33d19, "libkernel-usrstack-helper-ret", {0x48, 0x89, 0xf0, 0x5b}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x33536, "libkernel-usrstack-helper-call", {0x31, 0xff, 0xe8, 0xd3}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x3353d, "libkernel-usrstack-helper-result", {0x48, 0x85, 0xc0, 0x0f}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x33c10, "libkernel-usrstack-helper-entry", {0x55, 0x48, 0x89, 0xe5}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x3373c, "libkernel-usrstack-panic-site", {0x48, 0x8d, 0x3d, 0x39}},
            std::tuple<std::uint64_t, const char*, std::array<std::uint8_t, 4>>{
                0x3374f, "libkernel-usrstack-panic-call", {0xe8, 0xdc, 0x3f, 0xfd}}}) {
        const auto address = static_cast<std::uintptr_t>(kernel->load_bias + offset);
        std::array<std::uint8_t, 4> actual{};
        SIZE_T copied{};
        if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                actual.data(), actual.size(), &copied) == 0 || copied != actual.size() ||
            actual != signature) {
            std::fprintf(stderr,
                "USRSTACK-TRACE signature mismatch at libkernel+0x%llx\n",
                static_cast<unsigned long long>(offset));
            continue;
        }
        if (arm_fclose_trace_site(address, label, signature, offset, 8)) ++armed;
    }
    std::fprintf(stderr, "USRSTACK-TRACE libkernel breakpoints armed=%zu\n", armed);
}

bool arm_fopen_trace_sites(const nba16::Ps4LoadedModule& libc) {
    std::size_t armed_count{};
    for (auto& site : fopen_trace_sites) {
        if (site.label == nullptr) continue;
        site.address = static_cast<std::uintptr_t>(
            libc.image_memory().load_bias() + site.offset);
        std::array<std::uint8_t, 4> actual{};
        SIZE_T bytes_read{};
        if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(site.address),
                actual.data(), actual.size(), &bytes_read) == 0 ||
            bytes_read != actual.size() || actual != site.signature) {
            std::fprintf(stderr, "Fopen trace: ignorado +0x%llx (%s), assinatura diferente.\n",
                static_cast<unsigned long long>(site.offset), site.label);
            continue;
        }
        DWORD old_protection{};
        if (VirtualProtect(reinterpret_cast<void*>(site.address), 1,
                PAGE_EXECUTE_READWRITE, &old_protection) == 0) continue;
        site.original = actual[0];
        *reinterpret_cast<std::uint8_t*>(site.address) = 0xcc;
        DWORD ignored_protection{};
        VirtualProtect(reinterpret_cast<void*>(site.address), 1, old_protection,
            &ignored_protection);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(site.address), 1);
        site.armed = true;
        ++armed_count;
    }
    std::fprintf(stderr, "Fopen trace: %zu pontos de execução armados em libc.prx.\n",
        armed_count);
    return armed_count != 0;
}

bool arm_fclose_trace_site(std::uintptr_t address, const char* label,
                           std::array<std::uint8_t, 4> signature,
                           std::uint64_t display_offset = UINT64_MAX,
                           std::uint32_t max_hits = 0) {
    auto it = std::find_if(fopen_trace_sites.begin(), fopen_trace_sites.end(),
        [](const auto& site) { return site.label == nullptr; });
    if (it == fopen_trace_sites.end()) return false;
    it->address = address;
    it->label = label;
    it->signature = signature;
    if (display_offset != UINT64_MAX) it->offset = display_offset;
    it->max_hits = max_hits;
    std::array<std::uint8_t, 4> actual{};
    SIZE_T bytes_read{};
    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
            actual.data(), actual.size(), &bytes_read) == 0 ||
        bytes_read != actual.size() || actual != signature) {
        std::fprintf(stderr, "Fclose trace: assinatura diferente no ponto %s.\n", label);
        it->label = nullptr;
        return false;
    }
    DWORD old_protection{};
    if (VirtualProtect(reinterpret_cast<void*>(address), 1,
            PAGE_EXECUTE_READWRITE, &old_protection) == 0) return false;
    it->original = actual[0];
    *reinterpret_cast<std::uint8_t*>(address) = 0xcc;
    DWORD ignored_protection{};
    VirtualProtect(reinterpret_cast<void*>(address), 1, old_protection, &ignored_protection);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), 1);
    it->armed = true;
    return true;
}

bool patch_guest_heap_free_call(std::uintptr_t fclose_target) {
    std::array<std::uint8_t, 6> plt_instruction{};
    SIZE_T read{};
    if (ReadProcessMemory(GetCurrentProcess(),
            reinterpret_cast<const void*>(fclose_target + 0x18ca0), plt_instruction.data(),
            plt_instruction.size(), &read) == 0 || read != plt_instruction.size() ||
        plt_instruction[0] != 0xff || plt_instruction[1] != 0x25) {
        std::cerr << "Free do buffer de fclose não foi alterado: stub PLT diferente.\n";
        return false;
    }
    std::int32_t displacement{};
    std::memcpy(&displacement, plt_instruction.data() + 2, sizeof(displacement));
    const auto slot_address = fclose_target + 0x18ca6 +
        static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement));
    auto* slot = reinterpret_cast<void*>(slot_address);
    std::uintptr_t previous{};
    SIZE_T pointer_read{};
    if (ReadProcessMemory(GetCurrentProcess(), slot, &previous, sizeof(previous),
            &pointer_read) == 0 || pointer_read != sizeof(previous)) return false;
    const bool unresolved_libc_plt = std::any_of(probe_regions.begin(), probe_regions.end(),
        [previous](const auto& region) {
            return region.name == "libc.prx" && previous >= region.begin && previous < region.end;
        });
    if (!unresolved_libc_plt) {
        std::cerr << "Free do buffer de fclose mantido: destino atual não é stub de libc.\n";
        return false;
    }
    const auto replacement = reinterpret_cast<std::uintptr_t>(
        &nba16::guest_libc_free_fallback);
    DWORD old_protection{};
    if (VirtualProtect(slot, sizeof(replacement), PAGE_READWRITE, &old_protection) == 0)
        return false;
    std::memcpy(slot, &replacement, sizeof(replacement));
    DWORD ignored{};
    VirtualProtect(slot, sizeof(replacement), old_protection, &ignored);
    std::cerr << "Free do buffer de fclose redirecionado para o heap convidado; slot=0x"
              << std::hex << slot_address << " destino anterior=0x" << previous << std::dec << ".\n";
    return true;
}

bool install_guest_libc_file_allocator(std::uintptr_t libc_base,
                                       std::uintptr_t fclose_target) {
    std::array<std::uint8_t, 6> malloc_plt{};
    SIZE_T bytes_read{};
    const auto malloc_site = libc_base + 0x20150;
    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(malloc_site),
            malloc_plt.data(), malloc_plt.size(), &bytes_read) == 0 ||
        bytes_read != malloc_plt.size() || malloc_plt[0] != 0xff || malloc_plt[1] != 0x25) {
        std::cerr << "Adaptador do malloc interno da libc não instalado: stub PLT diferente.\n";
        return false;
    }

    std::int32_t displacement{};
    std::memcpy(&displacement, malloc_plt.data() + 2, sizeof(displacement));
    const auto slot_address = malloc_site + malloc_plt.size() +
        static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement));
    std::uintptr_t original_target{};
    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(slot_address),
            &original_target, sizeof(original_target), &bytes_read) == 0 ||
        bytes_read != sizeof(original_target)) {
        std::cerr << "Adaptador do malloc interno da libc não instalado: GOT ilegível.\n";
        return false;
    }

    const auto libc_region = std::find_if(probe_regions.begin(), probe_regions.end(),
        [original_target](const auto& region) {
            return region.name == "libc.prx" && original_target >= region.begin &&
                   original_target < region.end;
        });
    const auto fallback = reinterpret_cast<std::uintptr_t>(
        &nba16::guest_libc_malloc_fallback);
    if (libc_region == probe_regions.end()) {
        if (original_target == fallback) {
            std::cerr << "Adaptador do malloc interno da libc já estava instalado.\n";
            return true;
        }
        std::cerr << "Adaptador do malloc interno da libc não instalado: destino PLT não é "
                     "o stub interno esperado.\n";
        return false;
    }

    nba16::set_guest_libc_original_malloc(original_target);
    DWORD old_protection{};
    auto* slot = reinterpret_cast<void*>(slot_address);
    if (VirtualProtect(slot, sizeof(fallback), PAGE_READWRITE, &old_protection) == 0) {
        std::cerr << "Adaptador do malloc interno da libc não instalado: GOT protegida.\n";
        return false;
    }
    std::memcpy(slot, &fallback, sizeof(fallback));
    DWORD ignored{};
    VirtualProtect(slot, sizeof(fallback), old_protection, &ignored);
    std::cerr << "Adaptador do malloc interno da libc ligado ao heap guest; alvo anterior=0x"
              << std::hex << original_target << std::dec << ".\n";

    if (fclose_target != 0) {
        patch_guest_heap_free_call(fclose_target);
    } else {
        std::cerr << "Liberação interna de fclose não redirecionada: import não encontrado.\n";
    }
    return true;
}

void* NBA16_GUEST_SYSV_ABI trace_guest_fopen(const char* path, const char* mode) {
    using FopenFunction = void* (NBA16_GUEST_SYSV_ABI *)(const char*, const char*);
    if (diagnostic_fopen_target == 0) return nullptr;
    if (std::getenv("NBA16_TRACE_FS") != nullptr)
        std::fprintf(stderr, "FS eboot-fopen enter path='%s' mode='%s' target=0x%llx\n",
            path == nullptr ? "(null)" : path, mode == nullptr ? "(null)" : mode,
            static_cast<unsigned long long>(diagnostic_fopen_target));
    const auto result = reinterpret_cast<FopenFunction>(diagnostic_fopen_target)(path, mode);
    if (std::getenv("NBA16_TRACE_FS") != nullptr)
        std::fprintf(stderr, "FS eboot-fopen result=%p\n", result);
    return result;
}

std::size_t NBA16_GUEST_SYSV_ABI trace_guest_fread(void* buffer, std::size_t element_size,
                                                   std::size_t element_count, void* stream) {
    using FreadFunction = std::size_t (NBA16_GUEST_SYSV_ABI *)(
        void*, std::size_t, std::size_t, void*);
    if (diagnostic_fread_target == 0) return 0;
    if (stream == nullptr && std::getenv("NBA16_TRACE_FS") != nullptr) {
        const auto caller = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));
        std::fprintf(stderr,
            "FS eboot-fread rejected null FILE* buffer=%p size=%zu count=%zu caller=%p\n",
            buffer, element_size, element_count, reinterpret_cast<void*>(caller));
        return 0;
    }
    if (std::getenv("NBA16_TRACE_FS") != nullptr)
        std::fprintf(stderr, "FS eboot-fread enter buffer=%p size=%zu count=%zu stream=%p\n",
            buffer, element_size, element_count, stream);
    const auto result = reinterpret_cast<FreadFunction>(diagnostic_fread_target)(
        buffer, element_size, element_count, stream);
    if (std::getenv("NBA16_TRACE_FS") != nullptr)
        std::fprintf(stderr, "FS eboot-fread result=%zu\n", result);
    return result;
}

int NBA16_GUEST_SYSV_ABI trace_guest_fclose(void* stream) {
    using FcloseFunction = int (NBA16_GUEST_SYSV_ABI *)(void*);
    if (diagnostic_fclose_target == 0) return -1;
    if (stream == nullptr && std::getenv("NBA16_TRACE_FS") != nullptr) {
        const auto caller = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));
        std::fprintf(stderr, "FS eboot-fclose rejected null FILE* caller=%p\n",
            reinterpret_cast<void*>(caller));
        return -1;
    }
    if (std::getenv("NBA16_TRACE_FS") != nullptr) {
        std::fprintf(stderr, "FS eboot-fclose enter stream=%p\n", stream);
        std::array<unsigned char, 256> code{};
        SIZE_T copied{};
        if (ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(diagnostic_fclose_target), code.data(),
                code.size(), &copied) != 0 && copied != 0) {
            std::fprintf(stderr, "FS eboot-fclose target-bytes=");
            for (SIZE_T index = 0; index < copied; ++index)
                std::fprintf(stderr, "%02x", code[index]);
            std::fputc('\n', stderr);
        }
        constexpr std::array<std::size_t, 7> callees{
            0x170, 0x7650, 0xbc10, 0xbd80, 0xbda0, 0xbde0, 0x18ca0};
        for (const auto offset : callees) {
            std::array<unsigned char, 48> callee{};
            SIZE_T callee_copied{};
            const auto address = diagnostic_fclose_target + offset;
            if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                    callee.data(), callee.size(), &callee_copied) == 0 || callee_copied == 0)
                continue;
            std::fprintf(stderr, "FS fclose-callee +0x%zx=", offset);
            for (SIZE_T index = 0; index < callee_copied; ++index)
                std::fprintf(stderr, "%02x", callee[index]);
            std::fputc('\n', stderr);
        }
        if (stream != nullptr) {
            std::array<unsigned char, 32> stream_state{};
            SIZE_T stream_copied{};
            if (ReadProcessMemory(GetCurrentProcess(), stream, stream_state.data(),
                    stream_state.size(), &stream_copied) != 0 && stream_copied != 0) {
                std::fprintf(stderr, "FS fclose-stream-state=");
                for (SIZE_T index = 0; index < stream_copied; ++index)
                    std::fprintf(stderr, "%02x", stream_state[index]);
                std::fputc('\n', stderr);
            }
        }
        std::array<unsigned char, 64> lock_code{};
        SIZE_T lock_copied{};
        if (ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(diagnostic_fclose_target + 0xbaa0),
                lock_code.data(), lock_code.size(), &lock_copied) != 0 && lock_copied != 0) {
            std::fprintf(stderr, "FS fclose-lock-code=");
            for (SIZE_T index = 0; index < lock_copied; ++index)
                std::fprintf(stderr, "%02x", lock_code[index]);
            std::fputc('\n', stderr);
        }
        std::int32_t close_plt_displacement{};
        std::memcpy(&close_plt_displacement,
            reinterpret_cast<const void*>(diagnostic_fclose_target + 0x18ca2),
            sizeof(close_plt_displacement));
        const auto close_plt_slot = diagnostic_fclose_target + 0x18ca6 +
            static_cast<std::uintptr_t>(static_cast<std::intptr_t>(close_plt_displacement));
        std::uintptr_t close_plt_target{};
        SIZE_T target_copied{};
        ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(close_plt_slot),
            &close_plt_target, sizeof(close_plt_target), &target_copied);
        std::fprintf(stderr, "FS fclose-plt slot=%p target=%p bytes=%zu\n",
            reinterpret_cast<void*>(close_plt_slot),
            reinterpret_cast<void*>(close_plt_target), static_cast<std::size_t>(target_copied));
        for (const auto& region : probe_regions) {
            if (close_plt_target >= region.begin && close_plt_target < region.end) {
                std::fprintf(stderr, "FS fclose-plt owner=%s+0x%llx\n", region.name.c_str(),
                    static_cast<unsigned long long>(close_plt_target - region.load_bias));
                std::array<unsigned char, 32> target_code{};
                SIZE_T target_code_size{};
                if (ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(close_plt_target), target_code.data(),
                        target_code.size(), &target_code_size) != 0 && target_code_size != 0) {
                    std::fprintf(stderr, "FS fclose-plt-target-bytes=");
                    for (SIZE_T index = 0; index < target_code_size; ++index)
                        std::fprintf(stderr, "%02x", target_code[index]);
                    std::fputc('\n', stderr);
                }
                break;
            }
        }
    }
    const auto result = reinterpret_cast<FcloseFunction>(diagnostic_fclose_target)(stream);
    if (std::getenv("NBA16_TRACE_FS") != nullptr)
        std::fprintf(stderr, "FS eboot-fclose result=%d\n", result);
    return result;
}

std::uint64_t NBA16_GUEST_SYSV_ABI trace_guest_fios_open(
    std::uint64_t a, std::uint64_t b, std::uint64_t c,
    std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    using FiosOpenFunction = std::uint64_t (NBA16_GUEST_SYSV_ABI *)(
        std::uint64_t, std::uint64_t, std::uint64_t,
        std::uint64_t, std::uint64_t, std::uint64_t);
    if (diagnostic_fios_open_target == 0) return UINT64_MAX;
    const auto result = reinterpret_cast<FiosOpenFunction>(diagnostic_fios_open_target)(
        a, b, c, d, e, f);
    if (std::getenv("NBA16_TRACE_FS") != nullptr)
        std::fprintf(stderr,
            "FS FiosOpen args=%llx,%llx,%llx,%llx,%llx,%llx -> 0x%llx\n",
            static_cast<unsigned long long>(a), static_cast<unsigned long long>(b),
            static_cast<unsigned long long>(c), static_cast<unsigned long long>(d),
            static_cast<unsigned long long>(e), static_cast<unsigned long long>(f),
            static_cast<unsigned long long>(result));
    return result;
}

std::int64_t NBA16_GUEST_SYSV_ABI trace_guest_fios_close(std::uint64_t attributes,
                                                         std::uint64_t handle) {
    using FiosCloseFunction = std::int64_t (NBA16_GUEST_SYSV_ABI *)(
        std::uint64_t, std::uint64_t);
    if (diagnostic_fios_close_target == 0) return -1;
    const auto result = reinterpret_cast<FiosCloseFunction>(diagnostic_fios_close_target)(
        attributes, handle);
    if (std::getenv("NBA16_TRACE_FS") != nullptr)
        std::fprintf(stderr, "FS FiosCloseSync attrs=0x%llx handle=0x%llx -> %lld\n",
            static_cast<unsigned long long>(attributes),
            static_cast<unsigned long long>(handle), static_cast<long long>(result));
    return result;
}

LONG CALLBACK report_guest_exception(PEXCEPTION_POINTERS pointers) {
    if (pointers == nullptr || pointers->ExceptionRecord == nullptr ||
        pointers->ContextRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const auto* record = pointers->ExceptionRecord;
    auto* context = pointers->ContextRecord;
    if (record->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        (context->Dr6 & 1ULL) != 0 && context->Dr0 ==
            active_scheduler_state_address.load(std::memory_order_acquire)) {
        const auto target = static_cast<std::uintptr_t>(context->Dr0);
        const auto rip = static_cast<std::uintptr_t>(context->Rip);
        const ProbeRegion* owner = nullptr;
        for (const auto& region : probe_regions) {
            if (rip >= region.begin && rip < region.end) {
                owner = &region;
                break;
            }
        }
        const auto write_index = scheduler_state_write_count.fetch_add(
            1, std::memory_order_acq_rel) + 1;
        std::uint64_t state_after{};
        SIZE_T state_bytes{};
        (void)ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(target),
            &state_after, sizeof(state_after), &state_bytes);
        const bool shader_bound_watch =
            std::getenv("NBA16_TRACE_SHADER_BOUND_WRITES") != nullptr;
        if (write_index == 1 || write_index == 7) {
            const auto object = target - (shader_bound_watch ? 0x30U : 0x38U);
            std::array<std::uint64_t, 9> object_words{};
            SIZE_T object_bytes{};
            (void)ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(object), object_words.data(),
                sizeof(object_words), &object_bytes);
            std::uint64_t vtable_methods[2]{};
            SIZE_T vtable_bytes{};
            if (object_bytes >= sizeof(std::uint64_t) && object_words[0] != 0) {
                (void)ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(object_words[0] + 0x20),
                    vtable_methods, sizeof(vtable_methods), &vtable_bytes);
            }
            std::fprintf(stderr,
                "%s object write=%u object=0x%llx qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx vtable_methods20_28=0x%llx,0x%llx\n",
                shader_bound_watch ? "SHADER-BOUND" : "SCHED-STATE",
                write_index, static_cast<unsigned long long>(object),
                static_cast<unsigned long long>(object_words[0]),
                static_cast<unsigned long long>(object_words[1]),
                static_cast<unsigned long long>(object_words[2]),
                static_cast<unsigned long long>(object_words[3]),
                static_cast<unsigned long long>(object_words[4]),
                static_cast<unsigned long long>(object_words[5]),
                static_cast<unsigned long long>(object_words[6]),
                static_cast<unsigned long long>(object_words[7]),
                static_cast<unsigned long long>(object_words[8]),
                static_cast<unsigned long long>(vtable_methods[0]),
                static_cast<unsigned long long>(vtable_methods[1]));
        }
        if (owner != nullptr) {
            std::fprintf(stderr,
                "%s write=%u address=0x%llx state=%llx after=%s+0x%llx "
                "rip=0x%llx rax=0x%llx rcx=0x%llx rdx=0x%llx "
                "rsi=0x%llx rdi=0x%llx r12=0x%llx r13=0x%llx\n",
                shader_bound_watch ? "SHADER-BOUND" : "SCHED-STATE",
                write_index, static_cast<unsigned long long>(target),
                static_cast<unsigned long long>(state_bytes == sizeof(state_after)
                    ? state_after : UINT64_MAX), owner->name.c_str(),
                static_cast<unsigned long long>(rip - owner->load_bias),
                static_cast<unsigned long long>(rip),
                static_cast<unsigned long long>(context->Rax),
                static_cast<unsigned long long>(context->Rcx),
                static_cast<unsigned long long>(context->Rdx),
                static_cast<unsigned long long>(context->Rsi),
                static_cast<unsigned long long>(context->Rdi),
                static_cast<unsigned long long>(context->R12),
                static_cast<unsigned long long>(context->R13));
        } else {
            std::fprintf(stderr,
                "%s write=%u address=0x%llx state=%llx after host/unknown rip=0x%llx\n",
                shader_bound_watch ? "SHADER-BOUND" : "SCHED-STATE",
                write_index, static_cast<unsigned long long>(target),
                static_cast<unsigned long long>(state_bytes == sizeof(state_after)
                    ? state_after : UINT64_MAX), static_cast<unsigned long long>(rip));
        }
        if (write_index >= 128) {
            scheduler_state_watchpoint_hit.store(true, std::memory_order_release);
            context->Dr0 = 0;
            context->Dr7 &= ~0xF0003ULL;
        }
        context->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        const auto kernel = std::find_if(probe_regions.begin(), probe_regions.end(),
            [](const auto& region) { return region.name == "libkernel" ||
                                            region.name == "libkernel.prx"; });
        if (kernel != probe_regions.end()) {
            std::array<std::uint64_t, 7> state{};
            constexpr std::array<std::size_t, 7> offsets{
                0x8df80, 0x8df88, 0x8dc70, 0x8dc78, 0x8dc80, 0x8e430, 0x58380};
            bool complete = true;
            for (std::size_t index = 0; index < offsets.size(); ++index) {
                SIZE_T read{};
                if (ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(kernel->load_bias + offsets[index]),
                        &state[index], sizeof(state[index]), &read) == 0 ||
                    read != sizeof(state[index])) complete = false;
            }
            if (complete) {
                char line[320]{};
                const auto count = std::snprintf(line, sizeof(line),
                    "libkernel-thread-state mspace=%llx count=%llu sync=%llx,%llx,%llx,%llx,%llx\n",
                    static_cast<unsigned long long>(state[0]),
                    static_cast<unsigned long long>(state[1]),
                    static_cast<unsigned long long>(state[2]),
                    static_cast<unsigned long long>(state[3]),
                    static_cast<unsigned long long>(state[4]),
                    static_cast<unsigned long long>(state[5]),
                    static_cast<unsigned long long>(state[6]));
                if (count > 0) {
                    DWORD written{};
                    WriteFile(GetStdHandle(STD_ERROR_HANDLE), line,
                        static_cast<DWORD>(count), &written, nullptr);
                }
            }
        }
    }
    if (record->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        shader_state_instruction_trace_active) {
        const auto rip = static_cast<std::uintptr_t>(context->Rip);
        const ProbeRegion* owner = nullptr;
        for (const auto& region : probe_regions) {
            if (rip >= region.begin && rip < region.end) {
                owner = &region;
                break;
            }
        }
        if (owner != nullptr) {
            std::array<std::uint8_t, 12> code{};
            SIZE_T copied{};
            (void)ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(rip),
                code.data(), code.size(), &copied);
            std::fprintf(stderr,
                "SHADER-CONT step=%u module=%s+0x%llx bytes=",
                ++shader_state_instruction_trace_steps, owner->name.c_str(),
                static_cast<unsigned long long>(rip - owner->load_bias));
            for (SIZE_T index = 0; index < copied; ++index)
                std::fprintf(stderr, "%02x", code[index]);
            std::fprintf(stderr,
                " rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx "
                "r12=%llx r13=%llx r14=%llx r15=%llx rsp=%llx\n",
                static_cast<unsigned long long>(context->Rax),
                static_cast<unsigned long long>(context->Rbx),
                static_cast<unsigned long long>(context->Rcx),
                static_cast<unsigned long long>(context->Rdx),
                static_cast<unsigned long long>(context->Rsi),
                static_cast<unsigned long long>(context->Rdi),
                static_cast<unsigned long long>(context->R12),
                static_cast<unsigned long long>(context->R13),
                static_cast<unsigned long long>(context->R14),
                static_cast<unsigned long long>(context->R15),
                static_cast<unsigned long long>(context->Rsp));
        } else if (++shader_state_instruction_trace_host_steps >= 3000) {
            std::fputs("SHADER-CONT stopped while stepping host code\n", stderr);
            shader_state_instruction_trace_active = false;
            context->EFlags &= ~0x100UL;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        const auto diagnostic_step_limit =
            std::getenv("NBA16_TRACE_MAIN_DISPATCH_CONTINUE") != nullptr
                ? 900U
                : 240U;
        if (shader_state_instruction_trace_steps >= diagnostic_step_limit) {
            std::fputs("SHADER-CONT step limit reached\n", stderr);
            shader_state_instruction_trace_active = false;
            context->EFlags &= ~0x100UL;
        } else {
            context->EFlags |= 0x100UL;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (record->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        fs_eof_instruction_trace_active) {
        const auto rip = static_cast<std::uintptr_t>(context->Rip);
        const ProbeRegion* owner = nullptr;
        for (const auto& region : probe_regions) {
            if (rip >= region.begin && rip < region.end) {
                owner = &region;
                break;
            }
        }
        if (owner != nullptr) {
            std::array<unsigned char, 16> code{};
            SIZE_T copied{};
            (void)ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(rip),
                code.data(), code.size(), &copied);
            std::fprintf(stderr,
                "GUEST-INST step=%u module=%s offset=0x%llx bytes=",
                ++fs_eof_instruction_trace_guest_steps, owner->name.c_str(),
                static_cast<unsigned long long>(rip - owner->load_bias));
            for (SIZE_T index = 0; index < copied; ++index)
                std::fprintf(stderr, "%02x", code[index]);
            std::fprintf(stderr,
                " rax=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx r15=%llx rsp=%llx\n",
                static_cast<unsigned long long>(context->Rax),
                static_cast<unsigned long long>(context->Rcx),
                static_cast<unsigned long long>(context->Rdx),
                static_cast<unsigned long long>(context->Rsi),
                static_cast<unsigned long long>(context->Rdi),
                static_cast<unsigned long long>(context->R15),
                static_cast<unsigned long long>(context->Rsp));
            if (owner->name == "eboot.bin" &&
                rip - owner->load_bias == 0x688d3eU) {
                std::array<std::uint64_t, 16> task_words{};
                SIZE_T task_bytes{};
                (void)ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->R15), task_words.data(),
                    sizeof(task_words), &task_bytes);
                if (task_bytes == sizeof(task_words)) {
                    std::fprintf(stderr,
                        "FS-EOF-INST completed-task object=0x%llx result=0x%llx "
                        "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                        static_cast<unsigned long long>(context->R15),
                        static_cast<unsigned long long>(context->Rax),
                        static_cast<unsigned long long>(task_words[0]),
                        static_cast<unsigned long long>(task_words[1]),
                        static_cast<unsigned long long>(task_words[2]),
                        static_cast<unsigned long long>(task_words[3]),
                        static_cast<unsigned long long>(task_words[4]),
                        static_cast<unsigned long long>(task_words[5]),
                        static_cast<unsigned long long>(task_words[6]),
                        static_cast<unsigned long long>(task_words[7]),
                        static_cast<unsigned long long>(task_words[8]),
                        static_cast<unsigned long long>(task_words[9]),
                        static_cast<unsigned long long>(task_words[10]),
                        static_cast<unsigned long long>(task_words[11]),
                        static_cast<unsigned long long>(task_words[12]),
                        static_cast<unsigned long long>(task_words[13]),
                        static_cast<unsigned long long>(task_words[14]),
                        static_cast<unsigned long long>(task_words[15]));
                    for (const auto object_address : {
                            task_words[4], std::uint64_t{0x1039be8500}}) {
                        std::array<std::uint64_t, 8> object_words{};
                        SIZE_T object_bytes{};
                        (void)ReadProcessMemory(GetCurrentProcess(),
                            reinterpret_cast<const void*>(object_address),
                            object_words.data(), sizeof(object_words), &object_bytes);
                        if (object_bytes == sizeof(object_words)) {
                            std::fprintf(stderr,
                                "FS-EOF-INST task-linked-object address=0x%llx "
                                "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                                static_cast<unsigned long long>(object_address),
                                static_cast<unsigned long long>(object_words[0]),
                                static_cast<unsigned long long>(object_words[1]),
                                static_cast<unsigned long long>(object_words[2]),
                                static_cast<unsigned long long>(object_words[3]),
                                static_cast<unsigned long long>(object_words[4]),
                                static_cast<unsigned long long>(object_words[5]),
                                static_cast<unsigned long long>(object_words[6]),
                                static_cast<unsigned long long>(object_words[7]));
                        }
                    }
                }
            }
            if (owner->name == "eboot.bin" &&
                rip - owner->load_bias == 0x688d7eU && context->Rbp >= 0x38U) {
                std::uint64_t callback_target{};
                SIZE_T callback_bytes{};
                (void)ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rbp - 0x38U),
                    &callback_target, sizeof(callback_target), &callback_bytes);
                if (callback_bytes == sizeof(callback_target))
                    std::fprintf(stderr,
                        "FS-EOF-INST worker-callback target=0x%llx object=0x%llx\n",
                        static_cast<unsigned long long>(callback_target),
                        static_cast<unsigned long long>(context->Rdi));
            }
            if (owner->name == "eboot.bin" &&
                rip - owner->load_bias == 0xa9060U) {
                if (!fs_eof_instruction_trace_follow_wait) {
                    std::fputs("GUEST-INST stopped at worker wait entry\n", stderr);
                    for (std::size_t index = 0; index < 10; ++index) {
                        std::uintptr_t candidate{};
                        SIZE_T stack_bytes{};
                        const auto slot = context->Rsp + index * sizeof(candidate);
                        (void)ReadProcessMemory(GetCurrentProcess(),
                            reinterpret_cast<const void*>(slot), &candidate,
                            sizeof(candidate), &stack_bytes);
                        const ProbeRegion* frame_owner = nullptr;
                        if (stack_bytes == sizeof(candidate)) {
                            for (const auto& region : probe_regions) {
                                if (candidate >= region.begin && candidate < region.end) {
                                    frame_owner = &region;
                                    break;
                                }
                            }
                        }
                        if (stack_bytes == sizeof(candidate)) {
                            if (frame_owner != nullptr) {
                                std::fprintf(stderr,
                                    "GUEST-INST wait-stack[%zu]=%s+0x%llx raw=0x%llx\n",
                                    index, frame_owner->name.c_str(),
                                    static_cast<unsigned long long>(candidate -
                                        frame_owner->load_bias),
                                    static_cast<unsigned long long>(candidate));
                            } else {
                                std::fprintf(stderr,
                                    "GUEST-INST wait-stack[%zu]=host/unknown raw=0x%llx\n",
                                    index, static_cast<unsigned long long>(candidate));
                            }
                        }
                    }
                    context->EFlags &= ~0x100UL;
                    fs_eof_instruction_trace_active = false;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                const auto return_address = owner->load_bias + 0x688d5dU;
                DWORD old_protection{};
                if (VirtualProtect(reinterpret_cast<void*>(return_address), 1,
                        PAGE_EXECUTE_READWRITE, &old_protection) != 0) {
                    fs_eof_wait_return_original =
                        *reinterpret_cast<const std::uint8_t*>(return_address);
                    *reinterpret_cast<std::uint8_t*>(return_address) = 0xcc;
                    DWORD ignored_protection{};
                    VirtualProtect(reinterpret_cast<void*>(return_address), 1,
                        old_protection, &ignored_protection);
                    FlushInstructionCache(GetCurrentProcess(),
                        reinterpret_cast<void*>(return_address), 1);
                    fs_eof_wait_return_breakpoint = return_address;
                    fs_eof_wait_return_armed = true;
                    std::fprintf(stderr,
                        "GUEST-INST paused at worker wait; return breakpoint=0x%llx\n",
                        static_cast<unsigned long long>(return_address));
                } else {
                    std::fputs("GUEST-INST stopped at worker wait; could not arm return breakpoint\n",
                        stderr);
                }
                context->EFlags &= ~0x100UL;
                fs_eof_instruction_trace_active = false;
            } else if (fs_eof_instruction_trace_guest_steps >= 180) {
                context->EFlags &= ~0x100UL;
                fs_eof_instruction_trace_active = false;
            } else {
                context->EFlags |= 0x100UL;
            }
        } else if (++fs_eof_instruction_trace_host_steps >=
                   fs_eof_instruction_trace_remaining) {
            std::fputs("GUEST-INST stopped before returning to guest code\n", stderr);
            context->EFlags &= ~0x100UL;
            fs_eof_instruction_trace_active = false;
        } else {
            context->EFlags |= 0x100UL;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (record->ExceptionCode == EXCEPTION_BREAKPOINT && fs_eof_wait_return_armed &&
        (reinterpret_cast<std::uintptr_t>(record->ExceptionAddress) ==
                fs_eof_wait_return_breakpoint ||
         static_cast<std::uintptr_t>(context->Rip) == fs_eof_wait_return_breakpoint ||
         static_cast<std::uintptr_t>(context->Rip) == fs_eof_wait_return_breakpoint + 1)) {
        const auto address = fs_eof_wait_return_breakpoint;
        DWORD old_protection{};
        if (VirtualProtect(reinterpret_cast<void*>(address), 1,
                PAGE_EXECUTE_READWRITE, &old_protection) != 0) {
            *reinterpret_cast<std::uint8_t*>(address) = fs_eof_wait_return_original;
            DWORD ignored_protection{};
            VirtualProtect(reinterpret_cast<void*>(address), 1, old_protection,
                &ignored_protection);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), 1);
        }
        fs_eof_wait_return_armed = false;
        context->Rip = address;
        context->EFlags |= 0x100UL;
        fs_eof_instruction_trace_active = true;
        fs_eof_instruction_trace_remaining = 20000;
        fs_eof_instruction_trace_guest_steps = 0;
        fs_eof_instruction_trace_host_steps = 0;
        std::fputs("GUEST-INST worker woke; tracing after wait return\n", stderr);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (record->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        jm_worker_instruction_trace_active) {
        const auto rip = static_cast<std::uintptr_t>(context->Rip);
        const ProbeRegion* owner = nullptr;
        for (const auto& region : probe_regions) {
            if (rip >= region.begin && rip < region.end) {
                owner = &region;
                break;
            }
        }
        char line[384]{};
        const auto offset = owner != nullptr ? rip - owner->load_bias : rip;
        const int count = std::snprintf(line, sizeof(line),
            "JM-INST step=%u module=%s rip=0x%llx offset=0x%llx "
            "rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx rsi=0x%llx "
            "rdi=0x%llx r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx\n",
            201U - jm_worker_instruction_trace_remaining,
            owner != nullptr ? owner->name.c_str() : "host/unknown",
            static_cast<unsigned long long>(rip),
            static_cast<unsigned long long>(offset),
            static_cast<unsigned long long>(context->Rax),
            static_cast<unsigned long long>(context->Rbx),
            static_cast<unsigned long long>(context->Rcx),
            static_cast<unsigned long long>(context->Rdx),
            static_cast<unsigned long long>(context->Rsi),
            static_cast<unsigned long long>(context->Rdi),
            static_cast<unsigned long long>(context->R12),
            static_cast<unsigned long long>(context->R13),
            static_cast<unsigned long long>(context->R14),
            static_cast<unsigned long long>(context->R15));
        if (count > 0) {
            DWORD written{};
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), line,
                static_cast<DWORD>(std::min<int>(count, sizeof(line) - 1)),
                &written, nullptr);
        }
        if (jm_worker_instruction_trace_remaining > 0)
            --jm_worker_instruction_trace_remaining;
        if (jm_worker_instruction_trace_remaining == 0) {
            context->EFlags &= ~0x100UL;
            jm_worker_instruction_trace_active = false;
        } else {
            context->EFlags |= 0x100UL;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (record->ExceptionCode == EXCEPTION_SINGLE_STEP && fopen_trace_step_site >= 0) {
        auto& site = fopen_trace_sites[static_cast<std::size_t>(fopen_trace_step_site)];
        context->EFlags &= ~0x100UL;
        DWORD old_protection{};
        if (site.armed && VirtualProtect(reinterpret_cast<void*>(site.address), 1,
                PAGE_EXECUTE_READWRITE, &old_protection) != 0) {
            *reinterpret_cast<std::uint8_t*>(site.address) = 0xcc;
            DWORD ignored_protection{};
            VirtualProtect(reinterpret_cast<void*>(site.address), 1, old_protection,
                &ignored_protection);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(site.address), 1);
        }
        fopen_trace_step_site = -1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (record->ExceptionCode == EXCEPTION_BREAKPOINT) {
        const auto rip = static_cast<std::uintptr_t>(context->Rip);
        for (std::size_t index = 0; index < fopen_trace_sites.size(); ++index) {
            auto& site = fopen_trace_sites[index];
            if (!site.armed || (rip != site.address && rip != site.address + 1)) continue;
            DWORD old_protection{};
            if (VirtualProtect(reinterpret_cast<void*>(site.address), 1,
                    PAGE_EXECUTE_READWRITE, &old_protection) == 0) break;
            *reinterpret_cast<std::uint8_t*>(site.address) = site.original;
            DWORD ignored_protection{};
            VirtualProtect(reinterpret_cast<void*>(site.address), 1, old_protection,
                &ignored_protection);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(site.address), 1);
            const bool stop_tracing = site.max_hits != 0 && site.hit_count >= site.max_hits;
            ++site.hit_count;
            char line[512]{};
            std::uintptr_t return_address{};
            SIZE_T return_address_bytes{};
            ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(context->Rsp), &return_address,
                sizeof(return_address), &return_address_bytes);
            std::uintptr_t indirect_target{};
            std::uintptr_t target_slot{};
            if (std::strcmp(site.label, "eboot-callback-indirect-call") == 0) {
                target_slot = context->R13 + context->Rax * sizeof(std::uintptr_t) + 0x388;
            } else if (std::strcmp(site.label, "shader-queue-method-listener-call") == 0) {
                target_slot = context->Rax + 0x28;
            } else if (std::strcmp(site.label, "shader-queue-method-filter-call") == 0) {
                target_slot = context->Rax + 0x48;
            } else if (std::strcmp(site.label, "shader-bound-source-vcall") == 0) {
                target_slot = context->Rax + 0x28;
            } else if (std::strcmp(site.label,
                           "shader-state-source-operation-call") == 0) {
                target_slot = context->Rax + 0x78;
            } else if (std::strcmp(site.label,
                           "shader-bound-query-helper-dispatch") == 0) {
                std::int32_t displacement{};
                SIZE_T displacement_bytes{};
                if (ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(site.address + 2),
                        &displacement, sizeof(displacement), &displacement_bytes) != 0 &&
                    displacement_bytes == sizeof(displacement)) {
                    target_slot = static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(site.address + 6) + displacement);
                }
            }
            if (target_slot != 0) {
                SIZE_T target_bytes{};
                ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(target_slot),
                    &indirect_target, sizeof(indirect_target), &target_bytes);
                if (target_bytes != sizeof(indirect_target)) indirect_target = 0;
            }
            const int count = std::snprintf(line, sizeof(line),
                "Guest trace +0x%llx %s: rax=%llx rbx=%llx rcx=%llx rdx=%llx "
                "rsi=%llx rdi=%llx r8=%llx r9=%llx r12=%llx r14=%llx r15=%llx "
                "rip=%llx rsp=%llx return=%llx indirect_target=%llx\n",
                static_cast<unsigned long long>(site.offset), site.label,
                static_cast<unsigned long long>(context->Rax),
                static_cast<unsigned long long>(context->Rbx),
                static_cast<unsigned long long>(context->Rcx),
                static_cast<unsigned long long>(context->Rdx),
                static_cast<unsigned long long>(context->Rsi),
                static_cast<unsigned long long>(context->Rdi),
                static_cast<unsigned long long>(context->R8),
                static_cast<unsigned long long>(context->R9),
                static_cast<unsigned long long>(context->R12),
                static_cast<unsigned long long>(context->R14),
                static_cast<unsigned long long>(context->R15),
                static_cast<unsigned long long>(context->Rip),
                static_cast<unsigned long long>(context->Rsp),
                static_cast<unsigned long long>(return_address),
                static_cast<unsigned long long>(indirect_target));
            if (count > 0) {
                DWORD written{};
                WriteFile(GetStdHandle(STD_ERROR_HANDLE), line,
                    static_cast<DWORD>(std::min<int>(count, sizeof(line) - 1)),
                    &written, nullptr);
            }
            if (std::strcmp(site.label, "shader-main-state-getter-call") == 0 ||
                std::strcmp(site.label, "shader-main-state-getter-call-2") == 0) {
                std::uint64_t field{};
                SIZE_T bytes{};
                const auto queried_object = static_cast<std::uintptr_t>(context->Rsi);
                if (queried_object != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(queried_object + 0x38),
                        &field, sizeof(field), &bytes);
                write_atomic_diagnostic(
                    "SHADER-STATE main-getter before label=%s receiver=%llx queried=%llx field38=%llx valid=%u\n",
                    site.label, static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(queried_object),
                    static_cast<unsigned long long>(field),
                    bytes == sizeof(field) ? 1u : 0u);
            }
            if (std::strcmp(site.label, "shader-main-state-getter-return") == 0 ||
                std::strcmp(site.label, "shader-main-state-getter-return-2") == 0) {
                write_atomic_diagnostic(
                    "SHADER-STATE main-getter after label=%s result=%llx\n",
                    site.label, static_cast<unsigned long long>(context->Rax));
            }
            if (std::strcmp(site.label, "shader-state-update-call") == 0) {
                std::uint64_t before{};
                SIZE_T bytes{};
                shader_state_update_object = static_cast<std::uintptr_t>(context->Rdi);
                if (context->Rdi != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rdi + 0x38),
                        &before, sizeof(before), &bytes);
                write_atomic_diagnostic(
                    "SHADER-STATE update-before object=%llx field38=%llx requested=%llx valid=%u\n",
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(before),
                    static_cast<unsigned long long>(context->Rdx),
                    bytes == sizeof(before) ? 1u : 0u);
            }
            if (std::strcmp(site.label, "shader-state-update-return") == 0) {
                std::uint64_t after{};
                SIZE_T bytes{};
                if (shader_state_update_object != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(shader_state_update_object + 0x38),
                        &after, sizeof(after), &bytes);
                write_atomic_diagnostic(
                    "SHADER-STATE update-after object=%llx field38=%llx valid=%u result=%llx\n",
                    static_cast<unsigned long long>(shader_state_update_object),
                    static_cast<unsigned long long>(after),
                    bytes == sizeof(after) ? 1u : 0u,
                    static_cast<unsigned long long>(context->Rax));
                shader_state_update_object = 0;
            }
            if (std::strcmp(site.label,
                    "shader-state-source-operation-return") == 0) {
                std::uint64_t object70{};
                std::uint64_t object78{};
                std::uint64_t returned_local{};
                SIZE_T bytes70{};
                SIZE_T bytes78{};
                SIZE_T bytes_local{};
                if (context->R14 != 0) {
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->R14 + 0x70),
                        &object70, sizeof(object70), &bytes70);
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->R14 + 0x78),
                        &object78, sizeof(object78), &bytes78);
                }
                if (context->Rbp >= 0x90)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rbp - 0x90),
                        &returned_local, sizeof(returned_local), &bytes_local);
                std::fprintf(stderr,
                    "SHADER-STATE source-operation result: rax=%llx "
                    "state70=%llx state78=%llx local_m90=%llx "
                    "valid=%u/%u/%u\n",
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(object70),
                    static_cast<unsigned long long>(object78),
                    static_cast<unsigned long long>(returned_local),
                    bytes70 == sizeof(object70) ? 1u : 0u,
                    bytes78 == sizeof(object78) ? 1u : 0u,
                    bytes_local == sizeof(returned_local) ? 1u : 0u);
            }
            if (std::strcmp(site.label, "exception-guard-compare") == 0) {
                std::uint64_t saved_guard{};
                std::uint64_t pointed_guard{};
                std::uint64_t virtual_target{};
                SIZE_T saved_bytes{};
                SIZE_T pointed_bytes{};
                SIZE_T target_bytes{};
                if (context->Rbp >= 0x28)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rbp - 0x28),
                        &saved_guard, sizeof(saved_guard), &saved_bytes);
                if (context->R12 != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->R12),
                        &pointed_guard, sizeof(pointed_guard), &pointed_bytes);
                if (context->Rbx != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rbx),
                        &virtual_target, sizeof(virtual_target), &target_bytes);
                const ProbeRegion* target_owner = nullptr;
                for (const auto& region : probe_regions) {
                    if (virtual_target >= region.begin && virtual_target < region.end) {
                        target_owner = &region;
                        break;
                    }
                }
                std::fprintf(stderr,
                    "EXCEPTION-GUARD %s rax=%llx saved=0x%llx[%llu] "
                    "r12=0x%llx pointed=0x%llx[%llu] vcall=0x%llx target=%s+0x%llx\n",
                    site.label,
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(saved_guard),
                    static_cast<unsigned long long>(saved_bytes),
                    static_cast<unsigned long long>(context->R12),
                    static_cast<unsigned long long>(pointed_guard),
                    static_cast<unsigned long long>(pointed_bytes),
                    static_cast<unsigned long long>(virtual_target),
                    target_owner == nullptr ? "unknown" : target_owner->name.c_str(),
                    static_cast<unsigned long long>(target_owner == nullptr ? 0 :
                        virtual_target - target_owner->load_bias));
            }
            if (std::strcmp(site.label, "exception-init-helper-call") == 0) {
                std::int32_t displacement{};
                SIZE_T displacement_bytes{};
                (void)ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(site.address + 1),
                    &displacement, sizeof(displacement), &displacement_bytes);
                const auto target = displacement_bytes == sizeof(displacement)
                    ? static_cast<std::uint64_t>(static_cast<std::intptr_t>(site.address + 5) +
                        displacement) : 0;
                std::array<std::uint64_t, 6> object{};
                SIZE_T object_bytes{};
                if (context->Rdi != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rdi), object.data(),
                        sizeof(object), &object_bytes);
                const auto target_owner = std::find_if(probe_regions.begin(),
                    probe_regions.end(), [&](const ProbeRegion& region) {
                        return target >= region.begin && target < region.end;
                    });
                std::fprintf(stderr,
                    "INIT-HELPER call rdi=0x%llx rsi=0x%llx rdx=0x%llx "
                    "target=%s+0x%llx object_bytes=%llu object=%llx,%llx,%llx,%llx,%llx,%llx\n",
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    target_owner == probe_regions.end() ? "unknown" : target_owner->name.c_str(),
                    static_cast<unsigned long long>(target_owner == probe_regions.end() ? 0 :
                        target - target_owner->load_bias),
                    static_cast<unsigned long long>(object_bytes),
                    static_cast<unsigned long long>(object[0]),
                    static_cast<unsigned long long>(object[1]),
                    static_cast<unsigned long long>(object[2]),
                    static_cast<unsigned long long>(object[3]),
                    static_cast<unsigned long long>(object[4]),
                    static_cast<unsigned long long>(object[5]));
            }
            if (std::strcmp(site.label, "shader-bound-getter-entry") == 0 &&
                site.hit_count <= 8) {
                std::array<std::uint64_t, 8> object_words{};
                SIZE_T object_bytes{};
                if (context->Rdi != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rdi), object_words.data(),
                        sizeof(object_words), &object_bytes);
                std::fprintf(stderr,
                    "SHADER-BOUND getter-this=%llx bytes=%llu fields=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(object_bytes),
                    static_cast<unsigned long long>(object_words[0]),
                    static_cast<unsigned long long>(object_words[1]),
                    static_cast<unsigned long long>(object_words[2]),
                    static_cast<unsigned long long>(object_words[3]),
                    static_cast<unsigned long long>(object_words[4]),
                    static_cast<unsigned long long>(object_words[5]),
                    static_cast<unsigned long long>(object_words[6]),
                    static_cast<unsigned long long>(object_words[7]));
            }
            if (std::strcmp(site.label, "shader-bound-getter-dispatch") == 0 &&
                site.hit_count <= 8) {
                const auto target_region = std::find_if(probe_regions.begin(),
                    probe_regions.end(), [&](const ProbeRegion& region) {
                        return context->R8 >= region.begin && context->R8 < region.end;
                    });
                std::uintptr_t object_vtable{};
                std::uintptr_t method_target{};
                SIZE_T object_bytes{};
                SIZE_T method_bytes{};
                (void)ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rdi), &object_vtable,
                    sizeof(object_vtable), &object_bytes);
                if (object_bytes == sizeof(object_vtable))
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(object_vtable + 0x50),
                        &method_target, sizeof(method_target), &method_bytes);
                const auto method_region = std::find_if(probe_regions.begin(),
                    probe_regions.end(), [&](const ProbeRegion& region) {
                        return method_target >= region.begin && method_target < region.end;
                    });
                std::fprintf(stderr,
                    "SHADER-BOUND getter-dispatch target=%s+0x%llx address=%llx "
                    "args=%llx,%llx,%llx,%llx rsp=%llx vtable=%llx slot50=%s+0x%llx address=%llx\n",
                    target_region == probe_regions.end() ? "unknown" : target_region->name.c_str(),
                    static_cast<unsigned long long>(target_region == probe_regions.end() ? 0 :
                        context->R8 - target_region->load_bias),
                    static_cast<unsigned long long>(context->R8),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->Rsp),
                    static_cast<unsigned long long>(object_vtable),
                    method_region == probe_regions.end() ? "unknown" : method_region->name.c_str(),
                    static_cast<unsigned long long>(method_region == probe_regions.end() ? 0 :
                        method_target - method_region->load_bias),
                    static_cast<unsigned long long>(method_target));
            }
            if (std::strcmp(site.label, "shader-bound-query-helper-dispatch") == 0 &&
                site.hit_count <= 12) {
                const auto target_region = std::find_if(probe_regions.begin(),
                    probe_regions.end(), [&](const ProbeRegion& region) {
                        return indirect_target >= region.begin &&
                               indirect_target < region.end;
                    });
                std::uint64_t input_words[4]{};
                SIZE_T input_bytes{};
                if (context->Rsi != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rsi), input_words,
                        sizeof(input_words), &input_bytes);
                std::fprintf(stderr,
                    "SHADER-BOUND helper-dispatch target=%s+0x%llx address=%llx got=%llx args=%llx,%llx,%llx,%llx input_bytes=%llu input=%llx,%llx,%llx,%llx\n",
                    target_region == probe_regions.end() ? "unknown" : target_region->name.c_str(),
                    static_cast<unsigned long long>(target_region == probe_regions.end() ? 0 :
                        indirect_target - target_region->load_bias),
                    static_cast<unsigned long long>(indirect_target),
                    static_cast<unsigned long long>(target_slot),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(input_bytes),
                    static_cast<unsigned long long>(input_words[0]),
                    static_cast<unsigned long long>(input_words[1]),
                    static_cast<unsigned long long>(input_words[2]),
                    static_cast<unsigned long long>(input_words[3]));
            }
            if (std::strcmp(site.label, "shader-bound-getter-method-entry") == 0 &&
                site.hit_count <= 8) {
                std::array<std::uint64_t, 8> receiver_words{};
                SIZE_T receiver_bytes{};
                if (context->Rdi != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rdi), receiver_words.data(),
                        sizeof(receiver_words), &receiver_bytes);
                std::fprintf(stderr,
                    "SHADER-BOUND method-entry this=%llx bytes=%llu fields=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx args-rsi=%llx rdx=%llx rcx=%llx rsp=%llx\n",
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(receiver_bytes),
                    static_cast<unsigned long long>(receiver_words[0]),
                    static_cast<unsigned long long>(receiver_words[1]),
                    static_cast<unsigned long long>(receiver_words[2]),
                    static_cast<unsigned long long>(receiver_words[3]),
                    static_cast<unsigned long long>(receiver_words[4]),
                    static_cast<unsigned long long>(receiver_words[5]),
                    static_cast<unsigned long long>(receiver_words[6]),
                    static_cast<unsigned long long>(receiver_words[7]),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->Rsp));
            }
            if (std::strcmp(site.label, "shader-bound-getter-method-return") == 0 &&
                site.hit_count <= 8) {
                std::fprintf(stderr,
                    "SHADER-BOUND method-return rax=%llx rdx=%llx rsp=%llx\n",
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rsp));
            }
            if ((std::strcmp(site.label, "shader-bound-query-method-entry") == 0 ||
                 std::strcmp(site.label, "shader-bound-query-helper-return") == 0 ||
                 std::strcmp(site.label, "shader-bound-query-result") == 0) &&
                site.hit_count <= 8) {
                std::array<std::uint64_t, 18> frame_words{};
                SIZE_T frame_bytes{};
                const auto frame_start = context->Rbp >= 0x88
                    ? context->Rbp - 0x88 : 0;
                if (frame_start != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(frame_start), frame_words.data(),
                        sizeof(frame_words), &frame_bytes);
                std::uint32_t query_id{};
                SIZE_T query_bytes{};
                if (context->Rsi != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rsi), &query_id,
                        sizeof(query_id), &query_bytes);
                std::fprintf(stderr,
                    "SHADER-BOUND query-%s rdi=%llx rsi=%llx id=%x query_bytes=%llu rax=%llx rcx=%llx rbp=%llx frame_bytes=%llu local_result=%llx local_words=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                    site.label + std::strlen("shader-bound-query-"),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi), query_id,
                    static_cast<unsigned long long>(query_bytes),
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->Rbp),
                    static_cast<unsigned long long>(frame_bytes),
                    static_cast<unsigned long long>(frame_words[9]),
                    static_cast<unsigned long long>(frame_words[0]),
                    static_cast<unsigned long long>(frame_words[1]),
                    static_cast<unsigned long long>(frame_words[2]),
                    static_cast<unsigned long long>(frame_words[3]),
                    static_cast<unsigned long long>(frame_words[4]),
                    static_cast<unsigned long long>(frame_words[5]),
                    static_cast<unsigned long long>(frame_words[6]),
                    static_cast<unsigned long long>(frame_words[7]));
            }
            if (std::strcmp(site.label, "shader-queue-recursive-call") == 0 &&
                site.hit_count <= 8) {
                std::array<std::uintptr_t, 12> stack_words{};
                SIZE_T stack_bytes{};
                if (context->Rsp != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rsp), stack_words.data(),
                        sizeof(stack_words), &stack_bytes);
                char stack_line[384]{};
                int stack_count = std::snprintf(stack_line, sizeof(stack_line),
                    "SHADER-QUEUE stack-snapshot rsp=%llx bytes=%llu words=",
                    static_cast<unsigned long long>(context->Rsp),
                    static_cast<unsigned long long>(stack_bytes));
                for (std::size_t word = 0; word < stack_words.size() &&
                     stack_count > 0 && static_cast<std::size_t>(stack_count) < sizeof(stack_line);
                     ++word) {
                    const int appended = std::snprintf(stack_line + stack_count,
                        sizeof(stack_line) - static_cast<std::size_t>(stack_count),
                        "%s%llx", word == 0 ? "" : ",",
                        static_cast<unsigned long long>(stack_words[word]));
                    if (appended < 0) break;
                    stack_count += appended;
                }
                if (stack_count > 0 && static_cast<std::size_t>(stack_count) < sizeof(stack_line)) {
                    stack_line[stack_count++] = '\n';
                    DWORD written{};
                    WriteFile(GetStdHandle(STD_ERROR_HANDLE), stack_line,
                        static_cast<DWORD>(stack_count), &written, nullptr);
                }
            }
            if (std::strcmp(site.label, "shader-queue-cleanup-entry") == 0 ||
                std::strcmp(site.label, "shader-queue-method-entry") == 0) {
                std::array<std::uint64_t, 16> task_words{};
                SIZE_T task_bytes{};
                if (context->Rsi != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rsi), task_words.data(),
                        sizeof(task_words), &task_bytes);
                char task_line[640]{};
                int task_count = std::snprintf(task_line, sizeof(task_line),
                    "SHADER-QUEUE task-snapshot base=%llx bytes=%llu words=",
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(task_bytes));
                for (std::size_t word = 0; word < task_words.size() &&
                     task_count > 0 && static_cast<std::size_t>(task_count) < sizeof(task_line);
                     ++word) {
                    const int appended = std::snprintf(task_line + task_count,
                        sizeof(task_line) - static_cast<std::size_t>(task_count),
                        "%s%llx", word == 0 ? "" : ",",
                        static_cast<unsigned long long>(task_words[word]));
                    if (appended < 0) break;
                    task_count += appended;
                }
                if (task_count > 0 && static_cast<std::size_t>(task_count) < sizeof(task_line)) {
                    task_line[task_count++] = '\n';
                    DWORD written{};
                    WriteFile(GetStdHandle(STD_ERROR_HANDLE), task_line,
                        static_cast<DWORD>(task_count), &written, nullptr);
                }
            }
            if (std::strcmp(site.label, "shader-stream-read-entry") == 0 &&
                site.hit_count <= 12) {
                std::array<std::uint64_t, 8> stream_words{};
                SIZE_T stream_bytes{};
                if (context->Rdi != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rdi), stream_words.data(),
                        sizeof(stream_words), &stream_bytes);
                std::fprintf(stderr,
                    "SHADER-STREAM base=%llx bytes=%llu vtable=%llx cursor=%llx "
                    "end=%llx callback=%llx list=%llx status38=%llx\n",
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(stream_bytes),
                    static_cast<unsigned long long>(stream_words[0]),
                    static_cast<unsigned long long>(stream_words[3]),
                    static_cast<unsigned long long>(stream_words[4]),
                    static_cast<unsigned long long>(stream_words[5]),
                    static_cast<unsigned long long>(stream_words[6]),
                    static_cast<unsigned long long>(stream_words[7]));
            }
            if (std::strcmp(site.label, "shader-queue-process-entry") == 0 &&
                site.hit_count <= 8) {
                std::array<std::uint64_t, 12> object_words{};
                SIZE_T object_bytes{};
                if (context->Rdi != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rdi), object_words.data(),
                        sizeof(object_words), &object_bytes);
                std::fprintf(stderr,
                    "SHADER-QUEUE process-object base=%llx bytes=%llu "
                    "words=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(object_bytes),
                    static_cast<unsigned long long>(object_words[0]),
                    static_cast<unsigned long long>(object_words[1]),
                    static_cast<unsigned long long>(object_words[2]),
                    static_cast<unsigned long long>(object_words[3]),
                    static_cast<unsigned long long>(object_words[4]),
                    static_cast<unsigned long long>(object_words[5]),
                    static_cast<unsigned long long>(object_words[6]),
                    static_cast<unsigned long long>(object_words[7]),
                    static_cast<unsigned long long>(object_words[8]),
                    static_cast<unsigned long long>(object_words[9]),
                    static_cast<unsigned long long>(object_words[10]),
                    static_cast<unsigned long long>(object_words[11]));
            }
            if (std::strcmp(site.label, "shader-stream-reader-ctor") == 0 &&
                site.hit_count <= 16) {
                std::uintptr_t return_address{};
                SIZE_T return_bytes{};
                if (context->Rsp != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rsp), &return_address,
                        sizeof(return_address), &return_bytes);
                const auto caller_region = std::find_if(probe_regions.begin(),
                    probe_regions.end(), [&](const ProbeRegion& region) {
                        return return_bytes == sizeof(return_address) &&
                            return_address >= region.begin && return_address < region.end;
                    });
                const auto caller_offset = caller_region == probe_regions.end() ? 0 :
                    return_address - caller_region->load_bias;
                std::fprintf(stderr,
                    "SHADER-STREAM ctor hit=%u this=%llx caller=%s+%llx "
                    "args=%llx,%llx,%llx,%llx,%llx,%llx\n",
                    site.hit_count,
                    static_cast<unsigned long long>(context->Rdi),
                    caller_region == probe_regions.end() ? "unknown" : caller_region->name.c_str(),
                    static_cast<unsigned long long>(caller_offset),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->R8),
                    static_cast<unsigned long long>(context->R9));
            }
            if (std::strcmp(site.label, "shader-reader-bound-arg") == 0 &&
                site.hit_count <= 16) {
                std::array<std::uint64_t, 12> owner_words{};
                std::array<std::uint64_t, 4> field_words{};
                SIZE_T owner_bytes{};
                SIZE_T field_bytes{};
                if (context->R12 != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->R12), owner_words.data(),
                        sizeof(owner_words), &owner_bytes);
                if (context->R12 <= UINTPTR_MAX - 0x30U)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->R12 + 0x30U),
                        field_words.data(), sizeof(field_words), &field_bytes);
                std::fprintf(stderr,
                    "SHADER-BOUND arg hit=%u r12=%llx field30=%llx bytes=%llu "
                    "rdx=%llx rdi=%llx rsi=%llx rbx=%llx rax=%llx rcx=%llx "
                    "owner-bytes=%llu owner=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx "
                    "field=%llx,%llx,%llx,%llx\n",
                    site.hit_count,
                    static_cast<unsigned long long>(context->R12),
                    static_cast<unsigned long long>(field_words[0]),
                    static_cast<unsigned long long>(field_bytes),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rbx),
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(owner_bytes),
                    static_cast<unsigned long long>(owner_words[0]),
                    static_cast<unsigned long long>(owner_words[1]),
                    static_cast<unsigned long long>(owner_words[2]),
                    static_cast<unsigned long long>(owner_words[3]),
                    static_cast<unsigned long long>(owner_words[4]),
                    static_cast<unsigned long long>(owner_words[5]),
                    static_cast<unsigned long long>(owner_words[6]),
                    static_cast<unsigned long long>(owner_words[7]),
                    static_cast<unsigned long long>(field_words[0]),
                    static_cast<unsigned long long>(field_words[1]),
                    static_cast<unsigned long long>(field_words[2]),
                    static_cast<unsigned long long>(field_words[3]));
            }
            if (std::strcmp(site.label, "shader-queue-drain-method-entry") == 0 &&
                site.hit_count <= 12) {
                std::array<std::uint64_t, 12> object_words{};
                std::array<std::uint64_t, 8> call_stack{};
                std::array<std::uint64_t, 4> tail_words{};
                SIZE_T object_bytes{};
                SIZE_T stack_bytes{};
                SIZE_T tail_bytes{};
                if (context->Rdi != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rdi), object_words.data(),
                        sizeof(object_words), &object_bytes);
                ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rsp), call_stack.data(),
                    sizeof(call_stack), &stack_bytes);
                if (object_words[4] != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(object_words[4]), tail_words.data(),
                        sizeof(tail_words), &tail_bytes);
                const auto caller_region = std::find_if(probe_regions.begin(),
                    probe_regions.end(), [&](const ProbeRegion& region) {
                        return stack_bytes >= sizeof(std::uintptr_t) &&
                            call_stack[0] >= region.begin && call_stack[0] < region.end;
                    });
                const auto caller_offset = caller_region == probe_regions.end() ? 0 :
                    call_stack[0] - caller_region->load_bias;
                std::fprintf(stderr,
                    "SHADER-QUEUE drain-entry hit=%u obj=%llx bytes=%llu "
                    "ret=%llx caller=%s+%llx stackbytes=%llu stack=%llx,%llx,%llx,%llx "
                    "args=%llx,%llx,%llx,%llx,%llx,%llx "
                    "words=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx "
                    "tailbytes=%llu tail=%llx,%llx,%llx,%llx\n",
                    site.hit_count,
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(object_bytes),
                    static_cast<unsigned long long>(call_stack[0]),
                    caller_region == probe_regions.end() ? "unknown" : caller_region->name.c_str(),
                    static_cast<unsigned long long>(caller_offset),
                    static_cast<unsigned long long>(stack_bytes),
                    static_cast<unsigned long long>(call_stack[0]),
                    static_cast<unsigned long long>(call_stack[1]),
                    static_cast<unsigned long long>(call_stack[2]),
                    static_cast<unsigned long long>(call_stack[3]),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->R8),
                    static_cast<unsigned long long>(context->R9),
                    static_cast<unsigned long long>(object_words[0]),
                    static_cast<unsigned long long>(object_words[1]),
                    static_cast<unsigned long long>(object_words[2]),
                    static_cast<unsigned long long>(object_words[3]),
                    static_cast<unsigned long long>(object_words[4]),
                    static_cast<unsigned long long>(object_words[5]),
                    static_cast<unsigned long long>(object_words[6]),
                    static_cast<unsigned long long>(object_words[7]),
                    static_cast<unsigned long long>(object_words[8]),
                    static_cast<unsigned long long>(object_words[9]),
                    static_cast<unsigned long long>(object_words[10]),
                    static_cast<unsigned long long>(object_words[11]),
                    static_cast<unsigned long long>(tail_bytes),
                    static_cast<unsigned long long>(tail_words[0]),
                    static_cast<unsigned long long>(tail_words[1]),
                    static_cast<unsigned long long>(tail_words[2]),
                    static_cast<unsigned long long>(tail_words[3]));
            }
            if (std::strcmp(site.label, "shader-queue-item-call-entry") == 0 &&
                site.hit_count <= 32) {
                std::array<std::uint64_t, 8> receiver_words{};
                std::uintptr_t vtable{};
                std::uintptr_t method{};
                SIZE_T receiver_bytes{};
                SIZE_T method_bytes{};
                if (context->Rax != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rax), receiver_words.data(),
                        sizeof(receiver_words), &receiver_bytes);
                if (receiver_bytes >= sizeof(vtable)) {
                    vtable = static_cast<std::uintptr_t>(receiver_words[0]);
                    if (vtable <= UINTPTR_MAX - 0x28U)
                        (void)ReadProcessMemory(GetCurrentProcess(),
                            reinterpret_cast<const void*>(vtable + 0x28U), &method,
                            sizeof(method), &method_bytes);
                }
                const auto method_region = std::find_if(probe_regions.begin(),
                    probe_regions.end(), [&](const ProbeRegion& region) {
                        return method_bytes == sizeof(method) &&
                            method >= region.begin && method < region.end;
                    });
                std::uintptr_t return_address{};
                SIZE_T return_bytes{};
                if (context->Rsp != 0)
                    (void)ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rsp), &return_address,
                        sizeof(return_address), &return_bytes);
                std::fprintf(stderr,
                    "SHADER-QUEUE item-call-entry hit=%u receiver=%llx bytes=%llu "
                    "vtable=%llx method=%s+0x%llx address=%llx "
                    "args=%llx,%llx,%llx,%llx,%llx,%llx "
                    "fields=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx "
                    "ret=%llx\n",
                    site.hit_count,
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(receiver_bytes),
                    static_cast<unsigned long long>(vtable),
                    method_region == probe_regions.end() ? "unknown" : method_region->name.c_str(),
                    static_cast<unsigned long long>(method_region == probe_regions.end() ? 0 :
                        method - method_region->load_bias),
                    static_cast<unsigned long long>(method),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->R8),
                    static_cast<unsigned long long>(context->R9),
                    static_cast<unsigned long long>(receiver_words[0]),
                    static_cast<unsigned long long>(receiver_words[1]),
                    static_cast<unsigned long long>(receiver_words[2]),
                    static_cast<unsigned long long>(receiver_words[3]),
                    static_cast<unsigned long long>(receiver_words[4]),
                    static_cast<unsigned long long>(receiver_words[5]),
                    static_cast<unsigned long long>(receiver_words[6]),
                    static_cast<unsigned long long>(receiver_words[7]),
                    static_cast<unsigned long long>(return_bytes == sizeof(return_address) ?
                        return_address : 0));
            }
            if (std::strcmp(site.label, "shader-queue-item-call-return") == 0 &&
                site.hit_count <= 32) {
                std::fprintf(stderr,
                    "SHADER-QUEUE item-call-return hit=%u result=0x%llx "
                    "args-now=%llx,%llx,%llx,%llx,%llx,%llx rsp=%llx\n",
                    site.hit_count,
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->R8),
                    static_cast<unsigned long long>(context->R9),
                    static_cast<unsigned long long>(context->Rsp));
            }
            if (std::strcmp(site.label, "shader-queue-state-check") == 0 &&
                site.hit_count <= 24) {
                std::array<std::uintptr_t, 8> queue_words{};
                SIZE_T queue_bytes{};
                if (context->R14 != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->R14 + 0x18),
                        queue_words.data(), sizeof(queue_words), &queue_bytes);
                std::fprintf(stderr,
                    "SHADER-QUEUE state base=%llx bytes=%llu head=%llx tail=%llx "
                    "callback=%llx vector=%llx status38=%llx aux40=%llx aux48=%llx\n",
                    static_cast<unsigned long long>(context->R14),
                    static_cast<unsigned long long>(queue_bytes),
                    static_cast<unsigned long long>(queue_words[0]),
                    static_cast<unsigned long long>(queue_words[1]),
                    static_cast<unsigned long long>(queue_words[2]),
                    static_cast<unsigned long long>(queue_words[3]),
                    static_cast<unsigned long long>(queue_words[4]),
                    static_cast<unsigned long long>(queue_words[5]),
                    static_cast<unsigned long long>(queue_words[6]));
            }
            if (std::strcmp(site.label, "libkernel-set-call-record-entry") == 0) {
                std::array<std::uintptr_t, 8> guest_stack{};
                SIZE_T guest_stack_bytes{};
                if (context->Rsp != 0)
                    ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(context->Rsp), guest_stack.data(),
                        sizeof(guest_stack), &guest_stack_bytes);
                const auto return_owner = std::find_if(probe_regions.begin(),
                    probe_regions.end(), [&](const ProbeRegion& region) {
                        return guest_stack_bytes >= sizeof(std::uintptr_t) &&
                            guest_stack[0] >= region.begin && guest_stack[0] < region.end;
                    });
                std::fprintf(stderr,
                    "CALL-RECORD hit=%u selector=%u rsp=0x%llx return=0x%llx owner=%s+0x%llx "
                    "stack=%llx,%llx,%llx,%llx,%llx\n",
                    site.hit_count, static_cast<unsigned>(context->Rdi & 0xffffffffU),
                    static_cast<unsigned long long>(context->Rsp),
                    static_cast<unsigned long long>(guest_stack[0]),
                    return_owner == probe_regions.end() ? "unknown" : return_owner->name.c_str(),
                    return_owner == probe_regions.end() ? 0ULL :
                        static_cast<unsigned long long>(guest_stack[0] - return_owner->load_bias),
                    static_cast<unsigned long long>(guest_stack[1]),
                    static_cast<unsigned long long>(guest_stack[2]),
                    static_cast<unsigned long long>(guest_stack[3]),
                    static_cast<unsigned long long>(guest_stack[4]),
                    static_cast<unsigned long long>(guest_stack[5]));
            }
            if (std::strcmp(site.label, "jm-dispatch-fallback-target") == 0) {
                std::uint8_t target_byte{};
                SIZE_T target_bytes{};
                ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rax),
                    &target_byte, sizeof(target_byte), &target_bytes);
                std::fprintf(stderr,
                    "JM-TARGET expected=0x%llx first-byte=0x%02x readable=%u\n",
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned>(target_byte),
                    static_cast<unsigned>(target_bytes == sizeof(target_byte)));
            }
            if (std::strcmp(site.label, "null-path-vmethod-call") == 0) {
                std::uintptr_t target{};
                SIZE_T target_bytes{};
                ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rax + 0x98),
                    &target, sizeof(target), &target_bytes);
                std::fprintf(stderr,
                    "Null-path virtual call: receiver=0x%llx vtable=0x%llx "
                    "slot_0x98=0x%llx readable=%u rsi=0x%llx rdx=0x%llx "
                    "rcx=0x%llx r8=0x%llx r9=0x%llx r13=0x%llx r15=0x%llx\n",
                    static_cast<unsigned long long>(context->R12),
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(target),
                    static_cast<unsigned>(target_bytes == sizeof(target)),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->R8),
                    static_cast<unsigned long long>(context->R9),
                    static_cast<unsigned long long>(context->R13),
                    static_cast<unsigned long long>(context->R15));
                std::array<std::uintptr_t, 8> nearby_slots{};
                SIZE_T nearby_bytes{};
                ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rax + 0x80),
                    nearby_slots.data(), sizeof(nearby_slots), &nearby_bytes);
                std::fprintf(stderr,
                    "Null-path vtable slots 0x80..0xb8: %llx %llx %llx %llx %llx %llx %llx %llx readable=%u\n",
                    static_cast<unsigned long long>(nearby_slots[0]),
                    static_cast<unsigned long long>(nearby_slots[1]),
                    static_cast<unsigned long long>(nearby_slots[2]),
                    static_cast<unsigned long long>(nearby_slots[3]),
                    static_cast<unsigned long long>(nearby_slots[4]),
                    static_cast<unsigned long long>(nearby_slots[5]),
                    static_cast<unsigned long long>(nearby_slots[6]),
                    static_cast<unsigned long long>(nearby_slots[7]),
                    static_cast<unsigned>(nearby_bytes == sizeof(nearby_slots)));
            } else if (std::strcmp(site.label, "null-path-operation-call") == 0) {
                std::uintptr_t target{};
                SIZE_T target_bytes{};
                ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rax + 0x38),
                    &target, sizeof(target), &target_bytes);
                std::fprintf(stderr,
                    "Null-path operation call: receiver=0x%llx vtable=0x%llx "
                    "slot_0x38=0x%llx readable=%u rsi=0x%llx rdx=0x%llx "
                    "rcx=0x%llx r8=0x%llx r9=0x%llx r13=0x%llx\n",
                    static_cast<unsigned long long>(context->R12),
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(target),
                    static_cast<unsigned>(target_bytes == sizeof(target)),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->R8),
                    static_cast<unsigned long long>(context->R9),
                    static_cast<unsigned long long>(context->R13));
            } else if (std::strcmp(site.label, "null-path-file-read-entry") == 0) {
                std::array<std::uint64_t, 4> state{};
                SIZE_T state_bytes{};
                ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rsi),
                    state.data(), sizeof(state), &state_bytes);
                std::array<char, 128> path{};
                SIZE_T path_bytes{};
                ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rsi + sizeof(std::uint32_t)),
                    path.data(), path.size() - 1, &path_bytes);
                std::fprintf(stderr,
                    "Null-path file-read entry: manager=0x%llx state=0x%llx "
                    "buffer=0x%llx size=0x%llx state_qwords=%llx,%llx,%llx,%llx "
                    "path='%s' path_bytes=%llu readable=%u\n",
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(state[0]),
                    static_cast<unsigned long long>(state[1]),
                    static_cast<unsigned long long>(state[2]),
                    static_cast<unsigned long long>(state[3]),
                    path.data(),
                    static_cast<unsigned long long>(path_bytes),
                    static_cast<unsigned>(state_bytes == sizeof(state)));
            } else if (std::strcmp(site.label, "null-path-file-validate") == 0) {
                std::fprintf(stderr,
                    "Null-path file validation: handle=%u accepted=%u manager=0x%llx state=0x%llx\n",
                    static_cast<unsigned>(context->R13),
                    static_cast<unsigned>(context->Rax & 0xff),
                    static_cast<unsigned long long>(context->R14),
                    static_cast<unsigned long long>(context->R15));
            } else if (std::strcmp(site.label, "null-path-operation-return") == 0) {
                std::fprintf(stderr,
                    "Null-path operation return: receiver=0x%llx result=0x%llx\n",
                    static_cast<unsigned long long>(context->R12),
                    static_cast<unsigned long long>(context->Rax));
            } else if (std::strcmp(site.label, "null-path-vmethod-return") == 0) {
                std::fprintf(stderr,
                    "Null-path virtual return: receiver=0x%llx result=0x%llx\n",
                    static_cast<unsigned long long>(context->R12),
                    static_cast<unsigned long long>(context->Rax));
            }
            if (std::strcmp(site.label, "jm-worker-queue-entry") == 0) {
                std::array<std::uint64_t, 16> queue_words{};
                SIZE_T queue_bytes{};
                ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(context->Rdi), queue_words.data(),
                    sizeof(queue_words), &queue_bytes);
                std::fprintf(stderr,
                    "JM-QUEUE object=0x%llx bytes=%llu words=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(queue_bytes),
                    static_cast<unsigned long long>(queue_words[0]),
                    static_cast<unsigned long long>(queue_words[1]),
                    static_cast<unsigned long long>(queue_words[2]),
                    static_cast<unsigned long long>(queue_words[3]),
                    static_cast<unsigned long long>(queue_words[4]),
                    static_cast<unsigned long long>(queue_words[5]),
                    static_cast<unsigned long long>(queue_words[6]),
                    static_cast<unsigned long long>(queue_words[7]),
                    static_cast<unsigned long long>(queue_words[8]),
                    static_cast<unsigned long long>(queue_words[9]),
                    static_cast<unsigned long long>(queue_words[10]),
                    static_cast<unsigned long long>(queue_words[11]),
                    static_cast<unsigned long long>(queue_words[12]),
                    static_cast<unsigned long long>(queue_words[13]),
                    static_cast<unsigned long long>(queue_words[14]),
                    static_cast<unsigned long long>(queue_words[15]));
            }
            if ((std::strcmp(site.label,
                    "shader-main-state-getter-return") == 0 ||
                 std::strcmp(site.label,
                    "shader-main-state-getter-return-2") == 0) &&
                std::getenv("NBA16_TRACE_MAIN_DISPATCH_CONTINUE") != nullptr &&
                context->Rax >= 3) {
                site.armed = false;
                fopen_trace_step_site = -1;
                shader_state_instruction_trace_active = true;
                shader_state_instruction_trace_steps = 0;
                shader_state_instruction_trace_host_steps = 0;
                context->Rip = site.address;
                context->EFlags |= 0x100UL;
                write_atomic_diagnostic(
                    "SHADER-CONT main dispatcher stepping from +0x%llx result=%llx\n",
                    static_cast<unsigned long long>(site.offset),
                    static_cast<unsigned long long>(context->Rax));
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            if (stop_tracing) {
                site.armed = false;
                context->Rip = site.address;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            context->Rip = site.address;
            if (std::strcmp(site.label, "jm-worker-method-entry") == 0 ||
                std::strcmp(site.label, "jm-worker-semaphore-return") == 0 ||
                std::strcmp(site.label, "jm-worker-queue-entry") == 0) {
                site.armed = false;
                jm_worker_instruction_trace_active = true;
                jm_worker_instruction_trace_remaining = 200;
                context->EFlags |= 0x100UL;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            if (std::strcmp(site.label,
                    "shader-state-query-dispatch-skip") == 0 &&
                std::getenv("NBA16_TRACE_SHADER_CONTINUE") != nullptr) {
                site.armed = false;
                fopen_trace_step_site = -1;
                shader_state_instruction_trace_active = true;
                shader_state_instruction_trace_steps = 0;
                shader_state_instruction_trace_host_steps = 0;
                context->Rip = site.address;
                context->EFlags |= 0x100UL;
                std::fputs("SHADER-CONT instruction trace started at dispatch skip\n",
                    stderr);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            context->EFlags |= 0x100UL;
            fopen_trace_step_site = static_cast<int>(index);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    if (record->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        std::getenv("NBA16_TRACE_SHADER_BOUND_WRITES") != nullptr) {
        static thread_local std::uint32_t unclaimed_steps{};
        if (++unclaimed_steps <= 16)
            std::fprintf(stderr,
                "SHADER-BOUND unclaimed-step count=%u dr6=%llx dr0=%llx "
                "dr7=%llx rip=%llx eflags=%llx; clearing diagnostic debug state\n",
                unclaimed_steps,
                static_cast<unsigned long long>(context->Dr6),
                static_cast<unsigned long long>(context->Dr0),
                static_cast<unsigned long long>(context->Dr7),
                static_cast<unsigned long long>(context->Rip),
                static_cast<unsigned long long>(context->EFlags));
        context->Dr0 = context->Dr1 = context->Dr2 = context->Dr3 = 0;
        context->Dr6 = context->Dr7 = 0;
        context->EFlags &= ~0x100UL;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    const auto fault_address = record->NumberParameters >= 2
        ? static_cast<std::uint64_t>(record->ExceptionInformation[1]) : 0;
    const auto access_kind = record->NumberParameters >= 1
        ? static_cast<std::uint64_t>(record->ExceptionInformation[0]) : 0;
    const auto instruction = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(record->ExceptionAddress));
    HMODULE instruction_module{};
    char instruction_module_path[MAX_PATH]{};
    std::uintptr_t instruction_module_base{};
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(instruction), &instruction_module) != 0) {
        instruction_module_base = reinterpret_cast<std::uintptr_t>(instruction_module);
        GetModuleFileNameA(instruction_module, instruction_module_path,
                           static_cast<DWORD>(sizeof(instruction_module_path)));
    }
    ULONG_PTR host_stack_low{};
    ULONG_PTR host_stack_high{};
    GetCurrentThreadStackLimits(&host_stack_low, &host_stack_high);
    const ProbeRegion* owner = nullptr;
    for (const auto& region : probe_regions) {
        if (instruction >= region.begin && instruction < region.end) {
            owner = &region;
            break;
        }
    }
    std::array<std::uint64_t, 8> stack_words{};
    SIZE_T bytes_read{};
    ReadProcessMemory(GetCurrentProcess(),
        reinterpret_cast<const void*>(pointers->ContextRecord->Rsp),
        stack_words.data(), sizeof(stack_words), &bytes_read);
    std::uint64_t r12_dereference{};
    SIZE_T r12_bytes_read{};
    if (pointers->ContextRecord->R12 != 0 &&
        pointers->ContextRecord->R12 <= UINTPTR_MAX - sizeof(r12_dereference)) {
        ReadProcessMemory(GetCurrentProcess(),
            reinterpret_cast<const void*>(pointers->ContextRecord->R12),
            &r12_dereference, sizeof(r12_dereference), &r12_bytes_read);
    }
    std::uint64_t guard_local{};
    SIZE_T guard_bytes_read{};
    if (pointers->ContextRecord->Rbp >= 0x28) {
        ReadProcessMemory(GetCurrentProcess(),
            reinterpret_cast<const void*>(pointers->ContextRecord->Rbp - 0x28),
            &guard_local, sizeof(guard_local), &guard_bytes_read);
    }
    std::array<std::uint64_t, 4> object_words{};
    std::array<std::uint64_t, 4> vtable_words{};
    SIZE_T object_bytes{};
    SIZE_T vtable_bytes{};
    ReadProcessMemory(GetCurrentProcess(),
        reinterpret_cast<const void*>(pointers->ContextRecord->Rax),
        object_words.data(), sizeof(object_words), &object_bytes);
    ReadProcessMemory(GetCurrentProcess(),
        reinterpret_cast<const void*>(pointers->ContextRecord->Rbx),
        vtable_words.data(), sizeof(vtable_words), &vtable_bytes);
    const auto owner_for_address = [](std::uint64_t address) -> const ProbeRegion* {
        for (const auto& region : probe_regions) {
            if (address >= region.begin && address < region.end) return &region;
        }
        return nullptr;
    };
    const auto object_owner = owner_for_address(
        static_cast<std::uint64_t>(pointers->ContextRecord->Rax));
    const auto vtable_owner = owner_for_address(object_words[0]);
    std::array<std::uint64_t, 8> frame_returns{};
    auto frame = static_cast<std::uint64_t>(pointers->ContextRecord->Rbp);
    for (auto& return_address : frame_returns) {
        std::array<std::uint64_t, 2> pair{};
        SIZE_T frame_bytes{};
        if (frame == 0 || ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(frame), pair.data(), sizeof(pair),
                &frame_bytes) == 0 || frame_bytes != sizeof(pair)) break;
        frame = pair[0];
        return_address = pair[1];
    }
    std::array<char, 700> frame_owners{};
    std::size_t frame_owner_length{};
    for (std::size_t index = 0; index < frame_returns.size(); ++index) {
        const auto address = frame_returns[index];
        const ProbeRegion* frame_owner = nullptr;
        for (const auto& region : probe_regions) {
            if (address >= region.begin && address < region.end) {
                frame_owner = &region;
                break;
            }
        }
        const auto written = std::snprintf(frame_owners.data() + frame_owner_length,
            frame_owners.size() - frame_owner_length, " %zu=%s+0x%llx", index,
            frame_owner == nullptr ? "host/unknown" : frame_owner->name.c_str(),
            static_cast<unsigned long long>(frame_owner == nullptr ? 0 :
                address - frame_owner->load_bias));
        if (written <= 0) break;
        frame_owner_length += std::min<std::size_t>(static_cast<std::size_t>(written),
            frame_owners.size() - frame_owner_length - 1);
        if (frame_owner_length + 1 >= frame_owners.size()) break;
    }
    for (std::size_t index = 0; index < frame_returns.size(); ++index) {
        const ProbeRegion* frame_owner = nullptr;
        for (const auto& region : probe_regions) {
            if (region.name == "eboot.bin" && frame_returns[index] >= region.begin &&
                frame_returns[index] < region.end) { frame_owner = &region; break; }
        }
        constexpr std::uintptr_t caller_bytes_before = 128;
        if (frame_owner == nullptr ||
            frame_returns[index] < frame_owner->load_bias + caller_bytes_before) continue;
        std::array<std::uint8_t, 256> code{};
        SIZE_T code_size{};
        if (ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(frame_returns[index] - caller_bytes_before),
                code.data(), code.size(), &code_size) == 0 || code_size == 0) continue;
        char line[1024]{};
        std::size_t used = static_cast<std::size_t>(std::snprintf(line, sizeof(line),
            "eboot-caller[%zu]+0x%llx=", index,
            static_cast<unsigned long long>(frame_returns[index] - frame_owner->load_bias -
                caller_bytes_before)));
        for (SIZE_T byte = 0; byte < code_size && used + 3 < sizeof(line); ++byte)
            used += static_cast<std::size_t>(std::snprintf(line + used,
                sizeof(line) - used, "%02x", code[byte]));
        if (used + 1 < sizeof(line)) line[used++] = '\n';
        DWORD written{};
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), line, static_cast<DWORD>(used), &written, nullptr);
    }
    const auto eboot_region = std::find_if(probe_regions.begin(), probe_regions.end(),
        [](const auto& region) { return region.name == "eboot.bin"; });
    if (eboot_region != probe_regions.end()) {
        std::array<std::uint8_t, 512> code{};
        SIZE_T code_size{};
        constexpr std::uintptr_t helper_offset = 0x41f8c0;
        if (ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(eboot_region->load_bias + helper_offset),
                code.data(), code.size(), &code_size) != 0 && code_size != 0) {
            char line[1200]{};
            std::size_t used = static_cast<std::size_t>(std::snprintf(line, sizeof(line),
                "eboot-memory-helper+0x%llx=",
                static_cast<unsigned long long>(helper_offset)));
            for (SIZE_T byte = 0; byte < code_size && used + 3 < sizeof(line); ++byte)
                used += static_cast<std::size_t>(std::snprintf(line + used,
                    sizeof(line) - used, "%02x", code[byte]));
            if (used + 1 < sizeof(line)) line[used++] = '\n';
            DWORD written{};
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), line,
                static_cast<DWORD>(used), &written, nullptr);
        }
    }
    std::array<char, 256> stack_owners{};
    std::size_t stack_owner_length{};
    for (std::size_t index = 0; index < stack_words.size(); ++index) {
        const ProbeRegion* stack_owner = nullptr;
        for (const auto& region : probe_regions) {
            if (stack_words[index] >= region.begin && stack_words[index] < region.end) {
                stack_owner = &region;
                break;
            }
        }
        const auto written = std::snprintf(stack_owners.data() + stack_owner_length,
            stack_owners.size() - stack_owner_length, " %zu=%s+0x%llx", index,
            stack_owner == nullptr ? "host/unknown" : stack_owner->name.c_str(),
            static_cast<unsigned long long>(stack_owner == nullptr ? 0 :
                stack_words[index] - stack_owner->load_bias));
        if (written <= 0) break;
        stack_owner_length += std::min<std::size_t>(static_cast<std::size_t>(written),
            stack_owners.size() - stack_owner_length - 1);
        if (stack_owner_length + 1 >= stack_owners.size()) break;
    }
    char message[3000]{};
    const auto sysctl_history = nba16::guest_sysctl_dispatch_history();
    char sysctl_history_text[400]{};
    std::size_t sysctl_history_length{};
    for (std::size_t index = 0; index < sysctl_history.count; ++index) {
        const auto slot = index * 4U;
        const auto written = std::snprintf(sysctl_history_text + sysctl_history_length,
            sizeof(sysctl_history_text) - sysctl_history_length, " %llu,%llu=%lld@%llu",
            static_cast<unsigned long long>(sysctl_history.values[slot]),
            static_cast<unsigned long long>(sysctl_history.values[slot + 1]),
            static_cast<long long>(static_cast<std::int32_t>(sysctl_history.values[slot + 2])),
            static_cast<unsigned long long>(sysctl_history.values[slot + 3]));
        if (written <= 0) break;
        sysctl_history_length += std::min<std::size_t>(static_cast<std::size_t>(written),
            sizeof(sysctl_history_text) - sysctl_history_length - 1);
    }
    const auto sysctl_trace = nba16::guest_sysctl_last_trace();
    const auto usrstack_trace = nba16::guest_usrstack_sysctl_trace();
    std::array<char, 129> sysctl_name{};
    if (sysctl_trace.new_value != 0 && sysctl_trace.new_length > 0) {
        const auto amount = static_cast<SIZE_T>(std::min<std::uint64_t>(
            sysctl_trace.new_length, sysctl_name.size() - 1));
        SIZE_T name_bytes{};
        if (ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(sysctl_trace.new_value),
                sysctl_name.data(), amount, &name_bytes) == 0) {
            sysctl_name.fill('\0');
        } else {
            for (SIZE_T index = 0; index < name_bytes; ++index) {
                const auto value = static_cast<unsigned char>(sysctl_name[index]);
                if (value < 0x20 || value > 0x7e) sysctl_name[index] = '.';
            }
        }
    }
    const auto length = std::snprintf(message, sizeof(message),
        "EXCEPTION code=0x%08lx access=%llu ip=0x%llx owner=%s guest_ip=0x%llx "
        "fault=0x%llx rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx "
        "rsi=0x%llx rdi=0x%llx rsp=0x%llx rbp=0x%llx "
        "r8=0x%llx r9=0x%llx r10=0x%llx r11=0x%llx r12=0x%llx "
        "r13=0x%llx r14=0x%llx r15=0x%llx r12_deref_bytes=%llu r12_deref=0x%llx guard_bytes=%llu guard_rbp_minus_28=0x%llx stack_read=%llu sysctl=%llu sysctlbyname=%llu usrstack_calls=%llu sysctl_thunk_rax=0x%llx dispatch_mib=%llu,%llu dispatch_rax=0x%llx mmap=%llu cpuset=%llu "
        "last_mib=%llu,%llu/%llu old=0x%llx oldlenp=0x%llx oldlen=%llu new=0x%llx newlen=%llu "
        "usrstack_args=%llu,%llu/%llu oldlen=%llu newlen=%llu result=%llu outlen=%llu value=%llu "
        "frames=[0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx] "
        "stack=[0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx] owners:%s frame_owners:%s sysctl_history=%s sysctl_name=%s object_bytes=%llu object=[0x%llx,0x%llx,0x%llx,0x%llx] object_owner=%s+0x%llx vtable_bytes=%llu vtable=[0x%llx,0x%llx,0x%llx,0x%llx] vtable_owner=%s+0x%llx host_module=%s host_stack=[0x%llx,0x%llx]\n",
        static_cast<unsigned long>(record->ExceptionCode),
        static_cast<unsigned long long>(access_kind),
        static_cast<unsigned long long>(instruction),
        owner == nullptr ? "unknown" : owner->name.c_str(),
        static_cast<unsigned long long>(owner == nullptr ? 0 : instruction - owner->load_bias),
        static_cast<unsigned long long>(fault_address),
        static_cast<unsigned long long>(pointers->ContextRecord->Rax),
        static_cast<unsigned long long>(pointers->ContextRecord->Rbx),
        static_cast<unsigned long long>(pointers->ContextRecord->Rcx),
        static_cast<unsigned long long>(pointers->ContextRecord->Rdx),
        static_cast<unsigned long long>(pointers->ContextRecord->Rsi),
        static_cast<unsigned long long>(pointers->ContextRecord->Rdi),
        static_cast<unsigned long long>(pointers->ContextRecord->Rsp),
        static_cast<unsigned long long>(pointers->ContextRecord->Rbp),
        static_cast<unsigned long long>(pointers->ContextRecord->R8),
        static_cast<unsigned long long>(pointers->ContextRecord->R9),
        static_cast<unsigned long long>(pointers->ContextRecord->R10),
        static_cast<unsigned long long>(pointers->ContextRecord->R11),
        static_cast<unsigned long long>(pointers->ContextRecord->R12),
        static_cast<unsigned long long>(pointers->ContextRecord->R13),
        static_cast<unsigned long long>(pointers->ContextRecord->R14),
        static_cast<unsigned long long>(pointers->ContextRecord->R15),
        static_cast<unsigned long long>(r12_bytes_read),
        static_cast<unsigned long long>(r12_dereference),
        static_cast<unsigned long long>(guard_bytes_read),
        static_cast<unsigned long long>(guard_local),
        static_cast<unsigned long long>(bytes_read),
        static_cast<unsigned long long>(nba16::guest_sysctl_call_count()),
        static_cast<unsigned long long>(nba16::guest_sysctlbyname_call_count()),
        static_cast<unsigned long long>(nba16::guest_usrstack_sysctl_call_count()),
        static_cast<unsigned long long>(nba16::guest_sysctl_thunk_return_value()),
        static_cast<unsigned long long>(nba16::guest_sysctl_dispatch_mib0()),
        static_cast<unsigned long long>(nba16::guest_sysctl_dispatch_mib1()),
        static_cast<unsigned long long>(nba16::guest_sysctl_dispatch_result()),
        static_cast<unsigned long long>(nba16::guest_mmap_call_count()),
        static_cast<unsigned long long>(nba16::guest_cpuset_call_count()),
        static_cast<unsigned long long>(sysctl_trace.mib0),
        static_cast<unsigned long long>(sysctl_trace.mib1),
        static_cast<unsigned long long>(sysctl_trace.mib_count),
        static_cast<unsigned long long>(sysctl_trace.old_value),
        static_cast<unsigned long long>(sysctl_trace.old_length_ptr),
        static_cast<unsigned long long>(sysctl_trace.old_length),
        static_cast<unsigned long long>(sysctl_trace.new_value),
        static_cast<unsigned long long>(sysctl_trace.new_length),
        static_cast<unsigned long long>(usrstack_trace.mib0),
        static_cast<unsigned long long>(usrstack_trace.mib1),
        static_cast<unsigned long long>(usrstack_trace.mib_count),
        static_cast<unsigned long long>(usrstack_trace.old_length),
        static_cast<unsigned long long>(usrstack_trace.new_length),
        static_cast<unsigned long long>(usrstack_trace.result),
        static_cast<unsigned long long>(usrstack_trace.response_length),
        static_cast<unsigned long long>(usrstack_trace.response_value),
        static_cast<unsigned long long>(frame_returns[0]),
        static_cast<unsigned long long>(frame_returns[1]),
        static_cast<unsigned long long>(frame_returns[2]),
        static_cast<unsigned long long>(frame_returns[3]),
        static_cast<unsigned long long>(frame_returns[4]),
        static_cast<unsigned long long>(frame_returns[5]),
        static_cast<unsigned long long>(frame_returns[6]),
        static_cast<unsigned long long>(frame_returns[7]),
        static_cast<unsigned long long>(stack_words[0]),
        static_cast<unsigned long long>(stack_words[1]),
        static_cast<unsigned long long>(stack_words[2]),
        static_cast<unsigned long long>(stack_words[3]),
        static_cast<unsigned long long>(stack_words[4]),
        static_cast<unsigned long long>(stack_words[5]),
        static_cast<unsigned long long>(stack_words[6]),
        static_cast<unsigned long long>(stack_words[7]), stack_owners.data(), frame_owners.data(), sysctl_history_text,
        sysctl_name.data(),
        static_cast<unsigned long long>(object_bytes),
        static_cast<unsigned long long>(object_words[0]),
        static_cast<unsigned long long>(object_words[1]),
        static_cast<unsigned long long>(object_words[2]),
        static_cast<unsigned long long>(object_words[3]),
        object_owner == nullptr ? "unknown" : object_owner->name.c_str(),
        static_cast<unsigned long long>(object_owner == nullptr ? 0 :
            static_cast<std::uint64_t>(pointers->ContextRecord->Rax) - object_owner->load_bias),
        static_cast<unsigned long long>(vtable_bytes),
        static_cast<unsigned long long>(vtable_words[0]),
        static_cast<unsigned long long>(vtable_words[1]),
        static_cast<unsigned long long>(vtable_words[2]),
        static_cast<unsigned long long>(vtable_words[3]),
        vtable_owner == nullptr ? "unknown" : vtable_owner->name.c_str(),
        static_cast<unsigned long long>(vtable_owner == nullptr ? 0 :
            object_words[0] - vtable_owner->load_bias),
        instruction_module_path[0] == '\0' ? "unknown" : instruction_module_path,
        static_cast<unsigned long long>(host_stack_low),
        static_cast<unsigned long long>(host_stack_high));
    if (length > 0) {
        DWORD written{};
        const auto handle = GetStdHandle(STD_ERROR_HANDLE);
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
            WriteFile(handle, message, static_cast<DWORD>(length), &written, nullptr);
            if (owner != nullptr && owner->name == "libSceGnmDriver.prx") {
                std::array<std::uint8_t, 96> live_gnm_code{};
                SIZE_T live_gnm_code_size{};
                if (ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(instruction - 64),
                        live_gnm_code.data(), live_gnm_code.size(),
                        &live_gnm_code_size) != 0 && live_gnm_code_size != 0) {
                    std::array<char, 384> gnm_message{};
                    std::size_t gnm_used = static_cast<std::size_t>(
                        std::snprintf(gnm_message.data(), gnm_message.size(),
                            "GNM-LIVE-CODE offset=0x%llx bytes=",
                            static_cast<unsigned long long>(instruction - owner->load_bias - 64)));
                    for (SIZE_T byte = 0; byte < live_gnm_code_size &&
                            gnm_used + 4 < gnm_message.size(); ++byte)
                        gnm_used += static_cast<std::size_t>(std::snprintf(
                            gnm_message.data() + gnm_used,
                            gnm_message.size() - gnm_used, "%02x",
                            live_gnm_code[byte]));
                    if (gnm_used + 1 < gnm_message.size())
                        gnm_message[gnm_used++] = '\n';
                    WriteFile(handle, gnm_message.data(),
                        static_cast<DWORD>(gnm_used), &written, nullptr);
                }
            }
            std::array<std::uint8_t, 96> fault_code{};
            SIZE_T fault_code_size{};
            if (ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(instruction - 64), fault_code.data(),
                    fault_code.size(), &fault_code_size) != 0 && fault_code_size != 0) {
                std::array<char, 320> code_message{};
                std::size_t used{};
                used += static_cast<std::size_t>(std::snprintf(code_message.data(),
                    code_message.size(), "fault-code-from-ip-minus-64="));
                for (SIZE_T index = 0; index < fault_code_size &&
                        used + 4 < code_message.size(); ++index)
                    used += static_cast<std::size_t>(std::snprintf(
                        code_message.data() + used, code_message.size() - used,
                        "%02x", fault_code[index]));
                if (used + 1 < code_message.size()) code_message[used++] = '\n';
                WriteFile(handle, code_message.data(), static_cast<DWORD>(used),
                    &written, nullptr);
            }
            const auto caller = nba16::guest_sysctl_last_caller();
            const ProbeRegion* caller_owner = nullptr;
            for (const auto& region : probe_regions) {
                if (caller >= region.begin && caller < region.end) {
                    caller_owner = &region;
                    break;
                }
            }
            std::array<char, 160> caller_message{};
            const auto caller_length = std::snprintf(caller_message.data(),
                caller_message.size(), "sysctl_caller=0x%llx owner=%s+0x%llx\n",
                static_cast<unsigned long long>(caller),
                caller_owner == nullptr ? "host/unknown" : caller_owner->name.c_str(),
                static_cast<unsigned long long>(caller_owner == nullptr ? 0 :
                    caller - caller_owner->load_bias));
            if (caller_length > 0) {
                WriteFile(handle, caller_message.data(), static_cast<DWORD>(caller_length),
                          &written, nullptr);
            }
        }
        std::array<std::uint8_t, 16> instruction_bytes{};
        SIZE_T instruction_bytes_read{};
        ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(instruction),
            instruction_bytes.data(), instruction_bytes.size(), &instruction_bytes_read);
        char instruction_message[320]{};
        int instruction_length = std::snprintf(instruction_message,
            sizeof(instruction_message),
            "host_exception_module_base=0x%llx module_offset=0x%llx instruction_bytes=",
            static_cast<unsigned long long>(instruction_module_base),
            static_cast<unsigned long long>(instruction_module_base == 0 ? 0 :
                instruction - instruction_module_base));
        for (SIZE_T index = 0; instruction_length > 0 && index < instruction_bytes_read &&
                static_cast<std::size_t>(instruction_length) + 4 < sizeof(instruction_message);
             ++index) {
            instruction_length += std::snprintf(instruction_message + instruction_length,
                sizeof(instruction_message) - static_cast<std::size_t>(instruction_length),
                "%s%02x", index == 0 ? "" : " ", instruction_bytes[index]);
        }
        if (instruction_length > 0 && static_cast<std::size_t>(instruction_length) + 1 <
                sizeof(instruction_message)) {
            instruction_message[instruction_length++] = '\n';
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), instruction_message,
                static_cast<DWORD>(instruction_length), &written, nullptr);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
} // namespace
extern "C" void nba16_start_fs_eof_instruction_trace() {
    if (std::getenv("NBA16_TRACE_SCHED_STATE_WRITES") != nullptr)
        active_scheduler_state_address.store(0x1039be8538ULL,
            std::memory_order_release);
    start_fs_eof_instruction_trace();
    start_shader_state_instruction_trace();
}
extern "C" void nba16_start_gnm_submitdone_instruction_trace() {
    start_gnm_submitdone_instruction_trace();
}
#endif

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    bool valid_arguments = argc >= 3;
    bool dump_main_initializers = false;
    std::size_t run_constructor_count = 0;
    bool bootstrap_libkernel_pthreads = false;
    bool initialize_libc_internal_allocator = false;
    bool enable_libc_internal_mutexes = false;
    bool run_module_preinitializers = false;
    bool run_module_initializers = false;
    std::string start_module_name;
    bool run_guest_entrypoint = false;
    bool prepare_guest_process = false;
    bool trace_graphics_calls = false;
    bool trap_unimplemented_gnm = false;
    bool probe_gnm_submit_done = false;
    bool has_dump_constructor_index = false;
    std::size_t dump_constructor_index = 0;
    std::string dump_module_name;
    std::string search_module_name;
    std::string search_text;
    std::filesystem::path user_root;
    std::uint64_t dump_module_address = 0;
    std::vector<std::uint64_t> dump_module_addresses;
    bool has_dump_module_code = false;
    bool has_find_rip_relative_target = false;
    std::uint64_t find_rip_relative_target = 0;
    bool has_find_module_rip_relative_target = false;
    std::string find_module_rip_relative_name;
    std::uint64_t find_module_rip_relative_target = 0;
    bool has_find_relative_call_target = false;
    std::uint64_t find_relative_call_target = 0;
    bool has_find_relative_branch_target = false;
    std::uint64_t find_relative_branch_target = 0;
    std::string find_module_branch_name;
    std::uint64_t find_module_branch_target = 0;
    bool has_find_module_branch_target = false;
    bool has_find_member_field_writes = false;
    std::uint8_t find_member_field_offset = 0;
    std::uint64_t lookup_main_relocation = 0;
    bool has_lookup_main_relocation = false;
    bool has_search_module_string = false;
    std::string list_module_imports_name;
    std::vector<std::string> skipped_names;
    std::vector<std::string> hle_module_names;
    for (int index = 3; valid_arguments && index < argc;) {
        if (std::string_view(argv[index]) == "--dump-main-init") {
            dump_main_initializers = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--dump-module-startup") {
            dump_main_initializers = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--run-first-constructor") {
            dump_main_initializers = true;
            run_constructor_count = 1;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--bootstrap-libkernel-pthreads") {
            bootstrap_libkernel_pthreads = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--enable-libc-internal-mutexes") {
            enable_libc_internal_mutexes = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--initialize-libc-internal-allocator") {
            initialize_libc_internal_allocator = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--run-module-preinitializers") {
            run_module_preinitializers = true;
            dump_main_initializers = true;
            index++;
            continue;
        }
        if (std::string_view(argv[index]) == "--run-module-initializers") {
            run_module_initializers = true;
            dump_main_initializers = true;
            ++index;
            continue;
        }
        if ((std::string_view(argv[index]) == "--start-module" ||
             std::string_view(argv[index]) == "--run-module-dt-init") && index + 1 < argc) {
            start_module_name = argv[index + 1];
            dump_main_initializers = true;
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--run-entrypoint") {
            run_guest_entrypoint = true;
            dump_main_initializers = true;
            index++;
            continue;
        }
        if (std::string_view(argv[index]) == "--prepare-guest-process") {
            prepare_guest_process = true;
            dump_main_initializers = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--trace-graphics-calls") {
            trace_graphics_calls = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--trap-unimplemented-gnm") {
            trap_unimplemented_gnm = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--probe-gnm-submit-done") {
            probe_gnm_submit_done = true;
            ++index;
            continue;
        }
        if (std::string_view(argv[index]) == "--run-constructors" && index + 1 < argc) {
            const std::string_view value(argv[index + 1]);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                run_constructor_count);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                run_constructor_count == 0 || run_constructor_count > 4096) {
                valid_arguments = false;
                break;
            }
            dump_main_initializers = true;
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--dump-constructor-index" && index + 1 < argc) {
            const std::string_view value(argv[index + 1]);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                dump_constructor_index);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                dump_constructor_index > 4095) {
                valid_arguments = false;
                break;
            }
            has_dump_constructor_index = true;
            dump_main_initializers = true;
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--dump-module-code" && index + 2 < argc) {
            const std::string requested_module = argv[index + 1];
            if (!dump_module_name.empty() && dump_module_name != requested_module) {
                valid_arguments = false;
                break;
            }
            dump_module_name = requested_module;
            std::string_view value(argv[index + 2]);
            if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                dump_module_address, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                valid_arguments = false;
                break;
            }
            has_dump_module_code = true;
            dump_module_addresses.push_back(dump_module_address);
            index += 3;
            continue;
        }
        if (std::string_view(argv[index]) == "--find-rip-relative-target" &&
            index + 1 < argc) {
            std::string_view value(argv[index + 1]);
            if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                find_rip_relative_target, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                valid_arguments = false;
                break;
            }
            has_find_rip_relative_target = true;
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--find-module-rip-relative-target" &&
            index + 2 < argc) {
            if (has_find_module_rip_relative_target) {
                valid_arguments = false;
                break;
            }
            find_module_rip_relative_name = argv[index + 1];
            std::string_view value(argv[index + 2]);
            if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                find_module_rip_relative_target, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                valid_arguments = false;
                break;
            }
            has_find_module_rip_relative_target = true;
            index += 3;
            continue;
        }
        if (std::string_view(argv[index]) == "--find-relative-call-target" &&
            index + 1 < argc) {
            std::string_view value(argv[index + 1]);
            if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                find_relative_call_target, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                valid_arguments = false;
                break;
            }
            has_find_relative_call_target = true;
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--find-relative-branch-target" &&
            index + 1 < argc) {
            std::string_view value(argv[index + 1]);
            if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                find_relative_branch_target, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                valid_arguments = false;
                break;
            }
            has_find_relative_branch_target = true;
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--find-module-relative-branch-target" &&
            index + 2 < argc) {
            if (has_find_module_branch_target) {
                valid_arguments = false;
                break;
            }
            find_module_branch_name = argv[index + 1];
            std::string_view value(argv[index + 2]);
            if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                find_module_branch_target, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                valid_arguments = false;
                break;
            }
            has_find_module_branch_target = true;
            index += 3;
            continue;
        }
        if (std::string_view(argv[index]) == "--find-member-field-writes" &&
            index + 1 < argc) {
            std::string_view value(argv[index + 1]);
            if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
            unsigned parsed_value{};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                parsed_value, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                parsed_value > 0x7fU) {
                valid_arguments = false;
                break;
            }
            has_find_member_field_writes = true;
            find_member_field_offset = static_cast<std::uint8_t>(parsed_value);
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--lookup-main-relocation" && index + 1 < argc) {
            std::string_view value(argv[index + 1]);
            if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                lookup_main_relocation, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                valid_arguments = false;
                break;
            }
            has_lookup_main_relocation = true;
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--list-module-imports" && index + 1 < argc) {
            list_module_imports_name = argv[index + 1];
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) == "--find-module-string" && index + 2 < argc) {
            if (has_search_module_string) {
                valid_arguments = false;
                break;
            }
            search_module_name = argv[index + 1];
            search_text = argv[index + 2];
            has_search_module_string = !search_text.empty();
            if (!has_search_module_string) {
                valid_arguments = false;
                break;
            }
            index += 3;
            continue;
        }
        if (std::string_view(argv[index]) == "--user-root" && index + 1 < argc) {
            user_root = std::filesystem::path(argv[index + 1]);
            index += 2;
            continue;
        }
        if (index + 1 < argc && std::string_view(argv[index]) == "--hle-module") {
            hle_module_names.emplace_back(argv[index + 1]);
            index += 2;
            continue;
        }
        if (std::string_view(argv[index]) != "--skip-missing" || index + 1 >= argc) {
            valid_arguments = false;
            break;
        }
        skipped_names.emplace_back(argv[index + 1]);
        index += 2;
    }
    if (valid_arguments && run_constructor_count != 0 && run_guest_entrypoint) {
        std::cerr << "Não combine --run-constructors com --run-entrypoint: "
                     "a entrada normal do eboot executa a tabela de construtores. "
                     "Use uma opção por execução.\n";
        return 2;
    }
    if (!valid_arguments) {
        std::cerr << "Uso: nba16-module-set-inspect <eboot.bin> <pasta-sys_modules> "
                     "[--dump-main-init|--run-first-constructor] "
                     "[--run-constructors quantidade|--dump-constructor-index índice] "
                     "[--bootstrap-libkernel-pthreads] [--initialize-libc-internal-allocator] "
                     "[--enable-libc-internal-mutexes] "
                     "[--run-module-preinitializers] "
                     "[--run-module-initializers] "
                     "[--run-module-dt-init nome.prx (alias --start-module)] "
                     "[--prepare-guest-process] "
                      "[--trace-graphics-calls] "
                     "[--trap-unimplemented-gnm] "
                     "[--probe-gnm-submit-done] "
                     "[--user-root pasta] "
                     "[--run-entrypoint] "
                     "[--dump-module-code nome.prx endereço-hex] "
                     "[--find-rip-relative-target endereço-hex] "
                     "[--find-module-rip-relative-target módulo endereço-hex] "
                     "[--find-relative-call-target endereço-hex] "
                     "[--find-relative-branch-target endereço-hex] "
                     "[--find-module-relative-branch-target módulo endereço-hex] "
                     "[--find-member-field-writes deslocamento-hex] "
                     "[--lookup-main-relocation endereço-hex] "
                     "[--list-module-imports nome.prx] "
                     "[--find-module-string nome.prx texto] "
                     "[--skip-missing nome.prx]... [--hle-module nome.prx]...\n";
        return 2;
    }
    std::string error;
    nba16::NativeExecutableImage prepared_executable{};
    if (!nba16::prepare_native_executable_image(argv[1], prepared_executable, error)) {
        std::cerr << "Falha ao preparar a imagem principal: " << error << '\n';
        return 1;
    }
    auto& executable_image = prepared_executable.image;
    auto& executable_link = prepared_executable.dynamic;
    auto& executable_map = prepared_executable.map;
    auto& executable_memory = prepared_executable.memory;
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr) {
        for (std::size_t index = 0; index < executable_link.import_libraries.size(); ++index)
            std::fprintf(stderr, "MEM import-library[%zu]=%s id=%u\n", index,
                executable_link.import_libraries[index].name.c_str(),
                executable_link.import_libraries[index].library_id);
        for (std::size_t index = 0; index < executable_link.import_modules.size(); ++index)
            std::fprintf(stderr, "MEM import-module[%zu]=%s id=%u\n", index,
                executable_link.import_modules[index].name.c_str(),
                executable_link.import_modules[index].module_id);
        for (const auto& symbol : executable_link.symbols) {
            const auto library = symbol.has_nid_indices &&
                symbol.nid_library_index < executable_link.import_libraries.size()
                ? executable_link.import_libraries[symbol.nid_library_index].name : "?";
            const auto module = symbol.has_nid_indices &&
                symbol.nid_module_index < executable_link.import_modules.size()
                ? executable_link.import_modules[symbol.nid_module_index].name : "?";
            if (library != "libSceLibcInternal" && library != "libc" &&
                module != "libSceLibcInternal" && module != "libc" &&
                symbol.name.find("Mspace") == std::string::npos &&
                !symbol.name.starts_with("-hn1tcVHq5Q") &&
                !symbol.name.starts_with("OJjm-QOIHlI") &&
                !symbol.name.starts_with("Vla-Z+eXlxo")) continue;
            std::fprintf(stderr, "MEM mspace-import name=%s library=%s module=%s\n",
                symbol.name.c_str(), library.c_str(), module.c_str());
        }
    }
    const auto process_parameter = std::find_if(executable_image.program_headers.begin(),
        executable_image.program_headers.end(), [](const auto& header) {
            return header.type == 0x61000001U && header.memory_size >= 0x40;
        });
    if (process_parameter != executable_image.program_headers.end()) {
        auto* parameter = reinterpret_cast<void*>(static_cast<std::uintptr_t>(
            executable_memory.load_bias() + process_parameter->virtual_address));
        nba16::set_guest_process_parameter(parameter);
        std::cout << "PT_SCE_PROC_PARAM disponível em 0x" << std::hex
                  << reinterpret_cast<std::uintptr_t>(parameter) << std::dec << ".\n";
    } else {
        nba16::set_guest_process_parameter(nullptr);
        std::cout << "O executável não declara PT_SCE_PROC_PARAM.\n";
    }
    nba16::ImportResolver resolver{};
    const auto executable_path = std::filesystem::path(argv[1]);
    if (!nba16::register_native_runtime_services(resolver,
            executable_path.parent_path(), error)) {
        std::cerr << "Falha ao registrar HLE nativo: " << error << '\n';
        return 1;
    }
    if (trace_graphics_calls && !nba16::register_graphics_call_trace(
            resolver, error, probe_gnm_submit_done)) {
        std::cerr << "Falha ao registrar rastreamento gráfico: " << error << '\n';
        return 1;
    }
    if (probe_gnm_submit_done && !nba16::register_gnm_submit_done_probe(resolver, error)) {
        std::cerr << "Falha ao registrar probe de sceGnmSubmitDone: " << error << '\n';
        return 1;
    }
    if (probe_gnm_submit_done)
        std::cerr << "GPU-PROBE ativo: sceGnmSubmitDone retorna 0 sem executar GPU; diagnóstico apenas.\n";
    if (trace_graphics_calls) {
        nba16::set_native_video_out_trace_enabled(true);
        std::cerr << "GPU-TRACE ativo: imports GNM instrumentados retornam -1 sem executar comandos; "
                     "VideoOut usa HLE nativo instrumentado. Nenhum frame é renderizado.\n";
    }
    if (trap_unimplemented_gnm) {
        std::size_t registered_traps{};
        if (!nba16::register_unimplemented_gnm_import_traps(
                resolver, trace_graphics_calls, registered_traps, error)) {
            std::cerr << "Armadilhas diagnósticas GNM não puderam ser registradas: "
                      << error << '\n';
            return 1;
        }
        std::cerr << "GNM-FAIL-FAST ativo: " << registered_traps
                  << " imports sem HLE encerram o processo com identidade e caller; "
                     "nenhum resultado de sucesso será simulado.\n";
    }
    if (!resolver.register_function("libkernel", "libkernel", "6Z83sYWFlA8",
            &guest_process_exit_probe, error)) {
        std::cerr << "Interposição de _exit para diagnóstico falhou: " << error << '\n';
        return 1;
    }
    nba16::GuestTlsRuntime tls_runtime{};
    if (!tls_runtime.register_import(resolver, error)) {
        std::cerr << "Falha ao registrar o serviço TLS: " << error << '\n';
        return 1;
    }
    nba16::NativeProcessModules process_modules{};
    auto& modules = process_modules.modules();
    auto& summary = process_modules.summary();
    const std::vector<std::filesystem::path> module_directories{
        executable_path.parent_path() / "sce_module",
        std::filesystem::path(argv[2]),
    };
    if (!process_modules.load_dependencies(prepared_executable, module_directories, resolver,
            skipped_names, hle_module_names, error)) {
        std::cerr << "Módulos preparados antes da falha: " << modules.size()
                  << "; ausentes: " << summary.modules_missing << '\n'
                  << error << '\n';
        return 1;
    }
    std::cout << "Módulos preparados recursivamente: " << summary.modules_loaded << '\n';
    if (!list_module_imports_name.empty()) {
        const nba16::Ps4DynamicLinkInfo* link_pointer{};
        const nba16::Ps4LoadedModule* module{};
        if (list_module_imports_name == "eboot.bin") {
            link_pointer = &executable_link;
        } else {
            module = modules.find(list_module_imports_name);
            if (module == nullptr) {
                std::cerr << "Módulo não carregado para listar imports: "
                          << list_module_imports_name << '\n';
                return 1;
            }
            link_pointer = &module->dynamic_info();
        }
        const auto& link = *link_pointer;
        nba16::ImportResolution module_imports{};
        if (!resolver.resolve(link, module_imports, error,
                module == nullptr ? 0 : module->image_memory().load_bias())) {
            std::cerr << "Não foi possível resolver imports para inspeção: " << error << '\n';
            return 1;
        }
        std::cout << "Imports de " << list_module_imports_name << ":\n";
        std::cout << "Entradas especiais STT_SCE do módulo:\n";
        for (const auto& symbol : link.symbols) {
            if ((symbol.info & 0x0fU) != 11U || symbol.section_index == 0) continue;
            std::cout << "  " << (symbol.name.empty() ? "(sem nome)" : symbol.name)
                      << " value=0x" << std::hex << symbol.value
                      << " size=0x" << symbol.size << std::dec << '\n';
        }
        for (std::size_t symbol_index = 1; symbol_index < link.symbols.size(); ++symbol_index) {
            const auto& symbol = link.symbols[symbol_index];
            if (symbol.section_index != 0 || !symbol.has_nid_indices) continue;
            const auto library = std::find_if(link.import_libraries.begin(),
                link.import_libraries.end(), [&](const auto& item) {
                    return item.library_id == symbol.nid_library_index;
                });
            const auto imported_module = std::find_if(link.import_modules.begin(),
                link.import_modules.end(), [&](const auto& item) {
                    return item.module_id == symbol.nid_module_index;
                });
            std::size_t references{};
            std::vector<std::uint64_t> relocation_targets;
            for (const auto& relocation : link.relocations) {
                if (relocation.symbol_index != symbol_index) continue;
                ++references;
                relocation_targets.push_back(relocation.target);
            }
            std::cout << "  " << (library == link.import_libraries.end() ? "?" : library->name)
                      << "/" << (imported_module == link.import_modules.end() ? "?" : imported_module->name)
                      << " nid=" << symbol.name.substr(0, symbol.name.find('#'))
                      << " refs=" << references << " destino=0x" << std::hex
                      << module_imports.symbol_addresses[symbol_index].value_or(0)
                      << " reloc=";
            for (std::size_t index = 0; index < relocation_targets.size(); ++index) {
                if (index != 0) std::cout << ',';
                std::cout << "0x" << relocation_targets[index];
            }
            std::cout << std::dec << '\n';
        }
    }
    for (const auto& name : summary.skipped_module_names) {
        constexpr std::string_view hle_suffix = " (HLE)";
        if (name.ends_with(hle_suffix)) {
            std::cout << "Módulo LLE substituído por HLE: "
                      << name.substr(0, name.size() - hle_suffix.size()) << '\n';
        } else {
            std::cout << "Dependência ausente ignorada apenas para inspeção: "
                      << name << '\n';
        }
    }
if (!process_modules.relocate(resolver, error)) {
        std::cerr << "Conjunto carregado, mas ainda não pode ser finalizado: " << error << '\n';
        return 1;
    }
    nba16::ImportResolution executable_imports{};
    if (!prepared_executable.resolve_imports(resolver, executable_imports, error)) {
        std::cerr << "Imports do executável principal não puderam ser resolvidos: "
                  << error << '\n';
        return 1;
    }
    std::cout << "Imports do eboot resolvidos: " << executable_imports.resolved_count
              << "/" << executable_link.symbols.size() << " símbolos; "
              << executable_imports.resolved_relocation_references << " referências.\n";
    if (!executable_imports.unresolved.empty()) {
        std::cerr << "Imports pendentes do eboot: " << executable_imports.unresolved.size()
                  << " símbolos; execução ainda bloqueada.\n";
        for (const auto& item : executable_imports.unresolved) {
            std::cerr << "  " << item.library << "/" << item.module << ": "
                      << (item.nid.empty() ? item.symbol_name : item.nid) << '\n';
        }
        return 1;
    }
    nba16::RelocationApplicationSummary imported_relocations{};
    if (!prepared_executable.apply_imports(executable_imports, imported_relocations, error)) {
        std::cerr << "Executável principal não pôde ser finalizado: " << error << '\n';
        return 1;
    }
    if (!prepared_executable.patch_syscall_stubs(resolver, summary, error)) {
        std::cerr << "Stubs syscall do eboot não puderam ser redirecionados: "
                  << error << '\n';
        return 1;
    }
    if (process_parameter != executable_image.program_headers.end()) {
        auto* parameter = reinterpret_cast<void*>(static_cast<std::uintptr_t>(
            executable_memory.load_bias() + process_parameter->virtual_address));
        if (!nba16::configure_guest_libc_allocator(parameter, error)) {
            std::cerr << "Allocator substituto do libc não pôde ser preparado: "
                      << error << '\n';
            return 1;
        }
        std::cout << "Allocator guest configurado depois das relocations, em faixa abaixo de 2 GiB.\n";
    }
    std::uint64_t executable_tcb_loads{};
    if (!prepared_executable.finalize_memory(executable_tcb_loads, error)) {
        std::cerr << "Ponteiro de thread ou proteção do executável falhou: " << error << '\n';
        return 1;
    }
    nba16::GuestStartupPlan startup_plan{};
    if (!nba16::build_guest_startup_plan(executable_map, executable_link,
            startup_plan, error)) {
        std::cerr << "Inicializadores do eboot não passaram na validação: " << error << '\n';
        return 1;
    }
    if (!tls_runtime.initialize(modules.tls_images(), error)) {
        std::cerr << "Runtime TLS não preparado: " << error << '\n';
        return 1;
    }
    if (!nba16::initialize_guest_tcb(error)) {
        std::cerr << "TCB da thread principal não pôde ser instalado: " << error << '\n';
        return 1;
    }
    std::cout << "Leituras FS do TCB redirecionadas no eboot: "
              << executable_tcb_loads << '\n';
    std::cout << "Leituras FS do TCB adaptadas nos módulos: "
              << nba16::guest_tcb_patched_load_count() << '\n';
    std::cout << "Módulos com imports relocados e permissões finais: "
              << summary.modules_relocated << '\n'
              << "Stubs sysctl redirecionados: " << summary.sysctl_stubs_redirected
              << " sysctlbyname: " << summary.sysctlbyname_stubs_redirected << '\n'
              << "Inicializadores do executável validados: " << startup_plan.calls.size()
              << (run_constructor_count != 0
                    ? " (modo de teste: será executado o prefixo solicitado da tabela).\n"
                    : " (não executados).\n");
    if (dump_main_initializers) {
        std::array<std::byte, 64> entry_code{};
        if (nba16::read_guest_memory(executable_map,
                executable_memory.load_bias() + executable_map.entry_point,
                entry_code, error)) {
            std::cout << "Entry point eboot.bin em 0x" << std::hex
                      << executable_map.entry_point << std::dec << " bytes:";
            for (const auto byte : entry_code) {
                std::cout << ' ' << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
            }
            std::cout << std::dec << std::setfill(' ') << '\n';
        } else {
            std::cout << "Não foi possível ler o início do entry point: " << error << '\n';
            error.clear();
        }
        std::cout << "Planos de inicialização PRX carregados (somente leitura):\n";
        for (const auto& name : modules.loaded_module_names()) {
            const auto* module = modules.find(name);
            if (module == nullptr) continue;
            const auto& init = module->dynamic_info().initialization;
            std::cout << "  " << name << ": " << module->startup_plan().calls.size()
                      << " chamada(s), e_entry=0x" << std::hex
                      << module->image_map().entry_point << std::dec << ", DT_INIT=";
            if (init.init_function) std::cout << "0x" << std::hex << *init.init_function << std::dec;
            else std::cout << "-";
            std::cout << ", INIT_ARRAY=" << init.init_array_size.value_or(0) / 8
                      << ", PREINIT_ARRAY=" << init.preinit_array_size.value_or(0) / 8;
            if (const auto parameter = module->process_parameter_address()) {
                std::cout << ", procparam=0x" << std::hex << *parameter << std::dec;
            } else {
                std::cout << ", procparam=ausente";
            }
            for (const auto& call : module->startup_plan().calls) {
                std::cout << " " << call.source << "@0x" << std::hex
                          << call.guest_address << std::dec;
                std::array<std::byte, 32> prologue{};
                std::string read_error;
                if (nba16::read_guest_memory(module->image_map(),
                        module->image_memory().load_bias() + call.guest_address,
                        prologue, read_error)) {
                    std::cout << " bytes=";
                    for (const auto byte : prologue) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
                    }
                    std::cout << std::dec << std::setfill(' ');
                }
            }
            std::cout << '\n';
        }
        if (const auto* playgo = modules.find("libScePlayGo")) {
            const auto& playgo_map = playgo->image_map();
            std::cout << "libScePlayGo: bias=0x" << std::hex << playgo_map.load_bias
                      << " faixa=0x" << playgo_map.minimum_virtual_address << "-0x"
                      << playgo_map.maximum_virtual_address << std::dec
                      << "; inicializadores=" << playgo->startup_plan().calls.size()
                      << " (não executados).\n";
        } else {
            std::cout << "libScePlayGo não está carregado no conjunto de módulos.\n";
        }
        for (const auto& callback : startup_plan.calls) {
            std::array<std::byte, 128> code{};
            const auto runtime_address = executable_memory.load_bias() + callback.guest_address;
            if (!nba16::read_guest_memory(executable_map, runtime_address, code, error)) {
                std::cerr << "Não foi possível ler bytes de " << callback.source << ": "
                          << error << '\n';
                return 1;
            }
            std::cout << callback.source << " bytes em 0x" << std::hex
                      << callback.guest_address << ":";
            for (const auto byte : code) {
                std::cout << ' ' << std::setw(2) << std::setfill('0')
                          << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
            }
            std::cout << std::dec << std::setfill(' ') << '\n';
            if (callback.source == "DT_INIT" &&
                code[0x0a] == std::byte{0x48} && code[0x0b] == std::byte{0x8d} &&
                code[0x0c] == std::byte{0x1d}) {
                std::int32_t displacement{};
                std::memcpy(&displacement, code.data() + 0x0d, sizeof(displacement));
                const auto table_end_signed = static_cast<std::int64_t>(callback.guest_address) +
                                              0x11 + displacement;
                if (table_end_signed < 8) {
                    std::cerr << "Tabela de construtores fora do intervalo seguro.\n";
                    return 1;
                }
                auto table_cursor = static_cast<std::uint64_t>(table_end_signed);
                std::vector<std::uint64_t> constructors;
                bool sentinel_found = false;
                for (std::size_t index = 0; index < 4096; ++index) {
                    table_cursor -= sizeof(std::uint64_t);
                    std::array<std::byte, sizeof(std::uint64_t)> pointer_bytes{};
                    if (!nba16::read_guest_memory(executable_map,
                            executable_memory.load_bias() + table_cursor,
                            pointer_bytes, error)) {
                        std::cerr << "Fim da tabela de construtores não mapeado: "
                                  << error << '\n';
                        return 1;
                    }
                    std::uint64_t pointer{};
                    std::memcpy(&pointer, pointer_bytes.data(), sizeof(pointer));
                    if (pointer == 0 || pointer == std::numeric_limits<std::uint64_t>::max()) {
                        sentinel_found = true;
                        break;
                    }
                    constructors.push_back(pointer);
                }
                if (!sentinel_found) {
                    std::cerr << "Tabela de construtores excedeu o limite de segurança.\n";
                    return 1;
                }
                std::cout << "Construtores listados: " << constructors.size() << '\n';
                if (has_dump_constructor_index) {
                    if (dump_constructor_index >= constructors.size()) {
                        std::cerr << "Índice de construtor solicitado está fora da tabela.\n";
                        return 1;
                    }
                    const auto selected_address = constructors[dump_constructor_index] -
                                                  executable_memory.load_bias();
                    std::array<std::byte, 128> selected_code{};
                    if (!nba16::read_guest_memory(executable_map,
                            executable_memory.load_bias() + selected_address,
                            selected_code, error)) {
                        std::cerr << "Não foi possível ler construtor ["
                                  << dump_constructor_index << "]: " << error << '\n';
                        return 1;
                    }
                    std::cout << "Construtor [" << dump_constructor_index << "] em 0x"
                              << std::hex << selected_address << " bytes:";
                    for (const auto byte : selected_code) {
                        std::cout << ' ' << std::setw(2) << std::setfill('0')
                                  << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
                    }
                    std::cout << std::dec << std::setfill(' ') << '\n';
                    for (std::size_t offset = 0; offset < 0x40; ++offset) {
                        const auto opcode = selected_code[offset];
                        if (opcode != std::byte{0xe8} && opcode != std::byte{0xe9}) continue;
                        std::int32_t displacement{};
                        std::memcpy(&displacement, selected_code.data() + offset + 1,
                                    sizeof(displacement));
                        const auto target_signed = static_cast<std::int64_t>(selected_address) +
                            static_cast<std::int64_t>(offset) + 5 + displacement;
                        if (target_signed < 0) continue;
                        const auto target = static_cast<std::uint64_t>(target_signed);
                        std::array<std::byte, 128> target_bytes{};
                        if (!nba16::read_guest_memory(executable_map,
                                executable_memory.load_bias() + target,
                                target_bytes, error)) {
                            error.clear();
                            continue;
                        }
                        std::cout << "  alvo de " << (opcode == std::byte{0xe8} ? "call" : "jmp")
                                  << " em +0x" << std::hex << offset << " = 0x" << target
                                  << " bytes:";
                        for (const auto byte : target_bytes) {
                            std::cout << ' ' << std::setw(2) << std::setfill('0')
                                      << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
                        }
                        std::cout << std::dec << std::setfill(' ') << '\n';
                    }
                }
                const auto sample_count = std::min<std::size_t>(constructors.size(), 10);
                for (std::size_t index = 0; index < sample_count; ++index) {
                    std::cout << "  [" << index << "] guest=0x" << std::hex
                              << constructors[index] - executable_memory.load_bias()
                              << std::dec << '\n';
                }
                if (!constructors.empty()) {
                    const auto guest_address = constructors.front() - executable_memory.load_bias();
                    std::array<std::byte, 64> constructor_code{};
                    if (!nba16::read_guest_memory(executable_map,
                            executable_memory.load_bias() + guest_address,
                            constructor_code, error)) {
                        std::cerr << "Não foi possível ler o primeiro construtor: "
                                  << error << '\n';
                        return 1;
                    }
                    std::cout << "Primeiro construtor em 0x" << std::hex << guest_address
                              << " bytes:";
                    for (const auto byte : constructor_code) {
                        std::cout << ' ' << std::setw(2) << std::setfill('0')
                                  << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
                    }
                    std::cout << std::dec << std::setfill(' ') << '\n';
                    if (constructors.size() > 1) {
                        const auto second_address = constructors[1] - executable_memory.load_bias();
                        std::array<std::byte, 64> second_code{};
                        if (!nba16::read_guest_memory(executable_map,
                                executable_memory.load_bias() + second_address,
                                second_code, error)) {
                            std::cerr << "Não foi possível ler o segundo construtor: "
                                      << error << '\n';
                            return 1;
                        }
                        std::cout << "Segundo construtor em 0x" << std::hex << second_address
                                  << " bytes:";
                        for (const auto byte : second_code) {
                            std::cout << ' ' << std::setw(2) << std::setfill('0')
                                      << static_cast<unsigned>(
                                          std::to_integer<std::uint8_t>(byte));
                        }
                        std::cout << std::dec << std::setfill(' ') << '\n';
                    }
                    if (prepare_guest_process || run_constructor_count != 0 || run_module_preinitializers ||
                        run_module_initializers || !start_module_name.empty() ||
                        run_guest_entrypoint) {
                        if (run_constructor_count > constructors.size()) {
                            std::cerr << "A tabela tem menos construtores que o solicitado.\n";
                            return 1;
                        }
                        constexpr std::size_t guest_stack_size = 16U * 1024U * 1024U;
                        nba16::NativeRuntimePaths runtime_paths{};
                        if (!nba16::resolve_native_runtime_paths(std::filesystem::path(argv[1]),
                                user_root, "CUSA06321", runtime_paths, error)) {
                            std::cerr << "Caminhos do runtime não puderam ser resolvidos: "
                                      << error << '\n';
                            return 1;
                        }
                        nba16::NativeGuestProcess guest_process{};
                        if (!guest_process.initialize(runtime_paths, prepared_executable,
                                process_modules, guest_stack_size, error)) {
                            std::cerr << "Contexto do processo convidado não pôde ser preparado: "
                                      << error << '\n';
                            return 1;
                        }
                        if (prepare_guest_process) {
                            std::cout << "Contexto do processo convidado preparado; "
                                         "inicializadores e entry point não executados.\n";
                        }
                        auto& guest_stack = guest_process.stack();
                        auto& process_context = guest_process.context();
                        const auto guest_stack_begin = static_cast<std::uint64_t>(
                            reinterpret_cast<std::uintptr_t>(guest_stack.bottom()));
                        nba16::ScopedGuestProcessContext process_scope(&process_context);
                        nba16::GuestCallBridge bridge(executable_map, executable_memory,
                                                       nullptr, guest_stack.top());
#ifdef _WIN32
                        probe_regions.clear();
                        for (const auto& region : executable_map.regions) {
                            const auto begin = executable_memory.load_bias() +
                                               region.virtual_address;
                            probe_regions.push_back({"eboot.bin", executable_memory.load_bias(),
                                begin, begin + region.memory_size, region.flags});
                        }
                        for (const auto& name : modules.loaded_module_names()) {
                            const auto* module = modules.find(name);
                            if (module == nullptr) continue;
                            if (name == "libSceGnmDriver.prx") {
                                const auto path = modules.loaded_module_path(name);
                                const auto path_text = path.has_value()
                                    ? path->string() : std::string("<unknown>");
                                std::fprintf(stderr,
                                    "GNM-IMAGE path=%s load_bias=0x%llx\n",
                                    path_text.c_str(), static_cast<unsigned long long>(
                                        module->image_memory().load_bias()));
                            }
                            const auto& module_map = module->image_map();
                            for (const auto& region : module_map.regions) {
                                const auto begin = module_map.load_bias + region.virtual_address;
                                probe_regions.push_back({name, module_map.load_bias,
                                    begin, begin + region.memory_size, region.flags});
                            }
                        }
                        probe_regions.push_back({"guest-main-stack", 0, guest_stack_begin,
                            guest_stack_begin + guest_stack.size(), 0});
                        arm_eboot_memory_allocation_trace();
                        if (std::getenv("NBA16_TRACE_MUTEX_MAP") != nullptr) {
                            for (const auto& region : probe_regions) {
                                std::fprintf(stderr,
                                    "guest-region name=%s base=0x%llx begin=0x%llx end=0x%llx\n",
                                    region.name.c_str(),
                                    static_cast<unsigned long long>(region.load_bias),
                                    static_cast<unsigned long long>(region.begin),
                                    static_cast<unsigned long long>(region.end));
                            }
                        }
                        const auto exception_handler = AddVectoredExceptionHandler(
                            1, report_guest_exception);
                        start_shader_state_instruction_trace();
#endif
                        if (run_module_preinitializers) {
                            for (const auto& name : modules.loaded_module_names()) {
                                const auto* module = modules.find(name);
                                if (module == nullptr) continue;
                                for (const auto& call : module->startup_plan().calls) {
                                    if (call.source != "DT_PREINIT_ARRAY") continue;
                                    nba16::GuestCallBridge module_bridge(module->image_map(),
                                        module->image_memory(), nullptr, guest_stack.top());
                                    std::cout << "Executando preinit " << name << " em 0x"
                                              << std::hex << call.guest_address << std::dec << "...\n";
                                    if (!module_bridge.call_void<>(call.guest_address, error)) {
                                        std::cerr << "Preinit de " << name << " falhou: "
                                                  << error << '\n';
                                        return 1;
                                    }
                                    std::cout << "Preinit de " << name
                                              << " retornou normalmente.\n";
                                }
                            }
                        }
                        if (const auto* libc = modules.find("libSceLibcInternal")) {
                            const auto default_slot = static_cast<std::uintptr_t>(
                                libc->image_memory().load_bias() + 0x147000);
                            nba16::set_guest_mspace_default_slot(
                                reinterpret_cast<void**>(default_slot));
                            if (initialize_libc_internal_allocator) {
                                std::uint64_t arena_begin{};
                                std::size_t arena_size{};
                                if (!nba16::guest_libc_arena_region(arena_begin, arena_size) ||
                                    !nba16::initialize_guest_mspace_default(arena_begin, arena_size)) {
                                    std::cerr << "Não foi possível inicializar o mspace padrão antes do libc.\n";
                                    return 1;
                                }
                                std::cout << "Mspace padrão preparado em 0x" << std::hex
                                          << arena_begin << " (0x" << arena_size << ") antes do _malloc_init.\n"
                                          << std::dec;
                            }
                        }
                        if (initialize_libc_internal_allocator) {
                            const auto* libc = modules.find("libSceLibcInternal");
                            std::vector<nba16::LoadedPs4Export> libc_exports;
                            if (libc == nullptr ||
                                !libc->collect_exports("libSceLibcInternal", libc_exports, error)) {
                                std::cerr << "Exports de inicialização do libc indisponíveis: "
                                          << error << '\n';
                                return 1;
                            }
                            const auto allocator_export = std::find_if(libc_exports.begin(),
                                libc_exports.end(), [](const auto& item) {
                                    return item.nid == "z8GPiQwaAEY" && item.elf_symbol_kind == 2;
                                });
                            if (allocator_export == libc_exports.end()) {
                                std::cerr << "Export malloc-init de libSceLibcInternal não encontrado.\n";
                                return 1;
                            }
                            nba16::GuestCallBridge libc_bridge(libc->image_map(),
                                libc->image_memory(), nullptr, guest_stack.top());
                            std::int32_t init_result{};
                            std::cout << "Inicializando allocator de libSceLibcInternal em +0x"
                                      << std::hex << allocator_export->module_relative_value << std::dec << "...\n";
                            if (!libc_bridge.call(allocator_export->module_relative_value,
                                    init_result, error)) {
                                std::cerr << "Inicialização do allocator do libc falhou: "
                                          << error << '\n';
                                return 1;
                            }
                            std::cout << "_malloc_init retornou " << init_result << ".\n";
                            if (init_result != 0) return 1;
                        }
                        if (enable_libc_internal_mutexes) {
                            const auto* libc = modules.find("libSceLibcInternal");
                            std::vector<nba16::LoadedPs4Export> libc_exports;
                            if (libc == nullptr ||
                                !libc->collect_exports("libSceLibcInternal", libc_exports, error)) {
                                std::cerr << "Exports de inicialização do libc indisponíveis: "
                                          << error << '\n';
                                return 1;
                            }
                            const auto mutex_export = std::find_if(libc_exports.begin(),
                                libc_exports.end(), [](const auto& item) {
                                    return item.nid == "h8jq9ee4h5c" && item.elf_symbol_kind == 2;
                                });
                            if (mutex_export == libc_exports.end()) {
                                std::cerr << "Export mutex-enable de libSceLibcInternal não encontrado.\n";
                                return 1;
                            }
                            nba16::GuestCallBridge libc_bridge(libc->image_map(),
                                libc->image_memory(), nullptr, guest_stack.top());
                            std::cout << "Habilitando mutexes de libSceLibcInternal em +0x"
                                      << std::hex << mutex_export->module_relative_value << std::dec << "...\n";
                            if (!libc_bridge.call_void<>(mutex_export->module_relative_value, error)) {
                                std::cerr << "Inicialização dos mutexes do libc falhou: " << error << '\n';
                                return 1;
                            }
                            std::cout << "Mutexes de libSceLibcInternal habilitados.\n";
                        }
                        if (bootstrap_libkernel_pthreads) {
                            const auto* kernel = modules.find("libkernel");
                            if (kernel == nullptr) {
                                std::cerr << "libkernel não está carregado; bootstrap pthread indisponível.\n";
                                return 1;
                            }
                            constexpr std::array<std::byte, 12> expected_bootstrap{
                                std::byte{0x55}, std::byte{0x48}, std::byte{0x89}, std::byte{0xe5},
                                std::byte{0x53}, std::byte{0x50}, std::byte{0x48}, std::byte{0x8d},
                                std::byte{0x05}, std::byte{0x33}, std::byte{0x1c}, std::byte{0x04},
                            };
                            std::array<std::byte, expected_bootstrap.size()> actual_bootstrap{};
                            if (!nba16::read_guest_memory(kernel->image_map(),
                                    kernel->image_memory().load_bias() + 0x2f640,
                                    actual_bootstrap, error) || actual_bootstrap != expected_bootstrap) {
                                std::cerr << "Rotina pthread do libkernel não passou a validação de assinatura: "
                                          << error << '\n';
                                return 1;
                            }
                            nba16::GuestCallBridge kernel_bridge(kernel->image_map(),
                                kernel->image_memory(), nullptr, guest_stack.top());
                            std::cout << "Executando bootstrap pthread validado do libkernel em +0x2f640...\n";
                            if (!kernel_bridge.call_void<>(0x2f640, error)) {
                                std::cerr << "Bootstrap pthread do libkernel falhou: " << error << '\n';
                                return 1;
                            }
                            std::cout << "Bootstrap pthread do libkernel retornou normalmente.\n";
                            if (initialize_libc_internal_allocator) {
                                std::uint64_t arena_begin{};
                                std::size_t arena_size{};
                                if (!nba16::guest_libc_arena_region(arena_begin, arena_size) ||
                                    arena_size < 16) {
                                    std::cerr << "Heap baixo do guest indisponível para o libkernel.\n";
                                    return 1;
                                }
                                auto* thread_mspace_slot = reinterpret_cast<void**>(
                                    kernel->image_memory().load_bias() + 0x8e430);
                                if (*thread_mspace_slot != nullptr) {
                                    std::cerr << "Slot de mspace de threads do libkernel já foi inicializado; "
                                                 "não será sobrescrito.\n";
                                    return 1;
                                }
                                *thread_mspace_slot = reinterpret_cast<void*>(arena_begin);
                                std::cout << "Mspace do heap de threads do libkernel ligado a 0x"
                                          << std::hex << arena_begin << std::dec << ".\n";
                            }
                        }
                        if (run_module_initializers) {
                            std::vector<std::string> initialization_order;
                            std::set<std::string> visited;
                            std::set<std::string> visiting;
                            std::function<bool(const std::string&)> visit_dependencies =
                                [&](const std::string& name) {
                                    if (visited.contains(name)) return true;
                                    if (!visiting.insert(name).second) return true;
                                    const auto* module = modules.find(name);
                                    if (module == nullptr) {
                                        visiting.erase(name);
                                        visited.insert(name);
                                        return true;
                                    }
                                    for (const auto& dependency : module->dynamic_info().needed_modules) {
                                        if (!visit_dependencies(dependency)) return false;
                                    }
                                    visiting.erase(name);
                                    visited.insert(name);
                                    initialization_order.push_back(name);
                                    return true;
                                };
                            for (const auto& name : modules.loaded_module_names()) {
                                if (!visit_dependencies(name)) {
                                    std::cerr << "Não foi possível ordenar os inicializadores PRX.\n";
                                    return 1;
                                }
                            }
                            for (const auto& name : initialization_order) {
                                const auto* module = modules.find(name);
                                if (module == nullptr) continue;
                                for (const auto& call : module->startup_plan().calls) {
                                    if (call.source == "DT_PREINIT_ARRAY") continue;
                                    nba16::GuestCallBridge module_bridge(module->image_map(),
                                        module->image_memory(), nullptr, guest_stack.top());
                                    if (call.source == "DT_INIT" &&
                                        name == "libSceLibcInternal.prx") {
                                        auto* thread_record = static_cast<std::uint64_t*>(
                                            nba16::guest_tcb_current_thread_record());
                                        std::cout << "TCB thread record=" << thread_record;
                                        if (thread_record != nullptr) {
                                            std::cout << " waiter-tail=" << reinterpret_cast<void*>(
                                                thread_record[0x1a8 / sizeof(std::uint64_t)]);
                                        }
                                        std::cout << '\n';
                                    }
                                    std::cout << "Executando " << call.source << " de " << name
                                              << " em 0x" << std::hex << call.guest_address
                                              << std::dec << "...\n";
                                    if (call.source == "DT_INIT") {
                                        std::int32_t start_result{};
                                        void* process_parameter = nullptr;
                                        if (const auto parameter = module->process_parameter_address()) {
                                            process_parameter = reinterpret_cast<void*>(
                                                static_cast<std::uintptr_t>(*parameter));
                                        }
                                        if (!module_bridge.call(call.guest_address, start_result,
                                                error, std::uint64_t{0},
                                                static_cast<const void*>(nullptr),
                                                process_parameter)) {
                                            std::cerr << "DT_INIT de " << name
                                                      << " falhou: " << error << '\n';
                                            return 1;
                                        }
                                        std::cout << "DT_INIT de " << name
                                                  << " retornou " << start_result << ".\n";
                                        continue;
                                    }
                                    if (!module_bridge.call_void<>(call.guest_address, error)) {
                                        std::cerr << call.source << " de " << name
                                                  << " falhou: " << error << '\n';
                                        return 1;
                                    }
                                    std::cout << call.source << " de " << name
                                              << " retornou normalmente.\n";
                                }
                            }
                        }
                        if (!start_module_name.empty()) {
                            const auto* module = modules.find(start_module_name);
                            if (module == nullptr) {
                                std::cerr << "Módulo não carregado para module_start: "
                                          << start_module_name << '\n';
                                return 1;
                            }
                            const auto init = module->dynamic_info().initialization.init_function;
                            if (!init.has_value()) {
                                std::cerr << "O módulo não declara DT_INIT: "
                                          << start_module_name << '\n';
                                return 1;
                            }
                            const auto entry = *init;
                            if (!nba16::validate_guest_execute_access(module->image_map(),
                                    module->image_memory().load_bias() + entry, 1, error)) {
                                std::cerr << "module_start fora do segmento executável de "
                                          << start_module_name << ": " << error << '\n';
                                return 1;
                            }
                            void* process_parameter = nullptr;
                            if (const auto parameter = module->process_parameter_address()) {
                                process_parameter = reinterpret_cast<void*>(
                                    static_cast<std::uintptr_t>(*parameter));
                            }
                            nba16::GuestCallBridge module_bridge(module->image_map(),
                                module->image_memory(), nullptr, guest_stack.top());
                            std::int32_t start_result{};
                            std::cout << "Executando DT_INIT explicitamente de "
                                      << start_module_name << " em +0x" << std::hex
                                      << entry << std::dec << "...\n";
                            if (!module_bridge.call(entry, start_result, error,
                                    std::uint64_t{0}, static_cast<const void*>(nullptr),
                                    process_parameter)) {
                                std::cerr << "DT_INIT de " << start_module_name
                                          << " falhou: " << error << '\n';
                                return 1;
                            }
                            std::cout << "DT_INIT de " << start_module_name
                                      << " retornou " << start_result << ".\n";
                            if (start_module_name == "libSceGnmDriver.prx") {
                                const auto read_gnm_global = [&](std::uint64_t offset,
                                        std::size_t size, std::uint64_t& value) {
                                    std::array<std::byte, sizeof(value)> bytes{};
                                    if (!nba16::read_guest_memory(module->image_map(),
                                            module->image_memory().load_bias() + offset,
                                            std::span<std::byte>(bytes.data(), size), error))
                                        return false;
                                    std::memcpy(&value, bytes.data(), size);
                                    return true;
                                };
                                std::uint64_t driver_state{}, device_fd{}, gnm_context{},
                                              init_callback{},
                                              gpu_info_mapping{};
                                if (read_gnm_global(0xc030, 8, init_callback) &&
                                    read_gnm_global(0x100d8, 4, driver_state) &&
                                    read_gnm_global(0x100dc, 4, device_fd) &&
                                    read_gnm_global(0x100e8, 8, gnm_context) &&
                                    read_gnm_global(0x10500, 8, gpu_info_mapping)) {
                                    std::cout << "Estado GNM após DT_INIT: init=0x"
                                              << std::hex << init_callback
                                              << " state=0x"
                                              << std::hex << driver_state << " fd=0x" << device_fd
                                              << " contexto=0x" << gnm_context
                                              << " gpuInfo=0x" << gpu_info_mapping
                                              << std::dec << ".\n";
                                } else {
                                    std::cerr << "Não foi possível ler o estado GNM após module_start: "
                                              << error << '\n';
                                }
                            }
                        }
                        for (std::size_t index = 0; index < run_constructor_count; ++index) {
                            if (index == 351) nba16::reset_guest_sysctl_diagnostics();
                            const auto current_address = constructors[index] -
                                                         executable_memory.load_bias();
                            std::cout << "Executando construtor [" << index << "] em 0x"
                                      << std::hex << current_address << std::dec << "...\n";
                            if (!bridge.call_void<>(current_address, error)) {
                                std::cerr << "Construtor [" << index
                                          << "] não retornou normalmente: " << error << '\n';
                                return 1;
                            }
                            std::cout << "Construtor [" << index
                                      << "] retornou normalmente.\n";
                        }
                        if (run_guest_entrypoint) {
#ifdef _WIN32
                            if (std::getenv("NBA16_TRACE_CALL_RECORD") != nullptr) {
                                const auto* libkernel = modules.find("libkernel");
                                if (libkernel == nullptr || !arm_fclose_trace_site(
                                        static_cast<std::uintptr_t>(
                                            libkernel->image_memory().load_bias() + 0x22280),
                                        "libkernel-set-call-record-entry",
                                        {0x55, 0x48, 0x89, 0xe5}, 0x22280, 64)) {
                                    std::fputs("CALL-RECORD trace could not arm libkernel+0x22280.\n",
                                        stderr);
                                } else {
                                    std::fputs("CALL-RECORD trace armed at libkernel+0x22280.\n",
                                        stderr);
                                }
                            }
                            if (std::getenv("NBA16_TRACE_FS") == nullptr) {
                                const auto* libc_for_allocator = modules.find("libc");
                                std::uintptr_t fclose_target{};
                                for (const auto& relocation : executable_link.relocations) {
                                    if (relocation.symbol_index >= executable_link.symbols.size() ||
                                        relocation.symbol_index >= executable_imports.symbol_addresses.size())
                                        continue;
                                    if (!executable_link.symbols[relocation.symbol_index].name.starts_with(
                                            "uodLYyUip20#")) continue;
                                    fclose_target = static_cast<std::uintptr_t>(
                                        executable_imports.symbol_addresses[relocation.symbol_index].value_or(0));
                                    if (fclose_target != 0) break;
                                }
                                if (libc_for_allocator != nullptr) {
                                    install_guest_libc_file_allocator(
                                        static_cast<std::uintptr_t>(
                                            libc_for_allocator->image_memory().load_bias()),
                                        fclose_target);
                                }
                            }
                            if (std::getenv("NBA16_TRACE_FS") != nullptr) {
                                if (const auto* trace_libc = modules.find("libc");
                                    trace_libc != nullptr) {
                                    arm_fopen_trace_sites(*trace_libc);
                                }
                                bool fopen_interposed = false;
                                bool fread_interposed = false;
                                bool fclose_interposed = false;
                                for (const auto& relocation : executable_link.relocations) {
                                    if (relocation.symbol_index >= executable_link.symbols.size() ||
                                        relocation.symbol_index >= executable_imports.symbol_addresses.size())
                                        continue;
                                    const auto& symbol = executable_link.symbols[relocation.symbol_index];
                                    const bool is_fopen = symbol.name.starts_with("xeYO4u7uyJ0#");
                                    const bool is_fread = symbol.name.starts_with("lbB+UlZqVG0#");
                                    const bool is_fclose = symbol.name.starts_with("uodLYyUip20#");
                                    if (!is_fopen && !is_fread && !is_fclose) continue;
                                    const auto target = executable_imports
                                        .symbol_addresses[relocation.symbol_index].value_or(0);
                                    if (target == 0) continue;
                                    std::uintptr_t wrapper{};
                                    if (is_fopen) {
                                        diagnostic_fopen_target = static_cast<std::uintptr_t>(target);
                                        wrapper = reinterpret_cast<std::uintptr_t>(&trace_guest_fopen);
                                    } else if (is_fread) {
                                        diagnostic_fread_target = static_cast<std::uintptr_t>(target);
                                        wrapper = reinterpret_cast<std::uintptr_t>(&trace_guest_fread);
                                    } else {
                                        diagnostic_fclose_target = static_cast<std::uintptr_t>(target);
                                        wrapper = reinterpret_cast<std::uintptr_t>(&trace_guest_fclose);
                                    }
                                    auto* got_slot = reinterpret_cast<void*>(static_cast<std::uintptr_t>(
                                        executable_memory.load_bias() + relocation.target));
                                    DWORD old_protection{};
                                    if (VirtualProtect(got_slot, sizeof(wrapper), PAGE_READWRITE,
                                            &old_protection) == 0) {
                                        std::cerr << "Interposição diagnóstica de importação FS falhou: "
                                                     "não foi possível liberar o slot GOT.\n";
                                        continue;
                                    }
                                    std::memcpy(got_slot, &wrapper, sizeof(wrapper));
                                    DWORD ignored_protection{};
                                    if (VirtualProtect(got_slot, sizeof(wrapper), old_protection,
                                            &ignored_protection) == 0) {
                                        std::cerr << "Aviso: não foi possível restaurar a proteção "
                                                     "do slot GOT de FS.\n";
                                    }
                                    std::cerr << "Interposição diagnóstica de "
                                              << (is_fopen ? "fopen" : is_fread ? "fread" : "fclose")
                                              << " no GOT do eboot, destino original=0x"
                                              << std::hex << target << std::dec << ".\n";
                                    if (is_fopen) fopen_interposed = true;
                                    if (is_fread) fread_interposed = true;
                                    if (is_fclose) fclose_interposed = true;
                                }
                                if (!fopen_interposed) {
                                    std::cerr << "Import fopen do eboot não encontrado para diagnóstico.\n";
                                }
                                if (!fread_interposed)
                                    std::cerr << "Import fread do eboot não encontrado para diagnóstico.\n";
                                if (!fclose_interposed)
                                    std::cerr << "Import fclose do eboot não encontrado para diagnóstico.\n";
                                if (fclose_interposed) {
                                    patch_guest_heap_free_call(diagnostic_fclose_target);
                                    struct ReturnSite {
                                        std::uintptr_t offset;
                                        const char* label;
                                        std::array<std::uint8_t, 4> signature;
                                    };
                                    constexpr std::array close_returns{
                                        ReturnSite{0x2f, "after-stream-lock", {0x41, 0x89, 0xc7, 0xbf}},
                                        ReturnSite{0x3c, "after-global-lock", {0xf6, 0x03, 0x40, 0x74}},
                                        ReturnSite{0x4a, "after-fios-close", {0x48, 0xc7, 0x43, 0x08}},
                                        ReturnSite{0x5a, "after-fd-close", {0x83, 0xf8, 0x01, 0x45}},
                                        ReturnSite{0x66, "after-buffer-cleanup", {0x48, 0x89, 0xdf, 0xe8}},
                                        ReturnSite{0x78, "after-global-unlock", {0xeb, 0x27, 0xbf, 0x02}},
                                    };
                                    for (const auto& site : close_returns) {
                                        if (!arm_fclose_trace_site(diagnostic_fclose_target + site.offset,
                                                site.label, site.signature))
                                            std::cerr << "Fclose trace não armou " << site.label << ".\n";
                                    }
                                }
                                const auto* libc_module = modules.find("libc");
                                if (libc_module != nullptr) {
                                    const auto libc_base = libc_module->image_memory().load_bias();
                                    std::int32_t malloc_plt_displacement{};
                                    std::memcpy(&malloc_plt_displacement,
                                        reinterpret_cast<const void*>(libc_base + 0x20152),
                                        sizeof(malloc_plt_displacement));
                                    const auto malloc_plt_slot = static_cast<std::uint64_t>(
                                        static_cast<std::int64_t>(0x20156) + malloc_plt_displacement);
                                    std::uint64_t malloc_plt_target{};
                                    std::memcpy(&malloc_plt_target,
                                        reinterpret_cast<const void*>(libc_base + malloc_plt_slot),
                                        sizeof(malloc_plt_target));
                                    std::cerr << "Diagnostic libc allocation PLT +0x20150 slot=0x"
                                              << std::hex << malloc_plt_slot << " target=0x"
                                              << malloc_plt_target << std::dec;
                                    bool matched_export = false;
                                    for (const auto& loaded_name : modules.loaded_module_names()) {
                                        const auto* loaded_module = modules.find(loaded_name);
                                        if (loaded_module == nullptr) continue;
                                        const auto& loaded_map = loaded_module->image_map();
                                        const auto region_begin = loaded_module->image_memory().load_bias() +
                                                                  loaded_map.minimum_virtual_address;
                                        const auto region_end = loaded_module->image_memory().load_bias() +
                                                                loaded_map.maximum_virtual_address;
                                        if (malloc_plt_target >= region_begin && malloc_plt_target < region_end) {
                                            std::cerr << " owner=" << loaded_name << "+0x" << std::hex
                                                      << malloc_plt_target - loaded_module->image_memory().load_bias()
                                                      << std::dec;
                                        }
                                        std::vector<nba16::LoadedPs4Export> loaded_exports;
                                        if (!loaded_module->collect_exports(loaded_name,
                                                loaded_exports, error)) continue;
                                        for (const auto& exported : loaded_exports) {
                                            if (exported.host_address != malloc_plt_target) continue;
                                            std::cerr << " export=" << exported.module_name << '/'
                                                      << exported.library_name << ':' << exported.nid
                                                      << " +0x" << std::hex
                                                      << exported.module_relative_value << std::dec;
                                            matched_export = true;
                                            break;
                                        }
                                        if (matched_export) break;
                                    }
                                    std::cerr << (matched_export ? "\n" : " (sem export exato)\n");
                                    const auto fallback = reinterpret_cast<std::uintptr_t>(
                                        &nba16::guest_libc_malloc_fallback);
                                    nba16::set_guest_libc_original_malloc(
                                        static_cast<std::uintptr_t>(malloc_plt_target));
                                    auto* malloc_slot = reinterpret_cast<void*>(libc_base + malloc_plt_slot);
                                    DWORD old_slot_protection{};
                                    if (VirtualProtect(malloc_slot, sizeof(fallback), PAGE_READWRITE,
                                            &old_slot_protection) != 0) {
                                        std::memcpy(malloc_slot, &fallback, sizeof(fallback));
                                        DWORD ignored_slot_protection{};
                                        VirtualProtect(malloc_slot, sizeof(fallback),
                                            old_slot_protection, &ignored_slot_protection);
                                        std::cerr << "Diagnostic libc malloc PLT redirected to low guest heap.\n";
                                    } else {
                                        std::cerr << "Diagnostic libc malloc PLT redirection failed.\n";
                                    }
                                    const auto& libc_link = libc_module->dynamic_info();
                                    nba16::ImportResolution libc_imports{};
                                    if (resolver.resolve(libc_link, libc_imports, error,
                                            libc_module->image_memory().load_bias())) {
                                        for (std::size_t symbol_index = 0;
                                             symbol_index < libc_link.symbols.size() &&
                                                 symbol_index < libc_imports.symbol_addresses.size();
                                             ++symbol_index) {
                                            if (!libc_link.symbols[symbol_index].name.starts_with(
                                                    "tIhsqj0qsFE#")) continue;
                                            std::cerr << "libc free import target=0x" << std::hex
                                                << libc_imports.symbol_addresses[symbol_index].value_or(0)
                                                << std::dec << "\n";
                                        }
                                        std::size_t free_slots_patched{};
                                        const auto free_wrapper = reinterpret_cast<std::uintptr_t>(
                                            &nba16::guest_libc_free_fallback);
                                        for (const auto& relocation : libc_link.relocations) {
                                            if (relocation.symbol_index >= libc_link.symbols.size()) continue;
                                            const auto& symbol = libc_link.symbols[relocation.symbol_index];
                                            if (!symbol.name.starts_with("tIhsqj0qsFE#")) continue;
                                            auto* free_slot = reinterpret_cast<void*>(
                                                libc_module->image_memory().load_bias() + relocation.target);
                                            DWORD old_free_protection{};
                                            if (VirtualProtect(free_slot, sizeof(free_wrapper),
                                                    PAGE_READWRITE, &old_free_protection) == 0) {
                                                std::cerr << "Diagnostic libc free slot could not be made writable.\n";
                                                continue;
                                            }
                                            std::memcpy(free_slot, &free_wrapper, sizeof(free_wrapper));
                                            DWORD ignored_free_protection{};
                                            VirtualProtect(free_slot, sizeof(free_wrapper),
                                                old_free_protection, &ignored_free_protection);
                                            ++free_slots_patched;
                                        }
                                        std::cerr << "Diagnostic libc free PLT slots redirected to guest heap: "
                                                  << free_slots_patched << ".\n";
                                        std::int32_t fclose_plt_displacement{};
                                        std::memcpy(&fclose_plt_displacement,
                                            reinterpret_cast<const void*>(diagnostic_fclose_target + 0x18ca2),
                                            sizeof(fclose_plt_displacement));
                                        const auto fclose_plt_slot = diagnostic_fclose_target + 0x18ca6 +
                                            static_cast<std::uintptr_t>(static_cast<std::intptr_t>(
                                                fclose_plt_displacement));
                                        for (const auto& relocation : libc_link.relocations) {
                                            if (libc_module->image_memory().load_bias() + relocation.target !=
                                                    fclose_plt_slot ||
                                                relocation.symbol_index >= libc_link.symbols.size() ||
                                                relocation.symbol_index >= libc_imports.symbol_addresses.size())
                                                continue;
                                            const auto& symbol = libc_link.symbols[relocation.symbol_index];
                                            std::cerr << "Fclose PLT import=" << symbol.name
                                                << " target=0x" << std::hex
                                                << libc_imports.symbol_addresses[relocation.symbol_index].value_or(0)
                                                << std::dec << "\n";
                                        }
                                        for (const auto& relocation : libc_link.relocations) {
                                            if (relocation.symbol_index >= libc_link.symbols.size() ||
                                                relocation.symbol_index >= libc_imports.symbol_addresses.size())
                                                continue;
                                            const auto& symbol = libc_link.symbols[relocation.symbol_index];
                                            if (!symbol.name.starts_with("w13Ojm7ON9o#")) continue;
                                            diagnostic_fios_open_target = static_cast<std::uintptr_t>(
                                                libc_imports.symbol_addresses[relocation.symbol_index].value_or(0));
                                            if (diagnostic_fios_open_target == 0) break;
                                            const auto wrapper = reinterpret_cast<std::uintptr_t>(
                                                &trace_guest_fios_open);
                                            auto* got_slot = reinterpret_cast<void*>(static_cast<std::uintptr_t>(
                                                libc_module->image_memory().load_bias() + relocation.target));
                                            DWORD old_protection{};
                                            if (VirtualProtect(got_slot, sizeof(wrapper), PAGE_READWRITE,
                                                    &old_protection) == 0) {
                                                std::cerr << "Interposição diagnóstica de Fios open falhou.\n";
                                                break;
                                            }
                                            std::memcpy(got_slot, &wrapper, sizeof(wrapper));
                                            DWORD ignored_protection{};
                                            VirtualProtect(got_slot, sizeof(wrapper), old_protection,
                                                &ignored_protection);
                                            std::cerr << "Interposição diagnóstica de Fios open em libc.prx, "
                                                      << "destino original=0x" << std::hex
                                                      << diagnostic_fios_open_target << std::dec << ".\n";
                                            break;
                                        }
                                        for (const auto& relocation : libc_link.relocations) {
                                            if (relocation.symbol_index >= libc_link.symbols.size() ||
                                                relocation.symbol_index >= libc_imports.symbol_addresses.size())
                                                continue;
                                            const auto& symbol = libc_link.symbols[relocation.symbol_index];
                                            if (!symbol.name.starts_with("AOujSGqU+ms#")) continue;
                                            diagnostic_fios_close_target = static_cast<std::uintptr_t>(
                                                libc_imports.symbol_addresses[relocation.symbol_index].value_or(0));
                                            if (diagnostic_fios_close_target == 0) break;
                                            const auto wrapper = reinterpret_cast<std::uintptr_t>(
                                                &trace_guest_fios_close);
                                            auto* got_slot = reinterpret_cast<void*>(static_cast<std::uintptr_t>(
                                                libc_module->image_memory().load_bias() + relocation.target));
                                            DWORD old_protection{};
                                            if (VirtualProtect(got_slot, sizeof(wrapper), PAGE_READWRITE,
                                                    &old_protection) == 0) {
                                                std::cerr << "Interposição diagnóstica de Fios close falhou.\n";
                                                break;
                                            }
                                            std::memcpy(got_slot, &wrapper, sizeof(wrapper));
                                            DWORD ignored_protection{};
                                            VirtualProtect(got_slot, sizeof(wrapper), old_protection,
                                                &ignored_protection);
                                            std::cerr << "Interposição diagnóstica de Fios close em libc.prx, "
                                                      << "destino original=0x" << std::hex
                                                      << diagnostic_fios_close_target << std::dec << ".\n";
                                            break;
                                        }
                                    }
                                }
                            }
                            GuestEntryParams parameters{};
                            parameters.argc = 1;
                            parameters.argv[0] = argv[1];
                            parameters.entry_address = executable_memory.load_bias() +
                                                       executable_map.entry_point;
                            if (std::getenv("NBA16_TRACE_FS") != nullptr) {
                                std::fprintf(stderr, "Trace bases: eboot=0x%llx entry=0x%llx\n",
                                    static_cast<unsigned long long>(executable_memory.load_bias()),
                                    static_cast<unsigned long long>(parameters.entry_address));
                                if (const auto* internal_libc =
                                        modules.find("libSceLibcInternal")) {
                                    const auto base = static_cast<std::uintptr_t>(
                                        internal_libc->image_memory().load_bias());
                                    std::fprintf(stderr, "Trace base libSceLibcInternal=0x%llx\n",
                                        static_cast<unsigned long long>(base));
                                    if (!arm_fclose_trace_site(base + 0x8a550,
                                        "libc-internal-fatal-exit-entry",
                                        {0x55, 0x48, 0x89, 0xe5}))
                                        std::cerr << "Trace não armou fatal-exit-entry.\n";
                                    if (!arm_fclose_trace_site(base + 0x87548,
                                        "libc-internal-terminal-exit",
                                        {0x44, 0x89, 0xf7, 0xe8}))
                                        std::cerr << "Trace não armou libc-internal-terminal-exit.\n";
                                    if (!arm_fclose_trace_site(base + 0x8a5e1,
                                        "libc-internal-exit-status-call",
                                        {0x44, 0x89, 0xf7, 0xe8}))
                                        std::cerr << "Trace não armou libc-internal-exit-status-call.\n";
                                    if (!arm_fclose_trace_site(base + 0x87723,
                                        "libc-internal-signal-exit-call",
                                        {0x44, 0x89, 0xff, 0xe8}))
                                        std::cerr << "Trace não armou libc-internal-signal-exit-call.\n";
                                    if (!arm_fclose_trace_site(base + 0x866c7,
                                        "libc-internal-callback-exit-zero",
                                        {0x31, 0xff, 0xe8, 0x84}))
                                        std::cerr << "Trace não armou callback-exit-zero.\n";
                                    if (!arm_fclose_trace_site(base + 0x86817,
                                        "libc-internal-callback-exit-zero-b",
                                        {0x31, 0xff, 0xe8, 0x34}))
                                        std::cerr << "Trace não armou callback-exit-zero-b.\n";
                                }
                                arm_fclose_trace_site(
                                    static_cast<std::uintptr_t>(executable_memory.load_bias() +
                                        0x2414800),
                                    "eboot-memory-region-init",
                                    {0x55, 0x48, 0x89, 0xe5});
                                constexpr std::array<std::pair<std::uint64_t, const char*>, 6>
                                    return_sites{{
                                        {0x7e6a2, "entry-return-check-a"},
                                        {0x7ea77, "entry-return-check-b"},
                                        {0xca222, "entry-return-check-c"},
                                        {0x822, "entry-return-check-d"},
                                        {0x41f8c0, "memory-region-helper-entry"},
                                        {0x2414bc6, "memory-region-helper-return"},
                                    }};
                                if (!arm_fclose_trace_site(
                                        executable_memory.load_bias() + 0x41cb20,
                                        "eboot-callback-dispatch-entry",
                                        {0x55, 0x48, 0x89, 0xe5}))
                                    std::cerr << "Trace não armou callback-dispatch-entry.\n";
                                if (!arm_fclose_trace_site(
                                        executable_memory.load_bias() + 0x41d6b5,
                                        "eboot-callback-dispatch-call",
                                        {0xe8, 0x66, 0xf4, 0xff}))
                                    std::cerr << "Trace não armou callback-dispatch-call.\n";
                                if (!arm_fclose_trace_site(
                                        executable_memory.load_bias() + 0x41cb9a,
                                        "eboot-callback-indirect-call",
                                        {0x41, 0xff, 0x94, 0xc5}))
                                    std::cerr << "Trace não armou callback-indirect-call.\n";
                                if (!arm_fclose_trace_site(
                                        executable_memory.load_bias() + 0x41cba2,
                                        "eboot-callback-indirect-return",
                                        {0x49, 0x89, 0xc6, 0x49}))
                                    std::cerr << "Trace não armou callback-indirect-return.\n";
                                for (const auto& [offset, label] : std::array{
                                         std::pair<std::uint64_t, const char*>{0x365f4b0,
                                             "eboot-memory-object-provider"},
                                         std::pair<std::uint64_t, const char*>{0x2414b40,
                                             "eboot-memory-object-setup"},
                                         std::pair<std::uint64_t, const char*>{0x2414b6e,
                                             "eboot-memory-object-allocation-return"}}) {
                                    std::array<std::uint8_t, 4> signature{};
                                    SIZE_T bytes_read{};
                                    const auto address = static_cast<std::uintptr_t>(
                                        executable_memory.load_bias() + offset);
                                    if (ReadProcessMemory(GetCurrentProcess(),
                                            reinterpret_cast<const void*>(address),
                                            signature.data(), signature.size(), &bytes_read) == 0 ||
                                        bytes_read != signature.size() ||
                                        !arm_fclose_trace_site(address, label, signature))
                                        std::cerr << "Trace não armou " << label << ".\n";
                                }
                                for (const auto& [offset, label] : return_sites) {
                                    std::array<std::uint8_t, 4> signature{};
                                    SIZE_T read{};
                                    const auto address = static_cast<std::uintptr_t>(
                                        executable_memory.load_bias() + offset);
                                    if (ReadProcessMemory(GetCurrentProcess(),
                                            reinterpret_cast<const void*>(address),
                                            signature.data(), signature.size(), &read) != 0 &&
                                        read == signature.size()) {
                                        arm_fclose_trace_site(address, label, signature);
                                    }
                                }
                            }
                            if (std::getenv("NBA16_TRACE_WAIT") != nullptr) {
                                const auto base = static_cast<std::uintptr_t>(
                                    executable_memory.load_bias());
                                const auto arm_job_site = [&](std::uint64_t offset,
                                        const char* label,
                                        std::array<std::uint8_t, 4> signature) {
                                    if (!arm_fclose_trace_site(base + offset, label,
                                            signature, offset, 20)) {
                                        std::fprintf(stderr,
                                            "Job Manager trace did not arm %s.\n", label);
                                    }
                                };
                                arm_job_site(0xad970, "jm-worker-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_job_site(0xad9c6, "jm-worker-after-wait",
                                    {0x85, 0xc0, 0x74, 0x05});
                                arm_job_site(0xad9e5, "jm-worker-callback-call",
                                    {0xff, 0xd0, 0xeb, 0x0d});
                                arm_job_site(0xad9e7, "jm-worker-callback-return",
                                    {0xeb, 0x0d, 0x49, 0x8b});
                                arm_job_site(0x35500, "jm-callback-dispatch-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_job_site(0x3557a, "jm-dispatch-typecheck-result",
                                    {0x84, 0xc0, 0x74, 0x1f});
                                arm_job_site(0x3559b, "jm-dispatch-approved-target",
                                    {0xff, 0xe0, 0x49, 0x8b});
                                arm_job_site(0x355b4, "jm-dispatch-fallback-target",
                                    {0xff, 0xe0, 0x66, 0x2e});
                                arm_job_site(0xbc9a0, "jm-worker-method-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_job_site(0xbd5a0, "jm-worker-queue-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_job_site(0xb88d8, "jm-worker-semaphore-return",
                                    {0x41, 0xc6, 0x47, 0x42});
                                arm_job_site(0xbca3c, "jm-worker-method-return",
                                    {0xc3, 0x0f, 0x1f, 0x00});
                                arm_job_site(0xa8fe0, "path-lock-loop-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_job_site(0xa8ff1, "path-lock-loop-count",
                                    {0x4c, 0x8d, 0x35, 0x00});
                                arm_job_site(0xa9060, "path-lock-wait-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_job_site(0xa9010, "path-lock-attempt-return",
                                    {0x85, 0xc0, 0x7e, 0xec});
                                arm_job_site(0xa9096, "path-mutex-lock-return",
                                    {0x89, 0xc1, 0xb8, 0xff});
                                arm_job_site(0xa9159, "path-mutex-wait-return",
                                    {0x49, 0x8b, 0x0e, 0x48});
                                arm_job_site(0x38085, "path-register-root-call",
                                    {0xe8, 0x96, 0x1c, 0x65});
                                arm_job_site(0x3808a, "path-register-root-return",
                                    {0x41, 0xc6, 0x44, 0x24});
                                arm_job_site(0x3815f, "path-register-root-repeat-call",
                                    {0xe8, 0xbc, 0x1b, 0x65});
                                arm_job_site(0x38164, "path-register-root-repeat-return",
                                    {0x41, 0xc6, 0x44, 0x24});
                            }
                            if (std::getenv("NBA16_TRACE_NULL_PATH") != nullptr) {
                                const auto base = static_cast<std::uintptr_t>(
                                    executable_memory.load_bias());
                                const auto arm_null_path_site = [&](std::uint64_t offset,
                                        const char* label,
                                        std::array<std::uint8_t, 4> signature) {
                                    if (!arm_fclose_trace_site(base + offset, label,
                                            signature, offset, 32)) {
                                        std::fprintf(stderr,
                                            "Null-path trace did not arm %s.\n", label);
                                    }
                                };
                                arm_null_path_site(0x6837e0, "null-path-object-function-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_null_path_site(0x683812, "null-path-field-load",
                                    {0x48, 0x8b, 0x78, 0x60});
                                arm_null_path_site(0x683830, "null-path-helper-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_null_path_site(0x6838aa, "null-path-object-dereference",
                                    {0x41, 0x80, 0x7e, 0x10});
                                arm_null_path_site(0x68476a, "null-path-vmethod-call",
                                    {0x4c, 0x89, 0xe7, 0xff});
                                arm_null_path_site(0x684773, "null-path-vmethod-return",
                                    {0x49, 0x89, 0x45, 0x78});
                                arm_null_path_site(0x227b980, "null-path-vmethod-body",
                                    {0x31, 0xc0, 0xc3, 0x90});
                                arm_null_path_site(0x684650, "null-path-operation-call",
                                    {0xff, 0x50, 0x38, 0x89});
                                arm_null_path_site(0x684653, "null-path-operation-return",
                                    {0x89, 0x45, 0x98, 0x89});
                                arm_null_path_site(0x691f30, "null-path-file-read-entry",
                                    {0x55, 0x48, 0x89, 0xe5});
                                arm_null_path_site(0x691f88, "null-path-file-validate",
                                    {0x84, 0xc0, 0x74, 0x1c});
                            }
                            if (std::getenv("NBA16_TRACE_MEMORY") != nullptr) {
                                if (!arm_fclose_trace_site(
                                    static_cast<std::uintptr_t>(executable_memory.load_bias() + 0x41fdb7),
                                    "virtual-query-return-test",
                                    {0x85, 0xc0, 0x79, 0xc5}, 0x41fdb7, 512))
                                    std::cerr << "Trace de memoria não armou virtual-query-return-test.\n";
                                if (!arm_fclose_trace_site(
                                    static_cast<std::uintptr_t>(executable_memory.load_bias() + 0x41fdbb),
                                    "virtual-query-negative-branch",
                                    {0x4d, 0x85, 0xf6, 0x74}, 0x41fdbb, 16))
                                    std::cerr << "Trace de memória não armou virtual-query-negative-branch.\n";
                            }
                            if (std::getenv("NBA16_TRACE_MUTEX") != nullptr) {
                                std::fprintf(stderr,
                                    "MUTEX-EXECUTABLE bias=0x%llx span=0x%llx-0x%llx\n",
                                    static_cast<unsigned long long>(executable_map.load_bias),
                                    static_cast<unsigned long long>(executable_map.minimum_virtual_address),
                                    static_cast<unsigned long long>(executable_map.maximum_virtual_address));
                                for (const auto& module_name : modules.loaded_module_names()) {
                                    const auto* module = modules.find(module_name);
                                    if (module == nullptr) continue;
                                    const auto& image = module->image_map();
                                    std::fprintf(stderr,
                                        "MUTEX-MODULE name=%s bias=0x%llx span=0x%llx-0x%llx\n",
                                        module_name.c_str(),
                                        static_cast<unsigned long long>(image.load_bias),
                                        static_cast<unsigned long long>(image.minimum_virtual_address),
                                        static_cast<unsigned long long>(image.maximum_virtual_address));
                                }
                            }
                            std::cout << "Chamando entry point eboot.bin em 0x"
                                      << std::hex << executable_map.entry_point << std::dec
                                      << " com argc=1 e argv[0] apontando ao dump...\n";
                            auto* entry_address = executable_memory.translate_executable(
                                executable_map, parameters.entry_address, 1, error);
                            if (entry_address == nullptr) {
                                std::cerr << "Entry point do jogo inválido: " << error << '\n';
                                return 1;
                            }
                            if (std::getenv("NBA16_TRACE_WAIT") != nullptr) {
                                std::fprintf(stderr,
                                    "THREAD trace eboot-base=0x%llx entry-point=0x%llx\n",
                                    static_cast<unsigned long long>(executable_memory.load_bias()),
                                    static_cast<unsigned long long>(parameters.entry_address));
                            }
                            std::thread active_rip_sampler;
                            std::thread scheduler_state_watcher;
#ifdef _WIN32
                            const bool trace_shader_bound_writes =
                                std::getenv("NBA16_TRACE_SHADER_BOUND_WRITES") != nullptr;
                            const bool trace_scheduler_state_writes =
                                std::getenv("NBA16_TRACE_SCHED_STATE_WRITES") != nullptr;
                            if (trace_scheduler_state_writes || trace_shader_bound_writes)
                                active_scheduler_state_address.store(
                                    trace_shader_bound_writes
                                        ? 0x1000001420ULL : 0x1039be8538ULL,
                                    std::memory_order_release);
                            if (std::getenv("NBA16_TRACE_ACTIVE_RIP_ALL") != nullptr ||
                                std::getenv("NBA16_TRACE_ACTIVE_RIP") != nullptr ||
                                (trace_scheduler_state_writes && !trace_shader_bound_writes)) {
                                active_rip_sampler_stop.store(false, std::memory_order_release);
                                scheduler_state_watchpoint_hit.store(false,
                                    std::memory_order_release);
                                scheduler_state_write_count.store(0,
                                    std::memory_order_release);
                                if (std::getenv("NBA16_TRACE_ACTIVE_RIP_ALL") != nullptr &&
                                    !trace_scheduler_state_writes) {
                                    active_rip_sampler = std::thread(sample_active_process_threads,
                                        GetCurrentProcessId(), GetCurrentThreadId());
                                } else {
                                    active_rip_sampler = std::thread(sample_active_guest_rips,
                                        GetCurrentThreadId());
                                }
                            }
                            if (trace_scheduler_state_writes || trace_shader_bound_writes) {
                                active_rip_sampler_stop.store(false, std::memory_order_release);
                                scheduler_state_watchpoint_hit.store(false,
                                    std::memory_order_release);
                                scheduler_state_write_count.store(0,
                                    std::memory_order_release);
                                scheduler_state_watcher = std::thread(
                                    watch_scheduler_state_writes, GetCurrentProcessId());
                                if (trace_shader_bound_writes)
                                    std::this_thread::sleep_for(
                                        std::chrono::milliseconds(350));
                            }
#endif
                            arm_eboot_exception_guard_trace();
                            arm_libkernel_usrstack_panic_trace();
                            nba16::nba16_guest_run_process_entry(entry_address,
                                &parameters,
                                reinterpret_cast<void*>(&guest_entrypoint_exit_probe),
                                parameters.argv, static_cast<std::uint64_t>(parameters.argc));
                            std::cout << "Entry point do jogo retornou ao probe.\n";
#ifdef _WIN32
                            if (active_rip_sampler.joinable()) {
                                active_rip_sampler_stop.store(true, std::memory_order_release);
                                active_rip_sampler.join();
                            }
                            if (scheduler_state_watcher.joinable()) {
                                active_rip_sampler_stop.store(true, std::memory_order_release);
                                scheduler_state_watcher.join();
                            }
#endif
#else
                            std::cerr << "O modo de entrada de processo do probe só está implementado no Windows.\n";
                            return 2;
#endif
                        }
#ifdef _WIN32
                        if (exception_handler != nullptr) {
                            RemoveVectoredExceptionHandler(exception_handler);
                        }
#endif
                    }
                    if (constructor_code[0x0b] == std::byte{0xe8}) {
                        std::int32_t call_displacement{};
                        std::memcpy(&call_displacement, constructor_code.data() + 0x0c,
                                    sizeof(call_displacement));
                        const auto target_signed = static_cast<std::int64_t>(guest_address) +
                                                   0x10 + call_displacement;
                        if (target_signed < 0) {
                            std::cerr << "Chamada direta do construtor aponta antes da imagem.\n";
                            return 1;
                        }
                        const auto target = static_cast<std::uint64_t>(target_signed);
                        std::array<std::byte, 256> target_code{};
                        if (!nba16::read_guest_memory(executable_map,
                                executable_memory.load_bias() + target, target_code, error)) {
                            std::cerr << "Não foi possível ler o alvo da primeira chamada: "
                                      << error << '\n';
                            return 1;
                        }
                        std::cout << "Alvo da primeira chamada direta em 0x" << std::hex
                                  << target << " bytes:";
                        for (const auto byte : target_code) {
                            std::cout << ' ' << std::setw(2) << std::setfill('0')
                                      << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
                        }
                        std::cout << std::dec << std::setfill(' ') << '\n';
                        for (const auto& symbol : executable_link.symbols) {
                            if (symbol.value == target && !symbol.name.empty()) {
                                std::cout << "Símbolo do alvo: " << symbol.name << '\n';
                            }
                        }
                        for (std::size_t offset = 0; offset + 5 <= target_code.size(); ++offset) {
                            if (target_code[offset] != std::byte{0xe8}) continue;
                            std::int32_t displacement{};
                            std::memcpy(&displacement, target_code.data() + offset + 1,
                                        sizeof(displacement));
                            const auto call_target_signed = static_cast<std::int64_t>(target) +
                                static_cast<std::int64_t>(offset) + 5 + displacement;
                            if (call_target_signed < 0) continue;
                            const auto call_target = static_cast<std::uint64_t>(call_target_signed);
                            std::array<std::byte, 16> call_code{};
                            if (!nba16::read_guest_memory(executable_map,
                                    executable_memory.load_bias() + call_target,
                                    call_code, error)) {
                                std::cout << "Chamada em +0x" << std::hex << offset
                                          << " aponta para área sem leitura: " << error
                                          << std::dec << '\n';
                                error.clear();
                                continue;
                            }
                            std::cout << "Chamada em +0x" << std::hex << offset
                                      << " -> 0x" << call_target << " bytes:";
                            for (const auto byte : call_code) {
                                std::cout << ' ' << std::setw(2) << std::setfill('0')
                                          << static_cast<unsigned>(
                                              std::to_integer<std::uint8_t>(byte));
                            }
                            std::cout << std::dec << std::setfill(' ') << '\n';
                            if (call_code[0] == std::byte{0xff} &&
                                call_code[1] == std::byte{0x25}) {
                                std::int32_t got_displacement{};
                                std::memcpy(&got_displacement, call_code.data() + 2,
                                            sizeof(got_displacement));
                                const auto got_slot_signed = static_cast<std::int64_t>(
                                    call_target) + 6 + got_displacement;
                                if (got_slot_signed >= 0) {
                                    const auto got_slot = static_cast<std::uint64_t>(
                                        got_slot_signed);
                                    std::array<std::byte, sizeof(std::uint64_t)> got_bytes{};
                                    if (nba16::read_guest_memory(executable_map,
                                            executable_memory.load_bias() + got_slot,
                                            got_bytes, error)) {
                                        std::uint64_t resolved_address{};
                                        std::memcpy(&resolved_address, got_bytes.data(),
                                                    sizeof(resolved_address));
                                        std::cout << "  endereço resolvido: 0x" << std::hex
                                                  << resolved_address << std::dec << '\n';
                                        for (const auto& region : executable_map.regions) {
                                            const auto begin = executable_memory.load_bias() +
                                                               region.virtual_address;
                                            if (resolved_address >= begin &&
                                                resolved_address - begin < region.memory_size) {
                                                std::cout << "  fornecedor: executável principal\n";
                                                break;
                                            }
                                        }
                                        for (const auto& name : modules.loaded_module_names()) {
                                            const auto* provider = modules.find(name);
                                            if (provider == nullptr) continue;
                                            const auto& provider_map = provider->image_map();
                                            bool matched = false;
                                            for (const auto& region : provider_map.regions) {
                                                const auto begin = provider_map.load_bias +
                                                                   region.virtual_address;
                                                if (resolved_address >= begin &&
                                                    resolved_address - begin < region.memory_size) {
                                                    std::cout << "  fornecedor: " << name << '\n';
                                                    matched = true;
                                                    break;
                                                }
                                            }
                                            if (matched) break;
                                        }
                                    } else {
                                        error.clear();
                                    }
                                    for (const auto& relocation : executable_link.relocations) {
                                        if (relocation.target != got_slot ||
                                            relocation.symbol_index >= executable_link.symbols.size()) {
                                            continue;
                                        }
                                        const auto& symbol = executable_link.symbols[
                                            relocation.symbol_index];
                                        std::cout << "  PLT/GOT 0x" << std::hex << got_slot
                                                  << " -> import " << symbol.name << std::dec;
                                        if (symbol.has_nid_indices) {
                                            const auto library = std::find_if(
                                                executable_link.import_libraries.begin(),
                                                executable_link.import_libraries.end(),
                                                [&symbol](const auto& entry) {
                                                    return entry.library_id ==
                                                           symbol.nid_library_index;
                                                });
                                            const auto module = std::find_if(
                                                executable_link.import_modules.begin(),
                                                executable_link.import_modules.end(),
                                                [&symbol](const auto& entry) {
                                                    return entry.module_id ==
                                                           symbol.nid_module_index;
                                                });
                                            std::cout << " [lib-id=" << symbol.nid_library_index
                                                      << ", module-id=" << symbol.nid_module_index;
                                            if (library != executable_link.import_libraries.end()) {
                                                std::cout << ", library=" << library->name;
                                            }
                                            if (module != executable_link.import_modules.end()) {
                                                std::cout << ", module=" << module->name;
                                            }
                                            std::cout << ']';
                                        }
                                        std::cout << '\n';
                                    }
                                }
                            }
                            for (const auto& symbol : executable_link.symbols) {
                                if (symbol.value == call_target && !symbol.name.empty()) {
                                    std::cout << "  símbolo: " << symbol.name << '\n';
                                }
                            }
                        }
                        constexpr std::uint64_t global_slot = 0x3552138;
                        std::array<std::byte, sizeof(std::uint64_t)> global_bytes{};
                        if (nba16::read_guest_memory(executable_map,
                                executable_memory.load_bias() + global_slot,
                                global_bytes, error)) {
                            std::uint64_t global_value{};
                            std::memcpy(&global_value, global_bytes.data(), sizeof(global_value));
                            std::cout << "Ponteiro global em 0x" << std::hex << global_slot
                                      << " = 0x" << global_value << std::dec << '\n';
                        } else {
                            std::cout << "Slot global 0x" << std::hex << global_slot
                                      << " sem leitura: " << error << std::dec << '\n';
                            error.clear();
                        }
                    }
                }
            }
        }
    }
    if (has_find_rip_relative_target)
        find_rip_relative_references(executable_map, executable_memory,
                                     find_rip_relative_target, "eboot.bin");
    if (has_find_module_rip_relative_target) {
        const auto* module = modules.find(find_module_rip_relative_name);
        if (module == nullptr) {
            std::cerr << "Módulo não carregado para busca RIP-relativa: "
                      << find_module_rip_relative_name << '\n';
            return 1;
        }
        find_rip_relative_references(module->image_map(), module->image_memory(),
            find_module_rip_relative_target, find_module_rip_relative_name);
    }
    if (has_find_relative_call_target)
        find_relative_call_references(executable_map, executable_memory,
                                      find_relative_call_target);
    if (has_find_relative_branch_target)
        find_relative_branch_references(executable_map, executable_memory,
                                        find_relative_branch_target);
    if (has_find_module_branch_target) {
        const auto* module = modules.find(find_module_branch_name);
        if (module == nullptr) {
            std::cerr << "Módulo não carregado para busca de saltos: "
                      << find_module_branch_name << '\n';
            return 1;
        }
        find_relative_branch_references(module->image_map(), module->image_memory(),
            find_module_branch_target, find_module_branch_name);
    }
    if (has_find_member_field_writes)
        find_member_field_write_candidates(executable_map, executable_memory,
                                           find_member_field_offset);
    if (has_dump_module_code) {
      for (const auto requested_address : dump_module_addresses) {
        dump_module_address = requested_address;
        std::array<std::byte, 8192> bytes{};
        std::array<std::byte, 8192> image_bytes{};
        const nba16::GuestImageMap* selected_map = nullptr;
        const nba16::Ps4LoadedModule* selected_module = nullptr;
        if (dump_module_name == "eboot.bin") {
            selected_map = &executable_map;
            if (!nba16::read_guest_memory(executable_map,
                    executable_map.load_bias + dump_module_address, image_bytes, error)) {
                std::cerr << "Não foi possível ler os bytes originais do eboot: "
                          << error << '\n';
                return 1;
            }
            const auto* source = static_cast<const std::byte*>(executable_memory.translate(
                executable_map, executable_memory.load_bias() + dump_module_address,
                bytes.size(), false, error));
            if (source == nullptr) {
                std::cerr << "Não foi possível ler os bytes do eboot no endereço solicitado: "
                          << error << '\n';
                return 1;
            }
            std::memcpy(bytes.data(), source, bytes.size());
        } else {
            const auto* module = modules.find(dump_module_name);
            if (module == nullptr) {
                std::cerr << "Módulo não carregado: " << dump_module_name << '\n';
                return 1;
            }
            selected_module = module;
            const auto& module_map = module->image_map();
            selected_map = &module_map;
            if (!nba16::read_guest_memory(module_map,
                    module_map.load_bias + dump_module_address, image_bytes, error)) {
                std::cerr << "Não foi possível ler os bytes originais do módulo: "
                          << error << '\n';
                return 1;
            }
            const auto* source = static_cast<const std::byte*>(
                module->image_memory().translate(module_map,
                    module_map.load_bias + dump_module_address, bytes.size(), false, error));
            if (source == nullptr) {
                std::cerr << "Não foi possível ler os bytes do módulo no endereço solicitado: "
                          << error << '\n';
                return 1;
            }
            std::memcpy(bytes.data(), source, bytes.size());
        }
        if (selected_map != nullptr) {
            std::cout << "Imagem mapeada: VA 0x" << std::hex
                      << selected_map->minimum_virtual_address << "..0x"
                      << selected_map->maximum_virtual_address << std::dec << '\n';
            if (dump_module_name == "eboot.bin") {
                std::cout << "Load bias do eboot: 0x" << std::hex
                          << executable_memory.load_bias() << std::dec << '\n';
            }
            for (const auto& region : selected_map->regions) {
                std::cout << "  segmento VA 0x" << std::hex << region.virtual_address
                          << "..0x" << region.virtual_address + region.memory_size
                          << std::dec << " flags=" << region.flags << '\n';
            }
        }
        const auto print_ascii = [](std::string_view label,
                                    const auto& input) {
            std::cout << label;
            for (const auto byte : input) {
                const auto value = std::to_integer<unsigned char>(byte);
                std::cout << (value >= 0x20 && value <= 0x7e
                    ? static_cast<char>(value) : '.');
            }
            std::cout << '\n';
        };
        std::cout << "Bytes de " << dump_module_name << " em 0x" << std::hex
                  << dump_module_address << " bytes:";
        for (const auto byte : bytes) {
            std::cout << ' ' << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
        }
        std::cout << std::dec << std::setfill(' ') << '\n';
        if (selected_module != nullptr) {
            std::vector<nba16::LoadedPs4Export> exports;
            std::string export_error;
            if (selected_module->collect_exports(dump_module_name, exports, export_error)) {
                const auto begin = dump_module_address > 0x100
                    ? dump_module_address - 0x100 : 0;
                const auto end = dump_module_address <= UINT64_MAX - 0x100
                    ? dump_module_address + 0x100 : UINT64_MAX;
                for (const auto& item : exports) {
                    if (item.elf_symbol_kind != 2 ||
                        item.module_relative_value < begin || item.module_relative_value > end)
                        continue;
                    std::cout << "Export próximo: " << item.library_name << ':' << item.nid
                              << " em +0x" << std::hex << item.module_relative_value
                              << " tamanho=0x" << item.size << std::dec << '\n';
                }
            } else {
                std::cout << "Exports do módulo indisponíveis: " << export_error << '\n';
            }
        }
        print_ascii("ASCII runtime: ", bytes);
        print_ascii("ASCII ELF:     ", image_bytes);
      }
    }
    if (has_search_module_string) {
        const nba16::GuestImageMap* map = nullptr;
        if (search_module_name == "eboot.bin") {
            map = &executable_map;
        } else {
            const auto* module = modules.find(search_module_name);
            if (module == nullptr) {
                std::cerr << "Módulo não carregado para busca: " << search_module_name << '\n';
                return 1;
            }
            map = &module->image_map();
        }
        std::size_t matches = 0;
        for (const auto& region : map->regions) {
            const auto found_begin = std::search(region.bytes.begin(), region.bytes.end(),
                search_text.begin(), search_text.end(), [](std::uint8_t byte, char character) {
                    return byte == static_cast<std::uint8_t>(character);
                });
            if (found_begin == region.bytes.end()) continue;
            auto found = found_begin;
            while (found != region.bytes.end()) {
                const auto offset = static_cast<std::size_t>(found - region.bytes.begin());
                std::cout << "Texto encontrado em " << search_module_name << "+0x"
                          << std::hex << region.virtual_address + offset << std::dec << '\n';
                ++matches;
                const auto next = static_cast<std::size_t>(offset + 1U);
                if (next > region.bytes.size()) break;
                found = std::search(region.bytes.begin() + static_cast<std::ptrdiff_t>(next),
                    region.bytes.end(), search_text.begin(), search_text.end(),
                    [](std::uint8_t byte, char character) {
                        return byte == static_cast<std::uint8_t>(character);
                    });
            }
        }
        if (matches == 0) {
            std::cout << "Texto não encontrado em " << search_module_name << ".\n";
        }
    }
    if (has_lookup_main_relocation) {
        bool found = false;
        for (const auto& relocation : executable_link.relocations) {
            if (relocation.target != lookup_main_relocation) continue;
            found = true;
            std::cout << "Relocação eboot em 0x" << std::hex << relocation.target
                      << std::dec << ": tipo=" << relocation.type
                      << " PLT=" << relocation.is_plt
                      << " symbol_index=" << relocation.symbol_index;
            if (relocation.symbol_index < executable_link.symbols.size()) {
                const auto& symbol = executable_link.symbols[relocation.symbol_index];
                std::cout << " symbol='" << symbol.name << "'";
                if (relocation.symbol_index < executable_imports.symbol_addresses.size() &&
                    executable_imports.symbol_addresses[relocation.symbol_index].has_value()) {
                    const auto destination =
                        *executable_imports.symbol_addresses[relocation.symbol_index];
                    std::cout << " destino=0x" << std::hex
                              << destination
                              << std::dec;
                    bool owner_found = false;
                    for (const auto& module_name : modules.loaded_module_names()) {
                        const auto* owner_module = modules.find(module_name);
                        if (owner_module == nullptr) continue;
                        const auto bias = owner_module->image_memory().load_bias();
                        for (const auto& region : owner_module->image_map().regions) {
                            const auto begin = bias + region.virtual_address;
                            if (destination >= begin && destination - begin < region.memory_size) {
                                std::cout << " owner=" << module_name << "+0x" << std::hex
                                          << destination - bias << std::dec;
                                owner_found = true;
                                break;
                            }
                        }
                        if (owner_found) break;
                    }
                }
                if (symbol.has_nid_indices) {
                    std::cout << " library_id=" << symbol.nid_library_index
                              << " module_id=" << symbol.nid_module_index;
                }
            }
            std::cout << '\n';
        }
        if (!found) {
            std::cout << "Nenhuma relocação declarada no eboot em 0x" << std::hex
                      << lookup_main_relocation << std::dec << ".\n";
        }
    }
    return 0;
}
