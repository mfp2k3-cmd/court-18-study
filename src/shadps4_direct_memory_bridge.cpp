// SPDX-FileCopyrightText: Copyright 2026 NBA LIVE 16 independent port contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "shadps4_direct_memory_bridge.h"

#include "kernel_runtime.h"

#include "common/elf_info.h"
#include "core/file_format/psf.h"
#include "core/libraries/kernel/memory.h"
#include "core/libraries/kernel/orbis_error.h"
#include "core/linker.h"
#include "core/loader/elf.h"
#include "core/memory.h"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <limits>
#include <string_view>

namespace nba16 {
namespace {

std::uint64_t get_size(void*) {
    return Libraries::Kernel::sceKernelGetDirectMemorySize();
}

std::int32_t get_type(void*, std::uint64_t physical, std::int32_t* type,
                      void** start, void** end) {
    return Core::Memory::Instance()->GetDirectMemoryType(physical, type, start, end);
}

std::int32_t allocate(void*, std::int64_t low, std::int64_t high, std::uint64_t size,
                      std::uint64_t alignment, std::int32_t type, std::int64_t* physical) {
    return Libraries::Kernel::sceKernelAllocateDirectMemory(
        low, high, size, alignment, type, physical);
}

std::int32_t available(void*, std::int64_t low, std::int64_t high, std::uint64_t alignment,
                       std::int64_t* physical, std::uint64_t* size) {
    if (low < 0 || high < 0 || physical == nullptr || size == nullptr)
        return ORBIS_KERNEL_ERROR_EINVAL;

    std::uint64_t result_address{};
    const auto result = Libraries::Kernel::sceKernelAvailableDirectMemorySize(
        static_cast<std::uint64_t>(low), static_cast<std::uint64_t>(high), alignment,
        &result_address, size);
    if (result == 0) {
        if (result_address > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            return ORBIS_KERNEL_ERROR_EINVAL;
        *physical = static_cast<std::int64_t>(result_address);
    }
    return result;
}

std::int32_t map(void*, void** address, std::uint64_t size, std::int32_t protection,
                 std::int32_t flags, std::int64_t physical, std::uint64_t alignment) {
    return Libraries::Kernel::sceKernelMapDirectMemory(
        address, size, protection, flags, physical, alignment);
}

std::int32_t unmap(void*, std::uint64_t address, std::uint64_t size) {
    return Core::Memory::Instance()->UnmapMemory(address, size);
}

std::int32_t release(void*, std::int64_t physical, std::uint64_t size) {
    if (physical < 0) return ORBIS_KERNEL_ERROR_EINVAL;
    return Libraries::Kernel::sceKernelReleaseDirectMemory(
        static_cast<std::uint64_t>(physical), size);
}

std::uint32_t compiled_sdk_version(const std::filesystem::path& eboot_path,
                                   std::string& error) {
    Core::Loader::Elf elf;
    elf.Open(eboot_path);
    if (!elf.IsElfFile()) {
        error = "eboot.bin não é um ELF PS4 válido";
        return 0;
    }

    const auto headers = elf.GetProgramHeader();
    const auto proc_param = std::find_if(headers.begin(), headers.end(), [](const auto& entry) {
        return entry.p_type == PT_SCE_PROCPARAM;
    });
    if (proc_param == headers.end() || proc_param->p_filesz < sizeof(Core::OrbisProcParam)) {
        error = "eboot.bin não contém um parâmetro de processo completo";
        return 0;
    }

    Core::OrbisProcParam param{};
    elf.LoadSegment(reinterpret_cast<std::uint64_t>(&param), proc_param->p_offset,
                    sizeof(param));
    return static_cast<std::uint32_t>(param.sdk_version);
}

} // namespace

bool initialize_shadps4_game_metadata(const std::filesystem::path& game_root,
                                      std::string& error) {
    const auto sfo_path = game_root / "sce_sys" / "param.sfo";
    const auto eboot_path = game_root / "eboot.bin";
    PSF psf;
    if (!psf.Open(sfo_path)) {
        error = "não foi possível ler sce_sys/param.sfo";
        return false;
    }

    std::string serial;
    const auto content_id = psf.GetString("CONTENT_ID");
    const auto title_id = psf.GetString("TITLE_ID");
    if (content_id && content_id->size() >= 16) {
        serial = std::string(*content_id).substr(7, 9);
    } else if (title_id) {
        serial = *title_id;
    }
    const std::string title{psf.GetString("TITLE").value_or("NBA LIVE 18")};
    const std::string app_version{psf.GetString("APP_VER").value_or("1.00")};
    const auto raw_firmware = static_cast<std::uint32_t>(
        psf.GetInteger("SYSTEM_VER").value_or(0x04700000));
    Common::PSFAttributes attributes{};
    attributes.raw = static_cast<std::uint32_t>(psf.GetInteger("ATTRIBUTE").value_or(0));

    std::uint32_t sdk_version{};
    const auto pubtool = psf.GetString("PUBTOOLINFO").value_or("");
    const auto sdk_token = pubtool.find("sdk_ver=");
    if (sdk_token != std::string_view::npos) {
        auto value = pubtool.substr(sdk_token + 8);
        if (const auto comma = value.find(','); comma != std::string_view::npos)
            value = value.substr(0, comma);
        if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
        const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(),
                                                sdk_version, 16);
        if (ec != std::errc{} || end != value.data() + value.size()) sdk_version = 0;
    }
    if (sdk_version == 0) sdk_version = raw_firmware;

    std::string elf_error;
    const auto compiled_sdk = compiled_sdk_version(eboot_path, elf_error);
    if (compiled_sdk == 0) {
        error = std::move(elf_error);
        return false;
    }

    std::vector<std::uint8_t> splash;
    const auto splash_path = game_root / "sce_sys" / "pic1.png";
    if (std::ifstream input{splash_path, std::ios::binary}; input) {
        input.seekg(0, std::ios::end);
        const auto length = input.tellg();
        if (length > 0) {
            splash.resize(static_cast<std::size_t>(length));
            input.seekg(0, std::ios::beg);
            input.read(reinterpret_cast<char*>(splash.data()),
                       static_cast<std::streamsize>(length));
            if (!input) splash.clear();
        }
    }

    Common::ElfInfo::Instance().Initialize(std::move(serial), title, app_version,
        raw_firmware & 0xFFF00000U, raw_firmware, compiled_sdk, attributes,
        std::filesystem::absolute(game_root), std::move(splash));
    error.clear();
    return true;
}

bool install_shadps4_direct_memory_provider() noexcept {
    const DirectMemoryProvider provider{
        .context = nullptr,
        .get_size = get_size,
        .get_type = get_type,
        .allocate = allocate,
        .available = available,
        .map = map,
        .unmap = unmap,
        .release = release,
    };
    return install_direct_memory_provider(provider);
}

} // namespace nba16
