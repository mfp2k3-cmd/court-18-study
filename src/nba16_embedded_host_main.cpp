// SPDX-FileCopyrightText: Copyright 2026 NBA LIVE 16 independent port contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <windows.h>
#include <shellapi.h>
#include <SDL3/SDL_events.h>

#include <atomic>
#include <filesystem>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <cwchar>
#include <vector>

#include "common/key_manager.h"
#include "core/file_format/psf.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "emulator.h"
#include "core/emulator_settings.h"
#include "core/emulator_state.h"
#include "core/ipc/ipc.h"
#include "core/user_settings.h"

namespace {

constexpr wchar_t kDefaultGameRoot[] = L"";

struct LaunchOptions {
    std::filesystem::path game_root{kDefaultGameRoot};
    std::filesystem::path profile_base;
    std::wstring user_name{L"NBA Player"};
    DWORD wait_for_pid{};
};

bool is_supported_live18_id(std::string_view title_id) {
    return title_id == "CUSA06321" || title_id == "CUSA06316" || title_id == "CUSA08562";
}
LaunchOptions parse_launch_options() {
    LaunchOptions options;
    int count{};
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    if (arguments == nullptr) return options;
    for (int index = 1; index < count; ++index) {
        const std::wstring_view argument(arguments[index]);
        if (argument == L"--game-dir" && index + 1 < count) {
            options.game_root = arguments[++index];
        } else if (argument == L"--profile-base" && index + 1 < count) {
            options.profile_base = arguments[++index];
        } else if (argument == L"--user-name" && index + 1 < count) {
            options.user_name = arguments[++index];
        } else if (argument == L"--wait-for-pid" && index + 1 < count) {
            options.wait_for_pid = static_cast<DWORD>(std::wcstoul(arguments[++index], nullptr, 10));
        }
    }
    LocalFree(arguments);
    return options;
}

std::string to_utf8(const std::wstring& value) {
    if (value.empty()) return "NBA Player";
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1,
                                          nullptr, 0, nullptr, nullptr);
    if (bytes <= 1) return "NBA Player";
    std::string result(static_cast<size_t>(bytes), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1,
                             result.data(), bytes, nullptr, nullptr)) return "NBA Player";
    result.resize(static_cast<size_t>(bytes - 1));
    return result;
}

void show_error(const std::wstring& message) {
    MessageBoxW(nullptr, message.c_str(), L"NBA LIVE 18", MB_OK | MB_ICONERROR);
}

std::filesystem::path executable_directory() {
    std::vector<wchar_t> path(32768);
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) return std::filesystem::current_path();
    return std::filesystem::path(std::wstring(path.data(), length)).parent_path();
}

} // namespace

namespace {
std::atomic<int> g_requested_menu_action{};
}

extern "C" void NBA16_RequestMenuAction(int action) {
    g_requested_menu_action.store(action, std::memory_order_release);
    SDL_Event event{};
    event.type = SDL_EVENT_QUIT;
    SDL_PushEvent(&event);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    try {
        const auto options = parse_launch_options();
        if (options.wait_for_pid != 0) {
            HANDLE previous_process = OpenProcess(SYNCHRONIZE, FALSE, options.wait_for_pid);
            if (previous_process) {
                WaitForSingleObject(previous_process, INFINITE);
                CloseHandle(previous_process);
            }
        }
        const auto& game_root = options.game_root;
        if (!options.profile_base.empty() && !SetCurrentDirectoryW(options.profile_base.c_str())) {
            show_error(L"Não foi possível abrir a pasta-base dos saves.\n\n" + options.profile_base.wstring());
            return 1;
        }
        if (!std::filesystem::is_directory(game_root) ||
            !std::filesystem::is_regular_file(game_root / L"eboot.bin")) {
            show_error(L"Não encontrei eboot.bin na pasta do dump do NBA LIVE 18.\n\n" +
                       game_root.wstring());
            return 1;
        }
        PSF param_sfo;
        if (!param_sfo.Open(game_root / L"sce_sys" / L"param.sfo")) {
            show_error(L"Não foi possível ler sce_sys/param.sfo. Selecione um dump compatível do NBA LIVE 18.");
            return 1;
        }
        const auto title_id = param_sfo.GetString("TITLE_ID");
        if (!title_id || !is_supported_live18_id(*title_id)) {
            show_error(L"Este runtime aceita somente NBA LIVE 18: CUSA06321, CUSA06316 ou CUSA08562.");
            return 1;
        }

        Common::Log::Setup("nba16.log");
        IPC::Instance().Init();
        EmulatorState::SetInstance(std::make_shared<EmulatorState>());
        UserSettingsImpl::SetInstance(std::make_shared<UserSettingsImpl>());
        UserSettings.Load();
        auto& user_manager = UserSettings.GetUserManager();
        if (user_manager.GetUserByID(1000) != nullptr) {
            user_manager.RenameUser(1000, to_utf8(options.user_name));
            UserSettings.Save();
        }
        KeyManager::GetInstance()->LoadFromFile();
        EmulatorSettingsImpl::SetInstance(std::make_shared<EmulatorSettingsImpl>());
        EmulatorSettings.Load();
        const auto portable_user_dir = executable_directory() / L"user";
        const auto local_modules = portable_user_dir / L"sys_modules";
        const auto local_fonts = portable_user_dir / L"fonts";
        const auto system_modules = std::filesystem::is_directory(local_modules)
            ? local_modules : std::filesystem::path{};
        const auto system_fonts = std::filesystem::is_directory(local_fonts)
            ? local_fonts : std::filesystem::path{};
        if (std::filesystem::is_directory(system_modules))
            EmulatorSettings.SetSysModulesDir(system_modules);
        if (std::filesystem::is_directory(system_fonts))
            EmulatorSettings.SetFontsDir(system_fonts);

        auto* emulator = Common::Singleton<Core::Emulator>::Instance();
        emulator->executableName = "NBA LIVE 18.exe";
        emulator->Run(game_root, {}, game_root);
        const int menu_action = g_requested_menu_action.exchange(0, std::memory_order_acq_rel);
        if (menu_action == 1) {
            std::vector<wchar_t> executable_path(32768);
            const DWORD executable_length = GetModuleFileNameW(
                nullptr, executable_path.data(), static_cast<DWORD>(executable_path.size()));
            if (executable_length == 0 || executable_length >= executable_path.size()) {
                show_error(L"Não foi possível localizar o executável para reiniciar o jogo.");
                ExitProcess(1);
            }
            std::wstring command_line = GetCommandLineW();
            command_line += L" --wait-for-pid " + std::to_wstring(GetCurrentProcessId());
            const auto restart_directory = options.profile_base.empty()
                ? std::filesystem::current_path() : options.profile_base;
            STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
            if (!CreateProcessW(executable_path.data(), command_line.data(), nullptr, nullptr,
                                FALSE, 0, nullptr, restart_directory.c_str(), &startup, &process)) {
                show_error(L"Não foi possível reiniciar o NBA LIVE 18.");
                ExitProcess(1);
            }
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        ExitProcess(0);
        return 0;
    } catch (const std::exception& error) {
        const auto message = std::wstring(error.what(), error.what() + strlen(error.what()));
        show_error(L"Falha ao iniciar o port:\n\n" + message);
        return 1;
    }
}
