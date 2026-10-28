// SPDX-FileCopyrightText: Copyright 2026 NBA LIVE 16 independent port contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#define UNICODE
#define _UNICODE
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shobjidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace Gdiplus;
constexpr wchar_t kWindowClass[] = L"NBA16LauncherWindow";
constexpr wchar_t kOptionsClass[] = L"NBA16LauncherOptionsWindow";
constexpr wchar_t kUsersClass[] = L"NBA16LauncherUsersWindow";
constexpr wchar_t kDefaultGameRoot[] = L"";
constexpr int kPathEdit = 1001, kBrowse = 1002;
constexpr int kLaunch = 1005, kStatus = 1006, kSaves = 1007, kOptions = 1008;
constexpr int kSaveBaseEdit = 1009, kBrowseSaveBase = 1010;
constexpr int kUsers = 1012;
constexpr int kResolution = 1101, kRefresh = 1102, kFullscreen = 1103, kProMode = 1104;
constexpr int kSaveOptions = 1105, kRenderResolution = 1106, kFsrEnabled = 1107;
constexpr int kUserProfile = 1108, kUserName = 1109, kCreateUser = 1110, kRenameUser = 1111;
constexpr int kSaveUsers = 1112, kDeleteUser = 1113, kShowFps = 1114;

struct Resolution { const wchar_t* label; unsigned width; unsigned height; };
constexpr Resolution kResolutions[] = {
    {L"1280 × 720 (720p)", 1280, 720}, {L"1920 × 1080 (1080p)", 1920, 1080},
    {L"2560 × 1440 (1440p)", 2560, 1440}, {L"3840 × 2160 (4K)", 3840, 2160},
};

HWND g_window{}, g_options_window{}, g_users_window{};
HWND g_path_edit{}, g_save_base_edit{};
HWND g_resolution{}, g_render_resolution{}, g_refresh{}, g_fullscreen{}, g_pro_mode{}, g_fsr_enabled{}, g_show_fps{};
HWND g_user_profile{}, g_user_name{};
HFONT g_font{}, g_button_font{}, g_title_font{};
std::filesystem::path g_app_dir, g_launcher_ini;
std::unique_ptr<Bitmap> g_background_image;
std::unique_ptr<Bitmap> g_play_ball_image;
std::unique_ptr<Bitmap> g_button_leather_image;
HICON g_ball_icon{};
HBRUSH g_panel_brush{};
HBRUSH g_edit_brush{};
ULONG_PTR g_gdiplus_token{};
int g_resolution_index{1}, g_render_resolution_index{1}, g_refresh_index{}, g_volume_value_saved{100};
struct UserProfile { int id{}; std::wstring name; };
std::vector<UserProfile> g_user_profiles;
int g_selected_user_id{};
bool g_fullscreen_value{}, g_pro_mode_value{}, g_fsr_enabled_value{}, g_show_fps_value{};
bool g_drag_volume{}, g_drag_sharpness{};
std::wstring g_status_text{L"Pronto para iniciar."};
int g_slider_value{100};
int g_sharpness_value{83};

std::filesystem::path selected_save_base() {
    wchar_t value[32768]{};
    const int length = GetWindowTextW(g_save_base_edit, value, static_cast<int>(std::size(value)));
    return length > 0 ? std::filesystem::path(std::wstring(value, static_cast<size_t>(length)))
                      : g_app_dir;
}

std::filesystem::path selected_profile_base() {
    const auto base = selected_save_base();
    if (g_selected_user_id == 0) return base; // Keep existing saves in their original location.
    return base / L"profiles" / (L"user-" + std::to_wstring(g_selected_user_id));
}

std::filesystem::path actual_save_path() {
    return selected_profile_base() / L"user" / L"home" / L"1000" / L"savedata";
}

std::wstring profile_name(int id) {
    const auto it = std::find_if(g_user_profiles.begin(), g_user_profiles.end(),
                                 [id](const UserProfile& profile) { return profile.id == id; });
    return it == g_user_profiles.end() ? L"NBA Player" : it->name;
}

int profile_combo_index(int id) {
    for (size_t index = 0; index < g_user_profiles.size(); ++index) {
        if (g_user_profiles[index].id == id) return static_cast<int>(index);
    }
    return 0;
}

void persist_user_profiles() {
    std::error_code ec;
    std::filesystem::create_directories(g_launcher_ini.parent_path(), ec);
    WritePrivateProfileStringW(L"Users", L"Count",
                               std::to_wstring(g_user_profiles.size()).c_str(), g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Users", L"SelectedId",
                               std::to_wstring(g_selected_user_id).c_str(), g_launcher_ini.c_str());
    for (size_t index = 0; index < g_user_profiles.size(); ++index) {
        const auto suffix = std::to_wstring(index);
        WritePrivateProfileStringW(L"Users", (L"Id" + suffix).c_str(),
                                   std::to_wstring(g_user_profiles[index].id).c_str(), g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Users", (L"Name" + suffix).c_str(),
                                   g_user_profiles[index].name.c_str(), g_launcher_ini.c_str());
    }
}

void refresh_user_controls(int selected_id) {
    if (!g_user_profile || !g_user_name) return;
    SendMessageW(g_user_profile, CB_RESETCONTENT, 0, 0);
    for (const auto& profile : g_user_profiles)
        SendMessageW(g_user_profile, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(profile.name.c_str()));
    const int selected = profile_combo_index(selected_id);
    SendMessageW(g_user_profile, CB_SETCURSEL, selected, 0);
    SetWindowTextW(g_user_name, profile_name(selected_id).c_str());
    if (g_users_window) EnableWindow(GetDlgItem(g_users_window, kDeleteUser), selected_id != 0);
}

void load_user_profiles() {
    const int count = std::clamp(static_cast<int>(GetPrivateProfileIntW(
        L"Users", L"Count", 0, g_launcher_ini.c_str())), 0, 128);
    g_user_profiles.clear();
    for (int index = 0; index < count; ++index) {
        const auto suffix = std::to_wstring(index);
        const int id = GetPrivateProfileIntW(L"Users", (L"Id" + suffix).c_str(), -1,
                                             g_launcher_ini.c_str());
        wchar_t name[128]{};
        GetPrivateProfileStringW(L"Users", (L"Name" + suffix).c_str(), L"", name,
                                 static_cast<DWORD>(std::size(name)), g_launcher_ini.c_str());
        if (id < 0 || name[0] == L'\0') continue;
        g_user_profiles.push_back({id, name});
    }
    if (std::none_of(g_user_profiles.begin(), g_user_profiles.end(),
                     [](const UserProfile& profile) { return profile.id == 0; })) {
        g_user_profiles.insert(g_user_profiles.begin(), {0, L"NBA Player"});
    }
    g_selected_user_id = GetPrivateProfileIntW(L"Users", L"SelectedId", 0,
                                                g_launcher_ini.c_str());
    if (std::none_of(g_user_profiles.begin(), g_user_profiles.end(), [](const UserProfile& profile) {
            return profile.id == g_selected_user_id;
        })) g_selected_user_id = 0;
}

bool valid_profile_name(const std::wstring& name) {
    if (name.empty() || name.size() > 24) return false;
    return std::none_of(name.begin(), name.end(), [](wchar_t ch) {
        return ch < 32 || ch == L'\\' || ch == L'/' || ch == L':' || ch == L'*' ||
               ch == L'?' || ch == L'"' || ch == L'<' || ch == L'>' || ch == L'|';
    });
}

void draw_launcher_backdrop(Graphics& graphics, int window_width, int window_height,
                            int origin_x, int origin_y, int region_width, int region_height) {
    graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);
    if (g_background_image && g_background_image->GetLastStatus() == Ok) {
        const REAL iw = static_cast<REAL>(g_background_image->GetWidth());
        const REAL ih = static_cast<REAL>(g_background_image->GetHeight());
        const REAL scale = std::max(static_cast<REAL>(window_width) / iw, static_cast<REAL>(window_height) / ih);
        const REAL sw = static_cast<REAL>(region_width) / scale, sh = static_cast<REAL>(region_height) / scale;
        const REAL sx = static_cast<REAL>(origin_x) / scale + (iw - static_cast<REAL>(window_width) / scale) / 2;
        const REAL sy = static_cast<REAL>(origin_y) / scale + (ih - static_cast<REAL>(window_height) / scale) / 2;
        graphics.DrawImage(g_background_image.get(), Rect(0, 0, region_width, region_height),
                           static_cast<INT>(sx), static_cast<INT>(sy), static_cast<INT>(sw),
                           static_cast<INT>(sh), UnitPixel);
    } else graphics.Clear(Color(255, 24, 28, 32));

    SolidBrush overlay(Color(38, 0, 0, 0));
    graphics.FillRectangle(&overlay, 0, 0, region_width, region_height);

}

HWND make_control(HWND parent, DWORD ex_style, const wchar_t* cls, const wchar_t* text,
                  DWORD style, int x, int y, int width, int height, int id, HFONT font = nullptr) {
    HWND control = CreateWindowExW(ex_style, cls, text, style, x, y, width, height, parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    if (control && font) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return control;
}

int button_text_width(const wchar_t* text, HFONT font, int horizontal_padding) {
    HDC dc = GetDC(nullptr);
    if (!dc) return horizontal_padding + 40;
    HFONT old = static_cast<HFONT>(SelectObject(dc, font ? font : GetStockObject(DEFAULT_GUI_FONT)));
    SIZE size{};
    GetTextExtentPoint32W(dc, text, lstrlenW(text), &size);
    SelectObject(dc, old);
    ReleaseDC(nullptr, dc);
    return size.cx + horizontal_padding;
}

void draw_basketball_button(const DRAWITEMSTRUCT& item) {
    const int width = item.rcItem.right - item.rcItem.left;
    const int height = item.rcItem.bottom - item.rcItem.top;
    if (width <= 0 || height <= 0) return;
    Graphics graphics(item.hDC);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    const Rect bounds(item.rcItem.left, item.rcItem.top, width, height);
    const bool disabled = (item.itemState & ODS_DISABLED) != 0;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    const Color top = disabled ? Color(255, 130, 101, 76) :
        (pressed ? Color(255, 165, 76, 28) : Color(255, 224, 132, 51));
    const Color bottom = disabled ? Color(255, 83, 61, 46) :
        (pressed ? Color(255, 112, 43, 15) : Color(255, 164, 66, 22));
    LinearGradientBrush fill(bounds, top, bottom, LinearGradientModeVertical);
    graphics.FillRectangle(&fill, bounds);
    if (g_button_leather_image && g_button_leather_image->GetLastStatus() == Ok) {
        ImageAttributes texture_attributes;
        ColorMatrix texture_opacity{};
        texture_opacity.m[0][0] = texture_opacity.m[1][1] = texture_opacity.m[2][2] = 1.0f;
        texture_opacity.m[3][3] = disabled ? 0.30f : 0.58f;
        texture_opacity.m[4][4] = 1.0f;
        texture_attributes.SetColorMatrix(&texture_opacity, ColorMatrixFlagsDefault, ColorAdjustTypeBitmap);
        const UINT source_width = g_button_leather_image->GetWidth();
        const UINT source_height = std::min<UINT>(g_button_leather_image->GetHeight(), 56);
        graphics.DrawImage(g_button_leather_image.get(), bounds, 0, 0,
                           static_cast<INT>(source_width), static_cast<INT>(source_height),
                           UnitPixel, &texture_attributes);
        const Color tint = disabled ? Color(80, 75, 67, 59) :
            (pressed ? Color(55, 139, 55, 17) : Color(38, 255, 132, 36));
        SolidBrush warm_tint(tint);
        graphics.FillRectangle(&warm_tint, bounds);
    }
    Pen outline(Color(255, 77, 35, 14), 1.5f);
    graphics.DrawRectangle(&outline, bounds);
    if (width > 4 && height > 4) {
        Pen inner(Color(95, 255, 205, 126), 1.0f);
        graphics.DrawRectangle(&inner, item.rcItem.left + 2, item.rcItem.top + 2,
                               width - 4, height - 4);
    }
    if (item.itemState & ODS_FOCUS) {
        Pen focus(Color(230, 255, 226, 163), 1.0f);
        graphics.DrawRectangle(&focus, item.rcItem.left + 4, item.rcItem.top + 4,
                               std::max(1, width - 8), std::max(1, height - 8));
    }
    wchar_t text[128]{};
    GetWindowTextW(item.hwndItem, text, static_cast<int>(std::size(text)));
    RECT text_rect = item.rcItem;
    SetBkMode(item.hDC, TRANSPARENT);
    HFONT old = static_cast<HFONT>(SelectObject(item.hDC, g_button_font ? g_button_font : g_font));
    OffsetRect(&text_rect, 2, 2);
    SetTextColor(item.hDC, RGB(55, 21, 8));
    DrawTextW(item.hDC, text, -1, &text_rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    OffsetRect(&text_rect, -1, -1);
    SetTextColor(item.hDC, RGB(112, 48, 18));
    DrawTextW(item.hDC, text, -1, &text_rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    OffsetRect(&text_rect, -1, -1);
    SetTextColor(item.hDC, disabled ? RGB(230, 215, 196) : RGB(255, 255, 255));
    DrawTextW(item.hDC, text, -1, &text_rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(item.hDC, old);
}

std::filesystem::path module_directory() {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!length || length >= buffer.size()) return std::filesystem::current_path();
    return std::filesystem::path(std::wstring(buffer.data(), length)).parent_path();
}

void update_volume_label() { InvalidateRect(g_options_window, nullptr, FALSE); }

void load_preferences() {
    wchar_t path[32768]{};
    GetPrivateProfileStringW(L"Launcher", L"GamePath", kDefaultGameRoot, path,
                             static_cast<DWORD>(std::size(path)), g_launcher_ini.c_str());
    SetWindowTextW(g_path_edit, path);
    GetPrivateProfileStringW(L"Launcher", L"SaveBase", g_app_dir.c_str(), path,
                             static_cast<DWORD>(std::size(path)), g_launcher_ini.c_str());
    SetWindowTextW(g_save_base_edit, path);
    g_resolution_index = std::clamp(static_cast<int>(GetPrivateProfileIntW(L"Launcher", L"Resolution", 1,
                                           g_launcher_ini.c_str())), 0, 3);
    g_render_resolution_index = std::clamp(static_cast<int>(GetPrivateProfileIntW(
        L"Launcher", L"RenderResolution", g_resolution_index, g_launcher_ini.c_str())), 0, 3);
    g_refresh_index = GetPrivateProfileIntW(L"Launcher", L"RefreshRate", 60,
                                             g_launcher_ini.c_str()) >= 120 ? 1 : 0;
    g_fullscreen_value = GetPrivateProfileIntW(L"Launcher", L"Fullscreen", 0,
                                                g_launcher_ini.c_str()) != 0;
    g_pro_mode_value = GetPrivateProfileIntW(L"Launcher", L"ProMode", 0,
                                               g_launcher_ini.c_str()) != 0;
    g_fsr_enabled_value = GetPrivateProfileIntW(L"Launcher", L"Fsr1Enabled", 0,
                                                  g_launcher_ini.c_str()) != 0;
    g_sharpness_value = std::clamp(static_cast<int>(GetPrivateProfileIntW(
        L"Launcher", L"FsrSharpness", 83, g_launcher_ini.c_str())), 0, 100);
    g_show_fps_value = GetPrivateProfileIntW(L"Launcher", L"ShowFps", 0,
                                              g_launcher_ini.c_str()) != 0;
    g_volume_value_saved = std::clamp(static_cast<int>(GetPrivateProfileIntW(L"Launcher", L"Volume", 100,
                                              g_launcher_ini.c_str())), 50, 150);
    g_slider_value = g_volume_value_saved; update_volume_label();
    SendMessageW(g_resolution, CB_SETCURSEL, g_resolution_index, 0);
    SendMessageW(g_render_resolution, CB_SETCURSEL, g_render_resolution_index, 0);
    SendMessageW(g_refresh, CB_SETCURSEL, g_refresh_index, 0);
    SendMessageW(g_fullscreen, BM_SETCHECK, g_fullscreen_value ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_pro_mode, BM_SETCHECK, g_pro_mode_value ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_fsr_enabled, BM_SETCHECK, g_fsr_enabled_value ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_show_fps, BM_SETCHECK, g_show_fps_value ? BST_CHECKED : BST_UNCHECKED, 0);
}

void save_preferences(const std::filesystem::path& game_path) {
    std::error_code ec; std::filesystem::create_directories(g_launcher_ini.parent_path(), ec);
    WritePrivateProfileStringW(L"Launcher", L"GamePath", game_path.c_str(), g_launcher_ini.c_str());
    const auto save_base = selected_save_base();
    WritePrivateProfileStringW(L"Launcher", L"SaveBase", save_base.c_str(), g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"Resolution", std::to_wstring(g_resolution_index).c_str(), g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"RenderResolution", std::to_wstring(g_render_resolution_index).c_str(), g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"Fsr1Enabled", g_fsr_enabled_value ? L"1" : L"0", g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"FsrSharpness", std::to_wstring(g_sharpness_value).c_str(), g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"ShowFps", g_show_fps_value ? L"1" : L"0", g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"RefreshRate", g_refresh_index ? L"120" : L"60", g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"Fullscreen", g_fullscreen_value ? L"1" : L"0", g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"ProMode", g_pro_mode_value ? L"1" : L"0", g_launcher_ini.c_str());
    WritePrivateProfileStringW(L"Launcher", L"Volume", std::to_wstring(g_volume_value_saved).c_str(), g_launcher_ini.c_str());
}

void update_status(const wchar_t* message, bool error = false) {
    g_status_text = message; InvalidateRect(g_window, nullptr, FALSE);
    if (error) MessageBeep(MB_ICONWARNING);
}

void choose_game_folder() {
    IFileDialog* dialog{};
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) return;
    DWORD options{}; dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dialog->SetTitle(L"Selecione a pasta do dump CUSA06321");
    if (SUCCEEDED(dialog->Show(g_window))) {
        IShellItem* item{};
        if (SUCCEEDED(dialog->GetResult(&item))) {
            PWSTR selected{};
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &selected))) {
                SetWindowTextW(g_path_edit, selected); CoTaskMemFree(selected);
            }
            item->Release();
        }
    }
    dialog->Release();
}

void choose_save_base() {
    IFileDialog* dialog{};
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) return;
    DWORD options{}; dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dialog->SetTitle(L"Selecione a pasta-base dos saves");
    if (SUCCEEDED(dialog->Show(g_window))) {
        IShellItem* item{};
        if (SUCCEEDED(dialog->GetResult(&item))) {
            PWSTR selected{};
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &selected))) {
                SetWindowTextW(g_save_base_edit, selected); CoTaskMemFree(selected);
                InvalidateRect(g_window, nullptr, FALSE);
            }
            item->Release();
        }
    }
    dialog->Release();
}

void open_save_folder() {
    const auto save_root = actual_save_path();
    std::error_code ec; std::filesystem::create_directories(save_root, ec);
    ShellExecuteW(g_window, L"open", save_root.c_str(), nullptr, g_app_dir.c_str(), SW_SHOWNORMAL);
}

bool read_game_title_id(const std::filesystem::path& game_path, std::string& title_id) {
    std::ifstream input(game_path / L"sce_sys" / L"param.sfo", std::ios::binary);
    if (!input) return false;
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    if (bytes.size() < 0x14 || bytes.size() > 1024 * 1024 || bytes[0] != 0 ||
        bytes[1] != 'P' || bytes[2] != 'S' || bytes[3] != 'F') return false;
    const auto u16 = [&](size_t at) -> std::uint16_t {
        return static_cast<std::uint16_t>(bytes[at]) |
               (static_cast<std::uint16_t>(bytes[at + 1]) << 8);
    };
    const auto u32 = [&](size_t at) -> std::uint32_t {
        return static_cast<std::uint32_t>(bytes[at]) |
               (static_cast<std::uint32_t>(bytes[at + 1]) << 8) |
               (static_cast<std::uint32_t>(bytes[at + 2]) << 16) |
               (static_cast<std::uint32_t>(bytes[at + 3]) << 24);
    };
    const std::size_t key_table = u32(8), data_table = u32(12), count = u32(16);
    if (count > 4096 || key_table >= bytes.size() || data_table >= bytes.size() ||
        count > (bytes.size() - 0x14) / 0x10) return false;
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t entry = 0x14 + i * 0x10;
        const std::size_t key = key_table + u16(entry);
        if (key >= bytes.size()) continue;
        const auto key_end = std::find(bytes.begin() + key, bytes.end(), std::uint8_t{0});
        if (key_end == bytes.end() || std::string_view(
                reinterpret_cast<const char*>(bytes.data() + key),
                static_cast<std::size_t>(key_end - (bytes.begin() + key))) != "TITLE_ID") continue;
        const std::size_t length = u32(entry + 4);
        const std::size_t value = data_table + u32(entry + 12);
        if (length == 0 || value >= bytes.size() || length > bytes.size() - value) return false;
        const auto value_end = std::find(bytes.begin() + value, bytes.begin() + value + length,
                                         std::uint8_t{0});
        title_id.assign(reinterpret_cast<const char*>(bytes.data() + value),
                        static_cast<std::size_t>(value_end - (bytes.begin() + value)));
        return !title_id.empty();
    }
    return false;
}

bool supported_game_id(std::string_view title_id) {
    return title_id == "CUSA06321" || title_id == "CUSA06316" || title_id == "CUSA08562";
}
bool write_game_config(const std::filesystem::path& user_dir, const std::string& title_id) {
    const auto& output_resolution = kResolutions[g_resolution_index];
    const auto& render_resolution = kResolutions[g_render_resolution_index];
    unsigned window_width = output_resolution.width;
    unsigned window_height = output_resolution.height;
    if (!g_fullscreen_value) {
        RECT work_area{};
        if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0)) {
            const unsigned max_width = static_cast<unsigned>(std::max(640L, work_area.right - work_area.left - 32));
            const unsigned max_height = static_cast<unsigned>(std::max(360L, work_area.bottom - work_area.top - 64));
            const double scale = std::min({1.0, static_cast<double>(max_width) / window_width,
                                           static_cast<double>(max_height) / window_height});
            window_width = std::max(640u, static_cast<unsigned>(window_width * scale));
            window_height = std::max(360u, static_cast<unsigned>(window_height * scale));
        }
    }
    const auto config_dir = user_dir / L"custom_configs";
    std::error_code ec; std::filesystem::create_directories(config_dir, ec); if (ec) return false;
    std::ofstream out(config_dir / (title_id + ".json"), std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << "{\n  \"General\": {\"neo_mode\": " << (g_pro_mode_value ? "true" : "false")
        << ", \"show_fps_counter\": " << (g_show_fps_value ? "true" : "false")
        << ", \"volume_slider\": " << g_volume_value_saved
        << "},\n  \"Input\": {\"background_controller_input\": true},\n  \"GPU\": {\"window_width\": "
        << window_width << ", \"window_height\": " << window_height
        << ", \"internal_screen_width\": " << render_resolution.width
        << ", \"internal_screen_height\": " << render_resolution.height
        << ", \"readbacks_mode\": 2, \"readback_linear_images_enabled\": true"
        << ", \"fsr_enabled\": " << (g_fsr_enabled_value ? "true" : "false")
        << ", \"rcas_enabled\": true, \"rcas_attenuation\": " << ((100 - g_sharpness_value) * 15)
        << ", \"full_screen\": " << (g_fullscreen_value ? "true" : "false")
        << ", \"full_screen_mode\": \"" << (g_fullscreen_value ? "Fullscreen" : "Windowed")
        << "\", \"vblank_frequency\": " << (g_refresh_index ? 120 : 60) << "}\n}\n";
    return out.good();
}

void launch_game() {
    wchar_t selected[32768]{}; const int length = GetWindowTextW(g_path_edit, selected, static_cast<int>(std::size(selected)));
    const std::filesystem::path game_path(std::wstring(selected, static_cast<size_t>(std::max(length, 0))));
    std::error_code ec;
    if (!length || !std::filesystem::is_regular_file(game_path / L"eboot.bin", ec)) {
        update_status(L"A pasta selecionada não contém eboot.bin.", true); return;
    }
    std::string title_id;
    if (!read_game_title_id(game_path, title_id)) {
        update_status(L"Não foi possível ler o Title ID em sce_sys\\param.sfo.", true); return;
    }
    if (!supported_game_id(title_id)) {
        update_status(L"Esse jogo não é compatível. Selecione NBA LIVE 18: CUSA06321, CUSA06316 ou CUSA08562.", true); return;
    }
    g_volume_value_saved = g_slider_value;
    save_preferences(game_path);
    const auto profile_base = selected_profile_base();
    const auto user_dir = profile_base / L"user";
    if (!write_game_config(user_dir, title_id)) { update_status(L"Não foi possível gravar as opções do jogo.", true); return; }
    const auto exe = g_app_dir / L"NBA LIVE 18.exe";
    if (!std::filesystem::is_regular_file(exe, ec)) { update_status(L"Não encontrei NBA LIVE 18.exe ao lado do launcher.", true); return; }
    const auto user_name = profile_name(g_selected_user_id);
    std::wstring command = L"\"" + exe.wstring() + L"\" --game-dir \"" + game_path.wstring() +
        L"\" --profile-base \"" + profile_base.wstring() + L"\" --user-name \"" + user_name + L"\"";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr,
                        profile_base.c_str(), &startup, &process)) {
        update_status(L"Não consegui iniciar o jogo. Confira os arquivos do port.", true); return;
    }
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    update_status(L"Jogo iniciado.");
}

void create_options_window() {
    g_options_window = CreateWindowExW(WS_EX_DLGMODALFRAME, kOptionsClass, L"Opções — COURT 18",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 610, 650,
        g_window, nullptr, GetModuleHandleW(nullptr), nullptr);
    make_control(g_options_window, 0, L"STATIC", L"Imagem e exibição", WS_CHILD | WS_VISIBLE, 24, 22, 400, 30, -1, g_title_font);
    make_control(g_options_window, 0, L"STATIC", L"Resolução de saída", WS_CHILD | WS_VISIBLE, 28, 68, 190, 28, -1, g_font);
    g_resolution = make_control(g_options_window, 0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 230, 64, 300, 180, kResolution, g_font);
    for (const auto& option : kResolutions) SendMessageW(g_resolution, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(option.label));
    make_control(g_options_window, 0, L"STATIC", L"Resolução interna", WS_CHILD | WS_VISIBLE, 28, 112, 190, 28, -1, g_font);
    g_render_resolution = make_control(g_options_window, 0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 230, 108, 300, 180, kRenderResolution, g_font);
    for (const auto& option : kResolutions) SendMessageW(g_render_resolution, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(option.label));
    g_fsr_enabled = make_control(g_options_window, 0, L"BUTTON", L"Ativar FSR 1 (EASU + nitidez)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 28, 154, 360, 30, kFsrEnabled, g_font);
    make_control(g_options_window, 0, L"STATIC", L"Nitidez do FSR 1", WS_CHILD | WS_VISIBLE, 28, 194, 190, 28, -1, g_font);
    make_control(g_options_window, 0, L"STATIC", L"Sincronização de apresentação", WS_CHILD | WS_VISIBLE, 28, 248, 260, 28, -1, g_font);
    g_refresh = make_control(g_options_window, 0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 300, 244, 230, 100, kRefresh, g_font);
    SendMessageW(g_refresh, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"60 Hz"));
    SendMessageW(g_refresh, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"120 Hz"));
    g_fullscreen = make_control(g_options_window, 0, L"BUTTON", L"Tela cheia", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 28, 290, 260, 30, kFullscreen, g_font);
    g_pro_mode = make_control(g_options_window, 0, L"BUTTON", L"Modo PS4 Pro (experimental)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 28, 326, 340, 30, kProMode, g_font);
    g_show_fps = make_control(g_options_window, 0, L"BUTTON", L"Mostrar contador de FPS durante o jogo", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 28, 362, 430, 28, kShowFps, g_font);
    make_control(g_options_window, 0, L"STATIC", L"Volume do jogo", WS_CHILD | WS_VISIBLE, 28, 404, 190, 28, -1, g_font);
    make_control(g_options_window, 0, L"STATIC", L"A nitidez só tem efeito quando o FSR 1 está ativado.", WS_CHILD | WS_VISIBLE, 28, 498, 540, 28, -1, g_font);
    make_control(g_options_window, 0, L"STATIC", L"FSR 1 amplia quando a resolução interna é menor que a de saída.", WS_CHILD | WS_VISIBLE, 28, 526, 540, 28, -1, g_font);
    make_control(g_options_window, 0, L"BUTTON", L"Salvar e fechar", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 365, 558, 165, 38, kSaveOptions, g_font);
}

void create_users_window() {
    g_users_window = CreateWindowExW(WS_EX_DLGMODALFRAME, kUsersClass, L"Usuários — COURT 18",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 520, 370,
        g_window, nullptr, GetModuleHandleW(nullptr), nullptr);
    make_control(g_users_window, 0, L"STATIC", L"Perfil de usuário do jogo", WS_CHILD | WS_VISIBLE, 26, 24, 450, 30, -1, g_title_font);
    make_control(g_users_window, 0, L"STATIC", L"Perfil ativo", WS_CHILD | WS_VISIBLE, 28, 78, 150, 28, -1, g_font);
    g_user_profile = make_control(g_users_window, 0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 180, 72, 300, 180, kUserProfile, g_font);
    make_control(g_users_window, 0, L"STATIC", L"Nome", WS_CHILD | WS_VISIBLE, 28, 124, 120, 28, -1, g_font);
    g_user_name = make_control(g_users_window, 0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 180, 118, 300, 34, kUserName, g_font);
    const int create_w = button_text_width(L"Criar novo", g_button_font, 22);
    const int rename_w = button_text_width(L"Renomear", g_button_font, 22);
    const int delete_w = button_text_width(L"Excluir", g_button_font, 22);
    int user_button_x = 180;
    make_control(g_users_window, 0, L"BUTTON", L"Criar novo", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, user_button_x, 168, create_w, 36, kCreateUser, g_font);
    user_button_x += create_w + 8;
    make_control(g_users_window, 0, L"BUTTON", L"Renomear", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, user_button_x, 168, rename_w, 36, kRenameUser, g_font);
    user_button_x += rename_w + 8;
    make_control(g_users_window, 0, L"BUTTON", L"Excluir", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, user_button_x, 168, delete_w, 36, kDeleteUser, g_font);
    make_control(g_users_window, 0, L"STATIC", L"Perfil principal protegido; excluir apaga saves e configs.", WS_CHILD | WS_VISIBLE, 28, 218, 450, 26, -1, g_font);
    const int use_profile_w = button_text_width(L"Usar perfil", g_button_font, 28);
    make_control(g_users_window, 0, L"BUTTON", L"Usar perfil", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 480 - use_profile_w, 246, use_profile_w, 36, kSaveUsers, g_font);
    refresh_user_controls(g_selected_user_id);
}

LRESULT CALLBACK options_window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_COMMAND && LOWORD(wparam) == kFsrEnabled) {
        InvalidateRect(window, nullptr, FALSE);
        return 0;
    }
    if (message == WM_COMMAND && LOWORD(wparam) == kSaveOptions) {
        g_resolution_index = std::clamp(static_cast<int>(SendMessageW(g_resolution, CB_GETCURSEL, 0, 0)), 0, 3);
        g_render_resolution_index = std::clamp(static_cast<int>(SendMessageW(g_render_resolution, CB_GETCURSEL, 0, 0)), 0, 3);
        g_fsr_enabled_value = SendMessageW(g_fsr_enabled, BM_GETCHECK, 0, 0) == BST_CHECKED;
        g_refresh_index = SendMessageW(g_refresh, CB_GETCURSEL, 0, 0) == 1 ? 1 : 0;
        g_fullscreen_value = SendMessageW(g_fullscreen, BM_GETCHECK, 0, 0) == BST_CHECKED;
        g_pro_mode_value = SendMessageW(g_pro_mode, BM_GETCHECK, 0, 0) == BST_CHECKED;
        g_show_fps_value = SendMessageW(g_show_fps, BM_GETCHECK, 0, 0) == BST_CHECKED;
        g_volume_value_saved = g_slider_value;
        std::error_code ec; std::filesystem::create_directories(g_launcher_ini.parent_path(), ec);
        WritePrivateProfileStringW(L"Launcher", L"Volume", std::to_wstring(g_volume_value_saved).c_str(), g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Launcher", L"Resolution", std::to_wstring(g_resolution_index).c_str(), g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Launcher", L"RenderResolution", std::to_wstring(g_render_resolution_index).c_str(), g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Launcher", L"Fsr1Enabled", g_fsr_enabled_value ? L"1" : L"0", g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Launcher", L"FsrSharpness", std::to_wstring(g_sharpness_value).c_str(), g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Launcher", L"ShowFps", g_show_fps_value ? L"1" : L"0", g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Launcher", L"RefreshRate", g_refresh_index ? L"120" : L"60", g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Launcher", L"Fullscreen", g_fullscreen_value ? L"1" : L"0", g_launcher_ini.c_str());
        WritePrivateProfileStringW(L"Launcher", L"ProMode", g_pro_mode_value ? L"1" : L"0", g_launcher_ini.c_str());
        ShowWindow(window, SW_HIDE);
        return 0;
    }
    if (message == WM_PAINT) {
        PAINTSTRUCT ps{}; HDC dc = BeginPaint(window, &ps); RECT rc{}; GetClientRect(window, &rc);
        FillRect(dc, &rc, g_panel_brush);
        constexpr int left = 230, right = 500;
        Graphics graphics(dc); graphics.SetSmoothingMode(SmoothingModeAntiAlias);
        Pen rail(Color(245, 235, 237, 240), 4.0f);
        Pen tick(Color(225, 225, 229, 234), 1.0f);
        SolidBrush thumb(Color(255, 0, 126, 210));
        const auto draw_slider = [&](int mid, int value, int minimum, int maximum, bool enabled) {
            if (!enabled) rail.SetColor(Color(110, 160, 163, 168));
            graphics.DrawLine(&rail, static_cast<REAL>(left), static_cast<REAL>(mid),
                              static_cast<REAL>(right), static_cast<REAL>(mid));
            for (int i = 0; i <= 6; ++i) {
                const REAL px = static_cast<REAL>(left) + static_cast<REAL>(right-left) * i / 6.0f;
                graphics.DrawLine(&tick, px, static_cast<REAL>(mid+12), px, static_cast<REAL>(mid+18));
            }
            const REAL thumb_x = static_cast<REAL>(left) + static_cast<REAL>(right-left) *
                (value-minimum) / static_cast<REAL>(maximum-minimum);
            Point points[] = {{static_cast<INT>(thumb_x-8),mid-16},{static_cast<INT>(thumb_x+8),mid-16},
                {static_cast<INT>(thumb_x+8),mid+5},{static_cast<INT>(thumb_x),mid+13},{static_cast<INT>(thumb_x-8),mid+5}};
            graphics.FillPolygon(&thumb, points, static_cast<INT>(std::size(points)));
            rail.SetColor(Color(245, 235, 237, 240));
        };
        const bool fsr_checked = SendMessageW(g_fsr_enabled, BM_GETCHECK, 0, 0) == BST_CHECKED;
        draw_slider(220, g_sharpness_value, 0, 100, fsr_checked);
        draw_slider(425, g_slider_value, 50, 150, true);
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(245,246,248));
        HFONT old = static_cast<HFONT>(SelectObject(dc,g_font));
        wchar_t value_text[24]{};
        swprintf_s(value_text,L"%d%%",g_sharpness_value); RECT sharpness_rect{510,202,570,232};
        DrawTextW(dc,value_text,-1,&sharpness_rect,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        swprintf_s(value_text,L"%d%%",g_slider_value); RECT volume_rect{510,407,570,437};
        DrawTextW(dc,value_text,-1,&volume_rect,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc,old); EndPaint(window,&ps); return 0;
    }
    if (message == WM_LBUTTONDOWN || message == WM_MOUSEMOVE || message == WM_LBUTTONUP) {
        const int mx=GET_X_LPARAM(lparam), my=GET_Y_LPARAM(lparam);
        if (message == WM_LBUTTONDOWN && mx >= 220 && mx <= 510 && my >= 200 && my <= 245 &&
            SendMessageW(g_fsr_enabled, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            g_drag_sharpness=true; SetCapture(window);
        } else if (message == WM_LBUTTONDOWN && mx >= 220 && mx <= 510 && my >= 405 && my <= 452) {
            g_drag_volume=true; SetCapture(window);
        }
        if ((g_drag_volume || g_drag_sharpness) && (message != WM_MOUSEMOVE || (wparam & MK_LBUTTON))) {
            if (g_drag_volume) g_slider_value=50+std::clamp(mx-230,0,270)*100/270;
            if (g_drag_sharpness) g_sharpness_value=std::clamp(mx-230,0,270)*100/270;
            update_volume_label();
            if (message == WM_LBUTTONUP) { g_drag_volume=false; g_drag_sharpness=false; ReleaseCapture(); }
            return 0;
        }
    }
    if (message == WM_CTLCOLORSTATIC || message == WM_CTLCOLOREDIT ||
        message == WM_CTLCOLORBTN || message == WM_CTLCOLORLISTBOX) {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetTextColor(dc, RGB(235, 237, 240)); SetBkColor(dc, RGB(24, 27, 31)); SetBkMode(dc, OPAQUE);
        return reinterpret_cast<LRESULT>(g_panel_brush);
    }
    if (message == WM_DRAWITEM) {
        auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
        if (draw && draw->CtlID == kSaveOptions) {
            draw_basketball_button(*draw); return TRUE;
        }
    }
    if (message == WM_CLOSE) { ShowWindow(window, SW_HIDE); return 0; }
    return DefWindowProcW(window, message, wparam, lparam);
}

LRESULT CALLBACK users_window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_COMMAND && LOWORD(wparam) == kUserProfile && HIWORD(wparam) == CBN_SELCHANGE) {
        const int selected_index = static_cast<int>(SendMessageW(g_user_profile, CB_GETCURSEL, 0, 0));
        if (selected_index >= 0 && static_cast<size_t>(selected_index) < g_user_profiles.size()) {
            SetWindowTextW(g_user_name, g_user_profiles[static_cast<size_t>(selected_index)].name.c_str());
            EnableWindow(GetDlgItem(window, kDeleteUser),
                         g_user_profiles[static_cast<size_t>(selected_index)].id != 0);
        }
        return 0;
    }
    if (message == WM_COMMAND && LOWORD(wparam) == kDeleteUser) {
        const int selected_index = static_cast<int>(SendMessageW(g_user_profile, CB_GETCURSEL, 0, 0));
        if (selected_index < 0 || static_cast<size_t>(selected_index) >= g_user_profiles.size())
            return 0;
        const int id = g_user_profiles[static_cast<size_t>(selected_index)].id;
        if (id == 0) {
            MessageBoxW(window, L"O perfil principal não pode ser excluído para proteger os saves existentes.",
                        L"Excluir perfil", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        const std::wstring confirm = L"Excluir o perfil \"" + g_user_profiles[static_cast<size_t>(selected_index)].name +
            L"\" e apagar permanentemente os saves e as configurações dele?\n\nEssa ação não pode ser desfeita.";
        if (MessageBoxW(window, confirm.c_str(), L"Confirmar exclusão", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
            return 0;

        const auto profile_dir = selected_save_base() / L"profiles" / (L"user-" + std::to_wstring(id));
        std::error_code ec;
        std::filesystem::remove_all(profile_dir, ec);
        if (ec) {
            MessageBoxW(window, (L"Não foi possível apagar os dados do perfil.\n\n" + profile_dir.wstring()).c_str(),
                        L"Excluir perfil", MB_OK | MB_ICONERROR);
            return 0;
        }
        g_user_profiles.erase(g_user_profiles.begin() + selected_index);
        if (g_selected_user_id == id) g_selected_user_id = 0;
        persist_user_profiles();
        refresh_user_controls(g_selected_user_id);
        InvalidateRect(g_window, nullptr, FALSE);
        return 0;
    }
    if (message == WM_COMMAND && (LOWORD(wparam) == kCreateUser || LOWORD(wparam) == kRenameUser)) {
        wchar_t text[128]{};
        GetWindowTextW(g_user_name, text, static_cast<int>(std::size(text)));
        const std::wstring name(text);
        if (!valid_profile_name(name)) {
            MessageBoxW(window, L"Digite um nome de 1 a 24 caracteres. Evite \\ / : * ? \" < > |.",
                        L"Perfil de usuário", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        const int selected_index = static_cast<int>(SendMessageW(g_user_profile, CB_GETCURSEL, 0, 0));
        if (LOWORD(wparam) == kCreateUser) {
            int next_id = 1;
            for (const auto& profile : g_user_profiles) next_id = std::max(next_id, profile.id + 1);
            g_user_profiles.push_back({next_id, name});
            g_selected_user_id = next_id;
        } else {
            if (selected_index < 0 || static_cast<size_t>(selected_index) >= g_user_profiles.size())
                return 0;
            g_selected_user_id = g_user_profiles[static_cast<size_t>(selected_index)].id;
            g_user_profiles[static_cast<size_t>(selected_index)].name = name;
        }
        persist_user_profiles();
        refresh_user_controls(g_selected_user_id);
        InvalidateRect(g_window, nullptr, FALSE);
        return 0;
    }
    if (message == WM_COMMAND && LOWORD(wparam) == kSaveUsers) {
        const int selected_index = static_cast<int>(SendMessageW(g_user_profile, CB_GETCURSEL, 0, 0));
        if (selected_index >= 0 && static_cast<size_t>(selected_index) < g_user_profiles.size())
            g_selected_user_id = g_user_profiles[static_cast<size_t>(selected_index)].id;
        persist_user_profiles();
        InvalidateRect(g_window, nullptr, FALSE);
        ShowWindow(window, SW_HIDE);
        return 0;
    }
    if (message == WM_CTLCOLORSTATIC || message == WM_CTLCOLOREDIT ||
        message == WM_CTLCOLORBTN || message == WM_CTLCOLORLISTBOX) {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetTextColor(dc, RGB(235, 237, 240)); SetBkColor(dc, RGB(24, 27, 31)); SetBkMode(dc, OPAQUE);
        return reinterpret_cast<LRESULT>(g_panel_brush);
    }
    if (message == WM_DRAWITEM) {
        auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
        if (draw && (draw->CtlID == kCreateUser || draw->CtlID == kRenameUser || draw->CtlID == kDeleteUser || draw->CtlID == kSaveUsers)) {
            draw_basketball_button(*draw); return TRUE;
        }
    }
    if (message == WM_CLOSE) { ShowWindow(window, SW_HIDE); return 0; }
    return DefWindowProcW(window, message, wparam, lparam);
}

void layout_main(HWND window) {
    RECT rc{}; GetClientRect(window, &rc); const int w = rc.right, h = rc.bottom;
    const int s = std::clamp(h * 100 / 862, 75, 125), x = 36 * s / 100;
    auto q = [s](int value) { return value * s / 100; };
    const int col = std::min(w - 2 * x, q(426));
    const int browse_w = button_text_width(L"Localizar…", g_button_font, 28);
    const int field_w = std::max(q(180), col - q(14 + browse_w));
    MoveWindow(g_path_edit, x, q(176), field_w, q(38), TRUE);
    MoveWindow(GetDlgItem(window, kBrowse), x + field_w + q(14), q(174), q(browse_w), q(38), TRUE);
    MoveWindow(g_save_base_edit, x, q(270), field_w, q(38), TRUE);
    MoveWindow(GetDlgItem(window, kBrowseSaveBase), x + field_w + q(14), q(268), q(browse_w), q(38), TRUE);
    const int saves_w = button_text_width(L"Pasta dos saves", g_button_font, 36);
    const int options_w = button_text_width(L"Opções", g_button_font, 36);
    MoveWindow(GetDlgItem(window, kSaves), x, q(590), q(saves_w), q(46), TRUE);
    MoveWindow(GetDlgItem(window, kOptions), x + q(saves_w + 18), q(590), q(options_w), q(46), TRUE);
    const int users_w = button_text_width(L"Usuários…", g_button_font, 28);
    MoveWindow(GetDlgItem(window, kUsers), x + q(264), q(510), q(users_w), q(36), TRUE);
}

void create_ui(HWND window) {
    g_window = window;
    load_user_profiles();
    g_font = CreateFontW(19, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_button_font = CreateFontW(17, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_title_font = CreateFontW(38, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_path_edit = make_control(window, 0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 34, 176, 500, 38, kPathEdit, g_font);
    make_control(window, 0, L"BUTTON", L"Localizar…", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 550, 174, 130, 42, kBrowse, g_font);
    g_save_base_edit = make_control(window, 0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 34, 270, 500, 38, kSaveBaseEdit, g_font);
    make_control(window, 0, L"BUTTON", L"Localizar…", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 550, 268, 130, 42, kBrowseSaveBase, g_font);
    make_control(window, 0, L"BUTTON", L"Pasta dos saves", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 34, 590, 218, 56, kSaves, g_font);
    make_control(window, 0, L"BUTTON", L"Opções", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 276, 590, 180, 56, kOptions, g_font);
    make_control(window, 0, L"BUTTON", L"Usuários…", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 300, 510, 132, 36, kUsers, g_font);
    create_options_window(); create_users_window(); load_preferences(); layout_main(window);
}

void paint_background(HWND window) {
    PAINTSTRUCT ps{}; HDC hdc = BeginPaint(window, &ps);
    RECT rc{}; GetClientRect(window, &rc); Graphics graphics(hdc);
    draw_launcher_backdrop(graphics, rc.right, rc.bottom, 0, 0, rc.right, rc.bottom);
    const int s = std::clamp(static_cast<int>(rc.bottom) * 100 / 862, 75, 125), x = 36 * s / 100;
    auto q = [s](int value) { return value * s / 100; };
    SetBkMode(hdc, TRANSPARENT);
    HFONT old_font = static_cast<HFONT>(SelectObject(hdc, g_title_font));
    SetTextColor(hdc, RGB(222, 186, 105)); RECT title{x, q(14), x + q(470), q(67)};
    DrawTextW(hdc, L"COURT 18", -1, &title, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, g_font); SetTextColor(hdc, RGB(188, 198, 207));
    auto draw_text = [&](const wchar_t* text, int top, int width, UINT flags = DT_LEFT) {
        RECT r{x, q(top), x + q(width), q(top + 30)}; DrawTextW(hdc, text, -1, &r, flags | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    };
    draw_text(L"V: 1.00-A — BETA", 74, 500);
    draw_text(L"Pasta do jogo (CUSA06321, CUSA06316 ou CUSA08562)", 132, 650);
    draw_text(L"Pasta-base dos saves", 226, 650);
    std::wstring used = L"Perfil: " + profile_name(g_selected_user_id) + L"  |  Saves: " + actual_save_path().wstring();
    draw_text(used.c_str(), 310, 510);
    SetBkMode(hdc, TRANSPARENT); SelectObject(hdc, g_font); SetTextColor(hdc, RGB(175, 188, 200));
    draw_text(L"Resolução, sincronização e volume ficam no menu Opções.", 410, 710);
    SetTextColor(hdc, RGB(176, 196, 206)); draw_text(g_status_text.c_str(), 460, 590);
    const int play_x = x + q(470), play_y = q(560), ball_size = q(116);
    if (g_play_ball_image && g_play_ball_image->GetLastStatus() == Ok)
        graphics.DrawImage(g_play_ball_image.get(), Rect(play_x + (q(150)-ball_size)/2, play_y+q(4), ball_size, ball_size));
    SetTextColor(hdc, RGB(255,255,255));
    RECT play_label{play_x, play_y+q(120), play_x+q(150), play_y+q(170)};
    DrawTextW(hdc, L"JOGAR", -1, &play_label, DT_CENTER | DT_TOP | DT_SINGLELINE);
    SelectObject(hdc, old_font);
    EndPaint(window, &ps);
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE: create_ui(window); return 0;
    case WM_PAINT: paint_background(window); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_SIZE:
        if (g_path_edit) { layout_main(window); InvalidateRect(window, nullptr, TRUE); }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case kBrowse: choose_game_folder(); return 0;
        case kBrowseSaveBase: choose_save_base(); return 0;
        case kLaunch: launch_game(); return 0;
        case kSaves: open_save_folder(); return 0;
        case kUsers:
            refresh_user_controls(g_selected_user_id);
            ShowWindow(g_users_window, SW_SHOW); SetForegroundWindow(g_users_window); return 0;
        case kSaveBaseEdit:
            if (HIWORD(wparam) == EN_CHANGE) InvalidateRect(window, nullptr, FALSE);
            break;
        case kOptions:
            ShowWindow(g_options_window, SW_SHOW); SetForegroundWindow(g_options_window); return 0;
        }
        break;
    case WM_LBUTTONUP: {
        RECT rc{}; GetClientRect(window,&rc);
        const int s=std::clamp(static_cast<int>(rc.bottom)*100/862,75,125), x=36*s/100;
        auto q=[s](int v){return v*s/100;};
        const int play_x=x+q(470), play_y=q(560), mx=GET_X_LPARAM(lparam), my=GET_Y_LPARAM(lparam);
        if (mx>=play_x && mx<=play_x+q(150) && my>=play_y && my<=play_y+q(175)) { launch_game(); return 0; }
        return 0;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = reinterpret_cast<HDC>(wparam); SetTextColor(dc, RGB(245, 246, 248));
        SetBkColor(dc, RGB(36, 40, 45)); return reinterpret_cast<LRESULT>(g_edit_brush);
    }
    case WM_DRAWITEM: {
        auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
        if (draw && (draw->CtlID == kBrowse || draw->CtlID == kBrowseSaveBase || draw->CtlID == kSaves || draw->CtlID == kOptions || draw->CtlID == kUsers)) {
            draw_basketball_button(*draw); return TRUE;
        }
        break;
    }
    case WM_DESTROY:
        if (g_ball_icon) DestroyIcon(g_ball_icon); if (g_font) DeleteObject(g_font);
        if (g_button_font) DeleteObject(g_button_font); if (g_title_font) DeleteObject(g_title_font);
        if (g_panel_brush) DeleteObject(g_panel_brush);
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int) {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_BAR_CLASSES}; InitCommonControlsEx(&controls);
    const HRESULT com_result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    GdiplusStartupInput gdiplus_input{}; if (GdiplusStartup(&g_gdiplus_token, &gdiplus_input, nullptr) != Ok) return 1;
    g_app_dir = module_directory(); g_launcher_ini = g_app_dir / L"user" / L"launcher.ini";
    g_background_image = std::make_unique<Bitmap>((g_app_dir / L"assets" / L"nba-live16-background-with-ball.jpg").c_str());
    g_play_ball_image = std::make_unique<Bitmap>((g_app_dir / L"assets" / L"court18-play-ball.png").c_str());
    g_button_leather_image = std::make_unique<Bitmap>((g_app_dir / L"assets" / L"nba-live16-button-leather.png").c_str());
    g_ball_icon = static_cast<HICON>(LoadImageW(nullptr, (g_app_dir / L"assets" / L"court18.ico").c_str(), IMAGE_ICON, 48, 48, LR_LOADFROMFILE));
    g_panel_brush = CreateSolidBrush(RGB(24, 27, 31));
    g_edit_brush = CreateSolidBrush(RGB(36, 40, 45));
    WNDCLASSEXW options_class{}; options_class.cbSize = sizeof(options_class); options_class.lpfnWndProc = options_window_proc;
    options_class.hInstance = instance; options_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    options_class.hbrBackground = g_panel_brush; options_class.lpszClassName = kOptionsClass;
    RegisterClassExW(&options_class);
    WNDCLASSEXW users_class{}; users_class.cbSize = sizeof(users_class); users_class.lpfnWndProc = users_window_proc;
    users_class.hInstance = instance; users_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    users_class.hbrBackground = g_panel_brush; users_class.lpszClassName = kUsersClass;
    RegisterClassExW(&users_class);
    WNDCLASSEXW klass{}; klass.cbSize = sizeof(klass); klass.lpfnWndProc = window_proc; klass.hInstance = instance;
    klass.hCursor = LoadCursorW(nullptr, IDC_ARROW); klass.hbrBackground = nullptr; klass.lpszClassName = kWindowClass;
    klass.hIcon = g_ball_icon ? g_ball_icon : LoadIconW(nullptr, IDI_APPLICATION);
    klass.hIconSm = klass.hIcon; if (!RegisterClassExW(&klass)) return 1;
    HWND window = CreateWindowExW(0, kWindowClass, L"COURT 18 — V: 1.00-A (BETA)", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1180, 820, nullptr, nullptr, instance, nullptr);
    if (!window) return 1;
    ShowWindow(window, SW_SHOWMAXIMIZED); UpdateWindow(window);
    MSG message{}; while (GetMessageW(&message, nullptr, 0, 0) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
    if (g_options_window) DestroyWindow(g_options_window);
    if (g_users_window) DestroyWindow(g_users_window);
    if (SUCCEEDED(com_result)) CoUninitialize(); GdiplusShutdown(g_gdiplus_token);
    return static_cast<int>(message.wParam);
}
