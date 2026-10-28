#include "native_window_host.h"

#include <SDL3/SDL_timer.h>

#include <array>
#include <cstdio>
#include <string>

int main() {
    nba16::NativeWindowHost host;
    std::string error;
    if (!host.initialize("NBA LIVE 18 — Port nativo", 1280, 720, error)) {
        std::fprintf(stderr, "Não foi possível iniciar a janela Vulkan: %s\n", error.c_str());
        return 1;
    }

    constexpr std::array<float, 4> background{0.055F, 0.063F, 0.075F, 1.0F};
    bool should_close = false;
    while (!should_close) {
        if (!host.pump_events(should_close, error)) {
            std::fprintf(stderr, "Falha ao processar eventos da janela: %s\n", error.c_str());
            return 1;
        }
        if (should_close) break;
        if (!host.present_clear(background, error)) {
            std::fprintf(stderr, "Falha ao apresentar a janela Vulkan: %s\n", error.c_str());
            return 1;
        }
        SDL_Delay(16);
    }
    return 0;
}
