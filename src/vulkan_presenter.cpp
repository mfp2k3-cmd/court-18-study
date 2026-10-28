#include "vulkan_presenter.h"

#include <SDL3/SDL.h>
#include <SDL3/SDL_vulkan.h>
#include <vulkan/vulkan.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>
#include <utility>
#include <vector>

namespace nba16 {
namespace {

constexpr std::uint32_t frames_in_flight = 2;

std::string vk_error(const char* operation, VkResult result) {
    return std::string(operation) + " falhou (VkResult=" +
        std::to_string(static_cast<int>(result)) + ").";
}

struct QueueChoice {
    std::uint32_t graphics{};
    std::uint32_t present{};
    bool valid{};
};

QueueChoice find_queues(VkPhysicalDevice device, VkSurfaceKHR surface) {
    std::uint32_t count{};
    vkGetPhysicalDeviceQueueFamilyProperties(device, &count, nullptr);
    std::vector<VkQueueFamilyProperties> families(count);
    vkGetPhysicalDeviceQueueFamilyProperties(device, &count, families.data());
    QueueChoice choice{std::numeric_limits<std::uint32_t>::max(),
                       std::numeric_limits<std::uint32_t>::max(), false};
    for (std::uint32_t i = 0; i < count; ++i) {
        VkBool32 can_present{};
        if (vkGetPhysicalDeviceSurfaceSupportKHR(device, i, surface, &can_present) != VK_SUCCESS)
            continue;
        if ((families[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) != 0 &&
            choice.graphics == std::numeric_limits<std::uint32_t>::max())
            choice.graphics = i;
        if (can_present && choice.present == std::numeric_limits<std::uint32_t>::max())
            choice.present = i;
    }
    choice.valid = choice.graphics != std::numeric_limits<std::uint32_t>::max() &&
                   choice.present != std::numeric_limits<std::uint32_t>::max();
    return choice;
}

bool supports_swapchain(VkPhysicalDevice device) {
    std::uint32_t count{};
    if (vkEnumerateDeviceExtensionProperties(device, nullptr, &count, nullptr) != VK_SUCCESS)
        return false;
    std::vector<VkExtensionProperties> extensions(count);
    if (vkEnumerateDeviceExtensionProperties(device, nullptr, &count,
            extensions.data()) != VK_SUCCESS) return false;
    return std::any_of(extensions.begin(), extensions.end(), [](const auto& extension) {
        return std::string_view(extension.extensionName) == VK_KHR_SWAPCHAIN_EXTENSION_NAME;
    });
}

} // namespace

struct VulkanPresenter::State {
    struct Frame {
        VkCommandBuffer command{};
        VkSemaphore acquired{};
        VkSemaphore rendered{};
        VkFence fence{};
        VkBuffer upload_buffer{};
        VkDeviceMemory upload_memory{};
        void* upload_mapping{};
        VkDeviceSize upload_capacity{};
        bool upload_coherent{};
    };

    SDL_Window* window{};
    VkInstance instance{};
    VkSurfaceKHR surface{};
    VkPhysicalDevice physical{};
    VkDevice device{};
    VkQueue graphics_queue{};
    VkQueue present_queue{};
    VkCommandPool command_pool{};
    VkSwapchainKHR swapchain{};
    VkFormat format{};
    VkExtent2D extent{};
    std::vector<VkImage> images;
    std::vector<bool> initialized_images;
    std::vector<VkFence> image_fences;
    std::array<Frame, frames_in_flight> frames{};
    std::uint32_t frame_index{};
    std::uint32_t graphics_family{};
    std::uint32_t present_family{};
    bool sdl_initialized{};

    void destroy_upload(Frame& frame) noexcept {
        if (device == VK_NULL_HANDLE) return;
        if (frame.upload_mapping != nullptr && frame.upload_memory != VK_NULL_HANDLE)
            vkUnmapMemory(device, frame.upload_memory);
        if (frame.upload_buffer != VK_NULL_HANDLE)
            vkDestroyBuffer(device, frame.upload_buffer, nullptr);
        if (frame.upload_memory != VK_NULL_HANDLE)
            vkFreeMemory(device, frame.upload_memory, nullptr);
        frame.upload_buffer = VK_NULL_HANDLE;
        frame.upload_memory = VK_NULL_HANDLE;
        frame.upload_mapping = nullptr;
        frame.upload_capacity = 0;
        frame.upload_coherent = false;
    }

    bool ensure_upload_capacity(Frame& frame, VkDeviceSize size, std::string& error) {
        if (frame.upload_capacity >= size) return true;
        destroy_upload(frame);

        VkBufferCreateInfo buffer_info{};
        buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        buffer_info.size = size;
        buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        auto result = vkCreateBuffer(device, &buffer_info, nullptr, &frame.upload_buffer);
        if (result != VK_SUCCESS) {
            error = vk_error("Criar buffer de pixels", result);
            return false;
        }

        VkMemoryRequirements requirements{};
        vkGetBufferMemoryRequirements(device, frame.upload_buffer, &requirements);
        VkPhysicalDeviceMemoryProperties properties{};
        vkGetPhysicalDeviceMemoryProperties(physical, &properties);
        std::uint32_t selected_type = std::numeric_limits<std::uint32_t>::max();
        std::uint32_t visible_fallback = std::numeric_limits<std::uint32_t>::max();
        for (std::uint32_t i = 0; i < properties.memoryTypeCount; ++i) {
            if ((requirements.memoryTypeBits & (1U << i)) == 0) continue;
            const auto flags = properties.memoryTypes[i].propertyFlags;
            if ((flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) continue;
            if (visible_fallback == std::numeric_limits<std::uint32_t>::max())
                visible_fallback = i;
            if ((flags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0) {
                selected_type = i;
                break;
            }
        }
        if (selected_type == std::numeric_limits<std::uint32_t>::max())
            selected_type = visible_fallback;
        if (selected_type == std::numeric_limits<std::uint32_t>::max()) {
            error = "A GPU não oferece memória visível à CPU para enviar pixels.";
            destroy_upload(frame);
            return false;
        }
        frame.upload_coherent = (properties.memoryTypes[selected_type].propertyFlags &
                                 VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0;

        VkMemoryAllocateInfo allocation{};
        allocation.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        allocation.allocationSize = requirements.size;
        allocation.memoryTypeIndex = selected_type;
        result = vkAllocateMemory(device, &allocation, nullptr, &frame.upload_memory);
        if (result == VK_SUCCESS)
            result = vkBindBufferMemory(device, frame.upload_buffer, frame.upload_memory, 0);
        if (result == VK_SUCCESS)
            result = vkMapMemory(device, frame.upload_memory, 0, VK_WHOLE_SIZE, 0,
                                 &frame.upload_mapping);
        if (result != VK_SUCCESS) {
            error = vk_error("Reservar memória para pixels", result);
            destroy_upload(frame);
            return false;
        }
        frame.upload_capacity = requirements.size;
        return true;
    }

    void destroy_swapchain() noexcept {
        if (swapchain != VK_NULL_HANDLE && device != VK_NULL_HANDLE)
            vkDestroySwapchainKHR(device, swapchain, nullptr);
        swapchain = VK_NULL_HANDLE;
        images.clear();
        initialized_images.clear();
        image_fences.clear();
    }

    bool create_swapchain(std::string& error) {
        VkSurfaceCapabilitiesKHR caps{};
        auto result = vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physical, surface, &caps);
        if (result != VK_SUCCESS) { error = vk_error("Consultar capacidades da janela", result); return false; }
        if ((caps.supportedUsageFlags & VK_IMAGE_USAGE_TRANSFER_DST_BIT) == 0) {
            error = "A superfície Vulkan não aceita imagens de destino para apresentação.";
            return false;
        }

        std::uint32_t format_count{};
        result = vkGetPhysicalDeviceSurfaceFormatsKHR(physical, surface, &format_count, nullptr);
        if (result != VK_SUCCESS || format_count == 0) {
            error = result == VK_SUCCESS ? "A superfície Vulkan não oferece formatos de imagem."
                                         : vk_error("Consultar formatos da janela", result);
            return false;
        }
        std::vector<VkSurfaceFormatKHR> formats(format_count);
        result = vkGetPhysicalDeviceSurfaceFormatsKHR(physical, surface, &format_count,
                                                       formats.data());
        if (result != VK_SUCCESS) { error = vk_error("Ler formatos da janela", result); return false; }
        auto selected = formats.front();
        for (const auto& candidate : formats) {
            if (candidate.format == VK_FORMAT_B8G8R8A8_UNORM &&
                candidate.colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR) {
                selected = candidate;
                break;
            }
        }

        int pixel_width{}, pixel_height{};
        SDL_GetWindowSizeInPixels(window, &pixel_width, &pixel_height);
        if (pixel_width <= 0 || pixel_height <= 0) {
            error = "A janela está minimizada ou sem área de apresentação.";
            return false;
        }
        if (caps.currentExtent.width != std::numeric_limits<std::uint32_t>::max()) {
            extent = caps.currentExtent;
        } else {
            extent.width = std::clamp(static_cast<std::uint32_t>(pixel_width),
                                      caps.minImageExtent.width, caps.maxImageExtent.width);
            extent.height = std::clamp(static_cast<std::uint32_t>(pixel_height),
                                       caps.minImageExtent.height, caps.maxImageExtent.height);
        }
        const auto desired_count = std::max(caps.minImageCount, frames_in_flight);
        const auto image_count = caps.maxImageCount == 0
            ? desired_count : std::min(desired_count, caps.maxImageCount);
        const std::array<std::uint32_t, 2> queue_indices{graphics_family, present_family};
        VkSwapchainCreateInfoKHR create{};
        create.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
        create.surface = surface;
        create.minImageCount = image_count;
        create.imageFormat = selected.format;
        create.imageColorSpace = selected.colorSpace;
        create.imageExtent = extent;
        create.imageArrayLayers = 1;
        create.imageUsage = VK_IMAGE_USAGE_TRANSFER_DST_BIT;
        create.imageSharingMode = graphics_family == present_family
            ? VK_SHARING_MODE_EXCLUSIVE : VK_SHARING_MODE_CONCURRENT;
        create.queueFamilyIndexCount = graphics_family == present_family ? 0U : 2U;
        create.pQueueFamilyIndices = graphics_family == present_family ? nullptr : queue_indices.data();
        create.preTransform = caps.currentTransform;
        constexpr std::array<VkCompositeAlphaFlagBitsKHR, 4> alpha_modes{
            VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
            VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR,
            VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR,
            VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR};
        const auto alpha = std::find_if(alpha_modes.begin(), alpha_modes.end(),
            [&caps](const auto mode) { return (caps.supportedCompositeAlpha & mode) != 0; });
        if (alpha == alpha_modes.end()) {
            error = "A superfície Vulkan não oferece modo de composição compatível.";
            return false;
        }
        create.compositeAlpha = *alpha;
        create.presentMode = VK_PRESENT_MODE_FIFO_KHR;
        create.clipped = VK_TRUE;
        result = vkCreateSwapchainKHR(device, &create, nullptr, &swapchain);
        if (result != VK_SUCCESS) { error = vk_error("Criar swapchain", result); return false; }
        format = selected.format;
        std::uint32_t actual_count{};
        result = vkGetSwapchainImagesKHR(device, swapchain, &actual_count, nullptr);
        if (result != VK_SUCCESS || actual_count == 0) {
            error = result == VK_SUCCESS ? "A swapchain não retornou imagens."
                                         : vk_error("Consultar imagens da swapchain", result);
            return false;
        }
        images.resize(actual_count);
        result = vkGetSwapchainImagesKHR(device, swapchain, &actual_count, images.data());
        if (result != VK_SUCCESS) { error = vk_error("Ler imagens da swapchain", result); return false; }
        initialized_images.assign(images.size(), false);
        image_fences.assign(images.size(), VK_NULL_HANDLE);
        return true;
    }

    bool recreate_swapchain(std::string& error) {
        int width{}, height{};
        SDL_GetWindowSizeInPixels(window, &width, &height);
        if (width <= 0 || height <= 0) return true;
        const auto result = vkDeviceWaitIdle(device);
        if (result != VK_SUCCESS) { error = vk_error("Aguardar GPU antes do resize", result); return false; }
        destroy_swapchain();
        return create_swapchain(error);
    }
};

VulkanPresenter::VulkanPresenter() : state_(std::make_unique<State>()) {}
VulkanPresenter::~VulkanPresenter() { shutdown(); }
VulkanPresenter::VulkanPresenter(VulkanPresenter&&) noexcept = default;
VulkanPresenter& VulkanPresenter::operator=(VulkanPresenter&& other) noexcept {
    if (this == &other) return *this;
    shutdown();
    state_ = std::move(other.state_);
    return *this;
}

bool VulkanPresenter::create(const char* title, std::uint32_t width, std::uint32_t height,
                             std::string& error) {
    shutdown();
    state_ = std::make_unique<State>();
    auto& state = *state_;
    if (!SDL_Init(SDL_INIT_VIDEO)) { error = SDL_GetError(); return false; }
    state.sdl_initialized = true;
    state.window = SDL_CreateWindow(title, static_cast<int>(width), static_cast<int>(height),
        SDL_WINDOW_VULKAN | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY);
    if (state.window == nullptr) { error = SDL_GetError(); shutdown(); return false; }

    Uint32 extension_count{};
    const auto* extensions = SDL_Vulkan_GetInstanceExtensions(&extension_count);
    if (extensions == nullptr || extension_count == 0) {
        error = SDL_GetError(); shutdown(); return false;
    }
    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = title;
    app.applicationVersion = VK_MAKE_API_VERSION(0, 1, 0, 0);
    app.pEngineName = "NBA LIVE 18 Experimental Runtime";
    app.engineVersion = VK_MAKE_API_VERSION(0, 1, 0, 0);
    app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo instance_info{};
    instance_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instance_info.pApplicationInfo = &app;
    instance_info.enabledExtensionCount = extension_count;
    instance_info.ppEnabledExtensionNames = extensions;
    auto result = vkCreateInstance(&instance_info, nullptr, &state.instance);
    if (result != VK_SUCCESS) { error = vk_error("Criar instância Vulkan", result); shutdown(); return false; }
    if (!SDL_Vulkan_CreateSurface(state.window, state.instance, nullptr, &state.surface)) {
        error = SDL_GetError(); shutdown(); return false;
    }

    std::uint32_t device_count{};
    result = vkEnumeratePhysicalDevices(state.instance, &device_count, nullptr);
    if (result != VK_SUCCESS || device_count == 0) {
        error = result == VK_SUCCESS ? "Nenhuma GPU Vulkan disponível."
                                     : vk_error("Enumerar GPUs", result);
        shutdown(); return false;
    }
    std::vector<VkPhysicalDevice> devices(device_count);
    result = vkEnumeratePhysicalDevices(state.instance, &device_count, devices.data());
    if (result != VK_SUCCESS) { error = vk_error("Ler GPUs", result); shutdown(); return false; }
    for (const auto device : devices) {
        const auto queues = find_queues(device, state.surface);
        if (!queues.valid || !supports_swapchain(device)) continue;
        state.physical = device;
        state.graphics_family = queues.graphics;
        state.present_family = queues.present;
        break;
    }
    if (state.physical == VK_NULL_HANDLE) {
        error = "Nenhuma GPU oferece filas gráficas, apresentação e swapchain.";
        shutdown(); return false;
    }

    const float priority = 1.0F;
    std::vector<VkDeviceQueueCreateInfo> queue_infos;
    for (const auto family : {state.graphics_family, state.present_family}) {
        if (std::any_of(queue_infos.begin(), queue_infos.end(), [family](const auto& item) {
                return item.queueFamilyIndex == family;
            })) continue;
        VkDeviceQueueCreateInfo queue{};
        queue.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        queue.queueFamilyIndex = family;
        queue.queueCount = 1;
        queue.pQueuePriorities = &priority;
        queue_infos.push_back(queue);
    }
    constexpr const char* device_extensions[]{VK_KHR_SWAPCHAIN_EXTENSION_NAME};
    VkDeviceCreateInfo device_info{};
    device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_info.queueCreateInfoCount = static_cast<std::uint32_t>(queue_infos.size());
    device_info.pQueueCreateInfos = queue_infos.data();
    device_info.enabledExtensionCount = 1;
    device_info.ppEnabledExtensionNames = device_extensions;
    result = vkCreateDevice(state.physical, &device_info, nullptr, &state.device);
    if (result != VK_SUCCESS) { error = vk_error("Criar dispositivo Vulkan", result); shutdown(); return false; }
    vkGetDeviceQueue(state.device, state.graphics_family, 0, &state.graphics_queue);
    vkGetDeviceQueue(state.device, state.present_family, 0, &state.present_queue);

    VkCommandPoolCreateInfo pool{};
    pool.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    pool.queueFamilyIndex = state.graphics_family;
    result = vkCreateCommandPool(state.device, &pool, nullptr, &state.command_pool);
    if (result != VK_SUCCESS) { error = vk_error("Criar pool de comandos", result); shutdown(); return false; }
    std::array<VkCommandBuffer, frames_in_flight> commands{};
    VkCommandBufferAllocateInfo allocation{};
    allocation.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocation.commandPool = state.command_pool;
    allocation.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocation.commandBufferCount = frames_in_flight;
    result = vkAllocateCommandBuffers(state.device, &allocation, commands.data());
    if (result != VK_SUCCESS) { error = vk_error("Alocar comandos", result); shutdown(); return false; }
    for (std::uint32_t i = 0; i < frames_in_flight; ++i) {
        state.frames[i].command = commands[i];
        VkSemaphoreCreateInfo semaphore{};
        semaphore.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
        result = vkCreateSemaphore(state.device, &semaphore, nullptr, &state.frames[i].acquired);
        if (result == VK_SUCCESS)
            result = vkCreateSemaphore(state.device, &semaphore, nullptr, &state.frames[i].rendered);
        if (result != VK_SUCCESS) { error = vk_error("Criar semáforo", result); shutdown(); return false; }
        VkFenceCreateInfo fence{};
        fence.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        fence.flags = VK_FENCE_CREATE_SIGNALED_BIT;
        result = vkCreateFence(state.device, &fence, nullptr, &state.frames[i].fence);
        if (result != VK_SUCCESS) { error = vk_error("Criar fence", result); shutdown(); return false; }
    }
    if (!state.create_swapchain(error)) { shutdown(); return false; }
    error.clear();
    return true;
}

bool VulkanPresenter::poll_events(bool& should_close, std::string& error) {
    if (!state_ || state_->window == nullptr) { error = "A janela Vulkan não foi criada."; return false; }
    SDL_Event event{};
    while (SDL_PollEvent(&event)) {
        if (event.type == SDL_EVENT_QUIT ||
            (event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED &&
             event.window.windowID == SDL_GetWindowID(state_->window))) should_close = true;
    }
    error.clear();
    return true;
}

bool VulkanPresenter::present_clear(const std::array<float, 4>& color, std::string& error) {
    if (!state_ || state_->swapchain == VK_NULL_HANDLE) { error = "A swapchain não foi criada."; return false; }
    auto& state = *state_;
    auto& frame = state.frames[state.frame_index];
    auto result = vkWaitForFences(state.device, 1, &frame.fence, VK_TRUE, UINT64_MAX);
    if (result != VK_SUCCESS) { error = vk_error("Aguardar frame anterior", result); return false; }
    std::uint32_t image_index{};
    result = vkAcquireNextImageKHR(state.device, state.swapchain, UINT64_MAX,
                                  frame.acquired, VK_NULL_HANDLE, &image_index);
    if (result == VK_ERROR_OUT_OF_DATE_KHR) return state.recreate_swapchain(error);
    if (result != VK_SUCCESS && result != VK_SUBOPTIMAL_KHR) {
        error = vk_error("Adquirir imagem", result); return false;
    }
    if (state.image_fences[image_index] != VK_NULL_HANDLE) {
        result = vkWaitForFences(state.device, 1, &state.image_fences[image_index],
                                 VK_TRUE, UINT64_MAX);
        if (result != VK_SUCCESS) { error = vk_error("Aguardar imagem", result); return false; }
    }
    state.image_fences[image_index] = frame.fence;
    result = vkResetFences(state.device, 1, &frame.fence);
    if (result != VK_SUCCESS) { error = vk_error("Reiniciar fence", result); return false; }
    result = vkResetCommandBuffer(frame.command, 0);
    if (result != VK_SUCCESS) { error = vk_error("Reiniciar comandos", result); return false; }
    VkCommandBufferBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    result = vkBeginCommandBuffer(frame.command, &begin);
    if (result != VK_SUCCESS) { error = vk_error("Iniciar comandos", result); return false; }
    VkImageMemoryBarrier to_transfer{};
    to_transfer.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    to_transfer.srcAccessMask = 0;
    to_transfer.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    to_transfer.oldLayout = state.initialized_images[image_index]
        ? VK_IMAGE_LAYOUT_PRESENT_SRC_KHR : VK_IMAGE_LAYOUT_UNDEFINED;
    to_transfer.newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    to_transfer.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_transfer.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_transfer.image = state.images[image_index];
    to_transfer.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
    vkCmdPipelineBarrier(frame.command, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
        VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, nullptr, 0, nullptr, 1, &to_transfer);
    VkClearColorValue clear{};
    std::copy(color.begin(), color.end(), clear.float32);
    VkImageSubresourceRange range{VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
    vkCmdClearColorImage(frame.command, state.images[image_index],
        VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, &clear, 1, &range);
    VkImageMemoryBarrier to_present = to_transfer;
    to_present.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    to_present.dstAccessMask = 0;
    to_present.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    to_present.newLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
    vkCmdPipelineBarrier(frame.command, VK_PIPELINE_STAGE_TRANSFER_BIT,
        VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, 0, 0, nullptr, 0, nullptr, 1, &to_present);
    result = vkEndCommandBuffer(frame.command);
    if (result != VK_SUCCESS) { error = vk_error("Finalizar comandos", result); return false; }
    const VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.waitSemaphoreCount = 1;
    submit.pWaitSemaphores = &frame.acquired;
    submit.pWaitDstStageMask = &wait_stage;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &frame.command;
    submit.signalSemaphoreCount = 1;
    submit.pSignalSemaphores = &frame.rendered;
    result = vkQueueSubmit(state.graphics_queue, 1, &submit, frame.fence);
    if (result != VK_SUCCESS) { error = vk_error("Enviar frame à GPU", result); return false; }
    VkPresentInfoKHR present{};
    present.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    present.waitSemaphoreCount = 1;
    present.pWaitSemaphores = &frame.rendered;
    present.swapchainCount = 1;
    present.pSwapchains = &state.swapchain;
    present.pImageIndices = &image_index;
    result = vkQueuePresentKHR(state.present_queue, &present);
    state.initialized_images[image_index] = true;
    state.frame_index = (state.frame_index + 1U) % frames_in_flight;
    if (result == VK_ERROR_OUT_OF_DATE_KHR || result == VK_SUBOPTIMAL_KHR)
        return state.recreate_swapchain(error);
    if (result != VK_SUCCESS) { error = vk_error("Apresentar frame", result); return false; }
    error.clear();
    return true;
}

bool VulkanPresenter::present_rgba8(std::span<const std::byte> pixels,
                                    std::uint32_t width, std::uint32_t height,
                                    std::uint32_t pitch, std::string& error) {
    return present_4byte_pixels(pixels, width, height, pitch, false, error);
}

bool VulkanPresenter::present_bgra8(std::span<const std::byte> pixels,
                                    std::uint32_t width, std::uint32_t height,
                                    std::uint32_t pitch, std::string& error) {
    return present_4byte_pixels(pixels, width, height, pitch, true, error);
}

bool VulkanPresenter::present_4byte_pixels(std::span<const std::byte> pixels,
                                            std::uint32_t width, std::uint32_t height,
                                            std::uint32_t pitch, bool source_bgra,
                                            std::string& error) {
    if (!state_ || state_->swapchain == VK_NULL_HANDLE) {
        error = "A swapchain não foi criada.";
        return false;
    }
    auto& state = *state_;
    if (width == 0 || height == 0 || width != state.extent.width ||
        height != state.extent.height) {
        error = "O tamanho do buffer precisa corresponder à área atual da janela.";
        return false;
    }
    const bool destination_bgra = state.format == VK_FORMAT_B8G8R8A8_UNORM ||
                                  state.format == VK_FORMAT_B8G8R8A8_SRGB;
    const bool destination_rgba = state.format == VK_FORMAT_R8G8B8A8_UNORM ||
                                  state.format == VK_FORMAT_R8G8B8A8_SRGB;
    if (!destination_bgra && !destination_rgba) {
        error = "O formato da swapchain não é RGBA8 nem BGRA8.";
        return false;
    }
    const auto row_bytes = static_cast<std::uint64_t>(width) * 4U;
    if (pitch < row_bytes) {
        error = "O pitch do buffer de pixels é menor que uma linha RGBA8.";
        return false;
    }
    constexpr auto max_size = std::numeric_limits<std::uint64_t>::max();
    const auto preceding_rows = static_cast<std::uint64_t>(height - 1U);
    if ((pitch != 0 && preceding_rows > (max_size - row_bytes) / pitch) ||
        (row_bytes != 0 && height > max_size / row_bytes)) {
        error = "As dimensões do buffer de pixels excedem o limite endereçável.";
        return false;
    }
    const auto required_input = preceding_rows * pitch + row_bytes;
    const auto upload_bytes = row_bytes * height;
    if (required_input > pixels.size() ||
        upload_bytes > std::numeric_limits<VkDeviceSize>::max()) {
        error = "O buffer de pixels não contém todas as linhas declaradas.";
        return false;
    }

    auto& frame = state.frames[state.frame_index];
    auto result = vkWaitForFences(state.device, 1, &frame.fence, VK_TRUE, UINT64_MAX);
    if (result != VK_SUCCESS) {
        error = vk_error("Aguardar frame anterior", result);
        return false;
    }
    if (!state.ensure_upload_capacity(frame, static_cast<VkDeviceSize>(upload_bytes), error))
        return false;

    auto* destination = static_cast<std::uint8_t*>(frame.upload_mapping);
    const bool swap_red_blue = source_bgra != destination_bgra;
    for (std::uint32_t y = 0; y < height; ++y) {
        const auto* source_row = pixels.data() + static_cast<std::size_t>(y) * pitch;
        auto* destination_row = destination + static_cast<std::size_t>(y * row_bytes);
        if (!swap_red_blue) {
            std::memcpy(destination_row, source_row, static_cast<std::size_t>(row_bytes));
            continue;
        }
        for (std::uint32_t x = 0; x < width; ++x) {
            const auto source_pixel = source_row + static_cast<std::size_t>(x) * 4U;
            auto* destination_pixel = destination_row + static_cast<std::size_t>(x) * 4U;
            destination_pixel[0] = std::to_integer<std::uint8_t>(source_pixel[2]);
            destination_pixel[1] = std::to_integer<std::uint8_t>(source_pixel[1]);
            destination_pixel[2] = std::to_integer<std::uint8_t>(source_pixel[0]);
            destination_pixel[3] = std::to_integer<std::uint8_t>(source_pixel[3]);
        }
    }
    if (!frame.upload_coherent) {
        VkMappedMemoryRange flush{};
        flush.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
        flush.memory = frame.upload_memory;
        flush.offset = 0;
        flush.size = VK_WHOLE_SIZE;
        result = vkFlushMappedMemoryRanges(state.device, 1, &flush);
        if (result != VK_SUCCESS) {
            error = vk_error("Sincronizar pixels com a GPU", result);
            return false;
        }
    }

    std::uint32_t image_index{};
    result = vkAcquireNextImageKHR(state.device, state.swapchain, UINT64_MAX,
                                   frame.acquired, VK_NULL_HANDLE, &image_index);
    if (result == VK_ERROR_OUT_OF_DATE_KHR) return state.recreate_swapchain(error);
    if (result != VK_SUCCESS && result != VK_SUBOPTIMAL_KHR) {
        error = vk_error("Adquirir imagem", result);
        return false;
    }
    if (state.image_fences[image_index] != VK_NULL_HANDLE) {
        result = vkWaitForFences(state.device, 1, &state.image_fences[image_index],
                                 VK_TRUE, UINT64_MAX);
        if (result != VK_SUCCESS) {
            error = vk_error("Aguardar imagem", result);
            return false;
        }
    }
    state.image_fences[image_index] = frame.fence;
    result = vkResetCommandBuffer(frame.command, 0);
    if (result != VK_SUCCESS) {
        error = vk_error("Reiniciar comandos", result);
        return false;
    }
    VkCommandBufferBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    result = vkBeginCommandBuffer(frame.command, &begin);
    if (result != VK_SUCCESS) {
        error = vk_error("Iniciar comandos", result);
        return false;
    }

    VkImageMemoryBarrier to_transfer{};
    to_transfer.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    to_transfer.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    to_transfer.oldLayout = state.initialized_images[image_index]
        ? VK_IMAGE_LAYOUT_PRESENT_SRC_KHR : VK_IMAGE_LAYOUT_UNDEFINED;
    to_transfer.newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    to_transfer.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_transfer.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    to_transfer.image = state.images[image_index];
    to_transfer.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
    vkCmdPipelineBarrier(frame.command, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
                         VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, nullptr, 0, nullptr,
                         1, &to_transfer);

    VkBufferImageCopy copy{};
    copy.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1};
    copy.imageExtent = {width, height, 1};
    vkCmdCopyBufferToImage(frame.command, frame.upload_buffer, state.images[image_index],
                           VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &copy);

    auto to_present = to_transfer;
    to_present.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    to_present.dstAccessMask = 0;
    to_present.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    to_present.newLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
    vkCmdPipelineBarrier(frame.command, VK_PIPELINE_STAGE_TRANSFER_BIT,
                         VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, 0, 0, nullptr, 0, nullptr,
                         1, &to_present);
    result = vkEndCommandBuffer(frame.command);
    if (result != VK_SUCCESS) {
        error = vk_error("Finalizar comandos", result);
        return false;
    }
    result = vkResetFences(state.device, 1, &frame.fence);
    if (result != VK_SUCCESS) {
        error = vk_error("Reiniciar fence", result);
        return false;
    }
    const VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.waitSemaphoreCount = 1;
    submit.pWaitSemaphores = &frame.acquired;
    submit.pWaitDstStageMask = &wait_stage;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &frame.command;
    submit.signalSemaphoreCount = 1;
    submit.pSignalSemaphores = &frame.rendered;
    result = vkQueueSubmit(state.graphics_queue, 1, &submit, frame.fence);
    if (result != VK_SUCCESS) {
        error = vk_error("Enviar pixels à GPU", result);
        return false;
    }
    VkPresentInfoKHR present{};
    present.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    present.waitSemaphoreCount = 1;
    present.pWaitSemaphores = &frame.rendered;
    present.swapchainCount = 1;
    present.pSwapchains = &state.swapchain;
    present.pImageIndices = &image_index;
    result = vkQueuePresentKHR(state.present_queue, &present);
    state.initialized_images[image_index] = true;
    state.frame_index = (state.frame_index + 1U) % frames_in_flight;
    if (result == VK_ERROR_OUT_OF_DATE_KHR || result == VK_SUBOPTIMAL_KHR)
        return state.recreate_swapchain(error);
    if (result != VK_SUCCESS) {
        error = vk_error("Apresentar pixels", result);
        return false;
    }
    error.clear();
    return true;
}

void VulkanPresenter::shutdown() noexcept {
    if (!state_) return;
    auto& state = *state_;
    if (state.device != VK_NULL_HANDLE) {
        (void)vkDeviceWaitIdle(state.device);
        state.destroy_swapchain();
        for (auto& frame : state.frames) {
            state.destroy_upload(frame);
            if (frame.fence != VK_NULL_HANDLE) vkDestroyFence(state.device, frame.fence, nullptr);
            if (frame.rendered != VK_NULL_HANDLE) vkDestroySemaphore(state.device, frame.rendered, nullptr);
            if (frame.acquired != VK_NULL_HANDLE) vkDestroySemaphore(state.device, frame.acquired, nullptr);
        }
        if (state.command_pool != VK_NULL_HANDLE)
            vkDestroyCommandPool(state.device, state.command_pool, nullptr);
        vkDestroyDevice(state.device, nullptr);
    }
    if (state.surface != VK_NULL_HANDLE && state.instance != VK_NULL_HANDLE)
        SDL_Vulkan_DestroySurface(state.instance, state.surface, nullptr);
    if (state.instance != VK_NULL_HANDLE) vkDestroyInstance(state.instance, nullptr);
    if (state.window != nullptr) SDL_DestroyWindow(state.window);
    if (state.sdl_initialized) SDL_Quit();
    state_.reset();
}

} // namespace nba16
