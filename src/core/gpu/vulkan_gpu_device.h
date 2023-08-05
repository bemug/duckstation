// SPDX-FileCopyrightText: 2019-2022 Connor McLaughlin <stenzek@gmail.com>
// SPDX-License-Identifier: (GPL-3.0 OR CC-BY-NC-ND-4.0)

#pragma once
#include "common/timer.h"
#include "common/window_info.h"
#include "gpu_device.h"
#include "postprocessing_chain.h"
#include "vulkan/loader.h"
#include "vulkan/stream_buffer.h"
#include "vulkan/swap_chain.h"
#include <memory>
#include <string_view>

namespace Vulkan {
class StreamBuffer;
class SwapChain;
} // namespace Vulkan

class VulkanGPUDevice final : public GPUDevice
{
public:
  VulkanGPUDevice();
  ~VulkanGPUDevice();

  RenderAPI GetRenderAPI() const override;

  bool HasSurface() const override;

  bool CreateDevice(const WindowInfo& wi, bool vsync) override;
  bool SetupDevice() override;

  bool MakeCurrent() override;
  bool DoneCurrent() override;

  bool ChangeWindow(const WindowInfo& new_wi) override;
  void ResizeWindow(s32 new_window_width, s32 new_window_height) override;
  bool SupportsFullscreen() const override;
  bool IsFullscreen() override;
  bool SetFullscreen(bool fullscreen, u32 width, u32 height, float refresh_rate) override;
  AdapterAndModeList GetAdapterAndModeList() override;
  void DestroySurface() override;

  bool SetPostProcessingChain(const std::string_view& config) override;

  std::unique_ptr<GPUTexture> CreateTexture(u32 width, u32 height, u32 layers, u32 levels, u32 samples,
                                            GPUTexture::Type type, GPUTexture::Format format, const void* data,
                                            u32 data_stride, bool dynamic = false) override;
  bool DownloadTexture(GPUTexture* texture, u32 x, u32 y, u32 width, u32 height, void* out_data,
                       u32 out_data_stride) override;
  bool SupportsTextureFormat(GPUTexture::Format format) const override;

  void SetVSync(bool enabled) override;

  //bool Render(bool skip_present) override;

  bool SetGPUTimingEnabled(bool enabled) override;
  float GetAndResetAccumulatedGPUTime() override;

  static AdapterAndModeList StaticGetAdapterAndModeList(const WindowInfo* wi);

protected:
  struct PushConstants
  {
    float src_rect_left;
    float src_rect_top;
    float src_rect_width;
    float src_rect_height;
  };

  VkRenderPass GetRenderPassForDisplay() const;

  bool CheckStagingBufferSize(u32 required_size);
  void DestroyStagingBuffer();

  bool CreateResources() override;
  void DestroyResources() override;

  void BeginSwapChainRenderPass(VkFramebuffer framebuffer, u32 width, u32 height);
  void RenderDisplay();
  void RenderImGui();
  void RenderSoftwareCursor();

  void RenderDisplay(s32 left, s32 top, s32 width, s32 height, Vulkan::Texture* texture, s32 texture_view_x,
                     s32 texture_view_y, s32 texture_view_width, s32 texture_view_height, bool linear_filter);
  void RenderSoftwareCursor(s32 left, s32 top, s32 width, s32 height, GPUTexture* texture_handle);

  std::unique_ptr<Vulkan::SwapChain> m_swap_chain;

  VkDescriptorSetLayout m_descriptor_set_layout = VK_NULL_HANDLE;
  VkPipelineLayout m_pipeline_layout = VK_NULL_HANDLE;
  VkPipeline m_cursor_pipeline = VK_NULL_HANDLE;
  VkPipeline m_display_pipeline = VK_NULL_HANDLE;
  VkSampler m_point_sampler = VK_NULL_HANDLE;
  VkSampler m_linear_sampler = VK_NULL_HANDLE;
  VkSampler m_border_sampler = VK_NULL_HANDLE;

  VmaAllocation m_readback_staging_allocation = VK_NULL_HANDLE;
  VkBuffer m_readback_staging_buffer = VK_NULL_HANDLE;
  u8* m_readback_staging_buffer_map = nullptr;
  u32 m_readback_staging_buffer_size = 0;
  bool m_is_adreno = false;

  VkDescriptorSetLayout m_post_process_descriptor_set_layout = VK_NULL_HANDLE;
  VkDescriptorSetLayout m_post_process_ubo_descriptor_set_layout = VK_NULL_HANDLE;
  VkPipelineLayout m_post_process_pipeline_layout = VK_NULL_HANDLE;
  VkPipelineLayout m_post_process_ubo_pipeline_layout = VK_NULL_HANDLE;
};