// SPDX-FileCopyrightText: 2019-2023 Connor McLaughlin <stenzek@gmail.com>
// SPDX-License-Identifier: (GPL-3.0 OR CC-BY-NC-ND-4.0)

#include "gpu_device.h"
#include "../settings.h"
#include "../shadergen.h"
#include "postprocessing_chain.h"

#include "common/align.h"
#include "common/assert.h"
#include "common/file_system.h"
#include "common/hash_combine.h"
#include "common/log.h"
#include "common/path.h"
#include "common/string_util.h"
#include "common/timer.h"

#include "imgui.h"
#include "stb_image.h"
#include "stb_image_resize.h"
#include "stb_image_write.h"

#include <cerrno>
#include <cmath>
#include <cstring>
#include <thread>
#include <vector>

Log_SetChannel(GPUDevice);

#ifdef _WIN32
#include "common/windows_headers.h"
#include "d3d11_device.h"
#include "d3d12_gpu_device.h"
#endif

#ifdef WITH_OPENGL
#include "opengl_device.h"
#endif

#ifdef WITH_VULKAN
#include "vulkan_gpu_device.h"
#endif

// TODO: default sampler mode, create a persistent descriptor set in Vulkan for textures
// TODO: input layout => VAO in GL, buffer might change
// TODO: one big lookup table for render passes, or dynamic rendering

std::unique_ptr<GPUDevice> g_host_display;

GPUFramebuffer::GPUFramebuffer(GPUTexture* rt, GPUTexture* ds, u32 width, u32 height)
  : m_rt(rt), m_ds(ds), m_width(width), m_height(height)
{
}

GPUFramebuffer::~GPUFramebuffer() = default;

GPUSampler::GPUSampler() = default;

GPUSampler::~GPUSampler() = default;

GPUSampler::Config GPUSampler::GetNearestConfig()
{
  Config config = {};
  config.address_u = GPUSampler::AddressMode::ClampToEdge;
  config.address_v = GPUSampler::AddressMode::ClampToEdge;
  config.address_w = GPUSampler::AddressMode::ClampToEdge;
  config.min_filter = GPUSampler::Filter::Nearest;
  config.mag_filter = GPUSampler::Filter::Nearest;
  return config;
}

GPUSampler::Config GPUSampler::GetLinearConfig()
{
  Config config = {};
  config.address_u = GPUSampler::AddressMode::ClampToEdge;
  config.address_v = GPUSampler::AddressMode::ClampToEdge;
  config.address_w = GPUSampler::AddressMode::ClampToEdge;
  config.min_filter = GPUSampler::Filter::Linear;
  config.mag_filter = GPUSampler::Filter::Linear;
  return config;
}

GPUShader::GPUShader(GPUShaderStage stage) : m_stage(stage)
{
}

GPUShader::~GPUShader() = default;

const char* GPUShader::GetStageName(GPUShaderStage stage)
{
  switch (stage)
  {
    case GPUShaderStage::Vertex:
      return "Vertex";
    case GPUShaderStage::Fragment:
      return "Fragment";
    case GPUShaderStage::Compute:
      return "Compute";
    default:
      UnreachableCode();
      return "";
  }
}

GPUPipeline::GPUPipeline() = default;

GPUPipeline::~GPUPipeline() = default;

size_t GPUPipeline::InputLayoutHash::operator()(const InputLayout& il) const
{
  std::size_t h = 0;
  hash_combine(h, il.vertex_attributes.size(), il.vertex_stride);

  for (const VertexAttribute& va : il.vertex_attributes)
    hash_combine(h, va.key);

  return h;
}

bool GPUPipeline::InputLayout::operator==(const InputLayout& rhs) const
{
  return (vertex_stride == rhs.vertex_stride && vertex_attributes.size() == rhs.vertex_attributes.size() &&
          std::memcmp(vertex_attributes.data(), rhs.vertex_attributes.data(),
                      sizeof(VertexAttribute) * rhs.vertex_attributes.size()) == 0);
}

bool GPUPipeline::InputLayout::operator!=(const InputLayout& rhs) const
{
  return (vertex_stride != rhs.vertex_stride ||
          vertex_attributes.size() != rhs.vertex_attributes.size() &&
            std::memcmp(vertex_attributes.data(), rhs.vertex_attributes.data(),
                        sizeof(VertexAttribute) * rhs.vertex_attributes.size()) != 0);
}

GPUPipeline::RasterizationState GPUPipeline::RasterizationState::GetNoCullState()
{
  RasterizationState ret = {};
  ret.cull_mode = CullMode::None;
  return ret;
}

GPUPipeline::DepthState GPUPipeline::DepthState::GetNoTestsState()
{
  DepthState ret = {};
  ret.depth_test = DepthFunc::Always;
  return ret;
}

GPUPipeline::DepthState GPUPipeline::DepthState::GetAlwaysWriteState()
{
  DepthState ret = {};
  ret.depth_test = DepthFunc::Always;
  ret.depth_write = true;
  return ret;
}

GPUPipeline::BlendState GPUPipeline::BlendState::GetNoBlendingState()
{
  BlendState ret = {};
  ret.write_mask = 0xf;
  return ret;
}

GPUPipeline::BlendState GPUPipeline::BlendState::GetAlphaBlendingState()
{
  BlendState ret = {};
  ret.enable = true;
  ret.src_blend = BlendFunc::SrcAlpha;
  ret.dst_blend = BlendFunc::InvSrcAlpha;
  ret.blend_op = BlendOp::Add;
  ret.src_alpha_blend = BlendFunc::One;
  ret.dst_alpha_blend = BlendFunc::Zero;
  ret.alpha_blend_op = BlendOp::Add;
  ret.write_mask = 0xf;
  return ret;
}

GPUTextureBuffer::GPUTextureBuffer(Format format, u32 size) : m_format(format), m_size_in_elements(size)
{
}

GPUTextureBuffer::~GPUTextureBuffer() = default;

u32 GPUTextureBuffer::GetElementSize(Format format)
{
  static constexpr std::array<u32, static_cast<u32>(Format::MaxCount)> element_size = {{
    sizeof(u16),
  }};

  return element_size[static_cast<u32>(format)];
}

GPUDevice::~GPUDevice()
{
  // TODO: move to Destroy() method
  m_shader_cache.Close();
}

RenderAPI GPUDevice::GetPreferredAPI()
{
#ifdef _WIN32___ // TODO remove me
  return RenderAPI::D3D11;
#else
  return RenderAPI::OpenGL;
#endif
}

bool GPUDevice::SetupDevice()
{
  // TODO: option to disable shader cache
  if (true)
  {
    const std::string basename = GetShaderCacheBaseName("shaders", g_settings.gpu_use_debug_device);
    const std::string filename = Path::Combine(EmuFolders::Cache, basename);
    if (!m_shader_cache.Open(filename.c_str()))
      Log_WarningPrintf("Failed to open shader cache.");
  }
  else
  {
    Log_WarningPrintf("Shader cache is disabled.");
  }

  return true;
}

bool GPUDevice::CreateResources()
{
  if (!(m_nearest_sampler = CreateSampler(GPUSampler::GetNearestConfig())))
    return false;

  if (!(m_linear_sampler = CreateSampler(GPUSampler::GetLinearConfig())))
    return false;

  ShaderGen shadergen(GetRenderAPI(), m_features.dual_source_blend);

  GPUPipeline::GraphicsConfig plconfig;
  plconfig.layout = GPUPipeline::Layout::SingleTexturePushConstants;
  plconfig.primitive = GPUPipeline::Primitive::Triangles;
  plconfig.rasterization = GPUPipeline::RasterizationState::GetNoCullState();
  plconfig.depth = GPUPipeline::DepthState::GetNoTestsState();
  plconfig.blend = GPUPipeline::BlendState::GetNoBlendingState();
  plconfig.color_format = GPUTexture::Format::RGBA8; // FIXME m_window_info.surface_format;
  plconfig.depth_format = GPUTexture::Format::Unknown;
  plconfig.samples = 1;
  plconfig.per_sample_shading = false;

  std::unique_ptr<GPUShader> display_vs = CreateShader(GPUShaderStage::Vertex, shadergen.GenerateDisplayVertexShader());
  std::unique_ptr<GPUShader> display_fs =
    CreateShader(GPUShaderStage::Fragment, shadergen.GenerateDisplayFragmentShader(true));
  std::unique_ptr<GPUShader> cursor_fs =
    CreateShader(GPUShaderStage::Fragment, shadergen.GenerateDisplayFragmentShader(false));
  if (!display_vs || !display_fs || !cursor_fs)
    return false;
  GL_OBJECT_NAME(display_vs, "Display Vertex Shader");
  GL_OBJECT_NAME(display_fs, "Display Fragment Shader");
  GL_OBJECT_NAME(cursor_fs, "Cursor Fragment Shader");

  plconfig.vertex_shader = display_vs.get();
  plconfig.fragment_shader = display_fs.get();
  if (!(m_display_pipeline = CreatePipeline(plconfig)))
    return false;
  GL_OBJECT_NAME(m_display_pipeline, "Display Pipeline");

  plconfig.blend = GPUPipeline::BlendState::GetAlphaBlendingState();
  plconfig.fragment_shader = cursor_fs.get();
  if (!(m_cursor_pipeline = CreatePipeline(plconfig)))
    return false;
  GL_OBJECT_NAME(m_cursor_pipeline, "Cursor Pipeline");

  std::unique_ptr<GPUShader> imgui_vs = CreateShader(GPUShaderStage::Vertex, shadergen.GenerateImGuiVertexShader());
  std::unique_ptr<GPUShader> imgui_fs = CreateShader(GPUShaderStage::Fragment, shadergen.GenerateImGuiFragmentShader());
  if (!imgui_vs || !imgui_fs)
    return false;
  GL_OBJECT_NAME(imgui_vs, "ImGui Vertex Shader");
  GL_OBJECT_NAME(imgui_fs, "ImGui Fragment Shader");

  static constexpr GPUPipeline::VertexAttribute imgui_attributes[] = {
    GPUPipeline::VertexAttribute::Make(0, GPUPipeline::VertexAttribute::Type::Float, 2, offsetof(ImDrawVert, pos)),
    GPUPipeline::VertexAttribute::Make(1, GPUPipeline::VertexAttribute::Type::Float, 2, offsetof(ImDrawVert, uv)),
    GPUPipeline::VertexAttribute::Make(2, GPUPipeline::VertexAttribute::Type::UNorm8, 4, offsetof(ImDrawVert, col)),
  };

  plconfig.input_layout.vertex_attributes = imgui_attributes;
  plconfig.input_layout.vertex_stride = sizeof(ImDrawVert);
  plconfig.vertex_shader = imgui_vs.get();
  plconfig.fragment_shader = imgui_fs.get();

  m_imgui_pipeline = CreatePipeline(plconfig);
  if (!m_imgui_pipeline)
  {
    Log_ErrorPrintf("Failed to compile ImGui pipeline.");
    return false;
  }
  GL_OBJECT_NAME(m_imgui_pipeline, "ImGui Pipeline");

  return true;
}

void GPUDevice::DestroyResources()
{
  m_cursor_texture.reset();

  m_imgui_font_texture.reset();
  m_imgui_pipeline.reset();

  m_cursor_pipeline.reset();
  m_display_pipeline.reset();
  m_imgui_pipeline.reset();

  m_linear_sampler.reset();
  m_nearest_sampler.reset();

  m_shader_cache.Close();
}

bool GPUDevice::SetPostProcessingChain(const std::string_view& config)
{
  static constexpr GPUTexture::Format hdformat = GPUTexture::Format::RGBA8; // TODO FIXME m_window_info.surface_format

  m_post_processing_chain.reset();

  if (config.empty())
    return true;

  m_post_processing_chain = std::make_unique<PostProcessingChain>();
  if (!m_post_processing_chain->CreateFromString(config) || !m_post_processing_chain->CompilePipelines(hdformat))
  {
    m_post_processing_chain.reset();
    return false;
  }
  else if (m_post_processing_chain->IsEmpty())
  {
    m_post_processing_chain.reset();
    return true;
  }

  return true;
}

std::string GPUDevice::GetShaderCacheBaseName(const std::string_view& type, bool debug) const
{
  Panic("Not implemented");
  return {};
}

void GPUDevice::RenderImGui()
{
  GL_SCOPE("RenderImGui");

  ImGui::Render();

  const ImDrawData* draw_data = ImGui::GetDrawData();
  if (draw_data->CmdListsCount == 0)
    return;

  SetPipeline(m_imgui_pipeline.get());
  SetViewportAndScissor(0, 0, m_window_info.surface_width, m_window_info.surface_height);

  const float L = 0.0f;
  const float R = static_cast<float>(m_window_info.surface_width);
  const float T = 0.0f;
  const float B = static_cast<float>(m_window_info.surface_height);
  const float ortho_projection[4][4] = {
    {2.0f / (R - L), 0.0f, 0.0f, 0.0f},
    {0.0f, 2.0f / (T - B), 0.0f, 0.0f},
    {0.0f, 0.0f, 0.5f, 0.0f},
    {(R + L) / (L - R), (T + B) / (B - T), 0.5f, 1.0f},
  };
  PushUniformBuffer(ortho_projection, sizeof(ortho_projection));

  // Render command lists
  for (int n = 0; n < draw_data->CmdListsCount; n++)
  {
    const ImDrawList* cmd_list = draw_data->CmdLists[n];
    static_assert(sizeof(ImDrawIdx) == sizeof(DrawIndex));

    u32 base_vertex, base_index;
    UploadVertexBuffer(cmd_list->VtxBuffer.Data, sizeof(ImDrawVert), cmd_list->VtxBuffer.Size, &base_vertex);
    UploadIndexBuffer(cmd_list->IdxBuffer.Data, cmd_list->IdxBuffer.Size, &base_index);

    for (int cmd_i = 0; cmd_i < cmd_list->CmdBuffer.Size; cmd_i++)
    {
      const ImDrawCmd* pcmd = &cmd_list->CmdBuffer[cmd_i];
      DebugAssert(!pcmd->UserCallback);

      if (pcmd->ClipRect.z <= pcmd->ClipRect.x || pcmd->ClipRect.w <= pcmd->ClipRect.x)
        continue;

      SetScissor(static_cast<s32>(pcmd->ClipRect.x), static_cast<s32>(pcmd->ClipRect.y),
                 static_cast<s32>(pcmd->ClipRect.z - pcmd->ClipRect.x),
                 static_cast<s32>(pcmd->ClipRect.w - pcmd->ClipRect.y));
      SetTextureSampler(0, reinterpret_cast<GPUTexture*>(pcmd->TextureId), m_linear_sampler.get());
      DrawIndexed(pcmd->ElemCount, base_index + pcmd->IdxOffset, base_vertex + pcmd->VtxOffset);
    }
  }
}

void GPUDevice::MapVertexBuffer(u32 vertex_size, u32 vertex_count, void** map_ptr, u32* map_space, u32* map_base_vertex)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::UnmapVertexBuffer(u32 vertex_size, u32 vertex_count)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::MapIndexBuffer(u32 index_count, DrawIndex** map_ptr, u32* map_space, u32* map_base_index)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::UnmapIndexBuffer(u32 used_index_count)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::UploadVertexBuffer(const void* vertices, u32 vertex_size, u32 vertex_count, u32* base_vertex)
{
  void* map;
  u32 space;
  MapVertexBuffer(vertex_size, vertex_count, &map, &space, base_vertex);
  std::memcpy(map, vertices, vertex_size * vertex_count);
  UnmapVertexBuffer(vertex_size, vertex_count);
}

void GPUDevice::UploadIndexBuffer(const u16* indices, u32 index_count, u32* base_index)
{
  u16* map;
  u32 space;
  MapIndexBuffer(index_count, &map, &space, base_index);
  std::memcpy(map, indices, sizeof(u16) * index_count);
  UnmapIndexBuffer(index_count);
}

void GPUDevice::PushUniformBuffer(const void* data, u32 data_size)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void* GPUDevice::MapUniformBuffer(u32 size)
{
  // TODO: REMOVE ME
  UnreachableCode();
  return nullptr;
}

void GPUDevice::UnmapUniformBuffer(u32 size)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::UploadUniformBuffer(const void* data, u32 data_size)
{
  void* map = MapUniformBuffer(data_size);
  std::memcpy(map, data, data_size);
  UnmapUniformBuffer(data_size);
}

void GPUDevice::SetFramebuffer(GPUFramebuffer* fb)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::SetPipeline(GPUPipeline* pipeline)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::SetTextureSampler(u32 slot, GPUTexture* texture, GPUSampler* sampler)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::SetTextureBuffer(u32 slot, GPUTextureBuffer* buffer)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::SetViewport(s32 x, s32 y, s32 width, s32 height)
{
  // TODO: REMOVE ME
  // GL needs to invert if writing to the window framebuffer
  UnreachableCode();
}

void GPUDevice::SetScissor(s32 x, s32 y, s32 width, s32 height)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::SetViewportAndScissor(s32 x, s32 y, s32 width, s32 height)
{
  SetViewport(x, y, width, height);
  SetScissor(x, y, width, height);
}

void GPUDevice::Draw(u32 base_vertex, u32 vertex_count)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::DrawIndexed(u32 base_index, u32 index_count, u32 base_vertex)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

bool GPUDevice::BeginPresent(bool skip_present)
{
  // TODO: REMOVE ME
  UnreachableCode();
  return false;
}

void GPUDevice::EndPresent()
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::CopyTextureRegion(GPUTexture* dst, u32 dst_x, u32 dst_y, u32 dst_layer, u32 dst_level, GPUTexture* src,
                                  u32 src_x, u32 src_y, u32 src_layer, u32 src_level, u32 width, u32 height)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::ResolveTextureRegion(GPUTexture* dst, u32 dst_x, u32 dst_y, u32 dst_layer, u32 dst_level,
                                     GPUTexture* src, u32 src_x, u32 src_y, u32 src_layer, u32 src_level, u32 width,
                                     u32 height)
{
  // TODO: REMOVE ME
  UnreachableCode();
}

void GPUDevice::ClearRenderTarget(GPUTexture* t, u32 c)
{
  t->SetClearColor(c);
}

void GPUDevice::ClearDepth(GPUTexture* t, float d)
{
  t->SetClearDepth(d);
}

void GPUDevice::InvalidateRenderTarget(GPUTexture* t)
{
  t->SetState(GPUTexture::State::Invalidated);
}

std::unique_ptr<GPUShader> GPUDevice::CreateShaderFromBinary(GPUShaderStage stage, gsl::span<const u8> data)
{
  // TODO: REMOVE ME
  UnreachableCode();
  return {};
}

std::unique_ptr<GPUShader> GPUDevice::CreateShaderFromSource(GPUShaderStage stage, const std::string_view& source,
                                                             std::vector<u8>* out_binary /* = nullptr */)
{
  // TODO: REMOVE ME
  UnreachableCode();
  return {};
}

std::unique_ptr<GPUPipeline> GPUDevice::CreatePipeline(const GPUPipeline::GraphicsConfig& config)
{
  // TODO: REMOVE ME
  UnreachableCode();
  return {};
}

void GPUDevice::PushDebugGroup(const char* fmt, ...)
{
}

void GPUDevice::PopDebugGroup()
{
}

void GPUDevice::InsertDebugMessage(const char* fmt, ...)
{
}

std::unique_ptr<GPUSampler> GPUDevice::CreateSampler(const GPUSampler::Config& config)
{
  // TODO: REMOVE ME
  UnreachableCode();
  return {};
}

std::unique_ptr<GPUTextureBuffer> GPUDevice::CreateTextureBuffer(GPUTextureBuffer::Format format, u32 size_in_elements)
{
  // TODO: REMOVE ME
  UnreachableCode();
  return {};
}

std::unique_ptr<GPUFramebuffer> GPUDevice::CreateFramebuffer(GPUTexture* rt, u32 rt_layer, u32 rt_level, GPUTexture* ds,
                                                             u32 ds_layer, u32 ds_level)
{
  // TODO: REMOVE ME
  UnreachableCode();
  return {};
}

std::unique_ptr<GPUShader> GPUDevice::CreateShader(GPUShaderStage stage, const std::string_view& source)
{
  std::unique_ptr<GPUShader> shader;
  if (!m_shader_cache.IsOpen())
  {
    shader = CreateShaderFromSource(stage, source);
    return shader;
  }

  const GPUShaderCache::CacheIndexKey key = m_shader_cache.GetCacheKey(stage, source, "main");
  std::vector<u8> binary;
  if (m_shader_cache.Lookup(key, &binary))
  {
    shader = CreateShaderFromBinary(stage, binary);
    if (shader)
      return shader;

    Log_ErrorPrintf("Failed to create shader from binary (driver changed?). Clearing cache.");
    m_shader_cache.Clear();
  }

  binary.clear();
  shader = CreateShaderFromSource(stage, source, &binary);
  if (!shader)
    return shader;

  // Don't insert empty shaders into the cache...
  if (!binary.empty())
  {
    if (!m_shader_cache.Insert(key, binary.data(), static_cast<u32>(binary.size())))
      m_shader_cache.Close();
  }

  return shader;
}

bool GPUDevice::ParseFullscreenMode(const std::string_view& mode, u32* width, u32* height, float* refresh_rate)
{
  if (!mode.empty())
  {
    std::string_view::size_type sep1 = mode.find('x');
    if (sep1 != std::string_view::npos)
    {
      std::optional<u32> owidth = StringUtil::FromChars<u32>(mode.substr(0, sep1));
      sep1++;

      while (sep1 < mode.length() && std::isspace(mode[sep1]))
        sep1++;

      if (owidth.has_value() && sep1 < mode.length())
      {
        std::string_view::size_type sep2 = mode.find('@', sep1);
        if (sep2 != std::string_view::npos)
        {
          std::optional<u32> oheight = StringUtil::FromChars<u32>(mode.substr(sep1, sep2 - sep1));
          sep2++;

          while (sep2 < mode.length() && std::isspace(mode[sep2]))
            sep2++;

          if (oheight.has_value() && sep2 < mode.length())
          {
            std::optional<float> orefresh_rate = StringUtil::FromChars<float>(mode.substr(sep2));
            if (orefresh_rate.has_value())
            {
              *width = owidth.value();
              *height = oheight.value();
              *refresh_rate = orefresh_rate.value();
              return true;
            }
          }
        }
      }
    }
  }

  *width = 0;
  *height = 0;
  *refresh_rate = 0;
  return false;
}

std::string GPUDevice::GetFullscreenModeString(u32 width, u32 height, float refresh_rate)
{
  return StringUtil::StdStringFromFormat("%u x %u @ %f hz", width, height, refresh_rate);
}

bool GPUDevice::UpdateImGuiFontTexture()
{
  ImGuiIO& io = ImGui::GetIO();

  unsigned char* pixels;
  int width, height;
  io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);

  const u32 pitch = sizeof(u32) * width;

  if (m_imgui_font_texture && m_imgui_font_texture->GetWidth() == static_cast<u32>(width) &&
      m_imgui_font_texture->GetHeight() == static_cast<u32>(height) &&
      m_imgui_font_texture->Update(0, 0, static_cast<u32>(width), static_cast<u32>(height), pixels, pitch))
  {
    io.Fonts->SetTexID(m_imgui_font_texture.get());
    return true;
  }

  std::unique_ptr<GPUTexture> new_font =
    CreateTexture(width, height, 1, 1, 1, GPUTexture::Type::Texture, GPUTexture::Format::RGBA8, pixels, pitch);
  if (!new_font)
    return false;

  m_imgui_font_texture = std::move(new_font);
  io.Fonts->SetTexID(m_imgui_font_texture.get());
  return true;
}

bool GPUDevice::UsesLowerLeftOrigin() const
{
  const RenderAPI api = GetRenderAPI();
  return (api == RenderAPI::OpenGL || api == RenderAPI::OpenGLES);
}

void GPUDevice::SetDisplayMaxFPS(float max_fps)
{
  m_display_frame_interval = (max_fps > 0.0f) ? (1.0f / max_fps) : 0.0f;
}

bool GPUDevice::ShouldSkipDisplayingFrame()
{
  if (m_display_frame_interval == 0.0f)
    return false;

  const u64 now = Common::Timer::GetCurrentValue();
  const double diff = Common::Timer::ConvertValueToSeconds(now - m_last_frame_displayed_time);
  if (diff < m_display_frame_interval)
    return true;

  m_last_frame_displayed_time = now;
  return false;
}

void GPUDevice::ThrottlePresentation()
{
  const float throttle_rate = (m_window_info.surface_refresh_rate > 0.0f) ? m_window_info.surface_refresh_rate : 60.0f;

  const u64 sleep_period = Common::Timer::ConvertNanosecondsToValue(1e+9f / static_cast<double>(throttle_rate));
  const u64 current_ts = Common::Timer::GetCurrentValue();

  // Allow it to fall behind/run ahead up to 2*period. Sleep isn't that precise, plus we need to
  // allow time for the actual rendering.
  const u64 max_variance = sleep_period * 2;
  if (static_cast<u64>(std::abs(static_cast<s64>(current_ts - m_last_frame_displayed_time))) > max_variance)
    m_last_frame_displayed_time = current_ts + sleep_period;
  else
    m_last_frame_displayed_time += sleep_period;

  Common::Timer::SleepUntil(m_last_frame_displayed_time, false);
}

void GPUDevice::ClearDisplayTexture()
{
  m_display_texture = nullptr;
  m_display_texture_view_x = 0;
  m_display_texture_view_y = 0;
  m_display_texture_view_width = 0;
  m_display_texture_view_height = 0;
  m_display_changed = true;
}

void GPUDevice::SetDisplayTexture(GPUTexture* texture, s32 view_x, s32 view_y, s32 view_width, s32 view_height)
{
  DebugAssert(texture);
  texture->MakeReadyForSampling();
  m_display_texture = texture;
  m_display_texture_view_x = view_x;
  m_display_texture_view_y = view_y;
  m_display_texture_view_width = view_width;
  m_display_texture_view_height = view_height;
  m_display_changed = true;
}

void GPUDevice::SetDisplayTextureRect(s32 view_x, s32 view_y, s32 view_width, s32 view_height)
{
  m_display_texture_view_x = view_x;
  m_display_texture_view_y = view_y;
  m_display_texture_view_width = view_width;
  m_display_texture_view_height = view_height;
  m_display_changed = true;
}

void GPUDevice::SetDisplayParameters(s32 display_width, s32 display_height, s32 active_left, s32 active_top,
                                     s32 active_width, s32 active_height, float display_aspect_ratio)
{
  m_display_width = display_width;
  m_display_height = display_height;
  m_display_active_left = active_left;
  m_display_active_top = active_top;
  m_display_active_width = active_width;
  m_display_active_height = active_height;
  m_display_aspect_ratio = display_aspect_ratio;
  m_display_changed = true;
}

bool GPUDevice::GetHostRefreshRate(float* refresh_rate)
{
  if (m_window_info.surface_refresh_rate > 0.0f)
  {
    *refresh_rate = m_window_info.surface_refresh_rate;
    return true;
  }

  return WindowInfo::QueryRefreshRateForWindow(m_window_info, refresh_rate);
}

bool GPUDevice::SetGPUTimingEnabled(bool enabled)
{
  return false;
}

float GPUDevice::GetAndResetAccumulatedGPUTime()
{
  return 0.0f;
}

void GPUDevice::SetSoftwareCursor(std::unique_ptr<GPUTexture> texture, float scale /*= 1.0f*/)
{
  if (texture)
    texture->MakeReadyForSampling();

  m_cursor_texture = std::move(texture);
  m_cursor_texture_scale = scale;
}

bool GPUDevice::SetSoftwareCursor(const void* pixels, u32 width, u32 height, u32 stride, float scale /*= 1.0f*/)
{
  std::unique_ptr<GPUTexture> tex =
    CreateTexture(width, height, 1, 1, 1, GPUTexture::Type::Texture, GPUTexture::Format::RGBA8, pixels, stride, false);
  if (!tex)
    return false;

  SetSoftwareCursor(std::move(tex), scale);
  return true;
}

bool GPUDevice::SetSoftwareCursor(const char* path, float scale /*= 1.0f*/)
{
  auto fp = FileSystem::OpenManagedCFile(path, "rb");
  if (!fp)
  {
    return false;
  }

  int width, height, file_channels;
  u8* pixel_data = stbi_load_from_file(fp.get(), &width, &height, &file_channels, 4);
  if (!pixel_data)
  {
    const char* error_reason = stbi_failure_reason();
    Log_ErrorPrintf("Failed to load image from '%s': %s", path, error_reason ? error_reason : "unknown error");
    return false;
  }

  std::unique_ptr<GPUTexture> tex =
    CreateTexture(static_cast<u32>(width), static_cast<u32>(height), 1, 1, 1, GPUTexture::Type::Texture,
                  GPUTexture::Format::RGBA8, pixel_data, sizeof(u32) * static_cast<u32>(width), false);
  stbi_image_free(pixel_data);
  if (!tex)
    return false;

  Log_InfoPrintf("Loaded %dx%d image from '%s' for software cursor", width, height, path);
  SetSoftwareCursor(std::move(tex), scale);
  return true;
}

void GPUDevice::ClearSoftwareCursor()
{
  m_cursor_texture.reset();
  m_cursor_texture_scale = 1.0f;
}

bool GPUDevice::IsUsingLinearFiltering() const
{
  return g_settings.display_linear_filtering;
}

bool GPUDevice::Render(bool skip_present)
{
  if (skip_present)
  {
    // Should never return true here..
    if (UNLIKELY(BeginPresent(skip_present)))
      Panic("BeginPresent() returned true when skipping...");

    // Need to kick ImGui state.
    ImGui::Render();
    return false;
  }

  bool render_frame;
  if (HasDisplayTexture())
  {
    const auto [left, top, width, height] = CalculateDrawRect(GetWindowWidth(), GetWindowHeight());
    render_frame = RenderDisplay(nullptr, left, top, width, height, m_display_texture, m_display_texture_view_x,
                                 m_display_texture_view_y, m_display_texture_view_width, m_display_texture_view_height,
                                 IsUsingLinearFiltering());
  }
  else
  {
    render_frame = BeginPresent(false);
  }

  if (!render_frame)
  {
    // Window minimized etc.
    ImGui::Render();
    return false;
  }

  SetViewportAndScissor(0, 0, GetWindowWidth(), GetWindowHeight());

  RenderImGui();
  RenderSoftwareCursor();

  EndPresent();
  return true;
}

bool GPUDevice::RenderScreenshot(u32 width, u32 height, const Common::Rectangle<s32>& draw_rect,
                                 std::vector<u32>* out_pixels, u32* out_stride, GPUTexture::Format* out_format)
{
  static constexpr GPUTexture::Format hdformat = GPUTexture::Format::RGBA8; // TODO FIXME m_window_info.surface_format

  std::unique_ptr<GPUTexture> render_texture =
    CreateTexture(width, height, 1, 1, 1, GPUTexture::Type::RenderTarget, hdformat);
  if (!render_texture)
    return false;

  std::unique_ptr<GPUFramebuffer> render_fb = CreateFramebuffer(render_texture.get());
  if (!render_fb)
    return false;

  ClearRenderTarget(render_texture.get(), 0);

  RenderDisplay(render_fb.get(), draw_rect.left, draw_rect.top, draw_rect.GetWidth(), draw_rect.GetHeight(),
                m_display_texture, m_display_texture_view_x, m_display_texture_view_y, m_display_texture_view_width,
                m_display_texture_view_height, IsUsingLinearFiltering());

  SetFramebuffer(nullptr);

  const u32 stride = GPUTexture::GetPixelSize(hdformat) * width;
  out_pixels->resize(width * height);
  if (!DownloadTexture(render_texture.get(), 0, 0, width, height, out_pixels->data(), stride))
    return false;

  *out_stride = stride;
  *out_format = hdformat;
  return true;
}

bool GPUDevice::RenderDisplay(GPUFramebuffer* target, s32 left, s32 top, s32 width, s32 height, GPUTexture* texture,
                              s32 texture_view_x, s32 texture_view_y, s32 texture_view_width, s32 texture_view_height,
                              bool linear_filter)
{
  GL_SCOPE("RenderDisplay: %dx%d at %d,%d", left, top, width, height);

  static constexpr GPUTexture::Format hdformat = GPUTexture::Format::RGBA8; // TODO FIXME m_window_info.surface_format
  const u32 target_width = target ? target->GetWidth() : m_window_info.surface_width;
  const u32 target_height = target ? target->GetHeight() : m_window_info.surface_height;
  const bool postfx =
    (m_post_processing_chain && m_post_processing_chain->CheckTargets(hdformat, target_width, target_height));
  if (postfx)
  {
    ClearRenderTarget(m_post_processing_chain->GetInputTexture(), 0);
    SetFramebuffer(m_post_processing_chain->GetInputFramebuffer());
  }
  else
  {
    if (target)
      SetFramebuffer(target);
    else if (!BeginPresent(false))
      return false;
  }

  SetPipeline(m_display_pipeline.get());
  SetTextureSampler(0, texture, linear_filter ? m_linear_sampler.get() : m_nearest_sampler.get());

  const bool linear = IsUsingLinearFiltering();
  const float position_adjust = linear ? 0.5f : 0.0f;
  const float size_adjust = linear ? 1.0f : 0.0f;
  const float uniforms[4] = {
    (static_cast<float>(texture_view_x) + position_adjust) / static_cast<float>(texture->GetWidth()),
    (static_cast<float>(texture_view_y) + position_adjust) / static_cast<float>(texture->GetHeight()),
    (static_cast<float>(texture_view_width) - size_adjust) / static_cast<float>(texture->GetWidth()),
    (static_cast<float>(texture_view_height) - size_adjust) / static_cast<float>(texture->GetHeight())};
  PushUniformBuffer(uniforms, sizeof(uniforms));

  SetViewportAndScissor(left, top, width, height);
  Draw(3, 0);

  if (postfx)
  {
    return m_post_processing_chain->Apply(target, left, top, width, height, texture_view_width, texture_view_height,
                                          target_width, target_height);
  }
  else
  {
    return true;
  }
}

void GPUDevice::RenderSoftwareCursor()
{
  if (!HasSoftwareCursor())
    return;

  const auto [left, top, width, height] = CalculateSoftwareCursorDrawRect();
  RenderSoftwareCursor(left, top, width, height, m_cursor_texture.get());
}

void GPUDevice::RenderSoftwareCursor(s32 left, s32 top, s32 width, s32 height, GPUTexture* texture)
{
  SetPipeline(m_display_pipeline.get());
  SetTextureSampler(0, texture, m_linear_sampler.get());

  const float uniforms[4] = {0.0f, 0.0f, 1.0f, 1.0f};
  PushUniformBuffer(uniforms, sizeof(uniforms));

  SetViewportAndScissor(left, top, width, height);
  Draw(3, 0);
}

void GPUDevice::CalculateDrawRect(s32 window_width, s32 window_height, float* out_left, float* out_top,
                                  float* out_width, float* out_height, float* out_left_padding, float* out_top_padding,
                                  float* out_scale, float* out_x_scale, bool apply_aspect_ratio /* = true */) const
{
  const float window_ratio = static_cast<float>(window_width) / static_cast<float>(window_height);
  const float display_aspect_ratio = g_settings.display_stretch ? window_ratio : m_display_aspect_ratio;
  const float x_scale =
    apply_aspect_ratio ?
      (display_aspect_ratio / (static_cast<float>(m_display_width) / static_cast<float>(m_display_height))) :
      1.0f;
  const float display_width = g_settings.display_stretch_vertically ? static_cast<float>(m_display_width) :
                                                                      static_cast<float>(m_display_width) * x_scale;
  const float display_height = g_settings.display_stretch_vertically ? static_cast<float>(m_display_height) / x_scale :
                                                                       static_cast<float>(m_display_height);
  const float active_left = g_settings.display_stretch_vertically ? static_cast<float>(m_display_active_left) :
                                                                    static_cast<float>(m_display_active_left) * x_scale;
  const float active_top = g_settings.display_stretch_vertically ? static_cast<float>(m_display_active_top) / x_scale :
                                                                   static_cast<float>(m_display_active_top);
  const float active_width = g_settings.display_stretch_vertically ?
                               static_cast<float>(m_display_active_width) :
                               static_cast<float>(m_display_active_width) * x_scale;
  const float active_height = g_settings.display_stretch_vertically ?
                                static_cast<float>(m_display_active_height) / x_scale :
                                static_cast<float>(m_display_active_height);
  if (out_x_scale)
    *out_x_scale = x_scale;

  // now fit it within the window
  float scale;
  if ((display_width / display_height) >= window_ratio)
  {
    // align in middle vertically
    scale = static_cast<float>(window_width) / display_width;
    if (g_settings.display_integer_scaling)
      scale = std::max(std::floor(scale), 1.0f);

    if (out_left_padding)
    {
      if (g_settings.display_integer_scaling)
        *out_left_padding = std::max<float>((static_cast<float>(window_width) - display_width * scale) / 2.0f, 0.0f);
      else
        *out_left_padding = 0.0f;
    }
    if (out_top_padding)
    {
      switch (g_settings.display_alignment)
      {
        case DisplayAlignment::RightOrBottom:
          *out_top_padding = std::max<float>(static_cast<float>(window_height) - (display_height * scale), 0.0f);
          break;

        case DisplayAlignment::Center:
          *out_top_padding =
            std::max<float>((static_cast<float>(window_height) - (display_height * scale)) / 2.0f, 0.0f);
          break;

        case DisplayAlignment::LeftOrTop:
        default:
          *out_top_padding = 0.0f;
          break;
      }
    }
  }
  else
  {
    // align in middle horizontally
    scale = static_cast<float>(window_height) / display_height;
    if (g_settings.display_integer_scaling)
      scale = std::max(std::floor(scale), 1.0f);

    if (out_left_padding)
    {
      switch (g_settings.display_alignment)
      {
        case DisplayAlignment::RightOrBottom:
          *out_left_padding = std::max<float>(static_cast<float>(window_width) - (display_width * scale), 0.0f);
          break;

        case DisplayAlignment::Center:
          *out_left_padding =
            std::max<float>((static_cast<float>(window_width) - (display_width * scale)) / 2.0f, 0.0f);
          break;

        case DisplayAlignment::LeftOrTop:
        default:
          *out_left_padding = 0.0f;
          break;
      }
    }

    if (out_top_padding)
    {
      if (g_settings.display_integer_scaling)
        *out_top_padding = std::max<float>((static_cast<float>(window_height) - (display_height * scale)) / 2.0f, 0.0f);
      else
        *out_top_padding = 0.0f;
    }
  }

  *out_width = active_width * scale;
  *out_height = active_height * scale;
  *out_left = active_left * scale;
  *out_top = active_top * scale;
  if (out_scale)
    *out_scale = scale;
}

std::tuple<s32, s32, s32, s32> GPUDevice::CalculateDrawRect(s32 window_width, s32 window_height,
                                                            bool apply_aspect_ratio /* = true */) const
{
  float left, top, width, height, left_padding, top_padding;
  CalculateDrawRect(window_width, window_height, &left, &top, &width, &height, &left_padding, &top_padding, nullptr,
                    nullptr, apply_aspect_ratio);

  return std::make_tuple(static_cast<s32>(left + left_padding), static_cast<s32>(top + top_padding),
                         static_cast<s32>(width), static_cast<s32>(height));
}

std::tuple<s32, s32, s32, s32> GPUDevice::CalculateSoftwareCursorDrawRect() const
{
  return CalculateSoftwareCursorDrawRect(m_mouse_position_x, m_mouse_position_y);
}

std::tuple<s32, s32, s32, s32> GPUDevice::CalculateSoftwareCursorDrawRect(s32 cursor_x, s32 cursor_y) const
{
  const float scale = m_window_info.surface_scale * m_cursor_texture_scale;
  const u32 cursor_extents_x = static_cast<u32>(static_cast<float>(m_cursor_texture->GetWidth()) * scale * 0.5f);
  const u32 cursor_extents_y = static_cast<u32>(static_cast<float>(m_cursor_texture->GetHeight()) * scale * 0.5f);

  const s32 out_left = cursor_x - cursor_extents_x;
  const s32 out_top = cursor_y - cursor_extents_y;
  const s32 out_width = cursor_extents_x * 2u;
  const s32 out_height = cursor_extents_y * 2u;

  return std::tie(out_left, out_top, out_width, out_height);
}

std::tuple<float, float> GPUDevice::ConvertWindowCoordinatesToDisplayCoordinates(s32 window_x, s32 window_y,
                                                                                 s32 window_width,
                                                                                 s32 window_height) const
{
  float left, top, width, height, left_padding, top_padding;
  float scale, x_scale;
  CalculateDrawRect(window_width, window_height, &left, &top, &width, &height, &left_padding, &top_padding, &scale,
                    &x_scale);

  // convert coordinates to active display region, then to full display region
  const float scaled_display_x = static_cast<float>(window_x) - left_padding;
  const float scaled_display_y = static_cast<float>(window_y) - top_padding;

  // scale back to internal resolution
  const float display_x = scaled_display_x / scale / x_scale;
  const float display_y = scaled_display_y / scale;

  return std::make_tuple(display_x, display_y);
}

static bool CompressAndWriteTextureToFile(u32 width, u32 height, std::string filename, FileSystem::ManagedCFilePtr fp,
                                          bool clear_alpha, bool flip_y, u32 resize_width, u32 resize_height,
                                          std::vector<u32> texture_data, u32 texture_data_stride,
                                          GPUTexture::Format texture_format)
{

  const char* extension = std::strrchr(filename.c_str(), '.');
  if (!extension)
  {
    Log_ErrorPrintf("Unable to determine file extension for '%s'", filename.c_str());
    return false;
  }

  if (!GPUTexture::ConvertTextureDataToRGBA8(width, height, texture_data, texture_data_stride, texture_format))
    return false;

  if (clear_alpha)
  {
    for (u32& pixel : texture_data)
      pixel |= 0xFF000000;
  }

  if (flip_y)
    GPUTexture::FlipTextureDataRGBA8(width, height, texture_data, texture_data_stride);

  if (resize_width > 0 && resize_height > 0 && (resize_width != width || resize_height != height))
  {
    std::vector<u32> resized_texture_data(resize_width * resize_height);
    u32 resized_texture_stride = sizeof(u32) * resize_width;
    if (!stbir_resize_uint8(reinterpret_cast<u8*>(texture_data.data()), width, height, texture_data_stride,
                            reinterpret_cast<u8*>(resized_texture_data.data()), resize_width, resize_height,
                            resized_texture_stride, 4))
    {
      Log_ErrorPrintf("Failed to resize texture data from %ux%u to %ux%u", width, height, resize_width, resize_height);
      return false;
    }

    width = resize_width;
    height = resize_height;
    texture_data = std::move(resized_texture_data);
    texture_data_stride = resized_texture_stride;
  }

  const auto write_func = [](void* context, void* data, int size) {
    std::fwrite(data, 1, size, static_cast<std::FILE*>(context));
  };

  bool result = false;
  if (StringUtil::Strcasecmp(extension, ".png") == 0)
  {
    result =
      (stbi_write_png_to_func(write_func, fp.get(), width, height, 4, texture_data.data(), texture_data_stride) != 0);
  }
  else if (StringUtil::Strcasecmp(extension, ".jpg") == 0)
  {
    result = (stbi_write_jpg_to_func(write_func, fp.get(), width, height, 4, texture_data.data(), 95) != 0);
  }
  else if (StringUtil::Strcasecmp(extension, ".tga") == 0)
  {
    result = (stbi_write_tga_to_func(write_func, fp.get(), width, height, 4, texture_data.data()) != 0);
  }
  else if (StringUtil::Strcasecmp(extension, ".bmp") == 0)
  {
    result = (stbi_write_bmp_to_func(write_func, fp.get(), width, height, 4, texture_data.data()) != 0);
  }

  if (!result)
  {
    Log_ErrorPrintf("Unknown extension in filename '%s' or save error: '%s'", filename.c_str(), extension);
    return false;
  }

  return true;
}

bool GPUDevice::WriteTextureToFile(GPUTexture* texture, u32 x, u32 y, u32 width, u32 height, std::string filename,
                                   bool clear_alpha /* = true */, bool flip_y /* = false */, u32 resize_width /* = 0 */,
                                   u32 resize_height /* = 0 */, bool compress_on_thread /* = false */)
{
  std::vector<u32> texture_data(width * height);
  u32 texture_data_stride = Common::AlignUpPow2(GPUTexture::GetPixelSize(texture->GetFormat()) * width, 4);
  if (!DownloadTexture(texture, x, y, width, height, texture_data.data(), texture_data_stride))
  {
    Log_ErrorPrintf("Texture download failed");
    return false;
  }

  auto fp = FileSystem::OpenManagedCFile(filename.c_str(), "wb");
  if (!fp)
  {
    Log_ErrorPrintf("Can't open file '%s': errno %d", filename.c_str(), errno);
    return false;
  }

  if (!compress_on_thread)
  {
    return CompressAndWriteTextureToFile(width, height, std::move(filename), std::move(fp), clear_alpha, flip_y,
                                         resize_width, resize_height, std::move(texture_data), texture_data_stride,
                                         texture->GetFormat());
  }

  std::thread compress_thread(CompressAndWriteTextureToFile, width, height, std::move(filename), std::move(fp),
                              clear_alpha, flip_y, resize_width, resize_height, std::move(texture_data),
                              texture_data_stride, texture->GetFormat());
  compress_thread.detach();
  return true;
}

bool GPUDevice::WriteDisplayTextureToFile(std::string filename, bool full_resolution /* = true */,
                                          bool apply_aspect_ratio /* = true */, bool compress_on_thread /* = false */)
{
  if (!m_display_texture)
    return false;

  s32 resize_width = 0;
  s32 resize_height = std::abs(m_display_texture_view_height);
  if (apply_aspect_ratio)
  {
    const float ss_width_scale = static_cast<float>(m_display_active_width) / static_cast<float>(m_display_width);
    const float ss_height_scale = static_cast<float>(m_display_active_height) / static_cast<float>(m_display_height);
    const float ss_aspect_ratio = m_display_aspect_ratio * ss_width_scale / ss_height_scale;
    resize_width = g_settings.display_stretch_vertically ?
                     m_display_texture_view_width :
                     static_cast<s32>(static_cast<float>(resize_height) * ss_aspect_ratio);
    resize_height = g_settings.display_stretch_vertically ?
                      static_cast<s32>(static_cast<float>(resize_height) /
                                       (m_display_aspect_ratio /
                                        (static_cast<float>(m_display_width) / static_cast<float>(m_display_height)))) :
                      resize_height;
  }
  else
  {
    resize_width = m_display_texture_view_width;
  }

  if (!full_resolution)
  {
    const s32 resolution_scale = std::abs(m_display_texture_view_height) / m_display_active_height;
    resize_height /= resolution_scale;
    resize_width /= resolution_scale;
  }

  if (resize_width <= 0 || resize_height <= 0)
    return false;

  const bool flip_y = (m_display_texture_view_height < 0);
  s32 read_height = m_display_texture_view_height;
  s32 read_y = m_display_texture_view_y;
  if (flip_y)
  {
    read_height = -m_display_texture_view_height;
    read_y =
      (m_display_texture->GetHeight() - read_height) - (m_display_texture->GetHeight() - m_display_texture_view_y);
  }

  return WriteTextureToFile(m_display_texture, m_display_texture_view_x, read_y, m_display_texture_view_width,
                            read_height, std::move(filename), true, flip_y, static_cast<u32>(resize_width),
                            static_cast<u32>(resize_height), compress_on_thread);
}

bool GPUDevice::WriteDisplayTextureToBuffer(std::vector<u32>* buffer, u32 resize_width /* = 0 */,
                                            u32 resize_height /* = 0 */, bool clear_alpha /* = true */)
{
  if (!m_display_texture)
    return false;

  const bool flip_y = (m_display_texture_view_height < 0);
  s32 read_width = m_display_texture_view_width;
  s32 read_height = m_display_texture_view_height;
  s32 read_x = m_display_texture_view_x;
  s32 read_y = m_display_texture_view_y;
  if (flip_y)
  {
    read_height = -m_display_texture_view_height;
    read_y =
      (m_display_texture->GetHeight() - read_height) - (m_display_texture->GetHeight() - m_display_texture_view_y);
  }

  u32 width = static_cast<u32>(read_width);
  u32 height = static_cast<u32>(read_height);
  std::vector<u32> texture_data(width * height);
  u32 texture_data_stride = Common::AlignUpPow2(m_display_texture->GetPixelSize() * width, 4);
  if (!DownloadTexture(m_display_texture, read_x, read_y, width, height, texture_data.data(), texture_data_stride))
  {
    Log_ErrorPrintf("Failed to download texture from GPU.");
    return false;
  }

  if (!GPUTexture::ConvertTextureDataToRGBA8(width, height, texture_data, texture_data_stride,
                                             m_display_texture->GetFormat()))
  {
    return false;
  }

  if (clear_alpha)
  {
    for (u32& pixel : texture_data)
      pixel |= 0xFF000000;
  }

  if (flip_y)
  {
    std::vector<u32> temp(width);
    for (u32 flip_row = 0; flip_row < (height / 2); flip_row++)
    {
      u32* top_ptr = &texture_data[flip_row * width];
      u32* bottom_ptr = &texture_data[((height - 1) - flip_row) * width];
      std::memcpy(temp.data(), top_ptr, texture_data_stride);
      std::memcpy(top_ptr, bottom_ptr, texture_data_stride);
      std::memcpy(bottom_ptr, temp.data(), texture_data_stride);
    }
  }

  if (resize_width > 0 && resize_height > 0 && (resize_width != width || resize_height != height))
  {
    std::vector<u32> resized_texture_data(resize_width * resize_height);
    u32 resized_texture_stride = sizeof(u32) * resize_width;
    if (!stbir_resize_uint8(reinterpret_cast<u8*>(texture_data.data()), width, height, texture_data_stride,
                            reinterpret_cast<u8*>(resized_texture_data.data()), resize_width, resize_height,
                            resized_texture_stride, 4))
    {
      Log_ErrorPrintf("Failed to resize texture data from %ux%u to %ux%u", width, height, resize_width, resize_height);
      return false;
    }

    width = resize_width;
    height = resize_height;
    *buffer = std::move(resized_texture_data);
    texture_data_stride = resized_texture_stride;
  }
  else
  {
    *buffer = texture_data;
  }

  return true;
}

bool GPUDevice::WriteScreenshotToFile(std::string filename, bool internal_resolution /* = false */,
                                      bool compress_on_thread /* = false */)
{
  u32 width = m_window_info.surface_width;
  u32 height = m_window_info.surface_height;
  auto [draw_left, draw_top, draw_width, draw_height] = CalculateDrawRect(width, height);

  if (internal_resolution && m_display_texture_view_width != 0 && m_display_texture_view_height != 0)
  {
    // If internal res, scale the computed draw rectangle to the internal res.
    // We re-use the draw rect because it's already been AR corrected.
    const float sar =
      static_cast<float>(m_display_texture_view_width) / static_cast<float>(m_display_texture_view_height);
    const float dar = static_cast<float>(draw_width) / static_cast<float>(draw_height);
    if (sar >= dar)
    {
      // stretch height, preserve width
      const float scale = static_cast<float>(m_display_texture_view_width) / static_cast<float>(draw_width);
      width = m_display_texture_view_width;
      height = static_cast<u32>(std::round(static_cast<float>(draw_height) * scale));
    }
    else
    {
      // stretch width, preserve height
      const float scale = static_cast<float>(m_display_texture_view_height) / static_cast<float>(draw_height);
      width = static_cast<u32>(std::round(static_cast<float>(draw_width) * scale));
      height = m_display_texture_view_height;
    }

    // DX11 won't go past 16K texture size.
    constexpr u32 MAX_TEXTURE_SIZE = 16384;
    if (width > MAX_TEXTURE_SIZE)
    {
      height = static_cast<u32>(static_cast<float>(height) /
                                (static_cast<float>(width) / static_cast<float>(MAX_TEXTURE_SIZE)));
      width = MAX_TEXTURE_SIZE;
    }
    if (height > MAX_TEXTURE_SIZE)
    {
      height = MAX_TEXTURE_SIZE;
      width = static_cast<u32>(static_cast<float>(width) /
                               (static_cast<float>(height) / static_cast<float>(MAX_TEXTURE_SIZE)));
    }

    // Remove padding, it's not part of the framebuffer.
    draw_left = 0;
    draw_top = 0;
    draw_width = static_cast<s32>(width);
    draw_height = static_cast<s32>(height);
  }
  if (width == 0 || height == 0)
    return false;

  std::vector<u32> pixels;
  u32 pixels_stride;
  GPUTexture::Format pixels_format;
  if (!RenderScreenshot(width, height,
                        Common::Rectangle<s32>::FromExtents(draw_left, draw_top, draw_width, draw_height), &pixels,
                        &pixels_stride, &pixels_format))
  {
    Log_ErrorPrintf("Failed to render %ux%u screenshot", width, height);
    return false;
  }

  auto fp = FileSystem::OpenManagedCFile(filename.c_str(), "wb");
  if (!fp)
  {
    Log_ErrorPrintf("Can't open file '%s': errno %d", filename.c_str(), errno);
    return false;
  }

  if (!compress_on_thread)
  {
    return CompressAndWriteTextureToFile(width, height, std::move(filename), std::move(fp), true, UsesLowerLeftOrigin(),
                                         width, height, std::move(pixels), pixels_stride, pixels_format);
  }

  std::thread compress_thread(CompressAndWriteTextureToFile, width, height, std::move(filename), std::move(fp), true,
                              UsesLowerLeftOrigin(), width, height, std::move(pixels), pixels_stride, pixels_format);
  compress_thread.detach();
  return true;
}

std::unique_ptr<GPUDevice> Host::CreateDisplayForAPI(RenderAPI api)
{
  switch (api)
  {
#ifdef WITH_VULKAN
    case RenderAPI::Vulkan:
      return std::make_unique<VulkanGPUDevice>();
#endif

#ifdef WITH_OPENGL
    case RenderAPI::OpenGL:
    case RenderAPI::OpenGLES:
      return std::make_unique<OpenGLDevice>();
#endif

#ifdef _WIN32
    case RenderAPI::D3D12:
      return std::make_unique<D3D12GPUDevice>();

    case RenderAPI::D3D11:
      return std::make_unique<D3D11Device>();
#endif

    default:
#if defined(_WIN32) && defined(_M_ARM64)
      return std::make_unique<D3D12GPUDevice>();
#elif defined(_WIN32)
      return std::make_unique<D3D11Device>();
#elif defined(__APPLE__)
			return WrapNewMetalDevice();
#elif defined(WITH_OPENGL)
      return std::make_unique<OpenGLDevice>();
#elif defined(WITH_VULKAN)
      return std::make_unique<VulkanGPUDevice>();
#else
      return {};
#endif
  }
}