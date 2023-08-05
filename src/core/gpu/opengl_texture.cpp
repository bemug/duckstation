// SPDX-FileCopyrightText: 2019-2023 Connor McLaughlin <stenzek@gmail.com>
// SPDX-License-Identifier: (GPL-3.0 OR CC-BY-NC-ND-4.0)

#include "opengl_texture.h"
#include "opengl_device.h"
#include "opengl_stream_buffer.h"

#include "common/align.h"
#include "common/assert.h"
#include "common/log.h"
#include "common/string_util.h"

#include <array>
#include <limits>
#include <tuple>

Log_SetChannel(OpenGLDevice);

// Looking across a range of GPUs, the optimal copy alignment for Vulkan drivers seems
// to be between 1 (AMD/NV) and 64 (Intel). So, we'll go with 64 here.
static constexpr u32 TEXTURE_UPLOAD_ALIGNMENT = 64;

// The pitch alignment must be less or equal to the upload alignment.
// We need 32 here for AVX2, so 64 is also fine.
static constexpr u32 TEXTURE_UPLOAD_PITCH_ALIGNMENT = 64;

bool OpenGLTexture::s_use_pbo_for_uploads = false;

const std::tuple<GLenum, GLenum, GLenum>& OpenGLTexture::GetPixelFormatMapping(GPUTexture::Format format)
{
  static constexpr std::array<std::tuple<GLenum, GLenum, GLenum>, static_cast<u32>(GPUTexture::Format::Count)> mapping =
    {{
      {},                                                   // Unknown
      {GL_RGBA8, GL_RGBA, GL_UNSIGNED_BYTE},                // RGBA8
      {GL_RGBA8, GL_BGRA, GL_UNSIGNED_BYTE},                // BGRA8
      {GL_RGB565, GL_RGB, GL_UNSIGNED_SHORT_5_6_5},         // RGB565
      {GL_RGB5_A1, GL_BGRA, GL_UNSIGNED_SHORT_1_5_5_5_REV}, // RGBA5551
      {GL_R8, GL_RED, GL_UNSIGNED_BYTE},                    // R8
      {GL_DEPTH_COMPONENT16, GL_DEPTH_COMPONENT, GL_SHORT}, // D16
    }};

  return mapping[static_cast<u32>(format)];
}

OpenGLTexture::OpenGLTexture() = default;

OpenGLTexture::~OpenGLTexture()
{
  Destroy();
}

bool OpenGLTexture::UseTextureStorage(bool multisampled)
{
  return GLAD_GL_ARB_texture_storage || (multisampled ? GLAD_GL_ES_VERSION_3_1 : GLAD_GL_ES_VERSION_3_0);
}

bool OpenGLTexture::UseTextureStorage() const
{
  return UseTextureStorage(IsMultisampled());
}

bool OpenGLTexture::Create(u32 width, u32 height, u32 layers, u32 levels, u32 samples, Format format, const void* data,
                           u32 data_pitch)
{
  glGetError();

  if (width > MAX_WIDTH || height > MAX_HEIGHT || layers > MAX_LAYERS || levels > MAX_LEVELS || samples > MAX_SAMPLES)
  {
    Log_ErrorPrintf("Invalid dimensions: %ux%ux%u %u %u", width, height, layers, levels, samples);
    return false;
  }

  if (samples > 1 && levels > 1)
  {
    Log_ErrorPrintf("Multisampled textures can't have mip levels");
    return false;
  }

  if (layers > 1 && data)
  {
    Log_ErrorPrintf("Loading texture array data not currently supported");
    return false;
  }

  const GLenum target = ((samples > 1) ? ((layers > 1) ? GL_TEXTURE_2D_MULTISAMPLE : GL_TEXTURE_2D_MULTISAMPLE_ARRAY) :
                                         ((layers > 1) ? GL_TEXTURE_2D_ARRAY : GL_TEXTURE_2D));
  const auto [gl_internal_format, gl_format, gl_type] = GetPixelFormatMapping(format);

  OpenGLDevice::BindUpdateTextureUnit();

  GLuint id;
  glGenTextures(1, &id);
  glBindTexture(target, id);

  if (samples > 1)
  {
    Assert(!data);
    if (UseTextureStorage(true))
    {
      if (layers > 1)
        glTexStorage3DMultisample(target, samples, gl_internal_format, width, height, layers, GL_FALSE);
      else
        glTexStorage2DMultisample(target, samples, gl_internal_format, width, height, GL_FALSE);
    }
    else
    {
      if (layers > 1)
        glTexImage3DMultisample(target, samples, gl_internal_format, width, height, layers, GL_FALSE);
      else
        glTexImage2DMultisample(target, samples, gl_internal_format, width, height, GL_FALSE);
    }

    glTexParameteri(target, GL_TEXTURE_BASE_LEVEL, 0);
    glTexParameteri(target, GL_TEXTURE_MAX_LEVEL, levels);
  }
  else
  {
    if (UseTextureStorage(false))
    {
      if (layers > 1)
        glTexStorage3D(target, levels, gl_internal_format, width, height, layers);
      else
        glTexStorage2D(target, levels, gl_internal_format, width, height);

      if (data)
      {
        // TODO: Fix data for mipmaps here.
        if (layers > 1)
          glTexSubImage3D(target, 0, 0, 0, 0, width, height, layers, gl_format, gl_type, data);
        else
          glTexSubImage2D(target, 0, 0, 0, width, height, gl_format, gl_type, data);
      }
    }
    else
    {
      for (u32 i = 0; i < levels; i++)
      {
        // TODO: Fix data pointer here.
        if (layers > 1)
          glTexImage3D(target, i, gl_internal_format, width, height, layers, 0, gl_format, gl_type, data);
        else
          glTexImage2D(target, i, gl_internal_format, width, height, 0, gl_format, gl_type, data);
      }

      glTexParameteri(target, GL_TEXTURE_BASE_LEVEL, 0);
      glTexParameteri(target, GL_TEXTURE_MAX_LEVEL, levels);
    }
  }

  GLenum error = glGetError();
  if (error != GL_NO_ERROR)
  {
    Log_ErrorPrintf("Failed to create texture: 0x%X", error);
    glDeleteTextures(1, &id);
    return false;
  }

  if (IsValid())
    Destroy();

  m_id = id;
  m_width = static_cast<u16>(width);
  m_height = static_cast<u16>(height);
  m_layers = static_cast<u8>(layers);
  m_levels = static_cast<u8>(levels);
  m_samples = static_cast<u8>(samples);
  m_format = format;
  m_state = GPUTexture::State::Dirty;
  return true;
}

#if 0
void OpenGLTexture::Replace(u32 width, u32 height, GLenum internal_format, GLenum format, GLenum type, const void* data)
{
  Assert(IsValid() && width < MAX_WIDTH && height < MAX_HEIGHT && m_layers == 1 && m_samples == 1 && m_levels == 1);

  const bool size_changed = (width != m_width || height != m_height);

  m_width = static_cast<u16>(width);
  m_height = static_cast<u16>(height);
  m_levels = 1;

  const GLenum target = GetGLTarget();
  glBindTexture(target, m_id);

  if (UseTextureStorage())
  {
    if (size_changed)
    {
      if (m_layers > 0)
        glTexStorage3D(target, m_levels, internal_format, m_width, m_height, m_levels);
      else
        glTexStorage2D(target, m_levels, internal_format, m_width, m_height);
    }

    glTexSubImage2D(target, 0, 0, 0, m_width, m_height, format, type, data);
  }
  else
  {
    glTexImage2D(target, 0, internal_format, width, height, 0, format, type, data);
  }
}

void OpenGLTexture::ReplaceImage(u32 layer, u32 level, GLenum format, GLenum type, const void* data)
{
  Assert(IsValid() && !IsMultisampled());

  const GLenum target = GetGLTarget();
  if (IsTextureArray())
    glTexSubImage3D(target, level, 0, 0, layer, m_width, m_height, 1, format, type, data);
  else
    glTexSubImage2D(target, level, 0, 0, m_width, m_height, format, type, data);
}

void OpenGLTexture::ReplaceSubImage(u32 layer, u32 level, u32 x, u32 y, u32 width, u32 height, GLenum format,
                                    GLenum type, const void* data)
{
  Assert(IsValid() && !IsMultisampled());

  const GLenum target = GetGLTarget();
  if (IsTextureArray())
    glTexSubImage3D(target, level, x, y, layer, width, height, 1, format, type, data);
  else
    glTexSubImage2D(target, level, x, y, width, height, format, type, data);
}
#endif

void OpenGLTexture::Destroy()
{
  if (m_id != 0)
  {
    OpenGLDevice::GetInstance().UnbindTexture(m_id);
    glDeleteTextures(1, &m_id);
    m_id = 0;
  }

  ClearBaseProperties();
}

void OpenGLTexture::CommitClear()
{
  OpenGLDevice::GetInstance().CommitClear(this);
}

bool OpenGLTexture::Update(u32 x, u32 y, u32 width, u32 height, const void* data, u32 pitch, u32 layer /*= 0*/,
                           u32 level /*= 0*/)
{
  // TODO: perf counters

  // Worth using the PBO? Driver probably knows better...
  const GLenum target = GetGLTarget();
  const auto [gl_internal_format, gl_format, gl_type] = GetPixelFormatMapping(m_format);
  const u32 preferred_pitch =
    Common::AlignUpPow2(static_cast<u32>(width) * GetPixelSize(), TEXTURE_UPLOAD_PITCH_ALIGNMENT);
  const u32 map_size = preferred_pitch * static_cast<u32>(height);
  OpenGLStreamBuffer* sb = OpenGLDevice::GetTextureStreamBuffer();

  CommitClear();

  OpenGLDevice::BindUpdateTextureUnit();
  glBindTexture(target, m_id);

  if (!sb || map_size > sb->GetChunkSize())
  {
    GL_INS("Not using PBO for map size %u", map_size);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, pitch / GetPixelSize());
    glTextureSubImage2D(target, layer, x, y, width, height, gl_format, gl_type, data);
  }
  else
  {
    const auto map = sb->Map(TEXTURE_UPLOAD_ALIGNMENT, map_size);
    StringUtil::StrideMemCpy(map.pointer, preferred_pitch, data, pitch, width * GetPixelSize(), height);
    sb->Unmap(map_size);
    sb->Bind();

    glPixelStorei(GL_UNPACK_ROW_LENGTH, preferred_pitch / GetPixelSize());
    glTextureSubImage2D(GL_TEXTURE_2D, layer, x, y, width, height, gl_format, gl_type,
                        reinterpret_cast<void*>(static_cast<uintptr_t>(map.buffer_offset)));

    sb->Unbind();
  }

  glBindTexture(target, 0);

  UnreachableCode();
  return false;
}

bool OpenGLTexture::Map(void** map, u32* map_stride, u32 x, u32 y, u32 width, u32 height, u32 layer /*= 0*/,
                        u32 level /*= 0*/)
{
  if ((x + width) > GetMipWidth(level) || (y + height) > GetMipHeight(level) || layer > m_layers || level > m_levels)
    return false;

  const u32 pitch = Common::AlignUpPow2(static_cast<u32>(width) * GetPixelSize(), TEXTURE_UPLOAD_PITCH_ALIGNMENT);
  const u32 upload_size = pitch * static_cast<u32>(height);
  OpenGLStreamBuffer* sb = OpenGLDevice::GetTextureStreamBuffer();
  if (!sb || upload_size > sb->GetSize())
    return false;

  const auto res = sb->Map(TEXTURE_UPLOAD_ALIGNMENT, upload_size);
  *map = res.pointer;
  *map_stride = pitch;

  m_map_offset = res.buffer_offset;
  m_map_x = static_cast<u16>(x);
  m_map_y = static_cast<u16>(y);
  m_map_width = static_cast<u16>(width);
  m_map_height = static_cast<u16>(height);
  m_map_layer = static_cast<u8>(layer);
  m_map_level = static_cast<u8>(level);
  return true;
}

void OpenGLTexture::Unmap()
{
  CommitClear();

  const u32 pitch = Common::AlignUpPow2(static_cast<u32>(m_map_width) * GetPixelSize(), TEXTURE_UPLOAD_PITCH_ALIGNMENT);
  const u32 upload_size = pitch * static_cast<u32>(m_map_height);
  OpenGLStreamBuffer* sb = OpenGLDevice::GetTextureStreamBuffer();
  sb->Unmap(upload_size);
  sb->Bind();

  glPixelStorei(GL_UNPACK_ROW_LENGTH, m_map_width);

  OpenGLDevice::BindUpdateTextureUnit();

  const GLenum target = GetGLTarget();
  glBindTexture(target, m_id);

  const auto [gl_internal_format, gl_format, gl_type] = GetPixelFormatMapping(m_format);
  if (IsTextureArray())
  {
    glTexSubImage3D(target, m_map_level, m_map_x, m_map_y, m_map_layer, m_map_width, m_map_height, 1, gl_format,
                    gl_type, reinterpret_cast<void*>(static_cast<uintptr_t>(m_map_offset)));
  }
  else
  {
    glTexSubImage2D(target, m_map_level, m_map_x, m_map_y, m_map_width, m_map_height, gl_format, gl_type,
                    reinterpret_cast<void*>(static_cast<uintptr_t>(m_map_offset)));
  }

  glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);

  sb->Unbind();

  glBindTexture(target, 0);
}

void OpenGLTexture::SetDebugName(const std::string_view& name)
{
#ifdef _DEBUG
  if (glObjectLabel)
    glObjectLabel(GL_TEXTURE, m_id, static_cast<GLsizei>(name.length()), static_cast<const GLchar*>(name.data()));
#endif
}

#if 0
// If we don't have border clamp.. too bad, just hope for the best.
if (!m_gl_context->IsGLES() || GLAD_GL_ES_VERSION_3_2 || GLAD_GL_NV_texture_border_clamp ||
  GLAD_GL_EXT_texture_border_clamp || GLAD_GL_OES_texture_border_clamp)
#endif

//////////////////////////////////////////////////////////////////////////

OpenGLSampler::OpenGLSampler(GLuint id) : GPUSampler(), m_id(id)
{
}

OpenGLSampler::~OpenGLSampler()
{
  OpenGLDevice::GetInstance().UnbindSampler(m_id);
}

void OpenGLSampler::SetDebugName(const std::string_view& name)
{
#ifdef _DEBUG
  if (glObjectLabel)
    glObjectLabel(GL_SAMPLER, m_id, static_cast<GLsizei>(name.length()), static_cast<const GLchar*>(name.data()));
#endif
}

std::unique_ptr<GPUSampler> OpenGLDevice::CreateSampler(const GPUSampler::Config& config)
{
  static constexpr std::array<GLenum, static_cast<u8>(GPUSampler::AddressMode::MaxCount)> ta = {{
    GL_REPEAT,          // Repeat
    GL_CLAMP_TO_EDGE,   // ClampToEdge
    GL_CLAMP_TO_BORDER, // ClampToBorder
  }};

  // [mipmap_on_off][mipmap][filter]
  static constexpr GLenum filters[2][2][2] = {
    {
      // mipmap=off
      {GL_NEAREST, GL_LINEAR}, // mipmap=nearest
      {GL_NEAREST, GL_LINEAR}, // mipmap=linear
    },
    {
      // mipmap=on
      {GL_NEAREST_MIPMAP_NEAREST, GL_LINEAR_MIPMAP_NEAREST}, // mipmap=nearest
      {GL_NEAREST_MIPMAP_LINEAR, GL_LINEAR_MIPMAP_LINEAR},   // mipmap=linear
    },
  };

  GLuint sampler;
  glGetError();
  glGenSamplers(1, &sampler);
  if (glGetError() != GL_NO_ERROR)
  {
    Log_ErrorPrintf("Failed to create sampler: %u", sampler);
    return {};
  }

  glSamplerParameteri(sampler, GL_TEXTURE_WRAP_S, ta[static_cast<u8>(config.address_u.GetValue())]);
  glSamplerParameteri(sampler, GL_TEXTURE_WRAP_T, ta[static_cast<u8>(config.address_v.GetValue())]);
  glSamplerParameteri(sampler, GL_TEXTURE_WRAP_R, ta[static_cast<u8>(config.address_w.GetValue())]);
  const u8 mipmap_on_off = (config.min_lod != 0 || config.max_lod != 0);
  glSamplerParameteri(sampler, GL_TEXTURE_MIN_FILTER,
                      filters[mipmap_on_off][static_cast<u8>(config.mip_filter.GetValue())]
                             [static_cast<u8>(config.min_filter.GetValue())]);
  glSamplerParameteri(sampler, GL_TEXTURE_MAG_FILTER,
                      filters[mipmap_on_off][static_cast<u8>(config.mip_filter.GetValue())]
                             [static_cast<u8>(config.mag_filter.GetValue())]);
  glSamplerParameterf(sampler, GL_TEXTURE_MIN_LOD, static_cast<float>(config.min_lod));
  glSamplerParameterf(sampler, GL_TEXTURE_MAX_LOD, static_cast<float>(config.max_lod));
  glSamplerParameterfv(sampler, GL_TEXTURE_BORDER_COLOR, config.GetBorderFloatColor().data());
  if (config.anisotropy)
  {
    // TODO
  }

  return std::unique_ptr<GPUSampler>(new OpenGLSampler(sampler));
}

//////////////////////////////////////////////////////////////////////////

OpenGLFramebuffer::OpenGLFramebuffer(GPUTexture* rt, GPUTexture* ds, u32 width, u32 height, GLuint id)
  : GPUFramebuffer(rt, ds, width, height), m_id(id)
{
}

OpenGLFramebuffer::~OpenGLFramebuffer()
{
  OpenGLDevice::GetInstance().UnbindFramebuffer(this);
}

void OpenGLFramebuffer::SetDebugName(const std::string_view& name)
{
#ifdef _DEBUG
  if (glObjectLabel)
    glObjectLabel(GL_FRAMEBUFFER, m_id, static_cast<GLsizei>(name.length()), static_cast<const GLchar*>(name.data()));
#endif
}

void OpenGLFramebuffer::Bind(GLenum target)
{
  glBindFramebuffer(target, m_id);
}

std::unique_ptr<GPUFramebuffer> OpenGLDevice::CreateFramebuffer(GPUTexture* rt, u32 rt_layer, u32 rt_level,
                                                                GPUTexture* ds, u32 ds_layer, u32 ds_level)
{
  glGetError();

  GLuint fbo_id;
  glGenFramebuffers(1, &fbo_id);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, fbo_id);

  OpenGLTexture* RT = static_cast<OpenGLTexture*>(rt);
  OpenGLTexture* DS = static_cast<OpenGLTexture*>(ds);
  if (RT)
  {
    if (RT->IsTextureArray())
      glFramebufferTextureLayer(GL_DRAW_FRAMEBUFFER, fbo_id, RT->GetGLId(), rt_level, rt_layer);
    else
      glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, RT->GetGLId(), rt_level);
  }
  if (DS)
  {
    if (DS->IsTextureArray())
      glFramebufferTextureLayer(GL_DRAW_FRAMEBUFFER, fbo_id, DS->GetGLId(), rt_level, rt_layer);
    else
      glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_TEXTURE_2D, DS->GetGLId(), rt_level);
  }

  if (glGetError() != GL_NO_ERROR || glCheckFramebufferStatus(GL_DRAW_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
  {
    Log_ErrorPrintf("Failed to create GL framebuffer: %u", glGetError());
    glDeleteFramebuffers(1, &fbo_id);
    return {};
  }

  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, m_current_framebuffer ? m_current_framebuffer->GetGLId() : 0);
  return std::unique_ptr<GPUFramebuffer>(
    new OpenGLFramebuffer(rt, ds, rt ? rt->GetMipWidth(rt_level) : ds->GetMipWidth(ds_level),
                          rt ? rt->GetMipHeight(rt_level) : ds->GetMipHeight(ds_level), fbo_id));
}

void OpenGLDevice::CommitClear(OpenGLTexture* tex)
{
  switch (tex->GetState())
  {
    case GPUTexture::State::Invalidated:
    {
      tex->SetState(GPUTexture::State::Dirty);

      if (glInvalidateTexImage)
      {
        glInvalidateTexImage(tex->GetGLId(), 0);
      }
      else if (glInvalidateFramebuffer)
      {
        glBindFramebuffer(GL_DRAW_FRAMEBUFFER, m_write_fbo);

        const GLenum attachment = tex->IsDepthStencil() ? GL_DEPTH_ATTACHMENT : GL_COLOR_ATTACHMENT0;
        if (tex->IsTextureArray())
          glFramebufferTextureLayer(GL_DRAW_FRAMEBUFFER, attachment, tex->GetGLId(), 0, 0);
        else
          glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, attachment, GL_TEXTURE_2D, tex->GetGLId(), 0);

        glInvalidateFramebuffer(GL_DRAW_FRAMEBUFFER, 1, &attachment);

        glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, attachment, GL_TEXTURE_2D, 0, 0);
        glBindFramebuffer(GL_DRAW_FRAMEBUFFER, m_current_framebuffer ? m_current_framebuffer->GetGLId() : 0);
      }
    }
    break;

    case GPUTexture::State::Cleared:
    {
      tex->SetState(GPUTexture::State::Dirty);

      if (glClearTexImage)
      {
        const auto [gl_internal_format, gl_format, gl_type] = OpenGLTexture::GetPixelFormatMapping(tex->GetFormat());
        glClearTexImage(tex->GetGLId(), 0, gl_format, gl_type, &tex->GetClearValue());
      }
      else
      {
        glBindFramebuffer(GL_DRAW_FRAMEBUFFER, m_write_fbo);

        const GLenum attachment = tex->IsDepthStencil() ? GL_DEPTH_ATTACHMENT : GL_COLOR_ATTACHMENT0;
        if (tex->IsTextureArray())
          glFramebufferTextureLayer(GL_DRAW_FRAMEBUFFER, attachment, tex->GetGLId(), 0, 0);
        else
          glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, attachment, GL_TEXTURE_2D, tex->GetGLId(), 0);

        glDisable(GL_SCISSOR_TEST);
        if (tex->IsDepthStencil())
        {
          glClearDepth(tex->GetClearDepth());
          glClear(GL_DEPTH_BUFFER_BIT);
        }
        else
        {
          const auto color = tex->GetUNormClearColor();
          glClearColor(color[0], color[1], color[2], color[3]);
          glClear(GL_COLOR_BUFFER_BIT);
        }
        glEnable(GL_SCISSOR_TEST);

        glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, attachment, GL_TEXTURE_2D, 0, 0);
        glBindFramebuffer(GL_DRAW_FRAMEBUFFER, m_current_framebuffer ? m_current_framebuffer->GetGLId() : 0);
      }
    }
    break;

    case GPUTexture::State::Dirty:
      break;

    default:
      UnreachableCode();
      break;
  }
}

void OpenGLDevice::CommitClear(OpenGLFramebuffer* fb)
{
  GLenum clear_flags = 0;
  GLenum invalidate_attachments[2];
  GLuint num_invalidate_attachments = 0;

  if (OpenGLTexture* FB = static_cast<OpenGLTexture*>(fb->GetRT()))
  {
    switch (FB->GetState())
    {
      case GPUTexture::State::Invalidated:
      {
        invalidate_attachments[num_invalidate_attachments++] = GL_COLOR_ATTACHMENT0;
        FB->SetState(GPUTexture::State::Dirty);
      }
      break;

      case GPUTexture::State::Cleared:
      {
        const auto color = FB->GetUNormClearColor();
        glClearColor(color[0], color[1], color[2], color[3]);
        clear_flags |= GL_COLOR_BUFFER_BIT;
        FB->SetState(GPUTexture::State::Dirty);
      }

      case GPUTexture::State::Dirty:
        break;

      default:
        UnreachableCode();
        break;
    }
  }
  if (OpenGLTexture* DS = static_cast<OpenGLTexture*>(fb->GetDS()))
  {
    switch (DS->GetState())
    {
      case GPUTexture::State::Invalidated:
      {
        invalidate_attachments[num_invalidate_attachments++] = GL_DEPTH_ATTACHMENT;
        DS->SetState(GPUTexture::State::Dirty);
      }
      break;

      case GPUTexture::State::Cleared:
      {
        glClearDepth(DS->GetClearDepth());
        clear_flags |= GL_DEPTH_BUFFER_BIT;
        DS->SetState(GPUTexture::State::Dirty);
      }
      break;

      case GPUTexture::State::Dirty:
        break;

      default:
        UnreachableCode();
        break;
    }
  }

  if (clear_flags != 0)
  {
    glDisable(GL_SCISSOR_TEST);
    glClear(clear_flags);
    glEnable(GL_SCISSOR_TEST);
  }
  if (num_invalidate_attachments > 0 && glInvalidateFramebuffer)
    glInvalidateFramebuffer(GL_DRAW_FRAMEBUFFER, num_invalidate_attachments, invalidate_attachments);
}

//////////////////////////////////////////////////////////////////////////

OpenGLTextureBuffer::OpenGLTextureBuffer(Format format, u32 size_in_elements,
                                         std::unique_ptr<OpenGLStreamBuffer> buffer, GLuint texture_id)
  : GPUTextureBuffer(format, size_in_elements), m_buffer(std::move(buffer)), m_texture_id(texture_id)
{
}

OpenGLTextureBuffer::~OpenGLTextureBuffer()
{
  // TODO: unbind ssbo
  if (m_texture_id != 0)
  {
    OpenGLDevice::GetInstance().UnbindTexture(m_texture_id);
    glDeleteTextures(1, &m_texture_id);
  }
}

bool OpenGLTextureBuffer::CreateBuffer()
{
  const bool use_ssbo = OpenGLDevice::GetInstance().GetFeatures().texture_buffers_emulated_with_ssbo;

  const GLenum target = (use_ssbo ? GL_SHADER_STORAGE_BUFFER : GL_TEXTURE_BUFFER);
  m_buffer = OpenGLStreamBuffer::Create(target, GetSizeInBytes());
  if (!m_buffer)
    return false;

  if (!use_ssbo)
  {
    glGetError();
    glGenTextures(1, &m_texture_id);
    if (const GLenum err = glGetError(); err != GL_NO_ERROR)
    {
      Log_ErrorPrintf("Failed to create texture for buffer: %u", err);
      return false;
    }

    OpenGLDevice::BindUpdateTextureUnit();
    glBindTexture(GL_TEXTURE_BUFFER, m_texture_id);
    glTexBuffer(GL_TEXTURE_BUFFER, GL_R16UI, m_buffer->GetGLBufferId());
  }

  m_buffer->Unbind();

  return true;
}

void* OpenGLTextureBuffer::Map(u32 required_elements)
{
  const u32 esize = GetElementSize(m_format);
  const auto map = m_buffer->Map(esize, esize * required_elements);
  m_current_position = map.index_aligned;
  return map.pointer;
}

void OpenGLTextureBuffer::Unmap(u32 used_elements)
{
  m_buffer->Unmap(used_elements * GetElementSize(m_format));
}

std::unique_ptr<GPUTextureBuffer> OpenGLDevice::CreateTextureBuffer(GPUTextureBuffer::Format format,
                                                                    u32 size_in_elements)
{
  const bool use_ssbo = OpenGLDevice::GetInstance().GetFeatures().texture_buffers_emulated_with_ssbo;

  const GLenum target = (use_ssbo ? GL_SHADER_STORAGE_BUFFER : GL_TEXTURE_BUFFER);
  std::unique_ptr<OpenGLStreamBuffer> buffer =
    OpenGLStreamBuffer::Create(target, GPUTextureBuffer::GetElementSize(format) * size_in_elements);
  if (!buffer)
    return {};
  buffer->Unbind();

  GLuint texture_id = 0;
  if (!use_ssbo)
  {
    glGetError();
    glGenTextures(1, &texture_id);
    if (const GLenum err = glGetError(); err != GL_NO_ERROR)
    {
      Log_ErrorPrintf("Failed to create texture for buffer: %u", err);
      return {};
    }

    OpenGLDevice::BindUpdateTextureUnit();
    glBindTexture(GL_TEXTURE_BUFFER, texture_id);
    glTexBuffer(GL_TEXTURE_BUFFER, GL_R16UI, buffer->GetGLBufferId());
  }

  return std::unique_ptr<GPUTextureBuffer>(
    new OpenGLTextureBuffer(format, size_in_elements, std::move(buffer), texture_id));
}