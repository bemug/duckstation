// SPDX-FileCopyrightText: 2002-2024 PCSX2 Dev Team
// SPDX-License-Identifier: LGPL-3.0+

#include "pine_server.h"
#include "cpu_core.h"
#include "host.h"
#include "settings.h"
#include "system.h"

#include "scmversion/scmversion.h"

#include "util/platform_misc.h"
#include "util/sockets.h"

#include "common/binary_span_reader_writer.h"
#include "common/error.h"
#include "common/file_system.h"
#include "common/log.h"
#include "common/path.h"
#include "common/small_string.h"

#include "fmt/format.h"

Log_SetChannel(PINEServer);

#define PINE_EMULATOR_NAME "duckstation"

namespace PINEServer {
static int m_slot;
static std::unique_ptr<SocketMultiplexer> m_multiplexer;
static std::shared_ptr<ListenSocket> m_listen_socket;

/**
 * Maximum memory used by an IPC message request.
 * Equivalent to 50,000 Write64 requests.
 */
static constexpr u32 MAX_IPC_SIZE = 650000;

/**
 * Maximum memory used by an IPC message reply.
 * Equivalent to 50,000 Read64 replies.
 */
static constexpr u32 MAX_IPC_RETURN_SIZE = 450000;

/**
 * IPC Command messages opcodes.
 * A list of possible operations possible by the IPC.
 * Each one of them is what we call an "opcode" and is the first
 * byte sent by the IPC to differentiate between commands.
 */
enum IPCCommand : unsigned char
{
  MsgRead8 = 0,           /**< Read 8 bit value to memory. */
  MsgRead16 = 1,          /**< Read 16 bit value to memory. */
  MsgRead32 = 2,          /**< Read 32 bit value to memory. */
  MsgRead64 = 3,          /**< Read 64 bit value to memory. */
  MsgWrite8 = 4,          /**< Write 8 bit value to memory. */
  MsgWrite16 = 5,         /**< Write 16 bit value to memory. */
  MsgWrite32 = 6,         /**< Write 32 bit value to memory. */
  MsgWrite64 = 7,         /**< Write 64 bit value to memory. */
  MsgVersion = 8,         /**< Returns PCSX2 version. */
  MsgSaveState = 9,       /**< Saves a savestate. */
  MsgLoadState = 0xA,     /**< Loads a savestate. */
  MsgTitle = 0xB,         /**< Returns the game title. */
  MsgID = 0xC,            /**< Returns the game ID. */
  MsgUUID = 0xD,          /**< Returns the game UUID. */
  MsgGameVersion = 0xE,   /**< Returns the game verion. */
  MsgStatus = 0xF,        /**< Returns the emulator status. */
  MsgUnimplemented = 0xFF /**< Unimplemented IPC message. */
};

/**
 * Emulator status enum.
 * A list of possible emulator statuses.
 */
enum EmuStatus : uint32_t
{
  Running = 0, /**< Game is running */
  Paused = 1,  /**< Game is paused */
  Shutdown = 2 /**< Game is shutdown */
};

/**
 * IPC result codes.
 * A list of possible result codes the IPC can send back.
 * Each one of them is what we call an "opcode" or "tag" and is the
 * first byte sent by the IPC to differentiate between results.
 */
enum IPCResult : unsigned char
{
  IPC_OK = 0,     /**< IPC command successfully completed. */
  IPC_FAIL = 0xFF /**< IPC command failed to complete. */
};

namespace {
class PINESocket final : public BufferedStreamSocket
{
public:
  PINESocket();
  ~PINESocket() override;

protected:
  void OnConnected() override;
  void OnDisconnected(const Error& error) override;
  void OnRead() override;

private:
  void HandleCommand(IPCCommand command, BinarySpanReader rdbuf);

  BinarySpanWriter BeginSuccessReply(size_t required_bytes);
  void EndReply(const BinarySpanWriter& sw);

  void SendSuccessReply();
  void SendErrorReply();
};
} // namespace
} // namespace PINEServer

bool PINEServer::Initialize(u16 slot)
{
  m_slot = slot;

  Error error;
  m_multiplexer = SocketMultiplexer::Create(&error);
  if (!m_multiplexer)
  {
    ERROR_LOG("PINE: Failed to create multiplexer: {}", error.GetDescription());
    Deinitialize();
    return false;
  }

  std::optional<SocketAddress> address;
#ifdef _WIN32
  address = SocketAddress::Parse(SocketAddress::Type_IPv4, "127.0.0.1", slot, &error);
#else
  char* runtime_dir = nullptr;
#ifdef __APPLE__
  runtime_dir = std::getenv("TMPDIR");
#else
  runtime_dir = std::getenv("XDG_RUNTIME_DIR");
#endif
  // fallback in case macOS or other OSes don't implement the XDG base
  // spec
  if (runtime_dir == nullptr)
    m_socket_name = "/tmp/" PINE_EMULATOR_NAME ".sock";
  else
  {
    m_socket_name = runtime_dir;
    m_socket_name += "/" PINE_EMULATOR_NAME ".sock";
  }

  if (slot != Settings::DEFAULT_PINE_SLOT)
    m_socket_name += "." + std::to_string(slot);

  struct sockaddr_un server;

  m_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  server.sun_family = AF_UNIX;
  strcpy(server.sun_path, m_socket_name.c_str());

  // we unlink the socket so that when releasing this thread the socket gets
  // freed even if we didn't close correctly the loop
  unlink(m_socket_name.c_str());
  if (bind(m_sock, (struct sockaddr*)&server, sizeof(struct sockaddr_un)))
  {
    ERROR_LOG("PINE: Error while binding to socket! Shutting down...");
    Deinitialize();
    return false;
  }
#endif

  if (!address.has_value())
  {
    ERROR_LOG("PINE: Failed to resolve listen address: {}", error.GetDescription());
    Deinitialize();
    return false;
  }

  m_listen_socket = m_multiplexer->CreateListenSocket<PINESocket>(address.value(), &error);
  if (!m_listen_socket)
  {
    ERROR_LOG("PINE: Failed to create listen socket: {}", error.GetDescription());
    Deinitialize();
    return false;
  }

  return true;
}

bool PINEServer::IsInitialized()
{
  return static_cast<bool>(m_listen_socket);
}

int PINEServer::GetSlot()
{
  return m_slot;
}

PINEServer::PINESocket::PINESocket() : BufferedStreamSocket(MAX_IPC_SIZE, MAX_IPC_RETURN_SIZE)
{
}

PINEServer::PINESocket::~PINESocket() = default;

void PINEServer::PINESocket::OnConnected()
{
  INFO_LOG("PINE: New client at {} connected.", GetRemoteAddress().ToString());
}

void PINEServer::PINESocket::OnDisconnected(const Error& error)
{
  INFO_LOG("PINE: Client {} disconnected: {}", GetRemoteAddress().ToString(), error.GetDescription());
}

void PINEServer::PINESocket::OnRead()
{
  std::span<const u8> rdbuf = AcquireReadBuffer();

  size_t position = 0;
  size_t remaining = rdbuf.size();
  while (remaining >= sizeof(u32))
  {
    u32 packet_size;
    std::memcpy(&packet_size, &rdbuf[position], sizeof(u32));
    if (packet_size > MAX_IPC_SIZE || packet_size < 5)
    {
      ERROR_LOG("PINE: Received invalid packet size {}", packet_size);
      Close();
      return;
    }

    // whole thing received yet yet?
    if (packet_size > remaining)
      break;

    const IPCCommand command = static_cast<IPCCommand>(rdbuf[position + sizeof(u32)]);
    HandleCommand(command, BinarySpanReader(rdbuf.subspan(position + sizeof(u32) + sizeof(u8),
                                                          packet_size - sizeof(u32) - sizeof(u8))));
    position += packet_size;
    remaining -= packet_size;
  }
}

void PINEServer::Deinitialize()
{
  // also closes the listener
  m_listen_socket.reset();
  m_multiplexer.reset();

#ifndef _WIN32
  if (!m_socket_name.empty())
  {
    unlink(m_socket_name.c_str());
    m_socket_name = {};
  }
#endif
}

void PINEServer::Poll()
{
  if (m_multiplexer)
    m_multiplexer->PollEventsWithTimeout(0);
}

void PINEServer::PINESocket::HandleCommand(IPCCommand command, BinarySpanReader rdbuf)
{
  // example IPC messages: MsgRead/Write
  // refer to the client doc for more info on the format
  //         IPC Message event (1 byte)
  //         |  Memory address (4 byte)
  //         |  |           argument (VLE)
  //         |  |           |
  // format: XX YY YY YY YY ZZ ZZ ZZ ZZ
  //        reply code: 00 = OK, FF = NOT OK
  //        |  return value (VLE)
  //        |  |
  // reply: XX ZZ ZZ ZZ ZZ
  switch (command)
  {
    case MsgRead8:
    {
      if (!rdbuf.CheckRemaining(sizeof(PhysicalMemoryAddress)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const PhysicalMemoryAddress addr = rdbuf.ReadU32();
      u8 res;
      if (!CPU::SafeReadMemoryByte(addr, &res))
      {
        SendErrorReply();
        return;
      }

      if (BinarySpanWriter wrbuf = BeginSuccessReply(sizeof(res)); wrbuf.IsValid())
      {
        wrbuf << res;
        EndReply(wrbuf);
      }
    }
    break;

    case MsgRead16:
    {
      if (!rdbuf.CheckRemaining(sizeof(PhysicalMemoryAddress)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const PhysicalMemoryAddress addr = rdbuf.ReadU32();
      u16 res;
      if (!CPU::SafeReadMemoryHalfWord(addr, &res))
      {
        SendErrorReply();
        return;
      }

      if (BinarySpanWriter wrbuf = BeginSuccessReply(sizeof(res)); wrbuf.IsValid())
      {
        wrbuf << res;
        EndReply(wrbuf);
      }
    }
    break;

    case MsgRead32:
    {
      if (!rdbuf.CheckRemaining(sizeof(PhysicalMemoryAddress)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const PhysicalMemoryAddress addr = rdbuf.ReadU32();
      u32 res;
      if (!CPU::SafeReadMemoryWord(addr, &res))
      {
        SendErrorReply();
        return;
      }

      if (BinarySpanWriter wrbuf = BeginSuccessReply(sizeof(res)); wrbuf.IsValid())
      {
        wrbuf << res;
        EndReply(wrbuf);
      }
    }
    break;

    case MsgRead64:
    {
      if (!rdbuf.CheckRemaining(sizeof(PhysicalMemoryAddress)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const PhysicalMemoryAddress addr = rdbuf.ReadU32();
      u32 res_low, res_high;
      if (!CPU::SafeReadMemoryWord(addr, &res_low) || !CPU::SafeReadMemoryWord(addr + sizeof(u32), &res_high))
      {
        SendErrorReply();
        return;
      }

      if (BinarySpanWriter wrbuf = BeginSuccessReply(sizeof(u64)); wrbuf.IsValid())
      {
        wrbuf << ((ZeroExtend64(res_high) << 32) | ZeroExtend64(res_low));
        EndReply(wrbuf);
      }
    }
    break;

    case MsgWrite8:
    {
      if (!rdbuf.CheckRemaining(sizeof(PhysicalMemoryAddress) + sizeof(u8)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const PhysicalMemoryAddress addr = rdbuf.ReadU32();
      const u8 value = rdbuf.ReadU8();
      if (!CPU::SafeWriteMemoryByte(addr, value))
        SendErrorReply();
      else
        SendSuccessReply();
    }
    break;

    case MsgWrite16:
    {
      if (!rdbuf.CheckRemaining(sizeof(PhysicalMemoryAddress) + sizeof(u16)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const PhysicalMemoryAddress addr = rdbuf.ReadU32();
      const u16 value = rdbuf.ReadU16();
      if (!CPU::SafeWriteMemoryHalfWord(addr, value))
        SendErrorReply();
      else
        SendSuccessReply();
    }
    break;

    case MsgWrite32:
    {
      if (!rdbuf.CheckRemaining(sizeof(PhysicalMemoryAddress) + sizeof(u32)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const PhysicalMemoryAddress addr = rdbuf.ReadU32();
      const u32 value = rdbuf.ReadU32();
      if (!CPU::SafeWriteMemoryWord(addr, value))
        SendErrorReply();
      else
        SendSuccessReply();
    }
    break;

    case MsgWrite64:
    {
      if (!rdbuf.CheckRemaining(sizeof(PhysicalMemoryAddress) + sizeof(u64)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const PhysicalMemoryAddress addr = rdbuf.ReadU32();
      const u64 value = rdbuf.ReadU64();
      if (!CPU::SafeWriteMemoryWord(addr, Truncate32(value)) ||
          !CPU::SafeWriteMemoryWord(addr + sizeof(u32), Truncate32(value >> 32)))
      {
        SendErrorReply();
      }
      else
      {
        SendSuccessReply();
      }
    }
    break;

    case MsgVersion:
    {
      if (!System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const TinyString version = TinyString::from_format("DuckStation {}", g_scm_tag_str);
      if (BinarySpanWriter wrbuf = BeginSuccessReply(version.length() + 1); wrbuf.IsValid())
      {
        wrbuf << version;
        EndReply(wrbuf);
      }
    }
    break;

    case MsgSaveState:
    {
      if (!rdbuf.CheckRemaining(sizeof(u8)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const std::string& serial = System::GetGameSerial();
      if (!serial.empty())
      {
        SendErrorReply();
        return;
      }

      std::string state_filename = System::GetGameSaveStateFileName(serial, rdbuf.ReadU8());
      Host::RunOnCPUThread([state_filename = std::move(state_filename)] {
        Error error;
        if (!System::SaveState(state_filename.c_str(), &error, false))
          ERROR_LOG("PINE: Save state failed: {}", error.GetDescription());
      });

      SendSuccessReply();
    }
    break;

    case MsgLoadState:
    {
      if (!rdbuf.CheckRemaining(sizeof(u8)) || !System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const std::string& serial = System::GetGameSerial();
      if (!serial.empty())
      {
        SendErrorReply();
        return;
      }

      std::string state_filename = System::GetGameSaveStateFileName(serial, rdbuf.ReadU8());
      if (!FileSystem::FileExists(state_filename.c_str()))
      {
        SendErrorReply();
        return;
      }

      Host::RunOnCPUThread([state_filename = std::move(state_filename)] {
        Error error;
        if (!System::LoadState(state_filename.c_str(), &error))
          ERROR_LOG("PINE: Load state failed: {}", error.GetDescription());
      });

      SendSuccessReply();
    }
    break;

    case MsgTitle:
    {
      if (!System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const std::string& name = System::GetGameTitle();
      if (BinarySpanWriter wrbuf = BeginSuccessReply(name.length() + 1); wrbuf.IsValid())
      {
        wrbuf << name;
        EndReply(wrbuf);
      }
    }
    break;

    case MsgID:
    {
      if (!System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const std::string& serial = System::GetGameSerial();
      if (BinarySpanWriter wrbuf = BeginSuccessReply(serial.length() + 1); wrbuf.IsValid())
      {
        wrbuf << serial;
        EndReply(wrbuf);
      }
    }
    break;

    case MsgUUID:
    {
      if (!System::IsValid())
      {
        SendErrorReply();
        return;
      }

      const std::string crc = fmt::format("{:016x}", System::GetGameHash());
      if (BinarySpanWriter wrbuf = BeginSuccessReply(crc.length() + 1); wrbuf.IsValid())
      {
        wrbuf << crc;
        EndReply(wrbuf);
      }
    }
    break;

    case MsgGameVersion:
    {
      ERROR_LOG("PINE: MsgGameVersion not supported.");
      SendErrorReply();
    }
    break;

    case MsgStatus:
    {
      EmuStatus status;
      switch (System::GetState())
      {
        case System::State::Running:
          status = EmuStatus::Running;
          break;
        case System::State::Paused:
          status = EmuStatus::Paused;
          break;
        default:
          status = EmuStatus::Shutdown;
          break;
      }

      const std::string crc = fmt::format("{:016x}", System::GetGameHash());
      if (BinarySpanWriter wrbuf = BeginSuccessReply(sizeof(u32)); wrbuf.IsValid())
      {
        wrbuf << static_cast<u32>(status);
        EndReply(wrbuf);
      }
    }
    break;

    default:
    {
      ERROR_LOG("PINE: Unhandled IPC command {:02X}", static_cast<u8>(command));
      SendErrorReply();
    }
    break;
  }
}

BinarySpanWriter PINEServer::PINESocket::BeginSuccessReply(size_t required_bytes)
{
  BinarySpanWriter ret(AcquireWriteBuffer(sizeof(u32) + sizeof(u8) + required_bytes, false));
  if (ret.IsValid()) [[likely]]
  {
    ret << static_cast<u32>(0); // size placeholder
    ret << static_cast<u8>(IPC_OK);
  }

  return ret;
}

void PINEServer::PINESocket::EndReply(const BinarySpanWriter& sw)
{
  DebugAssert(sw.IsValid());
  const u32 total_size = sw.GetBufferWritten();
  std::memcpy(&sw.GetSpan()[0], &total_size, sizeof(u32));
  ReleaseWriteBuffer(sw.GetBufferWritten());
}

void PINEServer::PINESocket::SendSuccessReply()
{
  if (BinarySpanWriter wrbuf = BeginSuccessReply(sizeof(u32)); wrbuf.IsValid())
    EndReply(wrbuf);
}

void PINEServer::PINESocket::SendErrorReply()
{
  BinarySpanWriter sw(AcquireWriteBuffer(sizeof(u32) + sizeof(u8), false));
  if (!sw.IsValid())
    return;

  sw << static_cast<u32>(sizeof(u32) + sizeof(u8)); // size
  sw << static_cast<u8>(IPC_FAIL);
  ReleaseWriteBuffer(sw.GetBufferWritten());
}
