// SPDX-FileCopyrightText: 2015-2024 Connor McLaughlin <stenzek@gmail.com>
// SPDX-License-Identifier: (GPL-3.0 OR CC-BY-NC-ND-4.0)

#include "sockets.h"
#include "platform_misc.h"

#include "common/assert.h"
#include "common/log.h"

#include <algorithm>
#include <cstring>
#include <limits>

#ifdef _WIN32

#include "common/windows_headers.h"

#include <WS2tcpip.h>
#include <WinSock2.h>

#define SIZE_CAST(x) static_cast<int>(x)
using ssize_t = int;

#else

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define ioctlsocket ioctl
#define closesocket close
#define WSAEWOULDBLOCK EAGAIN
#define WSAGetLastError() errno
#define SIZE_CAST(x) x

#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
#endif

Log_SetChannel(Sockets);

void SocketAddress::SetFromSockaddr(const void* sa, size_t length)
{
  m_length = std::min(static_cast<u32>(length), static_cast<u32>(sizeof(m_data)));
  std::memcpy(m_data, sa, m_length);
  if (m_length < sizeof(m_data))
    std::memset(m_data + m_length, 0, sizeof(m_data) - m_length);
}

std::optional<SocketAddress> SocketAddress::Parse(Type type, const char* address, u32 port, Error* error)
{
  std::optional<SocketAddress> ret = SocketAddress();

  switch (type)
  {
    case Type_IPv4:
    {
      sockaddr_in* sain = reinterpret_cast<sockaddr_in*>(ret->m_data);
      std::memset(sain, 0, sizeof(sockaddr_in));
      sain->sin_family = AF_INET;
      sain->sin_port = htons(static_cast<u16>(port));
      int res = inet_pton(AF_INET, address, &sain->sin_addr);
      if (res == 1)
      {
        ret->m_length = sizeof(sockaddr_in);
      }
      else
      {
        Error::SetSocket(error, "inet_pton() failed: ", WSAGetLastError());
        ret.reset();
      }
    }
    break;

    case Type_IPv6:
    {
      sockaddr_in6* sain6 = reinterpret_cast<sockaddr_in6*>(ret->m_data);
      std::memset(sain6, 0, sizeof(sockaddr_in6));
      sain6->sin6_family = AF_INET;
      sain6->sin6_port = htons(static_cast<u16>(port));
      int res = inet_pton(AF_INET6, address, &sain6->sin6_addr);
      if (res == 1)
      {
        ret->m_length = sizeof(sockaddr_in6);
      }
      else
      {
        Error::SetSocket(error, "inet_pton() failed: ", WSAGetLastError());
        ret.reset();
      }
    }
    break;

    default:
      Error::SetStringView(error, "Unknown address type.");
      ret.reset();
      break;
  }

  return ret;
}

SmallString SocketAddress::ToString() const
{
  SmallString ret;

  const sockaddr* sa = reinterpret_cast<const sockaddr*>(m_data);
  switch (sa->sa_family)
  {
    case AF_INET:
    {
      ret.clear();
      ret.reserve(128);
      const char* res =
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(m_data)->sin_addr, ret.data(), ret.buffer_size());
      if (res == nullptr)
        ret.assign("<unknown>");
      else
        ret.update_size();

      ret.append_format(":{}", static_cast<u32>(ntohs(reinterpret_cast<const sockaddr_in*>(m_data)->sin_port)));
      break;
    }

    case AF_INET6:
    {
      ret.clear();
      ret.reserve(128);
      ret.append('[');
      const char* res = inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(m_data)->sin6_addr, ret.data() + 1,
                                  ret.buffer_size() - 1);
      if (res == nullptr)
        ret.assign("<unknown>");
      else
        ret.update_size();

      ret.append_format("]:{}", static_cast<u32>(ntohs(reinterpret_cast<const sockaddr_in6*>(m_data)->sin6_port)));
      break;
    }

    default:
    {
      ret.assign("<unknown>");
      break;
    }
  }

  return ret;
}

BaseSocket::BaseSocket() = default;

BaseSocket::~BaseSocket() = default;

SocketMultiplexer::SocketMultiplexer() = default;

SocketMultiplexer::~SocketMultiplexer()
{
  // StopWorkerThread();
  CloseAll();
}

std::unique_ptr<SocketMultiplexer> SocketMultiplexer::Create(Error* error)
{
  if (!PlatformMisc::InitializeSocketSupport(error))
    return {};

  return std::unique_ptr<SocketMultiplexer>(new SocketMultiplexer());
}

std::shared_ptr<ListenSocket> SocketMultiplexer::InternalCreateListenSocket(const SocketAddress& address,
                                                                            CreateStreamSocketCallback callback,
                                                                            Error* error)
{
  // create and bind socket
  const sockaddr* sa = reinterpret_cast<const sockaddr*>(address.GetData());
  SocketDescriptor descriptor = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (descriptor == INVALID_SOCKET)
  {
    Error::SetSocket(error, "socket() failed", WSAGetLastError());
    return {};
  }

  const int reuseaddr_enable = 1;
  if (setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuseaddr_enable),
                 sizeof(reuseaddr_enable)) < 0)
  {
    WARNING_LOG("Failed to set SO_REUSEADDR: {}", Error::CreateSocket(WSAGetLastError()).GetDescription());
  }

  if (bind(descriptor, sa, address.GetLength()) < 0)
  {
    Error::SetSocket(error, "bind() failed", WSAGetLastError());
    closesocket(descriptor);
    return {};
  }

  if (listen(descriptor, 5) < 0)
  {
    Error::SetSocket(error, "listen() failed", WSAGetLastError());
    closesocket(descriptor);
    return {};
  }

  // create listensocket
  std::shared_ptr<ListenSocket> ret = std::make_shared<ListenSocket>(this, callback, descriptor);

  // add to list, register for reads
  AddOpenSocket(std::static_pointer_cast<BaseSocket>(ret));
  SetNotificationMask(ret.get(), descriptor, SocketMultiplexer::EventType_Read);
  return ret;
}

std::shared_ptr<StreamSocket> SocketMultiplexer::InternalConnectStreamSocket(const SocketAddress& address,
                                                                             CreateStreamSocketCallback callback,
                                                                             Error* error)
{
  // create and bind socket
  const sockaddr* sa = reinterpret_cast<const sockaddr*>(address.GetData());
  SocketDescriptor descriptor = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (descriptor == INVALID_SOCKET)
  {
    Error::SetSocket(error, "socket() failed", WSAGetLastError());
    return {};
  }

  if (connect(descriptor, sa, address.GetLength()) < 0)
  {
    Error::SetSocket(error, "connect() failed", WSAGetLastError());
    closesocket(descriptor);
    return {};
  }

  // create stream socket
  std::shared_ptr<StreamSocket> csocket = callback();
  if (!csocket->InitializeSocket(this, descriptor, error))
    csocket.reset();

  return csocket;
}

void SocketMultiplexer::AddOpenSocket(std::shared_ptr<BaseSocket> socket)
{
  std::unique_lock lock(m_open_sockets_lock);

  DebugAssert(std::find(m_open_sockets.begin(), m_open_sockets.end(), socket) == m_open_sockets.end());
  m_open_sockets.push_back(std::move(socket));
}

void SocketMultiplexer::RemoveOpenSocket(BaseSocket* socket)
{
  std::unique_lock lock(m_open_sockets_lock);

#ifdef _DEBUG
  // double-locking, living dangerously!
  std::unique_lock lock2(m_bound_sockets_lock);
  DebugAssert(std::find_if(m_bound_sockets.begin(), m_bound_sockets.end(),
                           [&socket](const BoundSocket& bs) { return bs.socket == socket; }) == m_bound_sockets.end());
#endif

  const auto iter = std::find_if(m_open_sockets.begin(), m_open_sockets.end(),
                                 [&socket](const std::shared_ptr<BaseSocket>& rhs) { return rhs.get() == socket; });
  Assert(iter != m_open_sockets.end());
  m_open_sockets.erase(iter);
}

void SocketMultiplexer::CloseAll()
{
  std::unique_lock lock(m_open_sockets_lock);

  if (!m_open_sockets.empty())
  {
    // pull everything into a list first
    const size_t num_sockets = m_open_sockets.size();
    std::shared_ptr<BaseSocket>* const sockets =
      reinterpret_cast<std::shared_ptr<BaseSocket>*>(alloca(sizeof(std::shared_ptr<BaseSocket>) * num_sockets));
    for (size_t i = 0; i < num_sockets; i++)
      new (&sockets[i]) std::shared_ptr<BaseSocket>(m_open_sockets[i]);

    // unlock the list
    lock.unlock();

    // close all sockets
    for (size_t i = 0; i < num_sockets; i++)
    {
      sockets[i]->Close();
      sockets[i].~shared_ptr();
    }
  }
}

void SocketMultiplexer::SetNotificationMask(BaseSocket* socket, SocketDescriptor descriptor, u32 mask)
{
  std::unique_lock lock(m_open_sockets_lock);

  const auto iter = std::find_if(m_bound_sockets.begin(), m_bound_sockets.end(),
                                 [&descriptor](const BoundSocket& it) { return (it.descriptor == descriptor); });
  if (iter != m_bound_sockets.end())
  {
    DebugAssert(iter->socket == socket);

    // unbinding?
    if (mask != 0)
      iter->event_mask = mask;
    else
      m_bound_sockets.erase(iter);

    return;
  }

  // don't create entries for null masks
  if (mask != 0)
    m_bound_sockets.emplace_back(socket, descriptor, mask);
}

bool SocketMultiplexer::PollEventsWithTimeout(u32 milliseconds)
{
  // TODO: Convert this over to poll(), Windows has had it for ages.
  fd_set read_fds;
  fd_set write_fds;
  SocketDescriptor max_fd = 0;
  u32 set_count = 0;

  // clear set
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);

  // fill stuff
  {
    std::unique_lock lock(m_bound_sockets_lock);
    for (BoundSocket& bs : m_bound_sockets)
    {
      if (bs.event_mask & EventType_Read)
        FD_SET(bs.descriptor, &read_fds);
      if (bs.event_mask & EventType_Write)
        FD_SET(bs.descriptor, &write_fds);

      max_fd = std::max(bs.descriptor, max_fd);
      set_count++;
    }
  }

  if (set_count == 0)
    return false;

  // call select
  timeval tv;
  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;
  const int result = select(static_cast<int>(max_fd) + 1, &read_fds, &write_fds, nullptr,
                            (milliseconds != std::numeric_limits<u32>::max()) ? &tv : nullptr);
  if (result <= 0)
    return true;

  // find sockets that triggered, we use an array here so we can avoid holding the lock, and if a socket disconnects
  using PendingSocketPair = std::pair<std::shared_ptr<BaseSocket>, u32>;
  PendingSocketPair* triggered_sockets =
    reinterpret_cast<PendingSocketPair*>(alloca(sizeof(PendingSocketPair) * set_count));
  u32 num_triggered_sockets = 0;
  {
    std::unique_lock lock(m_bound_sockets_lock);
    for (BoundSocket& bs : m_bound_sockets)
    {
      u32 event_mask = 0;
      if (FD_ISSET(bs.descriptor, &read_fds))
        event_mask |= EventType_Read;
      if (FD_ISSET(bs.descriptor, &write_fds))
        event_mask |= EventType_Write;

      if (event_mask != 0)
      {
        // we add a reference here in case the read kills it with a write pending, or something like that
        new (&triggered_sockets[num_triggered_sockets++]) PendingSocketPair(bs.socket->shared_from_this(), event_mask);
      }
    }
  }

  // fire events
  for (u32 i = 0; i < num_triggered_sockets; i++)
  {
    PendingSocketPair& psp = triggered_sockets[i];

    // fire events
    if (psp.second & EventType_Read)
      psp.first->OnReadEvent();
    if (psp.second & EventType_Write)
      psp.first->OnWriteEvent();

    psp.first.~shared_ptr();
  }

  return true;
}

ListenSocket::ListenSocket(SocketMultiplexer* multiplexer,
                           SocketMultiplexer::CreateStreamSocketCallback accept_callback, SocketDescriptor descriptor)
  : m_multiplexer(multiplexer), m_accept_callback(accept_callback), m_num_connections_accepted(0),
    m_descriptor(descriptor)
{
  // get local address
  sockaddr_storage sa;
  socklen_t salen = sizeof(sa);
  if (getsockname(m_descriptor, reinterpret_cast<sockaddr*>(&sa), &salen) == 0)
    m_local_address.SetFromSockaddr(&sa, salen);
}

ListenSocket::~ListenSocket()
{
  DebugAssert(m_descriptor == INVALID_SOCKET);
}

void ListenSocket::Close()
{
  if (m_descriptor < 0)
    return;

  m_multiplexer->SetNotificationMask(this, m_descriptor, 0);
  m_multiplexer->RemoveOpenSocket(this);
  closesocket(m_descriptor);
  m_descriptor = INVALID_SOCKET;
}

void ListenSocket::OnReadEvent()
{
  // connection incoming
  sockaddr_storage sa;
  socklen_t salen = sizeof(sa);
  SocketDescriptor new_descriptor = accept(m_descriptor, (sockaddr*)&sa, &salen);
  if (new_descriptor == INVALID_SOCKET)
  {
    ERROR_LOG("accept() returned {}", Error::CreateSocket(WSAGetLastError()).GetDescription());
    return;
  }

  // create socket, we release our own reference.
  std::shared_ptr<StreamSocket> client = m_accept_callback();
  client->InitializeSocket(m_multiplexer, new_descriptor, nullptr);
  m_num_connections_accepted++;
}

void ListenSocket::OnWriteEvent()
{
}

StreamSocket::StreamSocket() : BaseSocket(), m_descriptor(INVALID_SOCKET)
{
}

StreamSocket::~StreamSocket()
{
  DebugAssert(m_descriptor == INVALID_SOCKET);
}

size_t StreamSocket::Read(void* buffer, size_t buffer_size)
{
  std::unique_lock lock(m_lock);
  if (!m_connected)
    return 0;

  // try a read
  const ssize_t len = recv(m_descriptor, static_cast<char*>(buffer), SIZE_CAST(buffer_size), 0);
  if (len <= 0)
  {
    // Check for EAGAIN
    if (len < 0 && WSAGetLastError() == WSAEWOULDBLOCK)
    {
      // Not an error. Just means no data is available.
      return 0;
    }

    // error
    CloseWithError();
    return 0;
  }

  return len;
}

size_t StreamSocket::Write(const void* buffer, size_t buffer_size)
{
  std::unique_lock lock(m_lock);
  if (!m_connected)
    return 0;

  // try a write
  const ssize_t len = send(m_descriptor, static_cast<const char*>(buffer), SIZE_CAST(buffer_size), 0);
  if (len <= 0)
  {
    // Check for EAGAIN
    if (len < 0 && WSAGetLastError() == WSAEWOULDBLOCK)
    {
      // Not an error. Just means no data is available.
      return 0;
    }

    // error
    CloseWithError();
    return 0;
  }

  return len;
}

size_t StreamSocket::WriteVector(const void** buffers, const size_t* buffer_lengths, size_t num_buffers)
{
  std::unique_lock lock(m_lock);
  if (!m_connected || num_buffers == 0)
    return 0;

#ifdef _WIN32

  WSABUF* bufs = static_cast<WSABUF*>(alloca(sizeof(WSABUF) * num_buffers));
  for (size_t i = 0; i < num_buffers; i++)
  {
    bufs[i].buf = (CHAR*)buffers[i];
    bufs[i].len = (ULONG)buffer_lengths[i];
  }

  DWORD bytesSent = 0;
  if (WSASend(m_descriptor, bufs, (DWORD)num_buffers, &bytesSent, 0, nullptr, nullptr) == SOCKET_ERROR)
  {
    if (WSAGetLastError() != WSAEWOULDBLOCK)
    {
      // Socket error.
      CloseWithError();
      return 0;
    }
  }

  return static_cast<size_t>(bytesSent);

#else // _WIN32

  iovec* bufs = static_cast<iovec*>(alloca(sizeof(iovec) * num_buffers));
  for (size_t i = 0; i < num_buffers; i++)
  {
    bufs[i].iov_base = (void*)buffers[i];
    bufs[i].iov_len = buffer_lengths[i];
  }

  const ssize_t res = writev(m_descriptor, bufs, num_buffers);
  if (res < 0)
  {
    if (errno != EAGAIN)
    {
      // Socket error.
      CloseWithError();
      return 0;
    }

    res = 0;
  }

  return static_cast<size_t>(res);

#endif
}

void StreamSocket::Close()
{
  std::unique_lock lock(m_lock);
  if (!m_connected)
    return;

  m_multiplexer->SetNotificationMask(this, m_descriptor, 0);
  closesocket(m_descriptor);
  m_descriptor = INVALID_SOCKET;
  m_connected = false;

  OnDisconnected(Error::CreateString("Connection explicitly closed."));

  // Remove the open socket last. This is because it may be the last reference holder.
  m_multiplexer->RemoveOpenSocket(this);
}

void StreamSocket::CloseWithError()
{
  std::unique_lock lock(m_lock);
  DebugAssert(m_connected);

  Error error;
  const int error_code = WSAGetLastError();
  if (error_code == 0)
    error.SetStringView("Connection closed by peer.");
  else
    error.SetSocket(error_code);

  m_multiplexer->SetNotificationMask(this, m_descriptor, 0);
  closesocket(m_descriptor);
  m_descriptor = INVALID_SOCKET;
  m_connected = false;

  OnDisconnected(error);

  // Remove the open socket last. This is because it may be the last reference holder.
  m_multiplexer->RemoveOpenSocket(this);
}

void StreamSocket::OnReadEvent()
{
  // forward through
  std::unique_lock lock(m_lock);
  if (m_connected)
    OnRead();
}

void StreamSocket::OnWriteEvent()
{
  // shouldn't be called
}

bool StreamSocket::InitializeSocket(SocketMultiplexer* multiplexer, SocketDescriptor descriptor, Error* error)
{
  DebugAssert(m_multiplexer == nullptr);
  m_multiplexer = multiplexer;
  m_descriptor = descriptor;
  m_connected = true;

  // get local address
  sockaddr_storage sa;
  socklen_t salen = sizeof(sa);
  if (getsockname(m_descriptor, (sockaddr*)&sa, &salen) == 0)
    m_local_address.SetFromSockaddr(&sa, salen);

  // get remote address
  salen = sizeof(sockaddr_storage);
  if (getpeername(m_descriptor, (sockaddr*)&sa, &salen) == 0)
    m_remote_address.SetFromSockaddr(&sa, salen);

  // switch to nonblocking mode
  unsigned long value = 1;
  if (ioctlsocket(m_descriptor, FIONBIO, &value) < 0)
  {
    Error::SetSocket(error, "ioctlsocket() failed: ", WSAGetLastError());
    return false;
  }

  // register for notifications
  m_multiplexer->AddOpenSocket(shared_from_this());
  m_multiplexer->SetNotificationMask(this, m_descriptor, SocketMultiplexer::EventType_Read);

  // trigger connected notitifcation
  std::unique_lock lock(m_lock);
  OnConnected();
  return true;
}

BufferedStreamSocket::BufferedStreamSocket(size_t receiveBufferSize /*= 16384*/, size_t sendBufferSize /*= 16384*/)
  : m_receive_buffer(receiveBufferSize), m_send_buffer(sendBufferSize)
{
}

BufferedStreamSocket::~BufferedStreamSocket()
{
}

std::unique_lock<std::recursive_mutex> BufferedStreamSocket::GetLock()
{
  return std::unique_lock(m_lock);
}

std::span<const u8> BufferedStreamSocket::AcquireReadBuffer() const
{
  return std::span<const u8>(m_receive_buffer.data() + m_receive_buffer_offset, m_receive_buffer_size);
}

void BufferedStreamSocket::ReleaseReadBuffer(size_t bytes_consumed)
{
  DebugAssert(bytes_consumed <= m_receive_buffer_size);
  m_receive_buffer_offset += bytes_consumed;
  m_receive_buffer_size -= bytes_consumed;

  // Anything left? If not, reset offset.
  m_receive_buffer_offset = (m_receive_buffer_size == 0) ? 0 : m_receive_buffer_offset;
}

std::span<u8> BufferedStreamSocket::AcquireWriteBuffer(size_t wanted_bytes, bool allow_smaller /* = false */)
{
  // If to get the desired space, we need to move backwards, do so.
  if ((m_send_buffer_offset + m_send_buffer_size + wanted_bytes) > m_send_buffer.size())
  {
    if ((m_send_buffer_size + wanted_bytes) > m_send_buffer.size() && !allow_smaller)
    {
      // Not enough space.
      return {};
    }

    // Shuffle buffer backwards.
    std::memmove(m_send_buffer.data(), m_send_buffer.data() + m_send_buffer_offset, m_send_buffer_size);
    m_send_buffer_offset = 0;
  }

  DebugAssert((m_send_buffer_offset + m_send_buffer_size + wanted_bytes) <= m_send_buffer.size());
  return std::span<u8>(m_send_buffer.data() + m_send_buffer_offset + m_send_buffer_size,
                       m_send_buffer.size() - m_send_buffer_offset - m_send_buffer_size);
}

void BufferedStreamSocket::ReleaseWriteBuffer(size_t bytes_written)
{
  const bool was_empty = (m_send_buffer_size == 0);
  DebugAssert((m_send_buffer_offset + m_send_buffer_size + bytes_written) <= m_send_buffer.size());
  m_send_buffer_size += bytes_written;

  // Send as much as we can.
  if (was_empty)
  {
    const ssize_t res = send(m_descriptor, reinterpret_cast<const char*>(m_send_buffer.data() + m_send_buffer_offset),
                             SIZE_CAST(m_send_buffer_size), 0);
    if (res < 0 && WSAGetLastError() != WSAEWOULDBLOCK)
    {
      CloseWithError();
      return;
    }

    m_send_buffer_offset += static_cast<size_t>(res);
    m_send_buffer_size -= static_cast<size_t>(res);
    if (m_send_buffer_size == 0)
    {
      m_send_buffer_offset = 0;
    }
    else
    {
      // Register for writes to finish it off.
      m_multiplexer->SetNotificationMask(this, m_descriptor,
                                         SocketMultiplexer::EventType_Read | SocketMultiplexer::EventType_Write);
    }
  }
}

size_t BufferedStreamSocket::Read(void* buffer, size_t buffer_size)
{
  // Read from receive buffer.
  const std::span<const u8> rdbuf = AcquireReadBuffer();
  if (rdbuf.empty())
    return 0;

  const size_t bytes_to_read = std::min(rdbuf.size(), buffer_size);
  std::memcpy(buffer, rdbuf.data(), bytes_to_read);
  ReleaseReadBuffer(bytes_to_read);
  return bytes_to_read;
}

size_t BufferedStreamSocket::Write(const void* buffer, size_t buffer_size)
{
  // Read from receive buffer.
  const std::span<u8> wrbuf = AcquireWriteBuffer(buffer_size, true);
  if (wrbuf.empty())
    return 0;

  const size_t bytes_to_write = std::min(wrbuf.size(), buffer_size);
  std::memcpy(wrbuf.data(), buffer, bytes_to_write);
  ReleaseWriteBuffer(bytes_to_write);
  return bytes_to_write;
}

size_t BufferedStreamSocket::WriteVector(const void** buffers, const size_t* buffer_lengths, size_t num_buffers)
{
  if (!m_connected || num_buffers == 0)
    return 0;

  size_t total_size = 0;
  for (size_t i = 0; i < num_buffers; i++)
    total_size += buffer_lengths[i];

  const std::span<u8> wrbuf = AcquireWriteBuffer(total_size, true);
  if (wrbuf.empty())
    return 0;

  size_t written_bytes = 0;
  for (size_t i = 0; i < num_buffers; i++)
  {
    const size_t bytes_to_write = std::min(wrbuf.size() - written_bytes, buffer_lengths[i]);
    if (bytes_to_write == 0)
      break;

    std::memcpy(&wrbuf[written_bytes], buffers[i], bytes_to_write);
    written_bytes += buffer_lengths[i];
  }

  return written_bytes;
}

void BufferedStreamSocket::OnReadEvent()
{
  std::unique_lock lock(m_lock);
  if (!m_connected)
    return;

  // Pull as many bytes as possible into the read buffer.
  for (;;)
  {
    const size_t buffer_space = m_receive_buffer.size() - m_receive_buffer_offset - m_receive_buffer_size;
    if (buffer_space == 0) [[unlikely]]
    {
      // If we're here again, it means OnRead() didn't consume the data, and we overflowed.
      ERROR_LOG("Receive buffer overflow, dropping client {}.", GetRemoteAddress().ToString());
      CloseWithError();
      return;
    }

    const ssize_t res = recv(
      m_descriptor, reinterpret_cast<char*>(m_receive_buffer.data() + m_receive_buffer_offset + m_receive_buffer_size),
      SIZE_CAST(buffer_space), 0);
    if (res <= 0 && WSAGetLastError() != WSAEWOULDBLOCK)
    {
      CloseWithError();
      return;
    }

    m_receive_buffer_size += static_cast<size_t>(res);
    OnRead();

    // Are we at the end?
    if ((m_receive_buffer_offset + m_receive_buffer_size) == m_receive_buffer.size())
    {
      // Try to claw back some of the buffer, and try reading again.
      if (m_receive_buffer_offset > 0)
      {
        std::memmove(m_receive_buffer.data(), m_receive_buffer.data() + m_receive_buffer_offset, m_receive_buffer_size);
        m_receive_buffer_offset = 0;
        continue;
      }
    }

    break;
  }
}

void BufferedStreamSocket::OnWriteEvent()
{
  std::unique_lock lock(m_lock);
  if (!m_connected)
    return;

  // Send as much as we can.
  if (m_send_buffer_size > 0)
  {
    const ssize_t res = send(m_descriptor, reinterpret_cast<const char*>(m_send_buffer.data() + m_send_buffer_offset),
                             SIZE_CAST(m_send_buffer_size), 0);
    if (res < 0 && WSAGetLastError() != WSAEWOULDBLOCK)
    {
      CloseWithError();
      return;
    }

    m_send_buffer_offset += static_cast<size_t>(res);
    m_send_buffer_size -= static_cast<size_t>(res);
    if (m_send_buffer_size == 0)
      m_send_buffer_offset = 0;
  }

  if (m_send_buffer_size == 0)
  {
    // Are we done? Switch back to reads only.
    m_multiplexer->SetNotificationMask(this, m_descriptor, SocketMultiplexer::EventType_Read);
  }
}
