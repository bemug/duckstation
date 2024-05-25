// SPDX-FileCopyrightText: 2015-2024 Connor McLaughlin <stenzek@gmail.com>
// SPDX-License-Identifier: (GPL-3.0 OR CC-BY-NC-ND-4.0)

#pragma once

#include "common/error.h"
#include "common/heap_array.h"
#include "common/small_string.h"
#include "common/threading.h"
#include "common/types.h"

#include <memory>
#include <mutex>
#include <optional>
#include <span>

#ifdef _WIN32
using SocketDescriptor = uintptr_t;
#else
using SocketDescriptor = int;
#endif

class BaseSocket;
class ListenSocket;
class StreamSocket;
class BufferedStreamSocket;
class SocketMultiplexer;

struct SocketAddress
{
  enum Type
  {
    Type_Unknown,
    Type_IPv4,
    Type_IPv6,
    Type_Unix,
  };

  // accessors
  const void* GetData() const { return m_data; }
  u32 GetLength() const { return m_length; }

  // parse interface
  static std::optional<SocketAddress> Parse(Type type, const char* address, u32 port, Error* error);

  // resolve interface
  static std::optional<SocketAddress> Resolve(const char* address, u32 port, Error* error);

  // to string interface
  SmallString ToString() const;

  // initializers
  void SetFromSockaddr(const void* sa, size_t length);

private:
  u8 m_data[128] = {};
  u32 m_length = 0;
};

class BaseSocket : public std::enable_shared_from_this<BaseSocket>
{
public:
  BaseSocket();
  virtual ~BaseSocket();

  virtual void Close() = 0;

private:
  virtual void OnReadEvent() = 0;
  virtual void OnWriteEvent() = 0;

  // Ugly, but needed in order to call the events.
  friend SocketMultiplexer;
};

class SocketMultiplexer
{
  // TODO: Re-introduce worker threads.

public:
  enum EventType
  {
    EventType_Read = (1 << 0),
    EventType_Write = (1 << 1),
    NumEventTypes
  };

  typedef std::shared_ptr<StreamSocket> (*CreateStreamSocketCallback)();
  friend BaseSocket;
  friend ListenSocket;
  friend StreamSocket;
  friend BufferedStreamSocket;

public:
  virtual ~SocketMultiplexer();

  // Factory method.
  static std::unique_ptr<SocketMultiplexer> Create(Error* error);

  // Public interface
  template<class T>
  std::shared_ptr<ListenSocket> CreateListenSocket(const SocketAddress& address, Error* error);
  template<class T>
  std::shared_ptr<T> ConnectStreamSocket(const SocketAddress& address, Error* error);


  // Close all sockets on this multiplexer.
  void CloseAll();

  // Poll for events. Returns false if there are no sockets registered.
  bool PollEventsWithTimeout(u32 milliseconds);

protected:
  // Internal interface
  std::shared_ptr<ListenSocket> InternalCreateListenSocket(const SocketAddress& address,
                                                           CreateStreamSocketCallback callback, Error* error);
  std::shared_ptr<StreamSocket> InternalConnectStreamSocket(const SocketAddress& address,
                                                            CreateStreamSocketCallback callback, Error* error);

private:
  // Hide the constructor.
  SocketMultiplexer();

  // Tracking of open sockets.
  void AddOpenSocket(std::shared_ptr<BaseSocket> socket);
  void RemoveOpenSocket(BaseSocket* socket);

  // Register for notifications
  void SetNotificationMask(BaseSocket* socket, SocketDescriptor descriptor, u32 mask);

private:
  // We store the fd in the struct to avoid the cache miss reading the object.
  struct BoundSocket
  {
    BaseSocket* socket;
    SocketDescriptor descriptor;
    u32 event_mask;
  };
  std::vector<BoundSocket> m_bound_sockets;
  std::mutex m_bound_sockets_lock;

  // Open socket list
  // TODO: deque or intrusive list.
  std::vector<std::shared_ptr<BaseSocket>> m_open_sockets;
  std::mutex m_open_sockets_lock;
};

template<class T>
std::shared_ptr<ListenSocket> SocketMultiplexer::CreateListenSocket(const SocketAddress& address, Error* error)
{
  const CreateStreamSocketCallback callback = []() -> std::shared_ptr<StreamSocket> {
    return std::static_pointer_cast<StreamSocket>(std::make_shared<T>());
  };
  return InternalCreateListenSocket(address, callback, error);
}

template<class T>
std::shared_ptr<T> SocketMultiplexer::ConnectStreamSocket(const SocketAddress& address, Error* error)
{
  const CreateStreamSocketCallback callback = []() -> std::shared_ptr<StreamSocket> {
    return std::static_pointer_cast<StreamSocket>(std::make_shared<T>());
  };
  return std::static_pointer_cast<T>(InternalConnectStreamSocket(address, callback, error));
}

class ListenSocket : public BaseSocket
{
  friend SocketMultiplexer;

public:
  ListenSocket(SocketMultiplexer* multiplexer, SocketMultiplexer::CreateStreamSocketCallback accept_callback,
               SocketDescriptor descriptor);
  virtual ~ListenSocket() override;

  const SocketAddress* GetLocalAddress() const { return &m_local_address; }
  u32 GetConnectionsAccepted() const { return m_num_connections_accepted; }

  virtual void Close() override final;

private:
  virtual void OnReadEvent() override final;
  virtual void OnWriteEvent() override final;

private:
  SocketMultiplexer* m_multiplexer;
  SocketMultiplexer::CreateStreamSocketCallback m_accept_callback;
  SocketAddress m_local_address;
  u32 m_num_connections_accepted;
  SocketDescriptor m_descriptor;
};

class StreamSocket : public BaseSocket
{
public:
  StreamSocket();
  virtual ~StreamSocket() override;

  virtual void Close() override final;

  // Accessors
  const SocketAddress& GetLocalAddress() const { return m_local_address; }
  const SocketAddress& GetRemoteAddress() const { return m_remote_address; }
  bool IsConnected() const { return m_connected; }

  // Read/write
  size_t Read(void* buffer, size_t buffer_size);
  size_t Write(const void* buffer, size_t buffer_size);
  size_t WriteVector(const void** buffers, const size_t* buffer_lengths, size_t num_buffers);

protected:
  virtual void OnConnected() = 0;
  virtual void OnDisconnected(const Error& error) = 0;
  virtual void OnRead() = 0;

private:
  virtual void OnReadEvent() override;
  virtual void OnWriteEvent() override;

  bool InitializeSocket(SocketMultiplexer* multiplexer, SocketDescriptor descriptor, Error* error);
  void CloseWithError();

private:
  SocketMultiplexer* m_multiplexer = nullptr;
  SocketAddress m_local_address = {};
  SocketAddress m_remote_address = {};
  std::recursive_mutex m_lock;
  SocketDescriptor m_descriptor;
  bool m_connected = false;

  // Ugly, but needed in order to call the events.
  friend SocketMultiplexer;
  friend ListenSocket;
  friend BufferedStreamSocket;
};

class BufferedStreamSocket : public StreamSocket
{
public:
  BufferedStreamSocket(size_t receive_buffer_size = 16384, size_t send_buffer_size = 16384);
  virtual ~BufferedStreamSocket() override;

  // Must hold the lock when not part of OnRead().
  std::unique_lock<std::recursive_mutex> GetLock();
  std::span<const u8> AcquireReadBuffer() const;
  void ReleaseReadBuffer(size_t bytes_consumed);
  std::span<u8> AcquireWriteBuffer(size_t wanted_bytes, bool allow_smaller = false);
  void ReleaseWriteBuffer(size_t bytes_written);

  // Hide StreamSocket read/write methods.
  size_t Read(void* buffer, size_t buffer_size);
  size_t Write(const void* buffer, size_t buffer_size);
  size_t WriteVector(const void** buffers, const size_t* buffer_lengths, size_t num_buffers);

private:
  virtual void OnReadEvent() override;
  virtual void OnWriteEvent() override;

private:
  std::vector<u8> m_receive_buffer;
  size_t m_receive_buffer_offset = 0;
  size_t m_receive_buffer_size = 0;

  std::vector<u8> m_send_buffer;
  size_t m_send_buffer_offset = 0;
  size_t m_send_buffer_size = 0;
};
