#include "netplay.h"
#include "common/byte_stream.h"
#include "common/gpu_texture.h"
#include "common/log.h"
#include "common/memory_settings_interface.h"
#include "common/string_util.h"
#include "common/timer.h"
#include "digital_controller.h"
#include "ggponet.h"
#include "host.h"
#include "host_settings.h"
#include "pad.h"
#include "spu.h"
#include "system.h"
#include <bitset>
#include <deque>
#include <xxhash.h>
Log_SetChannel(Netplay);

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

namespace Netplay {

using SaveStateBuffer = std::unique_ptr<System::MemorySaveState>;

struct Input
{
  u32 button_data;
};

static bool NpAdvFrameCb(void* ctx, int flags);
static bool NpSaveFrameCb(void* ctx, unsigned char** buffer, int* len, int* checksum, int frame);
static bool NpLoadFrameCb(void* ctx, unsigned char* buffer, int len, int rb_frames, int frame_to_load);
static bool NpBeginGameCb(void* ctx, const char* game_name);
static void NpFreeBuffCb(void* ctx, void* buffer, int frame);
static bool NpOnEventCb(void* ctx, GGPOEvent* ev);

static Input ReadLocalInput();
static GGPOErrorCode AddLocalInput(Netplay::Input input);
static GGPOErrorCode SyncInput(Input inputs[2], int* disconnect_flags);
static void SetInputs(Input inputs[2]);

static void SetSettings();

// l = local, r = remote
static s32 Start(s32 lhandle, u16 lport, std::string& raddr, u16 rport, s32 ldelay, u32 pred);

static void AdvanceFrame();
static void RunFrame();

static s32 CurrentFrame();

static void NetplayAdvanceFrame(Netplay::Input inputs[], int disconnect_flags);

/// Frame Pacing
static void InitializeFramePacing();
static void HandleTimeSyncEvent(float frame_delta, int update_interval);
static void Throttle();

// Desync Detection
static void GenerateChecksumForFrame(int* checksum, int frame, unsigned char* buffer, int buffer_size);
static void GenerateDesyncReport(s32 desync_frame);
//////////////////////////////////////////////////////////////////////////
// Variables
//////////////////////////////////////////////////////////////////////////

static MemorySettingsInterface s_settings_overlay;

static std::string s_game_path;

static GGPOPlayerHandle s_local_handle = GGPO_INVALID_HANDLE;
static GGPONetworkStats s_last_net_stats{};
static GGPOSession* s_ggpo = nullptr;

static std::deque<SaveStateBuffer> s_save_buffer_pool;

static std::array<std::array<float, 32>, NUM_CONTROLLER_AND_CARD_PORTS> s_net_input;

/// Frame timing. We manage our own frame pacing here, because we need to constantly adjust.
static float s_target_speed = 1.0f;
static Common::Timer::Value s_frame_period = 0;
static Common::Timer::Value s_next_frame_time = 0;
static s32 s_next_timesync_recovery_frame = -1;

} // namespace Netplay

// Netplay Impl

s32 Netplay::Start(s32 lhandle, u16 lport, std::string& raddr, u16 rport, s32 ldelay, u32 pred)
{
  SetSettings();
  InitializeFramePacing();

  /*
  TODO: since saving every frame during rollback loses us time to do actual gamestate iterations it might be better to
  hijack the update / save / load cycle to only save every confirmed frame only saving when actually needed.
  */
  GGPOSessionCallbacks cb{};

  cb.advance_frame = NpAdvFrameCb;
  cb.save_game_state = NpSaveFrameCb;
  cb.load_game_state = NpLoadFrameCb;
  cb.begin_game = NpBeginGameCb;
  cb.free_buffer = NpFreeBuffCb;
  cb.on_event = NpOnEventCb;

  GGPOErrorCode result;

  result =
    ggpo_start_session(&s_ggpo, &cb, "Duckstation-Netplay", 2, sizeof(Netplay::Input), lport, MAX_ROLLBACK_FRAMES);
  // result = ggpo_start_synctest(&s_ggpo, &cb, (char*)"asdf", 2, sizeof(Netplay::Input), 1);

  ggpo_set_disconnect_timeout(s_ggpo, 2000);
  ggpo_set_disconnect_notify_start(s_ggpo, 1000);

  for (int i = 1; i <= 2; i++)
  {
    GGPOPlayer player = {};
    GGPOPlayerHandle handle = 0;

    player.size = sizeof(GGPOPlayer);
    player.player_num = i;

    if (lhandle == i)
    {
      player.type = GGPOPlayerType::GGPO_PLAYERTYPE_LOCAL;
      result = ggpo_add_player(s_ggpo, &player, &handle);
      s_local_handle = handle;
    }
    else
    {
      player.type = GGPOPlayerType::GGPO_PLAYERTYPE_REMOTE;
      StringUtil::Strlcpy(player.u.remote.ip_address, raddr.c_str(), std::size(player.u.remote.ip_address));
      player.u.remote.port = rport;
      result = ggpo_add_player(s_ggpo, &player, &handle);
    }
  }
  ggpo_set_frame_delay(s_ggpo, s_local_handle, ldelay);
  ggpo_set_manual_network_polling(s_ggpo, true);

  return result;
}

void Netplay::CloseSession()
{
  Assert(IsActive());

  ggpo_close_session(s_ggpo);
  s_ggpo = nullptr;
  s_save_buffer_pool.clear();
  s_local_handle = GGPO_INVALID_HANDLE;

  // Restore original settings.
  Host::Internal::SetNetplaySettingsLayer(nullptr);
  System::ApplySettings(false);
}

bool Netplay::IsActive()
{
  return s_ggpo != nullptr;
}

//////////////////////////////////////////////////////////////////////////
// Settings Overlay
//////////////////////////////////////////////////////////////////////////

void Netplay::SetSettings()
{
  MemorySettingsInterface& si = s_settings_overlay;

  si.Clear();
  for (u32 i = 0; i < MAX_PLAYERS; i++)
  {
    // Only digital pads supported for now.
    si.SetStringValue(Controller::GetSettingsSection(i).c_str(), "Type",
                      Settings::GetControllerTypeName(ControllerType::DigitalController));
  }

  // No runahead or rewind, that'd be a disaster.
  si.SetIntValue("Main", "RunaheadFrameCount", 0);
  si.SetBoolValue("Main", "RewindEnable", false);

  // no block linking, it degrades savestate loading performance
  si.SetBoolValue("CPU", "RecompilerBlockLinking", false);
  // not sure its needed but enabled for now... TODO
  si.SetBoolValue("GPU", "UseSoftwareRendererForReadbacks", true);

  Host::Internal::SetNetplaySettingsLayer(&si);
  System::ApplySettings(false);
}

//////////////////////////////////////////////////////////////////////////
// Frame Pacing
//////////////////////////////////////////////////////////////////////////

void Netplay::InitializeFramePacing()
{
  // Start at 100% speed, adjust as soon as we get a timesync event.
  s_target_speed = 1.0f;
  UpdateThrottlePeriod();

  s_next_frame_time = Common::Timer::GetCurrentValue() + s_frame_period;
}

void Netplay::UpdateThrottlePeriod()
{
  s_frame_period =
    Common::Timer::ConvertSecondsToValue(1.0 / (static_cast<double>(System::GetThrottleFrequency()) * s_target_speed));
}

void Netplay::HandleTimeSyncEvent(float frame_delta, int update_interval)
{
  // Distribute the frame difference over the next N * 0.75 frames.
  // only part of the interval time is used since we want to come back to normal speed.
  // otherwise we will keep spiraling into unplayable gameplay.
  float total_time = (frame_delta * s_frame_period) / 4;
  float mun_timesync_frames = update_interval * 0.75f;
  float added_time_per_frame = -(total_time / mun_timesync_frames);
  float iterations_per_frame = 1.0f / s_frame_period;

  s_target_speed = (s_frame_period + added_time_per_frame) * iterations_per_frame;
  s_next_timesync_recovery_frame = CurrentFrame() + static_cast<s32>(std::ceil(mun_timesync_frames));

  UpdateThrottlePeriod();

  Log_VerbosePrintf("TimeSync: %f frames %s, target speed %.4f%%", std::abs(frame_delta),
                    (frame_delta >= 0.0f ? "ahead" : "behind"), s_target_speed * 100.0f);
}

void Netplay::Throttle()
{
  // if the s_next_timesync_recovery_frame has been reached revert back to the normal throttle speed
  s32 current_frame = CurrentFrame();
  if (s_target_speed != 1.0f && current_frame >= s_next_timesync_recovery_frame)
  {
    s_target_speed = 1.0f;
    UpdateThrottlePeriod();

    Log_VerbosePrintf("TimeSync Recovery: frame %d, target speed %.4f%%", current_frame, s_target_speed * 100.0f);
  }

  s_next_frame_time += s_frame_period;

  // If we're running too slow, advance the next frame time based on the time we lost. Effectively skips
  // running those frames at the intended time, because otherwise if we pause in the debugger, we'll run
  // hundreds of frames when we resume.
  Common::Timer::Value current_time = Common::Timer::GetCurrentValue();
  if (current_time > s_next_frame_time)
  {
    const Common::Timer::Value diff = static_cast<s64>(current_time) - static_cast<s64>(s_next_frame_time);
    s_next_frame_time += (diff / s_frame_period) * s_frame_period;
    return;
  }
  // Poll at 2ms throughout the sleep.
  // This way the network traffic comes through as soon as possible.
  const Common::Timer::Value sleep_period = Common::Timer::ConvertMillisecondsToValue(1);
  for (;;)
  {
    // Poll network.
    ggpo_poll_network(s_ggpo);

    current_time = Common::Timer::GetCurrentValue();
    if (current_time >= s_next_frame_time)
      break;

    // Spin for the last millisecond.
    if ((s_next_frame_time - current_time) <= sleep_period)
      Common::Timer::BusyWait(s_next_frame_time - current_time);
    else
      Common::Timer::SleepUntil(current_time + sleep_period, false);
  }
}

void Netplay::GenerateChecksumForFrame(int* checksum, int frame, unsigned char* buffer, int buffer_size)
{
  const u32 sliding_window_size = 4096 * 4; // 4 pages.
  const u32 num_group_of_pages = buffer_size / sliding_window_size;
  const u32 start_position = (frame % num_group_of_pages) * sliding_window_size;
  *checksum = XXH32(buffer + start_position, sliding_window_size, frame);
  // Log_VerbosePrintf("Netplay Checksum: f:%d wf:%d c:%u", frame, frame % num_group_of_pages, *checksum);
}

void Netplay::GenerateDesyncReport(s32 desync_frame) 
{
  std::string path = "\\netplaylogs\\desync_frame_" + std::to_string(desync_frame) + "_p" +
                     std::to_string(s_local_handle) + "_" + System::GetRunningSerial() + "_.txt";
  std::string filename = EmuFolders::Dumps + path;

  std::unique_ptr<ByteStream> stream =
    ByteStream::OpenFile(filename.c_str(), BYTESTREAM_OPEN_CREATE | BYTESTREAM_OPEN_WRITE | BYTESTREAM_OPEN_TRUNCATE |
                                             BYTESTREAM_OPEN_ATOMIC_UPDATE | BYTESTREAM_OPEN_STREAMED);
  if (!stream)
  {
    Log_VerbosePrint("desync log creation failed to create stream");
    return;
  }

  if (!ByteStream::WriteBinaryToStream(stream.get(),
                                       s_save_buffer_pool.back().get()->state_stream.get()->GetMemoryPointer(),
                                       s_save_buffer_pool.back().get()->state_stream.get()->GetMemorySize()))
  {
    Log_VerbosePrint("desync log creation failed to write the stream");
    stream->Discard();
    return;
  }
 /* stream->Write(s_save_buffer_pool.back().get()->state_stream.get()->GetMemoryPointer(),
                s_save_buffer_pool.back().get()->state_stream.get()->GetMemorySize());*/

  stream->Commit();

  Log_VerbosePrintf("desync log created for frame %d", desync_frame);
}


void Netplay::AdvanceFrame()
{
  ggpo_advance_frame(s_ggpo, 0);
}

void Netplay::RunFrame()
{
  // housekeeping
  ggpo_idle(s_ggpo);
  // run game
  auto result = GGPO_OK;
  int disconnect_flags = 0;
  Netplay::Input inputs[2] = {};
  // add local input
  if (s_local_handle != GGPO_INVALID_HANDLE)
  {
    auto inp = ReadLocalInput();
    result = AddLocalInput(inp);
  }
  // advance game
  if (GGPO_SUCCEEDED(result))
  {
    result = SyncInput(inputs, &disconnect_flags);
    if (GGPO_SUCCEEDED(result))
    {
      // enable again when rolling back done
      SPU::SetAudioOutputMuted(false);
      NetplayAdvanceFrame(inputs, disconnect_flags);
    }
  }
}

s32 Netplay::CurrentFrame()
{
  s32 current = -1;
  ggpo_get_current_frame(s_ggpo, current);
  return current;
}

void Netplay::CollectInput(u32 slot, u32 bind, float value)
{
  s_net_input[slot][bind] = value;
}

Netplay::Input Netplay::ReadLocalInput()
{
  // get controller data of the first controller (0 internally)
  Netplay::Input inp{0};
  for (u32 i = 0; i < (u32)DigitalController::Button::Count; i++)
  {
    if (s_net_input[0][i] >= 0.25f)
      inp.button_data |= 1 << i;
  }
  return inp;
}

void Netplay::SendMsg(const char* msg)
{
  ggpo_client_chat(s_ggpo, msg);
}

GGPOErrorCode Netplay::SyncInput(Netplay::Input inputs[2], int* disconnect_flags)
{
  return ggpo_synchronize_input(s_ggpo, inputs, sizeof(Netplay::Input) * 2, disconnect_flags);
}

GGPOErrorCode Netplay::AddLocalInput(Netplay::Input input)
{
  return ggpo_add_local_input(s_ggpo, s_local_handle, &input, sizeof(Netplay::Input));
}

s32 Netplay::GetPing()
{
  const int handle = s_local_handle == 1 ? 2 : 1;
  ggpo_get_network_stats(s_ggpo, handle, &s_last_net_stats);
  return s_last_net_stats.network.ping;
}

u32 Netplay::GetMaxPrediction()
{
  return MAX_ROLLBACK_FRAMES;
}

void Netplay::SetInputs(Netplay::Input inputs[2])
{
  for (u32 i = 0; i < 2; i++)
  {
    auto cont = Pad::GetController(i);
    std::bitset<sizeof(u32) * 8> button_bits(inputs[i].button_data);
    for (u32 j = 0; j < (u32)DigitalController::Button::Count; j++)
      cont->SetBindState(j, button_bits.test(j) ? 1.0f : 0.0f);
  }
}

void Netplay::StartNetplaySession(s32 local_handle, u16 local_port, std::string& remote_addr, u16 remote_port,
                                  s32 input_delay, std::string game_path)
{
  // dont want to start a session when theres already one going on.
  if (IsActive())
    return;
  // set game path for later loading during the begin game callback
  s_game_path = std::move(game_path);
  // create session
  int result = Netplay::Start(local_handle, local_port, remote_addr, remote_port, input_delay, MAX_ROLLBACK_FRAMES);
  // notify that the session failed
  if (result != GGPO_OK)
    Log_ErrorPrintf("Failed to Create Netplay Session! Error: %d", result);
  else
  {
    // Load savestate if available
    std::string save = EmuFolders::SaveStates + "/netplay/" + System::GetRunningSerial() + ".sav";
    System::LoadState(save.c_str());
  }
}

void Netplay::StopNetplaySession()
{
  if (!IsActive())
    return;

  // This will call back to us.
  System::ShutdownSystem(false);
}

void Netplay::NetplayAdvanceFrame(Netplay::Input inputs[], int disconnect_flags)
{
  Netplay::SetInputs(inputs);
  System::RunFrame();
  Netplay::AdvanceFrame();
}

void Netplay::ExecuteNetplay()
{
  while (System::IsRunning())
  {
    Netplay::RunFrame();

    // this can shut us down
    Host::PumpMessagesOnCPUThread();
    if (!System::IsValid())
      break;

    System::PresentFrame();
    System::UpdatePerformanceCounters();

    Throttle();
  }
}

bool Netplay::NpBeginGameCb(void* ctx, const char* game_name)
{
  // close system if its already running
  if (System::IsValid())
    System::ShutdownSystem(false);
  // fast boot the selected game and wait for the other player
  auto param = SystemBootParameters(s_game_path);
  param.override_fast_boot = true;
  if (!System::BootSystem(param))
  {
    StopNetplaySession();
    return false;
  }
  SPU::SetAudioOutputMuted(true);
  // Fast Forward to Game Start if needed.
  while (System::GetInternalFrameNumber() < 2)
    System::RunFrame();
  SPU::SetAudioOutputMuted(false);
  // Set Initial Frame Pacing
  InitializeFramePacing();
  return true;
}

bool Netplay::NpAdvFrameCb(void* ctx, int flags)
{
  Netplay::Input inputs[2] = {};
  int disconnect_flags;
  Netplay::SyncInput(inputs, &disconnect_flags);
  NetplayAdvanceFrame(inputs, disconnect_flags);
  return true;
}

bool Netplay::NpSaveFrameCb(void* ctx, unsigned char** buffer, int* len, int* checksum, int frame)
{
  SaveStateBuffer our_buffer;
  // min size is 2 because otherwise the desync logger doesnt have enough time to dump the state.
  if (s_save_buffer_pool.size() < 2)
  {
    our_buffer = std::make_unique<System::MemorySaveState>();
  }
  else
  {
    our_buffer = std::move(s_save_buffer_pool.front());
    s_save_buffer_pool.pop_front();
  }

  if (!System::SaveMemoryState(our_buffer.get()))
  {
    s_save_buffer_pool.push_front(std::move(our_buffer));
    return false;
  }

  // desync detection
  const u32 state_size = our_buffer.get()->state_stream.get()->GetMemorySize();
  unsigned char* state = reinterpret_cast<unsigned char*>(our_buffer.get()->state_stream.get()->GetMemoryPointer());
  GenerateChecksumForFrame(checksum, frame, state, state_size);

  *len = sizeof(System::MemorySaveState);
  *buffer = reinterpret_cast<unsigned char*>(our_buffer.release());

  return true;
}

bool Netplay::NpLoadFrameCb(void* ctx, unsigned char* buffer, int len, int rb_frames, int frame_to_load)
{
  // Disable Audio For upcoming rollback
  SPU::SetAudioOutputMuted(true);

  return System::LoadMemoryState(*reinterpret_cast<const System::MemorySaveState*>(buffer));
}

void Netplay::NpFreeBuffCb(void* ctx, void* buffer, int frame)
{
  // Log_VerbosePrintf("Reuse Buffer: %d", frame);
  SaveStateBuffer our_buffer(reinterpret_cast<System::MemorySaveState*>(buffer));
  s_save_buffer_pool.push_back(std::move(our_buffer));
}

bool Netplay::NpOnEventCb(void* ctx, GGPOEvent* ev)
{
  char buff[128];
  std::string msg, filename;
  switch (ev->code)
  {
    case GGPOEventCode::GGPO_EVENTCODE_CONNECTED_TO_PEER:
      sprintf(buff, "Netplay Connected To Player: %d", ev->u.connected.player);
      msg = buff;
      break;
    case GGPOEventCode::GGPO_EVENTCODE_SYNCHRONIZING_WITH_PEER:
      sprintf(buff, "Netplay Synchronzing: %d/%d", ev->u.synchronizing.count, ev->u.synchronizing.total);
      msg = buff;
      break;
    case GGPOEventCode::GGPO_EVENTCODE_SYNCHRONIZED_WITH_PEER:
      sprintf(buff, "Netplay Synchronized With Player: %d", ev->u.synchronized.player);
      msg = buff;
      break;
    case GGPOEventCode::GGPO_EVENTCODE_DISCONNECTED_FROM_PEER:
      sprintf(buff, "Netplay Player: %d Disconnected", ev->u.disconnected.player);
      msg = buff;
      break;
    case GGPOEventCode::GGPO_EVENTCODE_RUNNING:
      msg = "Netplay Is Running";
      break;
    case GGPOEventCode::GGPO_EVENTCODE_CONNECTION_INTERRUPTED:
      sprintf(buff, "Netplay Player: %d Connection Interupted, Timeout: %d", ev->u.connection_interrupted.player,
              ev->u.connection_interrupted.disconnect_timeout);
      msg = buff;
      break;
    case GGPOEventCode::GGPO_EVENTCODE_CONNECTION_RESUMED:
      sprintf(buff, "Netplay Player: %d Connection Resumed", ev->u.connection_resumed.player);
      msg = buff;
      break;
    case GGPOEventCode::GGPO_EVENTCODE_CHAT:
      sprintf(buff, "%s", ev->u.chat.msg);
      msg = buff;
      break;
    case GGPOEventCode::GGPO_EVENTCODE_TIMESYNC:
      HandleTimeSyncEvent(ev->u.timesync.frames_ahead, ev->u.timesync.timeSyncPeriodInFrames);
      break;
    case GGPOEventCode::GGPO_EVENTCODE_DESYNC:
      sprintf(buff, "Desync Detected: Current Frame: %d, Desync Frame: %d, Diff: %d, L:%u, R:%u", CurrentFrame(),
              ev->u.desync.nFrameOfDesync, CurrentFrame() - ev->u.desync.nFrameOfDesync, ev->u.desync.ourCheckSum,
              ev->u.desync.remoteChecksum);
      msg = buff;
      GenerateDesyncReport(ev->u.desync.nFrameOfDesync);
      Host::AddKeyedOSDMessage("Netplay", msg, 5);

      return true;
    default:
      sprintf(buff, "Netplay Event Code: %d", ev->code);
      msg = buff;
  }
  if (!msg.empty())
  {
    Host::OnNetplayMessage(msg);
    Log_InfoPrintf("%s", msg.c_str());
  }
  return true;
}
