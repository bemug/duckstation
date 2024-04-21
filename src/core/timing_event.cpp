// SPDX-FileCopyrightText: 2019-2022 Connor McLaughlin <stenzek@gmail.com>
// SPDX-License-Identifier: (GPL-3.0 OR CC-BY-NC-ND-4.0)

#include "timing_event.h"
#include "common/assert.h"
#include "common/log.h"
#include "cpu_core.h"
#include "cpu_core_private.h"
#include "system.h"
#include "util/state_wrapper.h"
Log_SetChannel(TimingEvents);

namespace TimingEvents {

static TimingEvent* s_active_events_head;
static TimingEvent* s_active_events_tail;
static TimingEvent* s_current_event = nullptr;
static u32 s_active_event_count = 0;
static GlobalTicks s_global_tick_counter = 0;
static GlobalTicks s_event_run_tick_counter = 0;
static bool s_frame_done = false;

GlobalTicks GetGlobalTickCounter()
{
  return s_global_tick_counter + CPU::GetPendingTicks();
}

GlobalTicks GetEventRunTickCounter()
{
  return s_event_run_tick_counter;
}

void Initialize()
{
  Reset();
}

void Reset()
{
  s_global_tick_counter = 0;
  s_event_run_tick_counter = 0;
}

void Shutdown()
{
  Assert(s_active_event_count == 0);
}

std::unique_ptr<TimingEvent> CreateTimingEvent(std::string name, TickCount period, TickCount interval,
                                               TimingEventCallback callback, void* callback_param, bool activate)
{
  std::unique_ptr<TimingEvent> event =
    std::make_unique<TimingEvent>(std::move(name), period, interval, callback, callback_param);
  if (activate)
    event->Activate();

  return event;
}

void UpdateCPUDowncount()
{
  DebugAssert(s_active_events_head->GetNextRunTime() >= s_global_tick_counter);
  const u32 event_downcount = static_cast<u32>(s_active_events_head->GetNextRunTime() - s_global_tick_counter);
  CPU::g_state.downcount = CPU::HasPendingInterrupt() ? 0 : event_downcount;
}

TimingEvent** GetHeadEventPtr()
{
  return &s_active_events_head;
}

static void SortEvent(TimingEvent* event)
{
  const GlobalTicks event_runtime = event->GetNextRunTime();

  if (event->prev && event->prev->GetNextRunTime() > event_runtime)
  {
    // move backwards
    TimingEvent* current = event->prev;
    while (current && current->GetNextRunTime() > event_runtime)
      current = current->prev;

    // unlink
    if (event->prev)
      event->prev->next = event->next;
    else
      s_active_events_head = event->next;
    if (event->next)
      event->next->prev = event->prev;
    else
      s_active_events_tail = event->prev;

    // insert after current
    if (current)
    {
      event->next = current->next;
      if (current->next)
        current->next->prev = event;
      else
        s_active_events_tail = event;

      event->prev = current;
      current->next = event;
    }
    else
    {
      // insert at front
      DebugAssert(s_active_events_head);
      s_active_events_head->prev = event;
      event->prev = nullptr;
      event->next = s_active_events_head;
      s_active_events_head = event;
      UpdateCPUDowncount();
    }
  }
  else if (event->next && event_runtime > event->next->GetNextRunTime())
  {
    // move forwards
    TimingEvent* current = event->next;
    while (current && event_runtime > current->GetNextRunTime())
      current = current->next;

    // unlink
    if (event->prev)
    {
      event->prev->next = event->next;
    }
    else
    {
      s_active_events_head = event->next;
      UpdateCPUDowncount();
    }
    if (event->next)
      event->next->prev = event->prev;
    else
      s_active_events_tail = event->prev;

    // insert before current
    if (current)
    {
      event->next = current;
      event->prev = current->prev;

      if (current->prev)
      {
        current->prev->next = event;
      }
      else
      {
        s_active_events_head = event;
        UpdateCPUDowncount();
      }

      current->prev = event;
    }
    else
    {
      // insert at back
      DebugAssert(s_active_events_tail);
      s_active_events_tail->next = event;
      event->next = nullptr;
      event->prev = s_active_events_tail;
      s_active_events_tail = event;
    }
  }
}

static void AddActiveEvent(TimingEvent* event)
{
  DebugAssert(!event->prev && !event->next);
  s_active_event_count++;

  const GlobalTicks event_runtime = event->GetNextRunTime();
  TimingEvent* current = nullptr;
  TimingEvent* next = s_active_events_head;
  while (next && event_runtime > next->GetNextRunTime())
  {
    current = next;
    next = next->next;
  }

  if (!next)
  {
    // new tail
    event->prev = s_active_events_tail;
    if (s_active_events_tail)
    {
      s_active_events_tail->next = event;
      s_active_events_tail = event;
    }
    else
    {
      // first event
      s_active_events_tail = event;
      s_active_events_head = event;
      UpdateCPUDowncount();
    }
  }
  else if (!current)
  {
    // new head
    event->next = s_active_events_head;
    s_active_events_head->prev = event;
    s_active_events_head = event;
    UpdateCPUDowncount();
  }
  else
  {
    // inbetween current < event > next
    event->prev = current;
    event->next = next;
    current->next = event;
    next->prev = event;
  }
}

static void RemoveActiveEvent(TimingEvent* event)
{
  DebugAssert(s_active_event_count > 0);

  if (event->next)
  {
    event->next->prev = event->prev;
  }
  else
  {
    s_active_events_tail = event->prev;
  }

  if (event->prev)
  {
    event->prev->next = event->next;
  }
  else
  {
    s_active_events_head = event->next;
    if (s_active_events_head && !s_current_event)
      UpdateCPUDowncount();
  }

  event->prev = nullptr;
  event->next = nullptr;

  s_active_event_count--;
}

static void SortEvents()
{
  std::vector<TimingEvent*> events;
  events.reserve(s_active_event_count);

  TimingEvent* next = s_active_events_head;
  while (next)
  {
    TimingEvent* current = next;
    events.push_back(current);
    next = current->next;
    current->prev = nullptr;
    current->next = nullptr;
  }

  s_active_events_head = nullptr;
  s_active_events_tail = nullptr;
  s_active_event_count = 0;

  for (TimingEvent* event : events)
    AddActiveEvent(event);
}

static TimingEvent* FindActiveEvent(const char* name)
{
  for (TimingEvent* event = s_active_events_head; event; event = event->next)
  {
    if (event->GetName().compare(name) == 0)
      return event;
  }

  return nullptr;
}

bool IsRunningEvents()
{
  return (s_current_event != nullptr);
}

void SetFrameDone()
{
  s_frame_done = true;
  CPU::g_state.downcount = 0;
}

void RunEvents()
{
  DebugAssert(!s_current_event);

  do
  {
    if (CPU::HasPendingInterrupt())
      CPU::DispatchInterrupt();

    // TODO: Get rid of pending completely...
    const GlobalTicks new_global_ticks = s_global_tick_counter + static_cast<GlobalTicks>(CPU::GetPendingTicks());
    if (new_global_ticks >= s_active_events_head->m_next_run_time)
    {
      CPU::ResetPendingTicks();
      s_event_run_tick_counter = new_global_ticks; // TODO: Might be wrong... should move below?but then it'd ping-pong.

      do
      {
        s_global_tick_counter = std::min(new_global_ticks, s_active_events_head->m_next_run_time);

        // Now we can actually run the callbacks.
        TimingEvent* event;
        while (s_global_tick_counter >= (event = s_active_events_head)->m_next_run_time)
        {
          s_current_event = event;

          // Factor late time into the time for the next invocation.
          const TickCount ticks_late =
            static_cast<TickCount>(s_global_tick_counter - s_active_events_head->m_next_run_time);
          const TickCount ticks_to_execute =
            static_cast<TickCount>(s_global_tick_counter - s_active_events_head->m_last_run_time);
          s_active_events_head->m_next_run_time += static_cast<GlobalTicks>(event->m_interval);
          s_active_events_head->m_last_run_time = s_global_tick_counter;

          // The cycles_late is only an indicator, it doesn't modify the cycles to execute.
          event->m_callback(event->m_callback_param, ticks_to_execute, ticks_late);
          if (event->m_active)
            SortEvent(event);
        }
      } while (new_global_ticks > s_event_run_tick_counter);

      s_current_event = nullptr;
    }

    if (s_frame_done)
    {
      s_frame_done = false;
      System::FrameDone();
    }

    UpdateCPUDowncount();
  } while (CPU::GetPendingTicks() >= CPU::g_state.downcount);
}

bool DoState(StateWrapper& sw)
{
  sw.Do(&s_global_tick_counter);

  if (sw.IsReading())
  {
    // Load timestamps for the clock events.
    // Any oneshot events should be recreated by the load state method, so we can fix up their times here.
    u32 event_count = 0;
    sw.Do(&event_count);

    for (u32 i = 0; i < event_count; i++)
    {
      std::string event_name;
      TickCount downcount, time_since_last_run, period, interval;
      sw.Do(&event_name);
      sw.Do(&downcount);
      sw.Do(&time_since_last_run);
      sw.Do(&period);
      sw.Do(&interval);
      if (sw.HasError())
        return false;

      TimingEvent* event = FindActiveEvent(event_name.c_str());
      if (!event)
      {
        Log_WarningPrintf("Save state has event '%s', but couldn't find this event when loading.", event_name.c_str());
        continue;
      }

      // Using reschedule is safe here since we call sort afterwards.
      Panic("Fixme");
      //event->m_downcount = downcount;
      //event->m_time_since_last_run = time_since_last_run;
      event->m_period = period;
      event->m_interval = interval;
    }

    if (sw.GetVersion() < 43)
    {
      u32 last_event_run_time = 0;
      sw.Do(&last_event_run_time);
    }

    Log_DebugPrintf("Loaded %u events from save state.", event_count);
    SortEvents();
  }
  else
  {

    sw.Do(&s_active_event_count);

    for (TimingEvent* event = s_active_events_head; event; event = event->next)
    {
      sw.Do(&event->m_name);
      //sw.Do(&event->m_downcount);
      //sw.Do(&event->m_time_since_last_run);
      sw.Do(&event->m_period);
      sw.Do(&event->m_interval);
    }

    Log_DebugPrintf("Wrote %u events to save state.", s_active_event_count);
  }

  return !sw.HasError();
}

} // namespace TimingEvents

TimingEvent::TimingEvent(std::string name, TickCount period, TickCount interval, TimingEventCallback callback,
                         void* callback_param)
  : m_callback(callback), m_callback_param(callback_param), m_next_run_time(TimingEvents::GetGlobalTickCounter() + static_cast<GlobalTicks>(interval)), m_last_run_time(TimingEvents::GetGlobalTickCounter()),
    m_period(period), m_interval(interval), m_name(std::move(name))
{
}

TimingEvent::~TimingEvent()
{
  if (m_active)
    TimingEvents::RemoveActiveEvent(this);
}

void TimingEvent::Delay(TickCount ticks)
{
  if (!m_active)
  {
    Panic("Trying to delay an inactive event");
    return;
  }

  m_next_run_time += static_cast<GlobalTicks>(ticks);

  DebugAssert(TimingEvents::s_current_event != this);
  TimingEvents::SortEvent(this);
  if (TimingEvents::s_active_events_head == this)
    TimingEvents::UpdateCPUDowncount();
}

void TimingEvent::Schedule(TickCount ticks)
{
  const GlobalTicks current_ticks = TimingEvents::GetGlobalTickCounter();
  m_next_run_time = current_ticks + static_cast<GlobalTicks>(ticks);

  if (!m_active)
  {
    // Event is going active, so we want it to only execute ticks from the current timestamp.
    m_last_run_time = current_ticks;
    m_active = true;
    TimingEvents::AddActiveEvent(this);
  }
  else
  {
    // Event is already active, so we leave the time since last run alone, and just modify the downcount.
    // If this is a call from an IO handler for example, re-sort the event queue.
    if (TimingEvents::s_current_event != this)
    {
      TimingEvents::SortEvent(this);
      if (TimingEvents::s_active_events_head == this)
        TimingEvents::UpdateCPUDowncount();
    }
  }
}

void TimingEvent::SetIntervalAndSchedule(TickCount ticks)
{
  SetInterval(ticks);
  Schedule(ticks);
}

void TimingEvent::SetPeriodAndSchedule(TickCount ticks)
{
  SetPeriod(ticks);
  SetInterval(ticks);
  Schedule(ticks);
}

void TimingEvent::Reset()
{
  if (!m_active)
    return;

  const GlobalTicks current_ticks = TimingEvents::GetGlobalTickCounter();
  m_next_run_time = current_ticks + static_cast<GlobalTicks>(m_interval);
  m_last_run_time = current_ticks;
  if (TimingEvents::s_current_event != this)
  {
    TimingEvents::SortEvent(this);
    if (TimingEvents::s_active_events_head == this)
      TimingEvents::UpdateCPUDowncount();
  }
}

void TimingEvent::InvokeEarly(bool force /* = false */)
{
  if (!m_active)
    return;

  const GlobalTicks current_ticks = TimingEvents::GetGlobalTickCounter();
  DebugAssert(current_ticks >= m_last_run_time);

  const TickCount ticks_to_execute = static_cast<TickCount>(current_ticks - m_last_run_time);
  if ((!force && ticks_to_execute < m_period) || ticks_to_execute <= 0)
    return;

  m_next_run_time = current_ticks + static_cast<GlobalTicks>(m_interval);
  m_last_run_time = current_ticks;
  m_callback(m_callback_param, ticks_to_execute, 0);

  // Since we've changed the downcount, we need to re-sort the events.
  DebugAssert(TimingEvents::s_current_event != this);
  TimingEvents::SortEvent(this);
  if (TimingEvents::s_active_events_head == this)
    TimingEvents::UpdateCPUDowncount();
}

void TimingEvent::Activate()
{
  if (m_active)
    return;

  const GlobalTicks current_ticks = TimingEvents::GetGlobalTickCounter();
  m_next_run_time = current_ticks + static_cast<GlobalTicks>(m_interval);
  m_last_run_time = current_ticks;

  m_active = true;
  TimingEvents::AddActiveEvent(this);
}

void TimingEvent::Deactivate()
{
  if (!m_active)
    return;

  m_active = false;
  TimingEvents::RemoveActiveEvent(this);
}
