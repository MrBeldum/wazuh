// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _SCHEDULER_TRIGGERABLE_TASK_HPP
#define _SCHEDULER_TRIGGERABLE_TASK_HPP

#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

#include <base/logging.hpp>

#include <scheduler/ischeduler.hpp>

namespace scheduler
{

/**
 * @brief A scheduler task that also runs when asked to.
 *
 * Runs on its interval like any recurring task and, in between, whenever @ref trigger is called. A
 * request is never lost and never runs the work twice at once: one that arrives while the work is
 * running makes it run once more right after, so every request is answered by a run that started
 * after it. Without an interval the task runs only when triggered.
 */
class TriggerableTask final
{
public:
    /**
     * @brief Describe the task. Nothing is scheduled until @ref start or @ref trigger.
     *
     * @param scheduler The scheduler that runs it.
     * @param name Task name, unique in the scheduler.
     * @param interval Seconds between runs; 0 = only when triggered.
     * @param cpuPriority Nice value of the runs.
     * @param work What a run does. Exceptions are logged and do not stop later runs.
     */
    TriggerableTask(std::weak_ptr<IScheduler> scheduler,
                    std::string name,
                    std::size_t interval,
                    int cpuPriority,
                    std::function<void()> work)
        : m_scheduler(std::move(scheduler))
        , m_state(std::make_shared<State>())
        , m_interval(interval)
        , m_cpuPriority(cpuPriority)
    {
        m_state->name = std::move(name);
        m_state->work = std::move(work);
    }

    /**
     * @brief Register the recurring task, first run immediately. A no-op without an interval.
     *
     * @throws std::exception whatever the scheduler throws (e.g. a duplicate name).
     */
    void start()
    {
        if (m_interval == 0)
        {
            return;
        }
        lockScheduler()->scheduleTask(m_state->name, config(m_interval));
    }

    /**
     * @brief Run as soon as possible. Never blocks and never throws.
     */
    void trigger() noexcept
    {
        {
            std::lock_guard<std::mutex> lock {m_state->mutex};
            if (m_state->running)
            {
                m_state->rerun = true;
                return;
            }
        }

        try
        {
            if (m_interval > 0)
            {
                lockScheduler()->scheduleTaskFirst(m_state->name);
            }
            else
            {
                lockScheduler()->scheduleTask(m_state->name, config(0));
            }
        }
        catch (const std::exception& e)
        {
            // Already queued (a one-time run not started yet), or the scheduler is gone: either way
            // the request is either already covered or cannot be served.
            LOG_DEBUG("[Scheduler] Task '{}' not queued again: {}", m_state->name, e.what());
        }
    }

private:
    struct State
    {
        std::string name;
        std::function<void()> work;
        std::mutex mutex;
        bool running {false};
        bool rerun {false};
    };

    /// One scheduler execution: the work, then once more for every request that arrived meanwhile.
    static void run(const std::shared_ptr<State>& state)
    {
        {
            std::lock_guard<std::mutex> lock {state->mutex};
            state->running = true;
            state->rerun = false;
        }

        while (true)
        {
            try
            {
                state->work();
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("[Scheduler] Task '{}' failed: {}", state->name, e.what());
            }

            std::lock_guard<std::mutex> lock {state->mutex};
            if (!state->rerun)
            {
                state->running = false;
                return;
            }
            state->rerun = false;
        }
    }

    TaskConfig config(std::size_t interval) const
    {
        return TaskConfig {interval, true, m_cpuPriority, [state = m_state]() { run(state); }};
    }

    std::shared_ptr<IScheduler> lockScheduler() const
    {
        auto scheduler = m_scheduler.lock();
        if (!scheduler)
        {
            throw std::runtime_error("the scheduler is gone");
        }
        return scheduler;
    }

    std::weak_ptr<IScheduler> m_scheduler;
    std::shared_ptr<State> m_state;
    std::size_t m_interval;
    int m_cpuPriority;
};

} // namespace scheduler

#endif // _SCHEDULER_TRIGGERABLE_TASK_HPP
