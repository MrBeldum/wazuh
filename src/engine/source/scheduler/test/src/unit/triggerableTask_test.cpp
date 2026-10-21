// SPDX-License-Identifier: AGPL-3.0-or-later
#include <memory>
#include <stdexcept>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <scheduler/mockScheduler.hpp>
#include <scheduler/triggerableTask.hpp>

using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;
using ::testing::Throw;

namespace
{

class TriggerableTaskTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    /// Remember the task function the scheduler was handed, so a test can run it.
    void captureNextSchedule()
    {
        EXPECT_CALL(*m_scheduler, scheduleTask(_, _))
            .WillOnce(Invoke(
                [this](std::string_view, scheduler::TaskConfig&& config)
                {
                    m_interval = config.interval;
                    m_run = std::move(config.taskFunction);
                }));
    }

    std::shared_ptr<StrictMock<scheduler::mocks::MockIScheduler>> m_scheduler {
        std::make_shared<StrictMock<scheduler::mocks::MockIScheduler>>()};
    std::function<void()> m_run;
    std::size_t m_interval {0};
};

} // namespace

TEST_F(TriggerableTaskTest, StartRegistersARecurringTask)
{
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler, "task", 60, 0, [&runs]() { ++runs; }};

    captureNextSchedule();
    task.start();

    EXPECT_EQ(m_interval, 60U);
    m_run();
    EXPECT_EQ(runs, 1);
}

TEST_F(TriggerableTaskTest, WithoutAnIntervalStartSchedulesNothing)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, []() {}};
    task.start(); // StrictMock: any scheduler call fails the test.
}

TEST_F(TriggerableTaskTest, ATriggerMovesARecurringTaskToTheFront)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 60, 0, []() {}};

    EXPECT_CALL(*m_scheduler, scheduleTaskFirst(std::string_view {"task"}));
    task.trigger();
}

TEST_F(TriggerableTaskTest, ATriggerWithoutAnIntervalSchedulesOneRun)
{
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, [&runs]() { ++runs; }};

    captureNextSchedule();
    task.trigger();

    EXPECT_EQ(m_interval, 0U) << "a one-time task";
    m_run();
    EXPECT_EQ(runs, 1);
}

TEST_F(TriggerableTaskTest, ATriggerDuringARunRunsOnceMoreRightAfter)
{
    int runs = 0;
    std::unique_ptr<scheduler::TriggerableTask> task;
    task = std::make_unique<scheduler::TriggerableTask>(m_scheduler,
                                                        "task",
                                                        60,
                                                        0,
                                                        [&runs, &task]()
                                                        {
                                                            // A request arriving mid-run: twice, to show
                                                            // requests coalesce into one more run.
                                                            if (++runs == 1)
                                                            {
                                                                task->trigger();
                                                                task->trigger();
                                                            }
                                                        });

    captureNextSchedule();
    task->start();
    m_run(); // StrictMock: the mid-run triggers must not reach the scheduler.

    EXPECT_EQ(runs, 2);
}

TEST_F(TriggerableTaskTest, AFailingRunIsContainedAndTheTaskStaysUsable)
{
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler,
                                     "task",
                                     60,
                                     0,
                                     [&runs]()
                                     {
                                         ++runs;
                                         throw std::runtime_error("boom");
                                     }};

    captureNextSchedule();
    task.start();
    EXPECT_NO_THROW(m_run());
    EXPECT_NO_THROW(m_run());
    EXPECT_EQ(runs, 2);

    EXPECT_CALL(*m_scheduler, scheduleTaskFirst(_));
    task.trigger();
}

TEST_F(TriggerableTaskTest, ASchedulerThatRefusesTheTriggerIsContained)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, []() {}};

    EXPECT_CALL(*m_scheduler, scheduleTask(_, _)).WillOnce(Throw(std::runtime_error("already exists")));
    EXPECT_NO_THROW(task.trigger());
}

TEST_F(TriggerableTaskTest, AGoneSchedulerIsContained)
{
    std::weak_ptr<scheduler::IScheduler> gone;
    scheduler::TriggerableTask task {gone, "task", 60, 0, []() {}};

    EXPECT_NO_THROW(task.trigger());
    EXPECT_THROW(task.start(), std::runtime_error);
}
