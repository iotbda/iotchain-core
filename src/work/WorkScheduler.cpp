// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "work/WorkScheduler.h"
#include "util/Logging.h"

namespace iotchain
{
WorkScheduler::WorkScheduler(Application& app)
    : Work(app, "work-scheduler", BasicWork::RETRY_NEVER)
{
}

WorkScheduler::~WorkScheduler()
{
}

std::shared_ptr<WorkScheduler>
WorkScheduler::create(Application& app)
{
    auto work = std::shared_ptr<WorkScheduler>(new WorkScheduler(app));
    work->startWork(nullptr);
    work->crankWork();
    return work;
};

BasicWork::State
WorkScheduler::doWork()
{
    if (anyChildRunning())
    {
        return State::WORK_RUNNING;
    }
    return State::WORK_WAITING;
}

void
WorkScheduler::scheduleOne(std::weak_ptr<WorkScheduler> weak)
{
    auto self = weak.lock();
    if (!self || self->mScheduled)
    {
        return;
    }

    self->mScheduled = true;
    self->mApp.getClock().getIOContext().post([weak]() {
        auto innerSelf = weak.lock();
        if (!innerSelf)
        {
            return;
        }
        innerSelf->mScheduled = false;
        innerSelf->crankWork();
        if (innerSelf->getState() == State::WORK_RUNNING)
        {
            scheduleOne(weak);
        }
    });
}

void
WorkScheduler::shutdown()
{
    Work::shutdown();
    std::weak_ptr<WorkScheduler> weak(
        std::static_pointer_cast<WorkScheduler>(shared_from_this()));
    scheduleOne(weak);
}
}
