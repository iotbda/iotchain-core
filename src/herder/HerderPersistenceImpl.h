#pragma once

// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderPersistence.h"

namespace iotchain
{
class Application;

class HerderPersistenceImpl : public HerderPersistence
{

  public:
    HerderPersistenceImpl(Application& app);
    ~HerderPersistenceImpl();

    void saveICPHistory(uint32_t seq, std::vector<ICPEnvelope> const& envs,
                        QuorumTracker::QuorumMap const& qmap) override;

  private:
    Application& mApp;
};
}
