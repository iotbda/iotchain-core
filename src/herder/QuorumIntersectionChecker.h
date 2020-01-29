#pragma once

// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/QuorumTracker.h"
#include <memory>

namespace iotchain
{

class Config;

class QuorumIntersectionChecker
{
  public:
    static std::shared_ptr<QuorumIntersectionChecker>
    create(iotchain::QuorumTracker::QuorumMap const& qmap,
           iotchain::Config const& cfg, bool quiet = false);

    static std::set<std::set<PublicKey>>
    getIntersectionCriticalGroups(iotchain::QuorumTracker::QuorumMap const& qmap,
                                  iotchain::Config const& cfg);

    virtual ~QuorumIntersectionChecker(){};
    virtual bool networkEnjoysQuorumIntersection() const = 0;
    virtual size_t getMaxQuorumsFound() const = 0;
    virtual std::pair<std::vector<PublicKey>, std::vector<PublicKey>>
    getPotentialSplit() const = 0;
};
}
