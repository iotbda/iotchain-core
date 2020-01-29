#pragma once

// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/QuorumTracker.h"
#include "overlay/Peer.h"
#include "xdr/IOTChain-ICP.h"
#include <cstdint>
#include <memory>
#include <vector>

namespace soci
{
class session;
}

namespace iotchain
{
class Application;
class Database;
class XDROutputFileStream;

class HerderPersistence
{
  public:
    static std::unique_ptr<HerderPersistence> create(Application& app);

    virtual ~HerderPersistence()
    {
    }

    virtual void saveICPHistory(uint32_t seq,
                                std::vector<ICPEnvelope> const& envs,
                                QuorumTracker::QuorumMap const& qmap) = 0;

    static size_t copyICPHistoryToStream(Database& db, soci::session& sess,
                                         uint32_t ledgerSeq,
                                         uint32_t ledgerCount,
                                         XDROutputFileStream& icpHistory);
    // quorum information lookup
    static optional<Hash> getNodeQuorumSet(Database& db, soci::session& sess,
                                           NodeID const& nodeID);
    static ICPQuorumSetPtr getQuorumSet(Database& db, soci::session& sess,
                                        Hash const& qSetHash);

    static void dropAll(Database& db);
    static void deleteOldEntries(Database& db, uint32_t ledgerSeq,
                                 uint32_t count);

    static void createQuorumTrackingTable(soci::session& sess);
};
}
