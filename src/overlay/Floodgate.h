#pragma once

// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "overlay/Peer.h"
#include "overlay/IOTChainXDR.h"
#include <map>

/**
 * FloodGate keeps track of which peers have sent us which broadcast messages,
 * in order to ensure that for each broadcast message M and for each peer P, we
 * either send M to P once (and only once), or receive M _from_ P (thereby
 * inhibit sending M to P at all).
 *
 * The broadcast message types are TRANSACTION and ICP_MESSAGE.
 *
 * All messages are marked with the ledger sequence number to which they
 * relate, and all flood-management information for a given ledger number
 * is purged from the FloodGate when the ledger closes.
 */

namespace medida
{
class Counter;
}

namespace iotchain
{

class Floodgate
{
    class FloodRecord
    {
      public:
        typedef std::shared_ptr<FloodRecord> pointer;

        uint32_t mLedgerSeq;
        IOTChainMessage mMessage;
        std::set<std::string> mPeersTold;

        FloodRecord(IOTChainMessage const& msg, uint32_t ledger,
                    Peer::pointer peer);
    };

    std::map<uint256, FloodRecord::pointer> mFloodMap;
    Application& mApp;
    medida::Counter& mFloodMapSize;
    medida::Meter& mSendFromBroadcast;
    bool mShuttingDown;

  public:
    Floodgate(Application& app);
    // Floodgate will be cleared after every ledger close
    void clearBelow(uint32_t currentLedger);
    // returns true if this is a new record
    bool addRecord(IOTChainMessage const& msg, Peer::pointer fromPeer);

    void broadcast(IOTChainMessage const& msg, bool force);

    // returns the list of peers that sent us the item with hash `h`
    std::set<Peer::pointer> getPeersKnows(Hash const& h);

    void shutdown();
};
}
