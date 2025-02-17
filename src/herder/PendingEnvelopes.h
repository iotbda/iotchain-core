﻿#pragma once
#include "crypto/SecretKey.h"
#include "herder/Herder.h"
#include "herder/QuorumTracker.h"
#include "lib/json/json.h"
#include "lib/util/lrucache.hpp"
#include "overlay/ItemFetcher.h"
#include <autocheck/function.hpp>
#include <chrono>
#include <map>
#include <medida/medida.h>
#include <queue>
#include <set>
#include <util/optional.h>

/*
ICP messages that you have received but are waiting to get the info of
before feeding into ICP
*/

namespace iotchain
{

class HerderImpl;

struct SlotEnvelopes
{
    // list of envelopes we have processed already
    std::vector<ICPEnvelope> mProcessedEnvelopes;
    // list of envelopes we have discarded already
    std::set<ICPEnvelope> mDiscardedEnvelopes;
    // list of envelopes we are fetching right now
    std::map<ICPEnvelope, std::chrono::steady_clock::time_point>
        mFetchingEnvelopes;
    // list of ready envelopes that haven't been sent to ICP yet
    std::vector<ICPEnvelope> mReadyEnvelopes;
};

class PendingEnvelopes
{
    Application& mApp;
    HerderImpl& mHerder;

    // ledger# and list of envelopes in various states
    std::map<uint64, SlotEnvelopes> mEnvelopes;

    // all the quorum sets we have learned about
    cache::lru_cache<Hash, ICPQuorumSetPtr> mQsetCache;

    ItemFetcher mTxSetFetcher;
    ItemFetcher mQuorumSetFetcher;

    using TxSetFramCacheItem = std::pair<uint64, TxSetFramePtr>;
    // all the txsets we have learned about per ledger#
    cache::lru_cache<Hash, TxSetFramCacheItem> mTxSetCache;

    bool mRebuildQuorum;
    QuorumTracker mQuorumTracker;

    medida::Counter& mProcessedCount;
    medida::Counter& mDiscardedCount;
    medida::Counter& mFetchingCount;
    medida::Counter& mReadyCount;
    medida::Timer& mFetchDuration;

    // discards all ICP envelopes thats use QSet with given hash,
    // as it is not sane QSet
    void discardICPEnvelopesWithQSet(Hash hash);

    void updateMetrics();

  public:
    PendingEnvelopes(Application& app, HerderImpl& herder);
    ~PendingEnvelopes();

    /**
     * Process received @p envelope.
     *
     * Return status of received envelope.
     */
    Herder::EnvelopeStatus recvICPEnvelope(ICPEnvelope const& envelope);

    /**
     * Add @p qset identified by @p hash to local cache. Notifies
     * @see ItemFetcher about that event - it may cause calls to Herder's
     * recvICPEnvelope which in turn may cause calls to @see recvICPEnvelope
     * in PendingEnvelopes.
     */
    void addICPQuorumSet(Hash hash, const ICPQuorumSet& qset);

    /**
     * Check if @p qset identified by @p hash was requested before from peers.
     * If not, ignores that @p qset. If it was requested, calls
     * @see addICPQuorumSet.
     *
     * Return true if ICPQuorumSet is sane and useful (was asked for).
     */
    bool recvICPQuorumSet(Hash hash, const ICPQuorumSet& qset);

    /**
     * Add @p txset identified by @p hash to local cache. Notifies
     * @see ItemFetcher about that event - it may cause calls to Herder's
     * recvICPEnvelope which in turn may cause calls to @see recvICPEnvelope
     * in PendingEnvelopes.
     */
    void addTxSet(Hash hash, uint64 lastSeenSlotIndex, TxSetFramePtr txset);

    /**
     * Check if @p txset identified by @p hash was requested before from peers.
     * If not, ignores that @p txset. If it was requested, calls
     * @see addTxSet.
     *
     * Return true if TxSet useful (was asked for).
     */
    bool recvTxSet(Hash hash, TxSetFramePtr txset);
    void discardICPEnvelope(ICPEnvelope const& envelope);

    void peerDoesntHave(MessageType type, Hash const& itemID,
                        Peer::pointer peer);

    bool isDiscarded(ICPEnvelope const& envelope) const;
    bool isFullyFetched(ICPEnvelope const& envelope);
    void startFetch(ICPEnvelope const& envelope);
    void stopFetch(ICPEnvelope const& envelope);
    void touchFetchCache(ICPEnvelope const& envelope);

    void envelopeReady(ICPEnvelope const& envelope);

    bool pop(uint64 slotIndex, ICPEnvelope& ret);

    void eraseBelow(uint64 slotIndex);

    void slotClosed(uint64 slotIndex);

    std::vector<uint64> readySlots();

    Json::Value getJsonInfo(size_t limit);

    TxSetFramePtr getTxSet(Hash const& hash);
    ICPQuorumSetPtr getQSet(Hash const& hash);

    // returns true if we think that the node is in the transitive quorum for
    // sure
    bool isNodeDefinitelyInQuorum(NodeID const& node);

    void rebuildQuorumTrackerState();
    QuorumTracker::QuorumMap const& getCurrentlyTrackedQuorum() const;

    // updates internal state when an envelope was succesfuly processed
    void envelopeProcessed(ICPEnvelope const& env);
};
}
