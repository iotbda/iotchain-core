#pragma once

// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/Herder.h"
#include "herder/HerderICPDriver.h"
#include "herder/PendingEnvelopes.h"
#include "herder/TransactionQueue.h"
#include "herder/Upgrades.h"
#include "util/Timer.h"
#include "util/XDROperators.h"
#include <deque>
#include <memory>
#include <unordered_map>
#include <vector>

namespace medida
{
class Meter;
class Counter;
class Timer;
}

namespace iotchain
{
class Application;
class LedgerManager;
class HerderICPDriver;

/*
 * Is in charge of receiving transactions from the network.
 */
class HerderImpl : public Herder
{
  public:
    HerderImpl(Application& app);
    ~HerderImpl();

    State getState() const override;
    std::string getStateHuman() const override;

    void syncMetrics() override;

    // Bootstraps the HerderImpl if we're creating a new Network
    void bootstrap() override;

    void restoreState() override;

    ICP& getICP();
    HerderICPDriver&
    getHerderICPDriver()
    {
        return mHerderICPDriver;
    }

    void valueExternalized(uint64 slotIndex, IOTChainValue const& value);
    void emitEnvelope(ICPEnvelope const& envelope);

    TransactionQueue::AddResult
    recvTransaction(TransactionFramePtr tx) override;

    EnvelopeStatus recvICPEnvelope(ICPEnvelope const& envelope) override;
    EnvelopeStatus recvICPEnvelope(ICPEnvelope const& envelope,
                                   const ICPQuorumSet& qset,
                                   TxSetFrame txset) override;

    void sendICPStateToPeer(uint32 ledgerSeq, Peer::pointer peer) override;

    bool recvICPQuorumSet(Hash const& hash, const ICPQuorumSet& qset) override;
    bool recvTxSet(Hash const& hash, const TxSetFrame& txset) override;
    void peerDoesntHave(MessageType type, uint256 const& itemID,
                        Peer::pointer peer) override;
    TxSetFramePtr getTxSet(Hash const& hash) override;
    ICPQuorumSetPtr getQSet(Hash const& qSetHash) override;

    void processICPQueue();

    uint32_t getCurrentLedgerSeq() const override;

    SequenceNumber getMaxSeqInPendingTxs(AccountID const&) override;

    void triggerNextLedger(uint32_t ledgerSeqToTrigger) override;

    void setUpgrades(Upgrades::UpgradeParameters const& upgrades) override;
    std::string getUpgradesJson() override;

    bool resolveNodeID(std::string const& s, PublicKey& retKey) override;

    Json::Value getJsonInfo(size_t limit, bool fullKeys = false) override;
    Json::Value getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys,
                                  uint64 index) override;
    Json::Value getJsonTransitiveQuorumIntersectionInfo(bool fullKeys) const;
    virtual Json::Value getJsonTransitiveQuorumInfo(NodeID const& id,
                                                    bool summary,
                                                    bool fullKeys) override;
    QuorumTracker::QuorumMap const& getCurrentlyTrackedQuorum() const override;

#ifdef BUILD_TESTS
    // used for testing
    PendingEnvelopes& getPendingEnvelopes();
#endif

    // helper function to verify envelopes are signed
    bool verifyEnvelope(ICPEnvelope const& envelope);
    // helper function to sign envelopes
    void signEnvelope(SecretKey const& s, ICPEnvelope& envelope);

    // helper function to verify ICPValues are signed
    bool verifyIOTChainValueSignature(IOTChainValue const& sv);
    // helper function to sign ICPValues
    void signIOTChainValue(SecretKey const& s, IOTChainValue& sv);

  private:
    // return true if values referenced by envelope have a valid close time:
    // * it's within the allowed range (using lcl if possible)
    // * it's recent enough (if `enforceRecent` is set)
    bool checkCloseTime(ICPEnvelope const& envelope, bool enforceRecent);

    void ledgerClosed();

    void startRebroadcastTimer();
    void rebroadcast();
    void broadcast(ICPEnvelope const& e);

    void processICPQueueUpToIndex(uint64 slotIndex);

    TransactionQueue mTransactionQueue;

    void
    updateTransactionQueue(std::vector<TransactionFramePtr> const& applied);

    PendingEnvelopes mPendingEnvelopes;
    Upgrades mUpgrades;
    HerderICPDriver mHerderICPDriver;

    void herderOutOfSync();

    // attempt to retrieve additional ICP messages from peers
    void getMoreICPState();

    // last slot that was persisted into the database
    // keep track of all messages for MAX_SLOTS_TO_REMEMBER slots
    uint64 mLastSlotSaved;

    // timer that detects that we're stuck on an ICP slot
    VirtualTimer mTrackingTimer;

    // tracks the last time externalize was called
    VirtualClock::time_point mLastExternalize;

    // saves the ICP messages that the instance sent out last
    void persistICPState(uint64 slot);
    // restores ICP state based on the last messages saved on disk
    void restoreICPState();

    // saves upgrade parameters
    void persistUpgrades();
    void restoreUpgrades();

    // called every time we get ledger externalized
    // ensures that if we don't hear from the network, we throw the herder into
    // indeterminate mode
    void trackingHeartBeat();

    VirtualTimer mTriggerTimer;

    VirtualTimer mRebroadcastTimer;

    Application& mApp;
    LedgerManager& mLedgerManager;

    struct ICPMetrics
    {
        medida::Meter& mLostSync;

        medida::Meter& mEnvelopeEmit;
        medida::Meter& mEnvelopeReceive;

        // Counters for things reached-through the
        // ICP maps: Slots and Nodes
        medida::Counter& mCumulativeStatements;

        // envelope signature verification
        medida::Meter& mEnvelopeValidSig;
        medida::Meter& mEnvelopeInvalidSig;

        ICPMetrics(Application& app);
    };

    ICPMetrics mICPMetrics;

    // Check that the quorum map intersection state is up to date, and if not
    // run a background job that re-analyzes the current quorum map.
    void checkAndMaybeReanalyzeQuorumMap();

    struct QuorumMapIntersectionState
    {
        uint32_t mLastCheckLedger{0};
        uint32_t mLastGoodLedger{0};
        size_t mNumNodes{0};
        Hash mLastCheckQuorumMapHash{};
        bool mRecalculating{false};
        std::pair<std::vector<PublicKey>, std::vector<PublicKey>>
            mPotentialSplit{};
        std::set<std::set<PublicKey>> mIntersectionCriticalNodes{};

        bool
        hasAnyResults() const
        {
            return mLastGoodLedger != 0;
        }

        bool
        enjoysQuorunIntersection() const
        {
            return mLastCheckLedger == mLastGoodLedger;
        }
    };
    QuorumMapIntersectionState mLastQuorumMapIntersectionState;
};
}
