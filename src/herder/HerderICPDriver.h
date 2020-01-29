#pragma once

// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/Herder.h"
#include "herder/TxSetFrame.h"
#include "icp/ICPDriver.h"
#include "xdr/IOTChain-ledger.h"

namespace medida
{
class Counter;
class Meter;
class Timer;
class Histogram;
}

namespace iotchain
{
class Application;
class HerderImpl;
class LedgerManager;
class PendingEnvelopes;
class ICP;
class Upgrades;
class VirtualTimer;
struct IOTChainValue;
struct ICPEnvelope;

class HerderICPDriver : public ICPDriver
{
  public:
    struct ConsensusData
    {
        uint64_t mConsensusIndex;
        IOTChainValue mConsensusValue;
        ConsensusData(uint64_t index, IOTChainValue const& b)
            : mConsensusIndex(index), mConsensusValue(b)
        {
        }
    };

    HerderICPDriver(Application& app, HerderImpl& herder,
                    Upgrades const& upgrades,
                    PendingEnvelopes& pendingEnvelopes);
    ~HerderICPDriver();

    void bootstrap();
    void lostSync();

    Herder::State getState() const;

    ConsensusData*
    trackingICP() const
    {
        return mTrackingICP.get();
    }
    ConsensusData*
    lastTrackingICP() const
    {
        return mLastTrackingICP.get();
    }

    void restoreICPState(uint64_t index, IOTChainValue const& value);

    // the ledger index that was last externalized
    uint32
    lastConsensusLedgerIndex() const
    {
        assert(mTrackingICP->mConsensusIndex <= UINT32_MAX);
        return static_cast<uint32>(mTrackingICP->mConsensusIndex);
    }

    // the ledger index that we expect to externalize next
    uint32
    nextConsensusLedgerIndex() const
    {
        return lastConsensusLedgerIndex() + 1;
    }

    ICP&
    getICP()
    {
        return mICP;
    }

    void recordICPExecutionMetrics(uint64_t slotIndex);
    void recordICPEvent(uint64_t slotIndex, bool isNomination);

    // envelope handling
    void signEnvelope(ICPEnvelope& envelope) override;
    void emitEnvelope(ICPEnvelope const& envelope) override;

    // value validation
    ICPDriver::ValidationLevel validateValue(uint64_t slotIndex,
                                             Value const& value,
                                             bool nomination) override;
    Value extractValidValue(uint64_t slotIndex, Value const& value) override;

    // value marshaling
    std::string toShortString(PublicKey const& pk) const override;
    std::string getValueString(Value const& v) const override;

    // timer handling
    void setupTimer(uint64_t slotIndex, int timerID,
                    std::chrono::milliseconds timeout,
                    std::function<void()> cb) override;

    // core ICP
    Value combineCandidates(uint64_t slotIndex,
                            std::set<Value> const& candidates) override;
    void valueExternalized(uint64_t slotIndex, Value const& value) override;

    // Submit a value to consider for slotIndex
    // previousValue is the value from slotIndex-1
    void nominate(uint64_t slotIndex, IOTChainValue const& value,
                  TxSetFramePtr proposedSet, IOTChainValue const& previousValue);

    ICPQuorumSetPtr getQSet(Hash const& qSetHash) override;

    // listeners
    void ballotDidHearFromQuorum(uint64_t slotIndex,
                                 ICPBallot const& ballot) override;
    void nominatingValue(uint64_t slotIndex, Value const& value) override;
    void updatedCandidateValue(uint64_t slotIndex, Value const& value) override;
    void startedBallotProtocol(uint64_t slotIndex,
                               ICPBallot const& ballot) override;
    void acceptedBallotPrepared(uint64_t slotIndex,
                                ICPBallot const& ballot) override;
    void confirmedBallotPrepared(uint64_t slotIndex,
                                 ICPBallot const& ballot) override;
    void acceptedCommit(uint64_t slotIndex, ICPBallot const& ballot) override;

    optional<VirtualClock::time_point> getPrepareStart(uint64_t slotIndex);

    // converts a Value into a IOTChainValue
    // returns false on error
    bool toIOTChainValue(Value const& v, IOTChainValue& sv);

    // validate close time as much as possible
    bool checkCloseTime(uint64_t slotIndex, uint64_t lastCloseTime,
                        IOTChainValue const& b) const;

  private:
    Application& mApp;
    HerderImpl& mHerder;
    LedgerManager& mLedgerManager;
    Upgrades const& mUpgrades;
    PendingEnvelopes& mPendingEnvelopes;
    ICP mICP;

    struct ICPMetrics
    {
        medida::Meter& mEnvelopeSign;

        medida::Meter& mValueValid;
        medida::Meter& mValueInvalid;

        // listeners
        medida::Meter& mCombinedCandidates;

        // Timers for nomination and ballot protocols
        medida::Timer& mNominateToPrepare;
        medida::Timer& mPrepareToExternalize;

        ICPMetrics(Application& app);
    };

    ICPMetrics mICPMetrics;

    // Nomination timeouts per ledger
    medida::Histogram& mNominateTimeout;
    // Prepare timeouts per ledger
    medida::Histogram& mPrepareTimeout;

    struct ICPTiming
    {
        optional<VirtualClock::time_point> mNominationStart;
        optional<VirtualClock::time_point> mPrepareStart;

        // Nomination timeouts before first prepare
        int64_t mNominationTimeoutCount{0};
        // Prepare timeouts before externalize
        int64_t mPrepareTimeoutCount{0};
    };

    // Map of time points for each slot to measure key protocol metrics:
    // * nomination to first prepare
    // * first prepare to externalize
    std::map<uint64_t, ICPTiming> mICPExecutionTimes;

    uint32_t mLedgerSeqNominating;
    Value mCurrentValue;

    // timers used by ICP
    // indexed by slotIndex, timerID
    std::map<uint64_t, std::map<int, std::unique_ptr<VirtualTimer>>> mICPTimers;

    // if the local instance is tracking the current state of ICP
    // herder keeps track of the consensus index and ballot
    // when not set, it just means that herder will try to snap to any slot that
    // reached consensus
    // on startup, this can be set to a value persisted from the database
    std::unique_ptr<ConsensusData> mTrackingICP;

    // when losing track of consensus, we remember the consensus value so that
    // we can ignore older ledgers (as we potentially receive old messages)
    // it only tracks actual consensus values (learned when externalizing)
    std::unique_ptr<ConsensusData> mLastTrackingICP;

    void stateChanged();

    ICPDriver::ValidationLevel validateValueHelper(uint64_t slotIndex,
                                                   IOTChainValue const& sv,
                                                   bool nomination) const;

    // returns true if the local instance is in a state compatible with
    // this slot
    bool isSlotCompatibleWithCurrentState(uint64_t slotIndex) const;

    void logQuorumInformation(uint64_t index);

    void clearICPExecutionEvents();

    void timerCallbackWrapper(uint64_t slotIndex, int timerID,
                              std::function<void()> cb);
};
}
