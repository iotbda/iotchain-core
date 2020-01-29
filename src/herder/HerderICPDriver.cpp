// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderICPDriver.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "crypto/SecretKey.h"
#include "herder/HerderImpl.h"
#include "herder/LedgerCloseData.h"
#include "herder/PendingEnvelopes.h"
#include "ledger/LedgerManager.h"
#include "main/Application.h"
#include "main/ErrorMessages.h"
#include "icp/ICP.h"
#include "icp/Slot.h"
#include "util/Logging.h"
#include "xdr/IOTChain-ICP.h"
#include "xdr/IOTChain-ledger-entries.h"
#include <medida/metrics_registry.h>
#include <util/format.h>
#include <xdrpp/marshal.h>

namespace iotchain
{

HerderICPDriver::ICPMetrics::ICPMetrics(Application& app)
    : mEnvelopeSign(
          app.getMetrics().NewMeter({"icp", "envelope", "sign"}, "envelope"))
    , mValueValid(app.getMetrics().NewMeter({"icp", "value", "valid"}, "value"))
    , mValueInvalid(
          app.getMetrics().NewMeter({"icp", "value", "invalid"}, "value"))
    , mCombinedCandidates(app.getMetrics().NewMeter(
          {"icp", "nomination", "combinecandidates"}, "value"))
    , mNominateToPrepare(
          app.getMetrics().NewTimer({"icp", "timing", "nominated"}))
    , mPrepareToExternalize(
          app.getMetrics().NewTimer({"icp", "timing", "externalized"}))
{
}

HerderICPDriver::HerderICPDriver(Application& app, HerderImpl& herder,
                                 Upgrades const& upgrades,
                                 PendingEnvelopes& pendingEnvelopes)
    : mApp{app}
    , mHerder{herder}
    , mLedgerManager{mApp.getLedgerManager()}
    , mUpgrades{upgrades}
    , mPendingEnvelopes{pendingEnvelopes}
    , mICP{*this, mApp.getConfig().NODE_SEED.getPublicKey(),
           mApp.getConfig().NODE_IS_VALIDATOR, mApp.getConfig().QUORUM_SET}
    , mICPMetrics{mApp}
    , mNominateTimeout{mApp.getMetrics().NewHistogram(
          {"icp", "timeout", "nominate"})}
    , mPrepareTimeout{mApp.getMetrics().NewHistogram(
          {"icp", "timeout", "prepare"})}
    , mLedgerSeqNominating(0)
{
}

HerderICPDriver::~HerderICPDriver()
{
}

void
HerderICPDriver::stateChanged()
{
    mApp.syncOwnMetrics();
}

void
HerderICPDriver::bootstrap()
{
    stateChanged();
    clearICPExecutionEvents();
}

void
HerderICPDriver::lostSync()
{
    stateChanged();

    // transfer ownership to mHerderICPDriver.lastTrackingICP()
    mLastTrackingICP.reset(mTrackingICP.release());
}

Herder::State
HerderICPDriver::getState() const
{
    // we're only returning "TRACKING" when we're tracking the actual network
    // (mLastTrackingICP is also set when this happens)
    return mTrackingICP && mLastTrackingICP ? Herder::HERDER_TRACKING_STATE
                                            : Herder::HERDER_SYNCING_STATE;
}

void
HerderICPDriver::restoreICPState(uint64_t index, IOTChainValue const& value)
{
    mTrackingICP = std::make_unique<ConsensusData>(index, value);
}

// envelope handling

void
HerderICPDriver::signEnvelope(ICPEnvelope& envelope)
{
    mICPMetrics.mEnvelopeSign.Mark();
    mHerder.signEnvelope(mApp.getConfig().NODE_SEED, envelope);
}

void
HerderICPDriver::emitEnvelope(ICPEnvelope const& envelope)
{
    mHerder.emitEnvelope(envelope);
}

// value validation

bool
HerderICPDriver::isSlotCompatibleWithCurrentState(uint64_t slotIndex) const
{
    bool res = false;
    if (mLedgerManager.isSynced())
    {
        auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();
        res = (slotIndex == (lcl.header.ledgerSeq + 1));
    }

    return res;
}

bool
HerderICPDriver::checkCloseTime(uint64_t slotIndex, uint64_t lastCloseTime,
                                IOTChainValue const& b) const
{
    // Check closeTime (not too old)
    if (b.closeTime <= lastCloseTime)
    {
        CLOG(TRACE, "Herder")
            << "Close time too old for slot " << slotIndex << ", got "
            << b.closeTime << " vs " << lastCloseTime;
        return false;
    }

    // Check closeTime (not too far in future)
    uint64_t timeNow = mApp.timeNow();
    if (b.closeTime > timeNow + Herder::MAX_TIME_SLIP_SECONDS.count())
    {
        CLOG(TRACE, "Herder")
            << "Close time too far in future for slot " << slotIndex << ", got "
            << b.closeTime << " vs " << timeNow;
        return false;
    }
    return true;
}

ICPDriver::ValidationLevel
HerderICPDriver::validateValueHelper(uint64_t slotIndex, IOTChainValue const& b,
                                     bool nomination) const
{
    uint64_t lastCloseTime;

    if (b.ext.v() == IOTCHAIN_VALUE_SIGNED)
    {
        if (nomination)
        {
            if (!mHerder.verifyIOTChainValueSignature(b))
            {
                return ICPDriver::kInvalidValue;
            }
        }
        else
        {
            // don't use signed values in ballot protocol
            return ICPDriver::kInvalidValue;
        }
    }

    bool compat = isSlotCompatibleWithCurrentState(slotIndex);

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;

    // when checking close time, start with what we have locally
    lastCloseTime = lcl.icpValue.closeTime;

    if (compat)
    {
        if (!checkCloseTime(slotIndex, lastCloseTime, b))
        {
            return ICPDriver::kInvalidValue;
        }
    }
    else
    {
        if (slotIndex == lcl.ledgerSeq)
        {
            // previous ledger
            if (b.closeTime != lastCloseTime)
            {
                CLOG(TRACE, "Herder")
                    << "Got a bad close time for ledger " << slotIndex
                    << ", got " << b.closeTime << " vs " << lastCloseTime;
                return ICPDriver::kInvalidValue;
            }
        }
        else if (slotIndex < lcl.ledgerSeq)
        {
            // basic sanity check on older value
            if (b.closeTime >= lastCloseTime)
            {
                CLOG(TRACE, "Herder")
                    << "Got a bad close time for ledger " << slotIndex
                    << ", got " << b.closeTime << " vs " << lastCloseTime;
                return ICPDriver::kInvalidValue;
            }
        }
        else if (!checkCloseTime(slotIndex, lastCloseTime, b))
        {
            // future messages must be valid compared to lastCloseTime
            return ICPDriver::kInvalidValue;
        }

        if (!mTrackingICP)
        {
            // if we're not tracking, there is not much more we can do to
            // validate
            if (Logging::logTrace("Herder"))
            {
                CLOG(TRACE, "Herder")
                    << "MaybeValidValue (not tracking) for slot " << slotIndex;
            }
            return ICPDriver::kMaybeValidValue;
        }

        // Check slotIndex.
        if (nextConsensusLedgerIndex() > slotIndex)
        {
            // we already moved on from this slot
            // still send it through for emitting the final messages
            if (Logging::logTrace("Herder"))
            {
                CLOG(TRACE, "Herder")
                    << "MaybeValidValue (already moved on) for slot "
                    << slotIndex << ", at " << nextConsensusLedgerIndex();
            }
            return ICPDriver::kMaybeValidValue;
        }
        if (nextConsensusLedgerIndex() < slotIndex)
        {
            // this is probably a bug as "tracking" means we're processing
            // messages only for smaller slots
            CLOG(ERROR, "Herder")
                << "HerderICPDriver::validateValue"
                << " i: " << slotIndex
                << " processing a future message while tracking "
                << "(tracking: " << mTrackingICP->mConsensusIndex << ", last: "
                << (mLastTrackingICP ? mLastTrackingICP->mConsensusIndex : 0)
                << " ) ";
            return ICPDriver::kInvalidValue;
        }

        // when tracking, we use the tracked time for last close time
        lastCloseTime = mTrackingICP->mConsensusValue.closeTime;
        if (!checkCloseTime(slotIndex, lastCloseTime, b))
        {
            return ICPDriver::kInvalidValue;
        }

        // this is as far as we can go if we don't have the state
        if (Logging::logTrace("Herder"))
        {
            CLOG(TRACE, "Herder")
                << "Can't validate locally, value may be valid for slot "
                << slotIndex;
        }
        return ICPDriver::kMaybeValidValue;
    }

    Hash const& txSetHash = b.txSetHash;

    // we are fully synced up

    if ((!nomination || lcl.ledgerVersion < 11) &&
        b.ext.v() != IOTCHAIN_VALUE_BASIC)
    {
        // ballot protocol or
        // pre version 11 only supports BASIC
        CLOG(TRACE, "Herder")
            << "HerderICPDriver::validateValue"
            << " i: " << slotIndex << " invalid value type - expected BASIC";
        return ICPDriver::kInvalidValue;
    }
    if (nomination &&
        (lcl.ledgerVersion >= 11 && b.ext.v() != IOTCHAIN_VALUE_SIGNED))
    {
        // v11 and above use SIGNED for nomination
        CLOG(TRACE, "Herder")
            << "HerderICPDriver::validateValue"
            << " i: " << slotIndex << " invalid value type - expected SIGNED";
        return ICPDriver::kInvalidValue;
    }

    TxSetFramePtr txSet = mPendingEnvelopes.getTxSet(txSetHash);

    ICPDriver::ValidationLevel res;

    if (!txSet)
    {
        CLOG(ERROR, "Herder") << "HerderICPDriver::validateValue"
                              << " i: " << slotIndex << " txSet not found?";

        res = ICPDriver::kInvalidValue;
    }
    else if (!txSet->checkValid(mApp))
    {
        if (Logging::logDebug("Herder"))
            CLOG(DEBUG, "Herder") << "HerderICPDriver::validateValue"
                                  << " i: " << slotIndex << " Invalid txSet:"
                                  << " " << hexAbbrev(txSet->getContentsHash());
        res = ICPDriver::kInvalidValue;
    }
    else
    {
        if (Logging::logDebug("Herder"))
            CLOG(DEBUG, "Herder")
                << "HerderICPDriver::validateValue"
                << " i: " << slotIndex
                << " txSet: " << hexAbbrev(txSet->getContentsHash()) << " OK";
        res = ICPDriver::kFullyValidatedValue;
    }
    return res;
}

ICPDriver::ValidationLevel
HerderICPDriver::validateValue(uint64_t slotIndex, Value const& value,
                               bool nomination)
{
    IOTChainValue b;
    try
    {
        xdr::xdr_from_opaque(value, b);
    }
    catch (...)
    {
        mICPMetrics.mValueInvalid.Mark();
        return ICPDriver::kInvalidValue;
    }

    ICPDriver::ValidationLevel res =
        validateValueHelper(slotIndex, b, nomination);
    if (res != ICPDriver::kInvalidValue)
    {
        auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

        LedgerUpgradeType lastUpgradeType = LEDGER_UPGRADE_VERSION;
        // check upgrades
        for (size_t i = 0;
             i < b.upgrades.size() && res != ICPDriver::kInvalidValue; i++)
        {
            LedgerUpgradeType thisUpgradeType;
            if (!mUpgrades.isValid(b.upgrades[i], thisUpgradeType, nomination,
                                   mApp.getConfig(), lcl.header))
            {
                CLOG(TRACE, "Herder")
                    << "HerderICPDriver::validateValue invalid step at index "
                    << i;
                res = ICPDriver::kInvalidValue;
            }
            else if (i != 0 && (lastUpgradeType >= thisUpgradeType))
            {
                CLOG(TRACE, "Herder")
                    << "HerderICPDriver::validateValue out of "
                       "order upgrade step at index "
                    << i;
                res = ICPDriver::kInvalidValue;
            }

            lastUpgradeType = thisUpgradeType;
        }
    }

    if (res)
    {
        mICPMetrics.mValueValid.Mark();
    }
    else
    {
        mICPMetrics.mValueInvalid.Mark();
    }
    return res;
}

Value
HerderICPDriver::extractValidValue(uint64_t slotIndex, Value const& value)
{
    IOTChainValue b;
    try
    {
        xdr::xdr_from_opaque(value, b);
    }
    catch (...)
    {
        return Value();
    }
    Value res;
    if (validateValueHelper(slotIndex, b, true) ==
        ICPDriver::kFullyValidatedValue)
    {
        auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

        // remove the upgrade steps we don't like
        LedgerUpgradeType thisUpgradeType;
        for (auto it = b.upgrades.begin(); it != b.upgrades.end();)
        {
            if (!mUpgrades.isValid(*it, thisUpgradeType, true, mApp.getConfig(),
                                   lcl.header))
            {
                it = b.upgrades.erase(it);
            }
            else
            {
                it++;
            }
        }

        res = xdr::xdr_to_opaque(b);
    }

    return res;
}

// value marshaling

std::string
HerderICPDriver::toShortString(PublicKey const& pk) const
{
    return mApp.getConfig().toShortString(pk);
}

std::string
HerderICPDriver::getValueString(Value const& v) const
{
    IOTChainValue b;
    if (v.empty())
    {
        return "[:empty:]";
    }

    try
    {
        xdr::xdr_from_opaque(v, b);

        return iotchainValueToString(mApp.getConfig(), b);
    }
    catch (...)
    {
        return "[:invalid:]";
    }
}

// timer handling
void
HerderICPDriver::timerCallbackWrapper(uint64_t slotIndex, int timerID,
                                      std::function<void()> cb)
{
    // reschedule timers for future slots when tracking
    if (trackingICP() && nextConsensusLedgerIndex() != slotIndex)
    {
        CLOG(WARNING, "Herder")
            << "Herder rescheduled timer " << timerID << " for slot "
            << slotIndex << " with next slot " << nextConsensusLedgerIndex();
        setupTimer(slotIndex, timerID, std::chrono::seconds(1),
                   std::bind(&HerderICPDriver::timerCallbackWrapper, this,
                             slotIndex, timerID, cb));
    }
    else
    {
        auto ICPTimingIt = mICPExecutionTimes.find(slotIndex);
        if (ICPTimingIt != mICPExecutionTimes.end())
        {
            auto& ICPTiming = ICPTimingIt->second;
            if (timerID == Slot::BALLOT_PROTOCOL_TIMER)
            {
                // Timeout happened in between first prepare and externalize
                ++ICPTiming.mPrepareTimeoutCount;
            }
            else
            {
                if (!ICPTiming.mPrepareStart)
                {
                    // Timeout happened between nominate and first prepare
                    ++ICPTiming.mNominationTimeoutCount;
                }
            }
        }

        cb();
    }
}

void
HerderICPDriver::setupTimer(uint64_t slotIndex, int timerID,
                            std::chrono::milliseconds timeout,
                            std::function<void()> cb)
{
    // don't setup timers for old slots
    if (slotIndex <= mApp.getHerder().getCurrentLedgerSeq())
    {
        mICPTimers.erase(slotIndex);
        return;
    }

    auto& slotTimers = mICPTimers[slotIndex];

    auto it = slotTimers.find(timerID);
    if (it == slotTimers.end())
    {
        it = slotTimers.emplace(timerID, std::make_unique<VirtualTimer>(mApp))
                 .first;
    }
    auto& timer = *it->second;
    timer.cancel();
    if (cb)
    {
        timer.expires_from_now(timeout);
        timer.async_wait(std::bind(&HerderICPDriver::timerCallbackWrapper, this,
                                   slotIndex, timerID, cb),
                         &VirtualTimer::onFailureNoop);
    }
}

// returns true if l < r
// lh, rh are the hashes of l,h
static bool
compareTxSets(TxSetFramePtr l, TxSetFramePtr r, Hash const& lh, Hash const& rh,
              LedgerHeader const& header, Hash const& s)
{
    if (l == nullptr)
    {
        return r != nullptr;
    }
    if (r == nullptr)
    {
        return false;
    }
    auto lSize = l->size(header);
    auto rSize = r->size(header);
    if (lSize < rSize)
    {
        return true;
    }
    else if (lSize > rSize)
    {
        return false;
    }
    if (header.ledgerVersion >= 11)
    {
        auto lFee = l->getTotalFees(header);
        auto rFee = r->getTotalFees(header);
        if (lFee < rFee)
        {
            return true;
        }
        else if (lFee > rFee)
        {
            return false;
        }
    }
    return lessThanXored(lh, rh, s);
}

Value
HerderICPDriver::combineCandidates(uint64_t slotIndex,
                                   std::set<Value> const& candidates)
{
    CLOG(DEBUG, "Herder") << "Combining " << candidates.size() << " candidates";
    mICPMetrics.mCombinedCandidates.Mark(candidates.size());

    Hash h;

    IOTChainValue comp(h, 0, emptyUpgradeSteps, IOTCHAIN_VALUE_BASIC);

    std::map<LedgerUpgradeType, LedgerUpgrade> upgrades;

    std::set<TransactionFramePtr> aggSet;

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

    Hash candidatesHash;

    std::vector<IOTChainValue> candidateValues;

    for (auto const& c : candidates)
    {
        candidateValues.emplace_back();
        IOTChainValue& sv = candidateValues.back();

        xdr::xdr_from_opaque(c, sv);
        candidatesHash ^= sha256(c);

        // max closeTime
        if (comp.closeTime < sv.closeTime)
        {
            comp.closeTime = sv.closeTime;
        }
        for (auto const& upgrade : sv.upgrades)
        {
            LedgerUpgrade lupgrade;
            xdr::xdr_from_opaque(upgrade, lupgrade);
            auto it = upgrades.find(lupgrade.type());
            if (it == upgrades.end())
            {
                upgrades.emplace(std::make_pair(lupgrade.type(), lupgrade));
            }
            else
            {
                LedgerUpgrade& clUpgrade = it->second;
                switch (lupgrade.type())
                {
                case LEDGER_UPGRADE_VERSION:
                    // pick the highest version
                    clUpgrade.newLedgerVersion() =
                        std::max(clUpgrade.newLedgerVersion(),
                                 lupgrade.newLedgerVersion());
                    break;
                case LEDGER_UPGRADE_BASE_FEE:
                    // take the max fee
                    clUpgrade.newBaseFee() =
                        std::max(clUpgrade.newBaseFee(), lupgrade.newBaseFee());
                    break;
                case LEDGER_UPGRADE_MAX_TX_SET_SIZE:
                    // take the max tx set size
                    clUpgrade.newMaxTxSetSize() =
                        std::max(clUpgrade.newMaxTxSetSize(),
                                 lupgrade.newMaxTxSetSize());
                    break;
                case LEDGER_UPGRADE_BASE_RESERVE:
                    // take the max base reserve
                    clUpgrade.newBaseReserve() = std::max(
                        clUpgrade.newBaseReserve(), lupgrade.newBaseReserve());
                    break;
                default:
                    // should never get there with values that are not valid
                    throw std::runtime_error("invalid upgrade step");
                }
            }
        }
    }

    // take the txSet with the biggest size, highest xored hash that we have
    TxSetFramePtr bestTxSet;
    {
        Hash highest;
        TxSetFramePtr highestTxSet;
        for (auto const& sv : candidateValues)
        {
            TxSetFramePtr cTxSet = mPendingEnvelopes.getTxSet(sv.txSetHash);

            if (cTxSet && cTxSet->previousLedgerHash() == lcl.hash)
            {
                if (compareTxSets(highestTxSet, cTxSet, highest, sv.txSetHash,
                                  lcl.header, candidatesHash))
                {
                    highestTxSet = cTxSet;
                    highest = sv.txSetHash;
                }
            }
        }
        // make a copy as we're about to modify it and we don't want to mess
        // with the txSet cache
        bestTxSet = std::make_shared<TxSetFrame>(*highestTxSet);
    }

    for (auto const& upgrade : upgrades)
    {
        Value v(xdr::xdr_to_opaque(upgrade.second));
        comp.upgrades.emplace_back(v.begin(), v.end());
    }

    // just to be sure
    auto removed = bestTxSet->trimInvalid(mApp);
    comp.txSetHash = bestTxSet->getContentsHash();

    if (removed.size() != 0)
    {
        CLOG(WARNING, "Herder") << "Candidate set had " << removed.size()
                                << " invalid transactions";

        // post to avoid triggering ICP handling code recursively
        mApp.postOnMainThreadWithDelay(
            [this, bestTxSet]() {
                mPendingEnvelopes.recvTxSet(bestTxSet->getContentsHash(),
                                            bestTxSet);
            },
            "HerderICPDriver: combineCandidates posts recvTxSet");
    }

    // Ballot Protocol uses BASIC values
    comp.ext.v(IOTCHAIN_VALUE_BASIC);
    return xdr::xdr_to_opaque(comp);
}

bool
HerderICPDriver::toIOTChainValue(Value const& v, IOTChainValue& sv)
{
    try
    {
        xdr::xdr_from_opaque(v, sv);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

void
HerderICPDriver::valueExternalized(uint64_t slotIndex, Value const& value)
{
    auto it = mICPTimers.begin(); // cancel all timers below this slot
    while (it != mICPTimers.end() && it->first <= slotIndex)
    {
        it = mICPTimers.erase(it);
    }

    if (slotIndex <= mApp.getHerder().getCurrentLedgerSeq())
    {
        // externalize may trigger on older slots:
        //  * when the current instance starts up
        //  * when getting back in sync (a gap potentially opened)
        // in both cases it's safe to just ignore those as we're already
        // tracking a more recent state
        CLOG(DEBUG, "Herder")
            << "Ignoring old ledger externalize " << slotIndex;
        return;
    }

    IOTChainValue b;
    try
    {
        xdr::xdr_from_opaque(value, b);
    }
    catch (...)
    {
        // This may not be possible as all messages are validated and should
        // therefore contain a valid IOTChainValue.
        CLOG(ERROR, "Herder") << "HerderICPDriver::valueExternalized"
                              << " Externalized IOTChainValue malformed";
        CLOG(ERROR, "Herder") << REPORT_INTERNAL_BUG;
        // no point in continuing as 'b' contains garbage at this point
        abort();
    }

    // log information from older ledger to increase the chances that
    // all messages made it
    if (slotIndex > 2)
    {
        logQuorumInformation(slotIndex - 2);
    }

    if (!mCurrentValue.empty())
    {
        // stop nomination
        // this may or may not be the ledger that is currently externalizing
        // in both cases, we want to stop nomination as:
        // either we're closing the current ledger (typical case)
        // or we're going to trigger catchup from history
        mICP.stopNomination(mLedgerSeqNominating);
        mCurrentValue.clear();
    }

    if (!mTrackingICP)
    {
        stateChanged();
    }

    mTrackingICP = std::make_unique<ConsensusData>(slotIndex, b);

    if (!mLastTrackingICP)
    {
        mLastTrackingICP = std::make_unique<ConsensusData>(*mTrackingICP);
    }

    mHerder.valueExternalized(slotIndex, b);
}

void
HerderICPDriver::logQuorumInformation(uint64_t index)
{
    std::string res;
    auto v = mApp.getHerder().getJsonQuorumInfo(mICP.getLocalNodeID(), true,
                                                false, index);
    auto qset = v.get("qset", "");
    if (!qset.empty())
    {
        std::string indexs = std::to_string(static_cast<uint32>(index));
        Json::FastWriter fw;
        CLOG(INFO, "Herder")
            << "Quorum information for " << index << " : " << fw.write(qset);
    }
}

void
HerderICPDriver::nominate(uint64_t slotIndex, IOTChainValue const& value,
                          TxSetFramePtr proposedSet,
                          IOTChainValue const& previousValue)
{
    mCurrentValue = xdr::xdr_to_opaque(value);
    mLedgerSeqNominating = static_cast<uint32_t>(slotIndex);

    auto valueHash = sha256(xdr::xdr_to_opaque(mCurrentValue));
    CLOG(DEBUG, "Herder") << "HerderICPDriver::triggerNextLedger"
                          << " txSet.size: "
                          << proposedSet->mTransactions.size()
                          << " previousLedgerHash: "
                          << hexAbbrev(proposedSet->previousLedgerHash())
                          << " value: " << hexAbbrev(valueHash)
                          << " slot: " << slotIndex;

    auto prevValue = xdr::xdr_to_opaque(previousValue);
    mICP.nominate(slotIndex, mCurrentValue, prevValue);
}

ICPQuorumSetPtr
HerderICPDriver::getQSet(Hash const& qSetHash)
{
    return mPendingEnvelopes.getQSet(qSetHash);
}

void
HerderICPDriver::ballotDidHearFromQuorum(uint64_t, ICPBallot const&)
{
}

void
HerderICPDriver::nominatingValue(uint64_t slotIndex, Value const& value)
{
    if (Logging::logDebug("Herder"))
        CLOG(DEBUG, "Herder") << "nominatingValue i:" << slotIndex
                              << " v: " << getValueString(value);
}

void
HerderICPDriver::updatedCandidateValue(uint64_t slotIndex, Value const& value)
{
}

void
HerderICPDriver::startedBallotProtocol(uint64_t slotIndex,
                                       ICPBallot const& ballot)
{
    recordICPEvent(slotIndex, false);
}
void
HerderICPDriver::acceptedBallotPrepared(uint64_t slotIndex,
                                        ICPBallot const& ballot)
{
}

void
HerderICPDriver::confirmedBallotPrepared(uint64_t slotIndex,
                                         ICPBallot const& ballot)
{
}

void
HerderICPDriver::acceptedCommit(uint64_t slotIndex, ICPBallot const& ballot)
{
}

optional<VirtualClock::time_point>
HerderICPDriver::getPrepareStart(uint64_t slotIndex)
{
    optional<VirtualClock::time_point> res;
    auto it = mICPExecutionTimes.find(slotIndex);
    if (it != mICPExecutionTimes.end())
    {
        res = it->second.mPrepareStart;
    }
    return res;
}

void
HerderICPDriver::recordICPEvent(uint64_t slotIndex, bool isNomination)
{

    auto& timing = mICPExecutionTimes[slotIndex];
    VirtualClock::time_point start = mApp.getClock().now();

    if (isNomination)
    {
        timing.mNominationStart =
            make_optional<VirtualClock::time_point>(start);
    }
    else
    {
        timing.mPrepareStart = make_optional<VirtualClock::time_point>(start);
    }
}

void
HerderICPDriver::recordICPExecutionMetrics(uint64_t slotIndex)
{
    auto externalizeStart = mApp.getClock().now();

    // Use threshold of 0 in case of a single node
    auto& qset = mApp.getConfig().QUORUM_SET;
    auto isSingleNode = qset.innerSets.size() == 0 &&
                        qset.validators.size() == 1 &&
                        qset.validators[0] == getICP().getLocalNodeID();
    auto threshold = isSingleNode ? std::chrono::nanoseconds::zero()
                                  : Herder::TIMERS_THRESHOLD_NANOSEC;

    auto ICPTimingIt = mICPExecutionTimes.find(slotIndex);
    if (ICPTimingIt == mICPExecutionTimes.end())
    {
        return;
    }

    auto& ICPTiming = ICPTimingIt->second;

    mNominateTimeout.Update(ICPTiming.mNominationTimeoutCount);
    mPrepareTimeout.Update(ICPTiming.mPrepareTimeoutCount);

    auto recordTiming = [&](VirtualClock::time_point start,
                            VirtualClock::time_point end, medida::Timer& timer,
                            std::string const& logStr) {
        auto delta =
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        CLOG(DEBUG, "Herder") << fmt::format("{} delta for slot {} is {} ns.",
                                             logStr, slotIndex, delta.count());
        if (delta >= threshold)
        {
            timer.Update(delta);
        }
    };

    // Compute nomination time
    if (ICPTiming.mNominationStart && ICPTiming.mPrepareStart)
    {
        recordTiming(*ICPTiming.mNominationStart, *ICPTiming.mPrepareStart,
                     mICPMetrics.mNominateToPrepare, "Nominate");
    }

    // Compute prepare time
    if (ICPTiming.mPrepareStart)
    {
        recordTiming(*ICPTiming.mPrepareStart, externalizeStart,
                     mICPMetrics.mPrepareToExternalize, "Prepare");
    }

    // Clean up timings map
    auto it = mICPExecutionTimes.begin();
    while (it != mICPExecutionTimes.end() && it->first < slotIndex)
    {
        it = mICPExecutionTimes.erase(it);
    }
}

void
HerderICPDriver::clearICPExecutionEvents()
{
    mICPExecutionTimes.clear();
}
}
