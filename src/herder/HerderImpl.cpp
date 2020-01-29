// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderImpl.h"
#include "crypto/Hex.h"
#include "crypto/KeyUtils.h"
#include "crypto/SHA.h"
#include "herder/HerderPersistence.h"
#include "herder/HerderUtils.h"
#include "herder/LedgerCloseData.h"
#include "herder/QuorumIntersectionChecker.h"
#include "herder/TxSetFrame.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "lib/json/json.h"
#include "main/Application.h"
#include "main/Config.h"
#include "main/ErrorMessages.h"
#include "main/PersistentState.h"
#include "overlay/OverlayManager.h"
#include "icp/LocalNode.h"
#include "icp/Slot.h"
#include "transactions/TransactionUtils.h"
#include "util/Logging.h"
#include "util/StatusManager.h"
#include "util/Timer.h"

#include "medida/counter.h"
#include "medida/meter.h"
#include "medida/metrics_registry.h"
#include "util/Decoder.h"
#include "util/XDRStream.h"
#include "xdrpp/marshal.h"

#include <ctime>
#include <lib/util/format.h>

using namespace std;

namespace iotchain
{

constexpr auto const TRANSACTION_QUEUE_SIZE = 4;
constexpr auto const TRANSACTION_QUEUE_BAN_SIZE = 10;

std::unique_ptr<Herder>
Herder::create(Application& app)
{
    return std::make_unique<HerderImpl>(app);
}

HerderImpl::ICPMetrics::ICPMetrics(Application& app)
    : mLostSync(app.getMetrics().NewMeter({"icp", "sync", "lost"}, "sync"))
    , mEnvelopeEmit(
          app.getMetrics().NewMeter({"icp", "envelope", "emit"}, "envelope"))
    , mEnvelopeReceive(
          app.getMetrics().NewMeter({"icp", "envelope", "receive"}, "envelope"))
    , mCumulativeStatements(app.getMetrics().NewCounter(
          {"icp", "memory", "cumulative-statements"}))
    , mEnvelopeValidSig(app.getMetrics().NewMeter(
          {"icp", "envelope", "validsig"}, "envelope"))
    , mEnvelopeInvalidSig(app.getMetrics().NewMeter(
          {"icp", "envelope", "invalidsig"}, "envelope"))
{
}

HerderImpl::HerderImpl(Application& app)
    : mTransactionQueue(app, TRANSACTION_QUEUE_SIZE, TRANSACTION_QUEUE_BAN_SIZE)
    , mPendingEnvelopes(app, *this)
    , mHerderICPDriver(app, *this, mUpgrades, mPendingEnvelopes)
    , mLastSlotSaved(0)
    , mTrackingTimer(app)
    , mLastExternalize(app.getClock().now())
    , mTriggerTimer(app)
    , mRebroadcastTimer(app)
    , mApp(app)
    , mLedgerManager(app.getLedgerManager())
    , mICPMetrics(app)
{
    Hash hash = getICP().getLocalNode()->getQuorumSetHash();
    mPendingEnvelopes.addICPQuorumSet(hash,
                                      getICP().getLocalNode()->getQuorumSet());
}

HerderImpl::~HerderImpl()
{
}

Herder::State
HerderImpl::getState() const
{
    return mHerderICPDriver.getState();
}

ICP&
HerderImpl::getICP()
{
    return mHerderICPDriver.getICP();
}

void
HerderImpl::syncMetrics()
{
    mICPMetrics.mCumulativeStatements.set_count(
        getICP().getCumulativeStatemtCount());
}

std::string
HerderImpl::getStateHuman() const
{
    static const char* stateStrings[HERDER_NUM_STATE] = {
        "HERDER_SYNCING_STATE", "HERDER_TRACKING_STATE"};
    return std::string(stateStrings[getState()]);
}

void
HerderImpl::bootstrap()
{
    CLOG(INFO, "Herder") << "Force joining ICP with local state";
    assert(getICP().isValidator());
    assert(mApp.getConfig().FORCE_ICP);

    mLedgerManager.bootstrap();
    mHerderICPDriver.bootstrap();

    ledgerClosed();
}

void
HerderImpl::valueExternalized(uint64 slotIndex, IOTChainValue const& value)
{
    const int DUMP_ICP_TIMEOUT_SECONDS = 20;

    // record metrics
    getHerderICPDriver().recordICPExecutionMetrics(slotIndex);

    // called both here and at the end (this one is in case of an exception)
    trackingHeartBeat();

    bool validated = getICP().isSlotFullyValidated(slotIndex);

    if (Logging::logDebug("Herder"))
        CLOG(DEBUG, "Herder") << fmt::format(
            "HerderICPDriver::valueExternalized index: {} txSet: {}", slotIndex,
            hexAbbrev(value.txSetHash));

    if (getICP().isValidator() && !validated)
    {
        CLOG(WARNING, "Herder")
            << fmt::format("Ledger {} ({}) closed and could NOT be fully "
                           "validated by validator",
                           slotIndex, hexAbbrev(value.txSetHash));
    }

    TxSetFramePtr externalizedSet = mPendingEnvelopes.getTxSet(value.txSetHash);

    // trigger will be recreated when the ledger is closed
    // we do not want it to trigger while downloading the current set
    // and there is no point in taking a position after the round is over
    mTriggerTimer.cancel();

    // save the ICP messages in the database
    mApp.getHerderPersistence().saveICPHistory(
        static_cast<uint32>(slotIndex),
        getICP().getExternalizingState(slotIndex),
        mPendingEnvelopes.getCurrentlyTrackedQuorum());

    // reflect upgrades with the ones included in this ICP round
    {
        bool updated;
        auto newUpgrades = mUpgrades.removeUpgrades(
            value.upgrades.begin(), value.upgrades.end(), updated);
        if (updated)
        {
            setUpgrades(newUpgrades);
        }
    }

    // dump ICP information if this ledger took a long time
    auto gap =
        std::chrono::duration<double>(mApp.getClock().now() - mLastExternalize)
            .count();
    if (gap > DUMP_ICP_TIMEOUT_SECONDS)
    {
        auto slotInfo = getJsonQuorumInfo(getICP().getLocalNodeID(), false,
                                          false, slotIndex);
        Json::FastWriter fw;
        CLOG(WARNING, "Herder")
            << fmt::format("Ledger took {} seconds, ICP information:{}", gap,
                           fw.write(slotInfo));
    }

    // tell the LedgerManager that this value got externalized
    // LedgerManager will perform the proper action based on its internal
    // state: apply, trigger catchup, etc
    LedgerCloseData ledgerData(mHerderICPDriver.lastConsensusLedgerIndex(),
                               externalizedSet, value);
    mLedgerManager.valueExternalized(ledgerData);

    // start timing next externalize from this point
    mLastExternalize = mApp.getClock().now();

    // perform cleanups
    updateTransactionQueue(externalizedSet->mTransactions);

    // Evict slots that are outside of our ledger validity bracket
    if (slotIndex > MAX_SLOTS_TO_REMEMBER)
    {
        getICP().purgeSlots(slotIndex - MAX_SLOTS_TO_REMEMBER);
    }

    ledgerClosed();

    // Check to see if quorums have changed and we need to reanalyze.
    checkAndMaybeReanalyzeQuorumMap();

    // heart beat *after* doing all the work (ensures that we do not include
    // the overhead of externalization in the way we track ICP)
    trackingHeartBeat();
}

void
HerderImpl::rebroadcast()
{
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    for (auto const& e : getICP().getLatestMessagesSend(lcl.ledgerSeq + 1))
    {
        broadcast(e);
    }

    if (!mHerderICPDriver.trackingICP())
    {
        getMoreICPState();
    }

    startRebroadcastTimer();
}

void
HerderImpl::broadcast(ICPEnvelope const& e)
{
    if (!mApp.getConfig().MANUAL_CLOSE)
    {
        IOTChainMessage m;
        m.type(ICP_MESSAGE);
        m.envelope() = e;

        CLOG(DEBUG, "Herder") << "broadcast "
                              << " s:" << e.statement.pledges.type()
                              << " i:" << e.statement.slotIndex;

        mICPMetrics.mEnvelopeEmit.Mark();
        mApp.getOverlayManager().broadcastMessage(m, true);
    }
}

void
HerderImpl::startRebroadcastTimer()
{
    mRebroadcastTimer.expires_from_now(std::chrono::seconds(2));

    mRebroadcastTimer.async_wait(std::bind(&HerderImpl::rebroadcast, this),
                                 &VirtualTimer::onFailureNoop);
}

void
HerderImpl::emitEnvelope(ICPEnvelope const& envelope)
{
    uint64 slotIndex = envelope.statement.slotIndex;

    if (Logging::logDebug("Herder"))
        CLOG(DEBUG, "Herder")
            << "emitEnvelope"
            << " s:" << envelope.statement.pledges.type() << " i:" << slotIndex
            << " a:" << mApp.getStateHuman();

    persistICPState(slotIndex);

    broadcast(envelope);

    // this resets the re-broadcast timer
    startRebroadcastTimer();
}

TransactionQueue::AddResult
HerderImpl::recvTransaction(TransactionFramePtr tx)
{
    auto result = mTransactionQueue.tryAdd(tx);
    if (result == TransactionQueue::AddResult::ADD_STATUS_PENDING)
    {
        if (Logging::logTrace("Herder"))
            CLOG(TRACE, "Herder")
                << "recv transaction " << hexAbbrev(tx->getFullHash())
                << " for " << KeyUtils::toShortString(tx->getSourceID());
    }
    return result;
}

bool
HerderImpl::checkCloseTime(ICPEnvelope const& envelope, bool enforceRecent)
{
    using std::placeholders::_1;
    auto const& st = envelope.statement;

    uint64_t ctCutoff = 0;

    if (enforceRecent)
    {
        ctCutoff = VirtualClock::to_time_t(mApp.getClock().now());
        if (ctCutoff >= mApp.getConfig().MAXIMUM_LEDGER_CLOSETIME_DRIFT)
        {
            ctCutoff -= mApp.getConfig().MAXIMUM_LEDGER_CLOSETIME_DRIFT;
        }
    }

    auto envLedgerIndex = envelope.statement.slotIndex;
    auto& icpD = getHerderICPDriver();

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    auto lastCloseIndex = lcl.ledgerSeq;
    auto lastCloseTime = lcl.icpValue.closeTime;

    // see if we can get a better estimate of lastCloseTime for validating this
    // statement using consensus data:
    // update lastCloseIndex/lastCloseTime to be the highest possible but still
    // be less than envLedgerIndex
    auto adjustLastCloseTime = [&](HerderICPDriver::ConsensusData const* cd) {
        if (cd && envLedgerIndex >= cd->mConsensusIndex &&
            cd->mConsensusIndex > lastCloseIndex)
        {
            lastCloseIndex = static_cast<uint32>(cd->mConsensusIndex);
            lastCloseTime = cd->mConsensusValue.closeTime;
        }
    };
    adjustLastCloseTime(mHerderICPDriver.trackingICP());
    adjustLastCloseTime(mHerderICPDriver.lastTrackingICP());

    IOTChainValue sv;
    // performs the most conservative check:
    // returns true if one of the values is valid
    auto checkCTHelper = [&](std::vector<Value> const& values) {
        return std::any_of(values.begin(), values.end(), [&](Value const& e) {
            auto r = icpD.toIOTChainValue(e, sv);
            // sv must be after cutoff
            r = r && sv.closeTime >= ctCutoff;
            if (r)
            {
                // statement received after the fact, only keep externalized
                // value
                r = (lastCloseIndex == envLedgerIndex &&
                     lastCloseTime == sv.closeTime);
                // for older messages, just ensure that they occurred before
                r = r || (lastCloseIndex > envLedgerIndex &&
                          lastCloseTime > sv.closeTime);
                // for future message, perform the same validity check than
                // within ICP
                r = r || icpD.checkCloseTime(envLedgerIndex, lastCloseTime, sv);
            }
            return r;
        });
    };

    bool b;

    switch (st.pledges.type())
    {
    case ICP_ST_NOMINATE:
        b = checkCTHelper(st.pledges.nominate().accepted) ||
            checkCTHelper(st.pledges.nominate().votes);
        break;
    case ICP_ST_PREPARE:
    {
        auto& prep = st.pledges.prepare();
        b = checkCTHelper({prep.ballot.value});
        if (!b && prep.prepared)
        {
            b = checkCTHelper({prep.prepared->value});
        }
        if (!b && prep.preparedPrime)
        {
            b = checkCTHelper({prep.preparedPrime->value});
        }
    }
    break;
    case ICP_ST_CONFIRM:
        b = checkCTHelper({st.pledges.confirm().ballot.value});
        break;
    case ICP_ST_EXTERNALIZE:
        b = checkCTHelper({st.pledges.externalize().commit.value});
        break;
    default:
        abort();
    }

    if (!b && Logging::logTrace("Herder"))
    {
        CLOG(TRACE, "Herder")
            << "Invalid close time processing " << getICP().envToStr(st);
    }
    return b;
}

Herder::EnvelopeStatus
HerderImpl::recvICPEnvelope(ICPEnvelope const& envelope)
{
    if (mApp.getConfig().MANUAL_CLOSE)
    {
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    if (!verifyEnvelope(envelope))
    {
        CLOG(DEBUG, "Herder") << "Received bad envelope, discarding";
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    if (Logging::logDebug("Herder"))
        CLOG(DEBUG, "Herder")
            << "recvICPEnvelope"
            << " from: "
            << mApp.getConfig().toShortString(envelope.statement.nodeID)
            << " s:" << envelope.statement.pledges.type()
            << " i:" << envelope.statement.slotIndex
            << " a:" << mApp.getStateHuman();

    mICPMetrics.mEnvelopeReceive.Mark();

    uint32_t minLedgerSeq = getCurrentLedgerSeq();
    if (minLedgerSeq > MAX_SLOTS_TO_REMEMBER)
    {
        minLedgerSeq -= MAX_SLOTS_TO_REMEMBER;
    }

    uint32_t maxLedgerSeq = std::numeric_limits<uint32>::max();

    if (!checkCloseTime(envelope, false))
    {
        // if the envelope contains an invalid close time, don't bother
        // processing it as we're not going to forward it anyways and it's
        // going to just sit in our ICP state not contributing anything useful.
        CLOG(DEBUG, "Herder")
            << "skipping invalid close time (incompatible with current state)";
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    if (mHerderICPDriver.trackingICP())
    {
        // when tracking, we can filter messages based on the information we got
        // from consensus for the max ledger

        // note that this filtering will cause a node on startup
        // to potentially drop messages outside of the bracket
        // causing it to discard CONSENSUS_STUCK_TIMEOUT_SECONDS worth of
        // ledger closing
        maxLedgerSeq = mHerderICPDriver.nextConsensusLedgerIndex() +
                       LEDGER_VALIDITY_BRACKET;
    }
    else if (!checkCloseTime(envelope,
                             minLedgerSeq <= LedgerManager::GENESIS_LEDGER_SEQ))
    {
        // if we've never been in sync, we can be more aggressive in how we
        // filter messages: we can ignore messages that are unlikely to be
        // the latest messages from the network
        CLOG(DEBUG, "Herder") << "recvICPEnvelope: skipping invalid close time "
                                 "(check MAXIMUM_LEDGER_CLOSETIME_DRIFT)";
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    // If envelopes are out of our validity brackets, we just ignore them.
    if (envelope.statement.slotIndex > maxLedgerSeq ||
        envelope.statement.slotIndex < minLedgerSeq)
    {
        CLOG(DEBUG, "Herder") << "Ignoring ICPEnvelope outside of range: "
                              << envelope.statement.slotIndex << "( "
                              << minLedgerSeq << "," << maxLedgerSeq << ")";
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    if (envelope.statement.nodeID == getICP().getLocalNode()->getNodeID())
    {
        CLOG(DEBUG, "Herder") << "recvICPEnvelope: skipping own message";
        return Herder::ENVELOPE_STATUS_SKIPPED_SELF;
    }

    auto status = mPendingEnvelopes.recvICPEnvelope(envelope);
    if (status == Herder::ENVELOPE_STATUS_READY)
    {
        processICPQueue();
    }
    return status;
}

Herder::EnvelopeStatus
HerderImpl::recvICPEnvelope(ICPEnvelope const& envelope,
                            const ICPQuorumSet& qset, TxSetFrame txset)
{
    mPendingEnvelopes.addTxSet(txset.getContentsHash(),
                               envelope.statement.slotIndex,
                               std::make_shared<TxSetFrame>(txset));
    mPendingEnvelopes.addICPQuorumSet(sha256(xdr::xdr_to_opaque(qset)), qset);
    return recvICPEnvelope(envelope);
}

void
HerderImpl::sendICPStateToPeer(uint32 ledgerSeq, Peer::pointer peer)
{
    if (getICP().empty())
    {
        return;
    }

    if (getICP().getLowSlotIndex() > std::numeric_limits<uint32_t>::max() ||
        getICP().getHighSlotIndex() >= std::numeric_limits<uint32_t>::max())
    {
        return;
    }

    auto minSeq =
        std::max(ledgerSeq, static_cast<uint32_t>(getICP().getLowSlotIndex()));
    auto maxSeq = static_cast<uint32_t>(getICP().getHighSlotIndex());

    for (uint32_t seq = minSeq; seq <= maxSeq; seq++)
    {
        auto const& envelopes = getICP().getCurrentState(seq);

        if (envelopes.size() != 0)
        {
            CLOG(DEBUG, "Herder")
                << "Send state " << envelopes.size() << " for ledger " << seq;

            for (auto const& e : envelopes)
            {
                IOTChainMessage m;
                m.type(ICP_MESSAGE);
                m.envelope() = e;
                peer->sendMessage(m);
            }
        }
    }
}

void
HerderImpl::processICPQueue()
{
    if (mHerderICPDriver.trackingICP())
    {
        // drop obsolete slots
        if (mHerderICPDriver.nextConsensusLedgerIndex() > MAX_SLOTS_TO_REMEMBER)
        {
            mPendingEnvelopes.eraseBelow(
                mHerderICPDriver.nextConsensusLedgerIndex() -
                MAX_SLOTS_TO_REMEMBER);
        }

        processICPQueueUpToIndex(mHerderICPDriver.nextConsensusLedgerIndex());
    }
    else
    {
        // we don't know which ledger we're in
        // try to consume the messages from the queue
        // starting from the smallest slot
        for (auto& slot : mPendingEnvelopes.readySlots())
        {
            processICPQueueUpToIndex(slot);
            if (mHerderICPDriver.trackingICP())
            {
                // one of the slots externalized
                // we go back to regular flow
                break;
            }
        }
    }
}

void
HerderImpl::processICPQueueUpToIndex(uint64 slotIndex)
{
    while (true)
    {
        ICPEnvelope env;
        if (mPendingEnvelopes.pop(slotIndex, env))
        {
            auto r = getICP().receiveEnvelope(env);
            if (r == ICP::EnvelopeState::VALID)
            {
                mPendingEnvelopes.envelopeProcessed(env);
            }
        }
        else
        {
            return;
        }
    }
}

#ifdef BUILD_TESTS
PendingEnvelopes&
HerderImpl::getPendingEnvelopes()
{
    return mPendingEnvelopes;
}
#endif

void
HerderImpl::ledgerClosed()
{
    mTriggerTimer.cancel();

    CLOG(TRACE, "Herder") << "HerderImpl::ledgerClosed";

    auto lastIndex = mHerderICPDriver.lastConsensusLedgerIndex();

    mPendingEnvelopes.slotClosed(lastIndex);

    mApp.getOverlayManager().ledgerClosed(lastIndex);

    uint64_t nextIndex = mHerderICPDriver.nextConsensusLedgerIndex();

    // process any statements up to this slot (this may trigger externalize)
    processICPQueueUpToIndex(nextIndex);

    // if externalize got called for a future slot, we don't
    // need to trigger (the now obsolete) next round
    if (nextIndex != mHerderICPDriver.nextConsensusLedgerIndex())
    {
        return;
    }

    if (!mLedgerManager.isSynced())
    {
        CLOG(DEBUG, "Herder")
            << "Not presently synced, not triggering ledger-close.";
        return;
    }

    auto seconds = mApp.getConfig().getExpectedLedgerCloseTime();

    // bootstrap with a pessimistic estimate of when
    // the ballot protocol started last
    auto lastBallotStart = mApp.getClock().now() - seconds;
    auto lastStart = mHerderICPDriver.getPrepareStart(lastIndex);
    if (lastStart)
    {
        lastBallotStart = *lastStart;
    }
    // even if ballot protocol started before triggering, we just use that time
    // as reference point for triggering again (this may trigger right away if
    // externalizing took a long time)
    mTriggerTimer.expires_at(lastBallotStart + seconds);

    if (!mApp.getConfig().MANUAL_CLOSE)
        mTriggerTimer.async_wait(std::bind(&HerderImpl::triggerNextLedger, this,
                                           static_cast<uint32_t>(nextIndex)),
                                 &VirtualTimer::onFailureNoop);
}

bool
HerderImpl::recvICPQuorumSet(Hash const& hash, const ICPQuorumSet& qset)
{
    return mPendingEnvelopes.recvICPQuorumSet(hash, qset);
}

bool
HerderImpl::recvTxSet(Hash const& hash, const TxSetFrame& t)
{
    auto txset = std::make_shared<TxSetFrame>(t);
    return mPendingEnvelopes.recvTxSet(hash, txset);
}

void
HerderImpl::peerDoesntHave(MessageType type, uint256 const& itemID,
                           Peer::pointer peer)
{
    mPendingEnvelopes.peerDoesntHave(type, itemID, peer);
}

TxSetFramePtr
HerderImpl::getTxSet(Hash const& hash)
{
    return mPendingEnvelopes.getTxSet(hash);
}

ICPQuorumSetPtr
HerderImpl::getQSet(Hash const& qSetHash)
{
    return mHerderICPDriver.getQSet(qSetHash);
}

uint32_t
HerderImpl::getCurrentLedgerSeq() const
{
    uint32_t res = mLedgerManager.getLastClosedLedgerNum();

    if (mHerderICPDriver.trackingICP() &&
        res < mHerderICPDriver.trackingICP()->mConsensusIndex)
    {
        res = static_cast<uint32_t>(
            mHerderICPDriver.trackingICP()->mConsensusIndex);
    }
    if (mHerderICPDriver.lastTrackingICP() &&
        res < mHerderICPDriver.lastTrackingICP()->mConsensusIndex)
    {
        res = static_cast<uint32_t>(
            mHerderICPDriver.lastTrackingICP()->mConsensusIndex);
    }
    return res;
}

SequenceNumber
HerderImpl::getMaxSeqInPendingTxs(AccountID const& acc)
{
    return mTransactionQueue.getAccountTransactionQueueInfo(acc).mMaxSeq;
}

// called to take a position during the next round
// uses the state in LedgerManager to derive a starting position
void
HerderImpl::triggerNextLedger(uint32_t ledgerSeqToTrigger)
{
    if (!mHerderICPDriver.trackingICP() || !mLedgerManager.isSynced())
    {
        CLOG(DEBUG, "Herder") << "triggerNextLedger: skipping (out of sync) : "
                              << mApp.getStateHuman();
        return;
    }

    // our first choice for this round's set is all the tx we have collected
    // during last few ledger closes
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();
    auto proposedSet = mTransactionQueue.toTxSet(lcl.hash);
    auto removed = proposedSet->trimInvalid(mApp);
    mTransactionQueue.ban(removed);

    proposedSet->surgePricingFilter(mApp);

    if (!proposedSet->checkValid(mApp))
    {
        throw std::runtime_error("wanting to emit an invalid txSet");
    }

    auto txSetHash = proposedSet->getContentsHash();

    // use the slot index from ledger manager here as our vote is based off
    // the last closed ledger stored in ledger manager
    uint32_t slotIndex = lcl.header.ledgerSeq + 1;

    // Inform the item fetcher so queries from other peers about his txSet
    // can be answered. Note this can trigger ICP callbacks, externalize, etc
    // if we happen to build a txset that we were trying to download.
    mPendingEnvelopes.addTxSet(txSetHash, slotIndex, proposedSet);

    // no point in sending out a prepare:
    // externalize was triggered on a more recent ledger
    if (ledgerSeqToTrigger != slotIndex)
    {
        return;
    }

    // We pick as next close time the current time unless it's before the last
    // close time. We don't know how much time it will take to reach consensus
    // so this is the most appropriate value to use as closeTime.
    uint64_t nextCloseTime = VirtualClock::to_time_t(mApp.getClock().now());
    if (nextCloseTime <= lcl.header.icpValue.closeTime)
    {
        nextCloseTime = lcl.header.icpValue.closeTime + 1;
    }

    IOTChainValue newProposedValue(txSetHash, nextCloseTime, emptyUpgradeSteps,
                                  IOTCHAIN_VALUE_BASIC);

    // see if we need to include some upgrades
    auto upgrades = mUpgrades.createUpgradesFor(lcl.header);
    for (auto const& upgrade : upgrades)
    {
        Value v(xdr::xdr_to_opaque(upgrade));
        if (v.size() >= UpgradeType::max_size())
        {
            CLOG(ERROR, "Herder")
                << "HerderImpl::triggerNextLedger"
                << " exceeded size for upgrade step (got " << v.size()
                << " ) for upgrade type " << std::to_string(upgrade.type());
            CLOG(ERROR, "Herder") << REPORT_INTERNAL_BUG;
        }
        else
        {
            newProposedValue.upgrades.emplace_back(v.begin(), v.end());
        }
    }

    getHerderICPDriver().recordICPEvent(slotIndex, true);

    // If we are not a validating node we stop here and don't start nomination
    if (!getICP().isValidator())
    {
        CLOG(DEBUG, "Herder")
            << "Non-validating node, skipping nomination (ICP).";
        return;
    }

    if (lcl.header.ledgerVersion >= 11)
    {
        // version 11 and above require values to be signed during nomination
        signIOTChainValue(mApp.getConfig().NODE_SEED, newProposedValue);
    }
    mHerderICPDriver.nominate(slotIndex, newProposedValue, proposedSet,
                              lcl.header.icpValue);
}

void
HerderImpl::setUpgrades(Upgrades::UpgradeParameters const& upgrades)
{
    mUpgrades.setParameters(upgrades, mApp.getConfig());
    persistUpgrades();

    auto desc = mUpgrades.toString();

    if (!desc.empty())
    {
        auto message = fmt::format("Armed with network upgrades: {}", desc);
        auto prev = mApp.getStatusManager().getStatusMessage(
            StatusCategory::REQUIRES_UPGRADES);
        if (prev != message)
        {
            CLOG(INFO, "Herder") << message;
            mApp.getStatusManager().setStatusMessage(
                StatusCategory::REQUIRES_UPGRADES, message);
        }
    }
    else
    {
        CLOG(INFO, "Herder") << "Network upgrades cleared";
        mApp.getStatusManager().removeStatusMessage(
            StatusCategory::REQUIRES_UPGRADES);
    }
}

std::string
HerderImpl::getUpgradesJson()
{
    return mUpgrades.getParameters().toJson();
}

bool
HerderImpl::resolveNodeID(std::string const& s, PublicKey& retKey)
{
    bool r = mApp.getConfig().resolveNodeID(s, retKey);
    if (!r)
    {
        if (s.size() > 1 && s[0] == '@')
        {
            std::string arg = s.substr(1);
            // go through ICP messages of the previous ledger
            // (to increase the chances of finding the node)
            uint32 seq = getCurrentLedgerSeq();
            if (seq > 2)
            {
                seq--;
            }
            auto const& envelopes = getICP().getCurrentState(seq);
            for (auto const& e : envelopes)
            {
                std::string curK = KeyUtils::toStrKey(e.statement.nodeID);
                if (curK.compare(0, arg.size(), arg) == 0)
                {
                    retKey = e.statement.nodeID;
                    r = true;
                    break;
                }
            }
        }
    }
    return r;
}

Json::Value
HerderImpl::getJsonInfo(size_t limit, bool fullKeys)
{
    Json::Value ret;
    ret["you"] = mApp.getConfig().toStrKey(
        mApp.getConfig().NODE_SEED.getPublicKey(), fullKeys);

    ret["icp"] = getICP().getJsonInfo(limit, fullKeys);
    ret["queue"] = mPendingEnvelopes.getJsonInfo(limit);
    return ret;
}

Json::Value
HerderImpl::getJsonTransitiveQuorumIntersectionInfo(bool fullKeys) const
{
    Json::Value ret;
    ret["intersection"] =
        mLastQuorumMapIntersectionState.enjoysQuorunIntersection();
    ret["node_count"] =
        static_cast<Json::UInt64>(mLastQuorumMapIntersectionState.mNumNodes);
    ret["last_check_ledger"] = static_cast<Json::UInt64>(
        mLastQuorumMapIntersectionState.mLastCheckLedger);
    if (mLastQuorumMapIntersectionState.enjoysQuorunIntersection())
    {
        Json::Value critical;
        for (auto const& group :
             mLastQuorumMapIntersectionState.mIntersectionCriticalNodes)
        {
            Json::Value jg;
            for (auto const& k : group)
            {
                auto s = mApp.getConfig().toStrKey(k, fullKeys);
                jg.append(s);
            }
            critical.append(jg);
        }
        ret["critical"] = critical;
    }
    else
    {
        ret["last_good_ledger"] = static_cast<Json::UInt64>(
            mLastQuorumMapIntersectionState.mLastGoodLedger);
        Json::Value split, a, b;
        auto const& pair = mLastQuorumMapIntersectionState.mPotentialSplit;
        for (auto const& k : pair.first)
        {
            auto s = mApp.getConfig().toStrKey(k, fullKeys);
            a.append(s);
        }
        for (auto const& k : pair.second)
        {
            auto s = mApp.getConfig().toStrKey(k, fullKeys);
            b.append(s);
        }
        split.append(a);
        split.append(b);
        ret["potential_split"] = split;
    }
    return ret;
}

Json::Value
HerderImpl::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys,
                              uint64 index)
{
    Json::Value ret;
    ret["node"] = mApp.getConfig().toStrKey(id, fullKeys);
    ret["qset"] = getICP().getJsonQuorumInfo(id, summary, fullKeys, index);
    bool isSelf = id == mApp.getConfig().NODE_SEED.getPublicKey();
    if (isSelf && mLastQuorumMapIntersectionState.hasAnyResults())
    {
        ret["transitive"] = getJsonTransitiveQuorumIntersectionInfo(fullKeys);
    }
    return ret;
}

Json::Value
HerderImpl::getJsonTransitiveQuorumInfo(NodeID const& rootID, bool summary,
                                        bool fullKeys)
{
    Json::Value ret;
    bool isSelf = rootID == mApp.getConfig().NODE_SEED.getPublicKey();
    if (isSelf && mLastQuorumMapIntersectionState.hasAnyResults())
    {
        ret = getJsonTransitiveQuorumIntersectionInfo(fullKeys);
    }

    Json::Value& nodes = ret["nodes"];

    auto& q = mPendingEnvelopes.getCurrentlyTrackedQuorum();

    auto rootLatest = getICP().getLatestMessage(rootID);
    std::map<Value, int> knownValues;

    // walk the quorum graph, starting at id
    std::unordered_set<NodeID> visited;
    std::vector<NodeID> next;
    next.push_back(rootID);
    visited.emplace(rootID);
    int distance = 0;
    int valGenID = 0;
    while (!next.empty())
    {
        std::vector<NodeID> frontier(std::move(next));
        next.clear();
        std::sort(frontier.begin(), frontier.end());
        for (auto const& id : frontier)
        {
            Json::Value cur;
            valGenID++;
            cur["node"] = mApp.getConfig().toStrKey(id, fullKeys);
            if (!summary)
            {
                cur["distance"] = distance;
            }
            auto it = q.find(id);
            std::string status;
            if (it != q.end())
            {
                auto qSet = it->second;
                if (qSet)
                {
                    if (!summary)
                    {
                        cur["qset"] =
                            getICP().getLocalNode()->toJson(*qSet, fullKeys);
                    }
                    LocalNode::forAllNodes(*qSet, [&](NodeID const& n) {
                        auto b = visited.emplace(n);
                        if (b.second)
                        {
                            next.emplace_back(n);
                        }
                    });
                }
                auto latest = getICP().getLatestMessage(id);
                if (latest)
                {
                    auto vals = Slot::getStatementValues(latest->statement);
                    // updates the `knownValues` map, and generate a unique ID
                    // for the value (heuristic to group votes)
                    int trackingValID = -1;
                    Value const* trackingValue = nullptr;
                    for (auto const& v : vals)
                    {
                        auto p =
                            knownValues.insert(std::make_pair(v, valGenID));
                        if (p.first->second > trackingValID)
                        {
                            trackingValID = p.first->second;
                            trackingValue = &v;
                        }
                    }

                    cur["heard"] =
                        static_cast<Json::UInt64>(latest->statement.slotIndex);
                    if (!summary)
                    {
                        cur["value"] = trackingValue
                                           ? mHerderICPDriver.getValueString(
                                                 *trackingValue)
                                           : "";
                        cur["value_id"] = trackingValID;
                    }
                    // give a sense of how this node is doing compared to rootID
                    if (rootLatest)
                    {
                        if (latest->statement.slotIndex <
                            rootLatest->statement.slotIndex)
                        {
                            status = "behind";
                        }
                        else if (latest->statement.slotIndex >
                                 rootLatest->statement.slotIndex)
                        {
                            status = "ahead";
                        }
                        else
                        {
                            status = "tracking";
                        }
                    }
                }
                else
                {
                    status = "missing";
                }
            }
            else
            {
                status = "unknown";
            }
            cur["status"] = status;
            nodes.append(cur);
        }
        distance++;
    }
    return ret;
}

QuorumTracker::QuorumMap const&
HerderImpl::getCurrentlyTrackedQuorum() const
{
    return mPendingEnvelopes.getCurrentlyTrackedQuorum();
}

static Hash
getQmapHash(QuorumTracker::QuorumMap const& qmap)
{
    std::unique_ptr<SHA256> hasher = SHA256::create();
    std::map<NodeID, ICPQuorumSetPtr> ordered_map(qmap.begin(), qmap.end());
    for (auto const& pair : ordered_map)
    {
        hasher->add(xdr::xdr_to_opaque(pair.first));
        if (pair.second)
        {
            hasher->add(xdr::xdr_to_opaque(*pair.second));
        }
        else
        {
            hasher->add("\0");
        }
    }
    return hasher->finish();
}

void
HerderImpl::checkAndMaybeReanalyzeQuorumMap()
{
    if (!mApp.getConfig().QUORUM_INTERSECTION_CHECKER)
    {
        return;
    }
    if (!mLastQuorumMapIntersectionState.mRecalculating)
    {
        QuorumTracker::QuorumMap const& qmap = getCurrentlyTrackedQuorum();
        Hash curr = getQmapHash(qmap);
        if (mLastQuorumMapIntersectionState.mLastCheckQuorumMapHash != curr)
        {
            CLOG(INFO, "Herder")
                << "Transitive closure of quorum has changed, re-analyzing.";
            mLastQuorumMapIntersectionState.mRecalculating = true;
            auto& cfg = mApp.getConfig();
            auto ledger = getCurrentLedgerSeq();
            auto nNodes = qmap.size();
            auto qic = QuorumIntersectionChecker::create(qmap, cfg);
            auto& hState = mLastQuorumMapIntersectionState;
            auto& app = mApp;
            auto worker = [curr, ledger, nNodes, qic, qmap, cfg, &app,
                           &hState] {
                bool ok = qic->networkEnjoysQuorumIntersection();
                auto split = qic->getPotentialSplit();
                std::set<std::set<PublicKey>> critical;
                if (ok)
                {
                    // Only bother calculating the _critical_ groups if we're
                    // intersecting; if not intersecting we should finish ASAP
                    // and raise an alarm.
                    critical = QuorumIntersectionChecker::
                        getIntersectionCriticalGroups(qmap, cfg);
                }
                app.postOnMainThread(
                    [ok, curr, ledger, nNodes, split, critical, &hState] {
                        hState.mRecalculating = false;
                        hState.mNumNodes = nNodes;
                        hState.mLastCheckLedger = ledger;
                        hState.mLastCheckQuorumMapHash = curr;
                        hState.mPotentialSplit = split;
                        hState.mIntersectionCriticalNodes = critical;
                        if (ok)
                        {
                            hState.mLastGoodLedger = ledger;
                        }
                    },
                    "QuorumIntersectionChecker");
            };
            mApp.postOnBackgroundThread(worker, "QuorumIntersectionChecker");
        }
    }
}

void
HerderImpl::persistICPState(uint64 slot)
{
    if (slot < mLastSlotSaved)
    {
        return;
    }

    mLastSlotSaved = slot;

    // saves ICP messages and related data (transaction sets, quorum sets)
    xdr::xvector<ICPEnvelope> latestEnvs;
    std::map<Hash, TxSetFramePtr> txSets;
    std::map<Hash, ICPQuorumSetPtr> quorumSets;

    for (auto const& e : getICP().getLatestMessagesSend(slot))
    {
        latestEnvs.emplace_back(e);

        // saves transaction sets referred by the statement
        for (auto const& h : getTxSetHashes(e))
        {
            auto txSet = mPendingEnvelopes.getTxSet(h);
            if (txSet)
            {
                txSets.insert(std::make_pair(h, txSet));
            }
        }
        Hash qsHash = Slot::getCompanionQuorumSetHashFromStatement(e.statement);
        ICPQuorumSetPtr qSet = mPendingEnvelopes.getQSet(qsHash);
        if (qSet)
        {
            quorumSets.insert(std::make_pair(qsHash, qSet));
        }
    }

    xdr::xvector<TransactionSet> latestTxSets;
    for (auto it : txSets)
    {
        latestTxSets.emplace_back();
        it.second->toXDR(latestTxSets.back());
    }

    xdr::xvector<ICPQuorumSet> latestQSets;
    for (auto it : quorumSets)
    {
        latestQSets.emplace_back(*it.second);
    }

    auto latestICPData =
        xdr::xdr_to_opaque(latestEnvs, latestTxSets, latestQSets);
    std::string icpState;
    icpState = decoder::encode_b64(latestICPData);

    mApp.getPersistentState().setICPStateForSlot(slot, icpState);
}

void
HerderImpl::restoreICPState()
{
    // setup a sufficient state that we can participate in consensus
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();
    if (!mApp.getConfig().FORCE_ICP &&
        lcl.header.ledgerSeq == LedgerManager::GENESIS_LEDGER_SEQ)
    {
        // if we're on genesis ledger, there is no point in claiming
        // that we're "in sync"
        return;
    }

    mHerderICPDriver.restoreICPState(lcl.header.ledgerSeq, lcl.header.icpValue);

    trackingHeartBeat();

    // load saved state from database
    auto latest64 = mApp.getPersistentState().getICPStateAllSlots();
    for (auto const& state : latest64)
    {
        std::vector<uint8_t> buffer;
        decoder::decode_b64(state, buffer);

        xdr::xvector<ICPEnvelope> latestEnvs;
        xdr::xvector<TransactionSet> latestTxSets;
        xdr::xvector<ICPQuorumSet> latestQSets;

        try
        {
            xdr::xdr_from_opaque(buffer, latestEnvs, latestTxSets, latestQSets);

            for (auto const& txset : latestTxSets)
            {
                TxSetFramePtr cur =
                    make_shared<TxSetFrame>(mApp.getNetworkID(), txset);
                Hash h = cur->getContentsHash();
                mPendingEnvelopes.addTxSet(h, 0, cur);
            }
            for (auto const& qset : latestQSets)
            {
                Hash hash = sha256(xdr::xdr_to_opaque(qset));
                mPendingEnvelopes.addICPQuorumSet(hash, qset);
            }
            for (auto const& e : latestEnvs)
            {
                getICP().setStateFromEnvelope(e.statement.slotIndex, e);
                mLastSlotSaved =
                    std::max<uint64>(mLastSlotSaved, e.statement.slotIndex);
            }
        }
        catch (std::exception& e)
        {
            // we may have exceptions when upgrading the protocol
            // this should be the only time we get exceptions decoding old
            // messages.
            CLOG(INFO, "Herder") << "Error while restoring old icp messages, "
                                    "proceeding without them : "
                                 << e.what();
        }
        mPendingEnvelopes.rebuildQuorumTrackerState();
    }

    startRebroadcastTimer();
}

void
HerderImpl::persistUpgrades()
{
    auto s = mUpgrades.getParameters().toJson();
    mApp.getPersistentState().setState(PersistentState::kLedgerUpgrades, s);
}

void
HerderImpl::restoreUpgrades()
{
    std::string s =
        mApp.getPersistentState().getState(PersistentState::kLedgerUpgrades);
    if (!s.empty())
    {
        Upgrades::UpgradeParameters p;
        p.fromJson(s);
        try
        {
            // use common code to set status
            setUpgrades(p);
        }
        catch (std::exception e)
        {
            CLOG(INFO, "Herder") << "Error restoring upgrades '" << e.what()
                                 << "' with upgrades '" << s << "'";
        }
    }
}

void
HerderImpl::restoreState()
{
    restoreICPState();
    restoreUpgrades();
}

void
HerderImpl::trackingHeartBeat()
{
    if (mApp.getConfig().MANUAL_CLOSE)
    {
        return;
    }

    assert(mHerderICPDriver.trackingICP());
    mTrackingTimer.expires_from_now(
        std::chrono::seconds(CONSENSUS_STUCK_TIMEOUT_SECONDS));
    mTrackingTimer.async_wait(std::bind(&HerderImpl::herderOutOfSync, this),
                              &VirtualTimer::onFailureNoop);
}

void
HerderImpl::updateTransactionQueue(
    std::vector<TransactionFramePtr> const& applied)
{
    // remove all these tx from mTransactionQueue
    mTransactionQueue.removeAndReset(applied);
    mTransactionQueue.shift();

    // rebroadcast entries, sorted in apply-order to maximize chances of
    // propagation
    {
        auto toBroadcast = mTransactionQueue.toTxSet({});
        for (auto tx : toBroadcast->sortForApply())
        {
            auto msg = tx->toIOTChainMessage();
            mApp.getOverlayManager().broadcastMessage(msg);
        }
    }
}

void
HerderImpl::herderOutOfSync()
{
    CLOG(WARNING, "Herder") << "Lost track of consensus";

    auto s = getJsonInfo(20).toStyledString();
    CLOG(WARNING, "Herder") << "Out of sync context: " << s;

    mICPMetrics.mLostSync.Mark();
    mHerderICPDriver.lostSync();

    getMoreICPState();

    processICPQueue();
}

void
HerderImpl::getMoreICPState()
{
    int const NB_PEERS_TO_ASK = 2;
    auto low = mApp.getLedgerManager().getLastClosedLedgerNum() + 1;
    if (low > Herder::MAX_SLOTS_TO_REMEMBER)
    {
        low -= Herder::MAX_SLOTS_TO_REMEMBER;
    }
    else
    {
        low = 1;
    }

    // ask a few random peers their ICP messages
    auto r = mApp.getOverlayManager().getRandomAuthenticatedPeers();
    for (int i = 0; i < NB_PEERS_TO_ASK && i < r.size(); i++)
    {
        r[i]->sendGetScpState(low);
    }
}

bool
HerderImpl::verifyEnvelope(ICPEnvelope const& envelope)
{
    auto b = PubKeyUtils::verifySig(
        envelope.statement.nodeID, envelope.signature,
        xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_ICP,
                           envelope.statement));
    if (b)
    {
        mICPMetrics.mEnvelopeValidSig.Mark();
    }
    else
    {
        mICPMetrics.mEnvelopeInvalidSig.Mark();
    }

    return b;
}
void
HerderImpl::signEnvelope(SecretKey const& s, ICPEnvelope& envelope)
{
    envelope.signature = s.sign(xdr::xdr_to_opaque(
        mApp.getNetworkID(), ENVELOPE_TYPE_ICP, envelope.statement));
}
bool
HerderImpl::verifyIOTChainValueSignature(IOTChainValue const& sv)
{
    auto b = PubKeyUtils::verifySig(
        sv.ext.lcValueSignature().nodeID, sv.ext.lcValueSignature().signature,
        xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_ICPVALUE,
                           sv.txSetHash, sv.closeTime));
    return b;
}

void
HerderImpl::signIOTChainValue(SecretKey const& s, IOTChainValue& sv)
{
    sv.ext.v(IOTCHAIN_VALUE_SIGNED);
    sv.ext.lcValueSignature().nodeID = s.getPublicKey();
    sv.ext.lcValueSignature().signature =
        s.sign(xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_ICPVALUE,
                                  sv.txSetHash, sv.closeTime));
}
}
