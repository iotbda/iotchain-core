// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "BallotProtocol.h"

#include "Slot.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "lib/json/json.h"
#include "icp/LocalNode.h"
#include "icp/QuorumSetUtils.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"
#include <functional>

namespace iotchain
{
using namespace std::placeholders;

// max number of transitions that can occur from processing one message
static const int MAX_ADVANCE_SLOT_RECURSION = 50;

BallotProtocol::BallotProtocol(Slot& slot)
    : mSlot(slot)
    , mHeardFromQuorum(false)
    , mPhase(ICP_PHASE_PREPARE)
    , mCurrentMessageLevel(0)
{
}

bool
BallotProtocol::isNewerStatement(NodeID const& nodeID, ICPStatement const& st)
{
    auto oldp = mLatestEnvelopes.find(nodeID);
    bool res = false;

    if (oldp == mLatestEnvelopes.end())
    {
        res = true;
    }
    else
    {
        res = isNewerStatement(oldp->second.statement, st);
    }
    return res;
}

bool
BallotProtocol::isNewerStatement(ICPStatement const& oldst,
                                 ICPStatement const& st)
{
    bool res = false;

    // total ordering described in ICP paper.
    auto t = st.pledges.type();

    // statement type (PREPARE < CONFIRM < EXTERNALIZE)
    if (oldst.pledges.type() != t)
    {
        res = (oldst.pledges.type() < t);
    }
    else
    {
        // can't have duplicate EXTERNALIZE statements
        if (t == ICPStatementType::ICP_ST_EXTERNALIZE)
        {
            res = false;
        }
        else if (t == ICPStatementType::ICP_ST_CONFIRM)
        {
            // sorted by (b, p, p', h) (p' = 0 implicitely)
            auto const& oldC = oldst.pledges.confirm();
            auto const& c = st.pledges.confirm();
            int compBallot = compareBallots(oldC.ballot, c.ballot);
            if (compBallot < 0)
            {
                res = true;
            }
            else if (compBallot == 0)
            {
                if (oldC.nPrepared == c.nPrepared)
                {
                    res = (oldC.nH < c.nH);
                }
                else
                {
                    res = (oldC.nPrepared < c.nPrepared);
                }
            }
        }
        else
        {
            // Lexicographical order between PREPARE statements:
            // (b, p, p', h)
            auto const& oldPrep = oldst.pledges.prepare();
            auto const& prep = st.pledges.prepare();

            int compBallot = compareBallots(oldPrep.ballot, prep.ballot);
            if (compBallot < 0)
            {
                res = true;
            }
            else if (compBallot == 0)
            {
                compBallot = compareBallots(oldPrep.prepared, prep.prepared);
                if (compBallot < 0)
                {
                    res = true;
                }
                else if (compBallot == 0)
                {
                    compBallot = compareBallots(oldPrep.preparedPrime,
                                                prep.preparedPrime);
                    if (compBallot < 0)
                    {
                        res = true;
                    }
                    else if (compBallot == 0)
                    {
                        res = (oldPrep.nH < prep.nH);
                    }
                }
            }
        }
    }

    return res;
}

void
BallotProtocol::recordEnvelope(ICPEnvelope const& env)
{
    auto const& st = env.statement;
    auto oldp = mLatestEnvelopes.find(st.nodeID);
    if (oldp == mLatestEnvelopes.end())
    {
        mLatestEnvelopes.insert(std::make_pair(st.nodeID, env));
    }
    else
    {
        oldp->second = env;
    }
    mSlot.recordStatement(env.statement);
}

ICP::EnvelopeState
BallotProtocol::processEnvelope(ICPEnvelope const& envelope, bool self)
{
    ICP::EnvelopeState res = ICP::EnvelopeState::INVALID;
    dbgAssert(envelope.statement.slotIndex == mSlot.getSlotIndex());

    ICPStatement const& statement = envelope.statement;
    NodeID const& nodeID = statement.nodeID;

    if (!isStatementSane(statement, self))
    {
        if (self)
        {
            CLOG(ERROR, "ICP") << "not sane statement from self, skipping "
                               << "  e: " << mSlot.getICP().envToStr(envelope);
        }

        return ICP::EnvelopeState::INVALID;
    }

    if (!isNewerStatement(nodeID, statement))
    {
        if (self)
        {
            CLOG(ERROR, "ICP") << "stale statement from self, skipping "
                               << "  e: " << mSlot.getICP().envToStr(envelope);
        }
        else
        {
            CLOG(TRACE, "ICP") << "stale statement, skipping "
                               << " i: " << mSlot.getSlotIndex();
        }

        return ICP::EnvelopeState::INVALID;
    }

    auto validationRes = validateValues(statement);
    if (validationRes != ICPDriver::kInvalidValue)
    {
        bool processed = false;

        if (mPhase != ICP_PHASE_EXTERNALIZE)
        {
            if (validationRes == ICPDriver::kMaybeValidValue)
            {
                mSlot.setFullyValidated(false);
            }

            recordEnvelope(envelope);
            processed = true;
            advanceSlot(statement);
            res = ICP::EnvelopeState::VALID;
        }

        if (!processed)
        {
            // note: this handles also our own messages
            // in particular our final EXTERNALIZE message
            if (mPhase == ICP_PHASE_EXTERNALIZE &&
                mCommit->value == getWorkingBallot(statement).value)
            {
                recordEnvelope(envelope);
                res = ICP::EnvelopeState::VALID;
            }
            else
            {
                if (self)
                {
                    CLOG(ERROR, "ICP")
                        << "externalize statement with invalid value from "
                           "self, skipping "
                        << "  e: " << mSlot.getICP().envToStr(envelope);
                }

                res = ICP::EnvelopeState::INVALID;
            }
        }
    }
    else
    {
        // If the value is not valid, we just ignore it.
        if (self)
        {
            CLOG(ERROR, "ICP") << "invalid value from self, skipping "
                               << "  e: " << mSlot.getICP().envToStr(envelope);
        }
        else
        {
            CLOG(TRACE, "ICP") << "invalid value "
                               << " i: " << mSlot.getSlotIndex();
        }

        res = ICP::EnvelopeState::INVALID;
    }
    return res;
}

bool
BallotProtocol::isStatementSane(ICPStatement const& st, bool self)
{
    auto qSet = mSlot.getQuorumSetFromStatement(st);
    bool res = qSet != nullptr && isQuorumSetSane(*qSet, false);
    if (!res)
    {
        CLOG(DEBUG, "ICP") << "Invalid quorum set received";
        return false;
    }

    switch (st.pledges.type())
    {
    case ICPStatementType::ICP_ST_PREPARE:
    {
        auto const& p = st.pledges.prepare();
        // self is allowed to have b = 0 (as long as it never gets emitted)
        bool isOK = self || p.ballot.counter > 0;

        isOK = isOK &&
               ((!p.preparedPrime || !p.prepared) ||
                (areBallotsLessAndIncompatible(*p.preparedPrime, *p.prepared)));

        isOK =
            isOK && (p.nH == 0 || (p.prepared && p.nH <= p.prepared->counter));

        // c != 0 -> c <= h <= b
        isOK = isOK && (p.nC == 0 || (p.nH != 0 && p.ballot.counter >= p.nH &&
                                      p.nH >= p.nC));

        if (!isOK)
        {
            CLOG(TRACE, "ICP") << "Malformed PREPARE message";
            res = false;
        }
    }
    break;
    case ICPStatementType::ICP_ST_CONFIRM:
    {
        auto const& c = st.pledges.confirm();
        // c <= h <= b
        res = c.ballot.counter > 0;
        res = res && (c.nH <= c.ballot.counter);
        res = res && (c.nCommit <= c.nH);
        if (!res)
        {
            CLOG(TRACE, "ICP") << "Malformed CONFIRM message";
        }
    }
    break;
    case ICPStatementType::ICP_ST_EXTERNALIZE:
    {
        auto const& e = st.pledges.externalize();

        res = e.commit.counter > 0;
        res = res && e.nH >= e.commit.counter;

        if (!res)
        {
            CLOG(TRACE, "ICP") << "Malformed EXTERNALIZE message";
        }
    }
    break;
    default:
        dbgAbort();
    }

    return res;
}

bool
BallotProtocol::abandonBallot(uint32 n)
{
    CLOG(TRACE, "ICP") << "BallotProtocol::abandonBallot";
    bool res = false;
    Value v = mSlot.getLatestCompositeCandidate();
    if (v.empty())
    {
        if (mCurrentBallot)
        {
            v = mCurrentBallot->value;
        }
    }
    if (!v.empty())
    {
        if (n == 0)
        {
            res = bumpState(v, true);
        }
        else
        {
            res = bumpState(v, n);
        }
    }
    return res;
}

bool
BallotProtocol::bumpState(Value const& value, bool force)
{
    uint32 n;
    if (!force && mCurrentBallot)
    {
        return false;
    }

    n = mCurrentBallot ? (mCurrentBallot->counter + 1) : 1;

    return bumpState(value, n);
}

bool
BallotProtocol::bumpState(Value const& value, uint32 n)
{
    if (mPhase != ICP_PHASE_PREPARE && mPhase != ICP_PHASE_CONFIRM)
    {
        return false;
    }

    ICPBallot newb;

    newb.counter = n;

    if (mValueOverride)
    {
        // we use the value that we saw confirmed prepared
        // or that we at least voted to commit to
        newb.value = *mValueOverride;
    }
    else
    {
        newb.value = value;
    }

    if (Logging::logTrace("ICP"))
        CLOG(TRACE, "ICP") << "BallotProtocol::bumpState"
                           << " i: " << mSlot.getSlotIndex()
                           << " v: " << mSlot.getICP().ballotToStr(newb);

    bool updated = updateCurrentValue(newb);

    if (updated)
    {
        emitCurrentStateStatement();
        checkHeardFromQuorum();
    }

    return updated;
}

// updates the local state based to the specified ballot
// (that could be a prepared ballot) enforcing invariants
bool
BallotProtocol::updateCurrentValue(ICPBallot const& ballot)
{
    if (mPhase != ICP_PHASE_PREPARE && mPhase != ICP_PHASE_CONFIRM)
    {
        return false;
    }

    bool updated = false;
    if (!mCurrentBallot)
    {
        bumpToBallot(ballot, true);
        updated = true;
    }
    else
    {
        dbgAssert(compareBallots(*mCurrentBallot, ballot) <= 0);

        if (mCommit && !areBallotsCompatible(*mCommit, ballot))
        {
            return false;
        }

        int comp = compareBallots(*mCurrentBallot, ballot);
        if (comp < 0)
        {
            bumpToBallot(ballot, true);
            updated = true;
        }
        else if (comp > 0)
        {
            // this code probably changes with the final version
            // of the conciliator

            // this case may happen if the other nodes are not
            // following the protocol (and we end up with a smaller value)
            // not sure what is the best way to deal
            // with this situation
            CLOG(ERROR, "ICP")
                << "BallotProtocol::updateCurrentValue attempt to bump to "
                   "a smaller value";
            // can't just bump to the value as we may already have
            // statements at counter+1
            return false;
        }
    }

    if (updated)
    {
        CLOG(TRACE, "ICP") << "BallotProtocol::updateCurrentValue updated";
    }

    checkInvariants();

    return updated;
}

void
BallotProtocol::bumpToBallot(ICPBallot const& ballot, bool check)
{
    if (Logging::logTrace("ICP"))
        CLOG(TRACE, "ICP") << "BallotProtocol::bumpToBallot"
                           << " i: " << mSlot.getSlotIndex()
                           << " b: " << mSlot.getICP().ballotToStr(ballot);

    // `bumpToBallot` should be never called once we committed.
    dbgAssert(mPhase != ICP_PHASE_EXTERNALIZE);

    if (check)
    {
        // We should move mCurrentBallot monotonically only
        dbgAssert(!mCurrentBallot ||
                  compareBallots(ballot, *mCurrentBallot) >= 0);
    }

    bool gotBumped =
        !mCurrentBallot || (mCurrentBallot->counter != ballot.counter);

    if (!mCurrentBallot)
    {
        mSlot.getICPDriver().startedBallotProtocol(mSlot.getSlotIndex(),
                                                   ballot);
    }

    mCurrentBallot = std::make_unique<ICPBallot>(ballot);

    // invariant: h.value = b.value
    if (mHighBallot && !areBallotsCompatible(*mCurrentBallot, *mHighBallot))
    {
        mHighBallot.reset();
    }

    if (gotBumped)
    {
        mHeardFromQuorum = false;
    }
}

void
BallotProtocol::startBallotProtocolTimer()
{
    std::chrono::milliseconds timeout =
        mSlot.getICPDriver().computeTimeout(mCurrentBallot->counter);

    std::shared_ptr<Slot> slot = mSlot.shared_from_this();
    mSlot.getICPDriver().setupTimer(
        mSlot.getSlotIndex(), Slot::BALLOT_PROTOCOL_TIMER, timeout,
        [slot]() { slot->getBallotProtocol().ballotProtocolTimerExpired(); });
}

void
BallotProtocol::stopBallotProtocolTimer()
{
    std::shared_ptr<Slot> slot = mSlot.shared_from_this();
    mSlot.getICPDriver().setupTimer(mSlot.getSlotIndex(),
                                    Slot::BALLOT_PROTOCOL_TIMER,
                                    std::chrono::seconds::zero(), nullptr);
}

void
BallotProtocol::ballotProtocolTimerExpired()
{
    abandonBallot(0);
}

ICPStatement
BallotProtocol::createStatement(ICPStatementType const& type)
{
    ICPStatement statement;

    checkInvariants();

    statement.pledges.type(type);
    switch (type)
    {
    case ICPStatementType::ICP_ST_PREPARE:
    {
        auto& p = statement.pledges.prepare();
        p.quorumSetHash = getLocalNode()->getQuorumSetHash();
        if (mCurrentBallot)
        {
            p.ballot = *mCurrentBallot;
        }
        if (mCommit)
        {
            p.nC = mCommit->counter;
        }
        if (mPrepared)
        {
            p.prepared.activate() = *mPrepared;
        }
        if (mPreparedPrime)
        {
            p.preparedPrime.activate() = *mPreparedPrime;
        }
        if (mHighBallot)
        {
            p.nH = mHighBallot->counter;
        }
    }
    break;
    case ICPStatementType::ICP_ST_CONFIRM:
    {
        auto& c = statement.pledges.confirm();
        c.quorumSetHash = getLocalNode()->getQuorumSetHash();
        c.ballot = *mCurrentBallot;
        c.nPrepared = mPrepared->counter;
        c.nCommit = mCommit->counter;
        c.nH = mHighBallot->counter;
    }
    break;
    case ICPStatementType::ICP_ST_EXTERNALIZE:
    {
        auto& e = statement.pledges.externalize();
        e.commit = *mCommit;
        e.nH = mHighBallot->counter;
        e.commitQuorumSetHash = getLocalNode()->getQuorumSetHash();
    }
    break;
    default:
        dbgAbort();
    }

    return statement;
}

void
BallotProtocol::emitCurrentStateStatement()
{
    ICPStatementType t;

    switch (mPhase)
    {
    case ICP_PHASE_PREPARE:
        t = ICP_ST_PREPARE;
        break;
    case ICP_PHASE_CONFIRM:
        t = ICP_ST_CONFIRM;
        break;
    case ICP_PHASE_EXTERNALIZE:
        t = ICP_ST_EXTERNALIZE;
        break;
    default:
        dbgAbort();
    }

    ICPStatement statement = createStatement(t);
    ICPEnvelope envelope = mSlot.createEnvelope(statement);

    bool canEmit = (mCurrentBallot != nullptr);

    // if we generate the same envelope, don't process it again
    // this can occur when updating h in PREPARE phase
    // as statements only keep track of h.n (but h.x could be different)
    auto lastEnv = mLatestEnvelopes.find(mSlot.getICP().getLocalNodeID());

    if (lastEnv == mLatestEnvelopes.end() || !(lastEnv->second == envelope))
    {
        if (mSlot.processEnvelope(envelope, true) == ICP::EnvelopeState::VALID)
        {
            if (canEmit &&
                (!mLastEnvelope || isNewerStatement(mLastEnvelope->statement,
                                                    envelope.statement)))
            {
                mLastEnvelope = std::make_shared<ICPEnvelope>(envelope);
                // this will no-op if invoked from advanceSlot
                // as advanceSlot consolidates all messages sent
                sendLatestEnvelope();
            }
        }
        else
        {
            // there is a bug in the application if it queued up
            // a statement for itself that it considers invalid
            throw std::runtime_error("moved to a bad state (ballot protocol)");
        }
    }
}

void
BallotProtocol::checkInvariants()
{
    if (mCurrentBallot)
    {
        dbgAssert(mCurrentBallot->counter != 0);
    }
    if (mPrepared && mPreparedPrime)
    {
        dbgAssert(areBallotsLessAndIncompatible(*mPreparedPrime, *mPrepared));
    }
    if (mHighBallot)
    {
        dbgAssert(mCurrentBallot);
        dbgAssert(areBallotsLessAndCompatible(*mHighBallot, *mCurrentBallot));
    }
    if (mCommit)
    {
        dbgAssert(mCurrentBallot);
        dbgAssert(areBallotsLessAndCompatible(*mCommit, *mHighBallot));
        dbgAssert(areBallotsLessAndCompatible(*mHighBallot, *mCurrentBallot));
    }

    switch (mPhase)
    {
    case ICP_PHASE_PREPARE:
        break;
    case ICP_PHASE_CONFIRM:
        dbgAssert(mCommit);
        break;
    case ICP_PHASE_EXTERNALIZE:
        dbgAssert(mCommit);
        dbgAssert(mHighBallot);
        break;
    default:
        dbgAbort();
    }
}

std::set<ICPBallot>
BallotProtocol::getPrepareCandidates(ICPStatement const& hint)
{
    std::set<ICPBallot> hintBallots;

    switch (hint.pledges.type())
    {
    case ICP_ST_PREPARE:
    {
        auto const& prep = hint.pledges.prepare();
        hintBallots.insert(prep.ballot);
        if (prep.prepared)
        {
            hintBallots.insert(*prep.prepared);
        }
        if (prep.preparedPrime)
        {
            hintBallots.insert(*prep.preparedPrime);
        }
    }
    break;
    case ICP_ST_CONFIRM:
    {
        auto const& con = hint.pledges.confirm();
        hintBallots.insert(ICPBallot(con.nPrepared, con.ballot.value));
        hintBallots.insert(ICPBallot(UINT32_MAX, con.ballot.value));
    }
    break;
    case ICP_ST_EXTERNALIZE:
    {
        auto const& ext = hint.pledges.externalize();
        hintBallots.insert(ICPBallot(UINT32_MAX, ext.commit.value));
    }
    break;
    default:
        abort();
    };

    std::set<ICPBallot> candidates;

    while (!hintBallots.empty())
    {
        auto last = --hintBallots.end();
        ICPBallot topVote = *last;
        hintBallots.erase(last);

        auto const& val = topVote.value;

        // find candidates that may have been prepared
        for (auto const& e : mLatestEnvelopes)
        {
            ICPStatement const& st = e.second.statement;
            switch (st.pledges.type())
            {
            case ICP_ST_PREPARE:
            {
                auto const& prep = st.pledges.prepare();
                if (areBallotsLessAndCompatible(prep.ballot, topVote))
                {
                    candidates.insert(prep.ballot);
                }
                if (prep.prepared &&
                    areBallotsLessAndCompatible(*prep.prepared, topVote))
                {
                    candidates.insert(*prep.prepared);
                }
                if (prep.preparedPrime &&
                    areBallotsLessAndCompatible(*prep.preparedPrime, topVote))
                {
                    candidates.insert(*prep.preparedPrime);
                }
            }
            break;
            case ICP_ST_CONFIRM:
            {
                auto const& con = st.pledges.confirm();
                if (areBallotsCompatible(topVote, con.ballot))
                {
                    candidates.insert(topVote);
                    if (con.nPrepared < topVote.counter)
                    {
                        candidates.insert(ICPBallot(con.nPrepared, val));
                    }
                }
            }
            break;
            case ICP_ST_EXTERNALIZE:
            {
                auto const& ext = st.pledges.externalize();
                if (areBallotsCompatible(topVote, ext.commit))
                {
                    candidates.insert(topVote);
                }
            }
            break;
            default:
                abort();
            }
        }
    }

    return candidates;
}

bool
BallotProtocol::updateCurrentIfNeeded(ICPBallot const& h)
{
    bool didWork = false;
    if (!mCurrentBallot || compareBallots(*mCurrentBallot, h) < 0)
    {
        bumpToBallot(h, true);
        didWork = true;
    }
    return didWork;
}

bool
BallotProtocol::attemptAcceptPrepared(ICPStatement const& hint)
{
    if (mPhase != ICP_PHASE_PREPARE && mPhase != ICP_PHASE_CONFIRM)
    {
        return false;
    }

    auto candidates = getPrepareCandidates(hint);

    // see if we can accept any of the candidates, starting with the highest
    for (auto cur = candidates.rbegin(); cur != candidates.rend(); cur++)
    {
        ICPBallot ballot = *cur;

        if (mPhase == ICP_PHASE_CONFIRM)
        {
            // only consider the ballot if it may help us increase
            // p (note: at this point, p ~ c)
            if (!areBallotsLessAndCompatible(*mPrepared, ballot))
            {
                continue;
            }
            dbgAssert(areBallotsCompatible(*mCommit, ballot));
        }

        // if we already prepared this ballot, don't bother checking again

        // if ballot <= p' ballot is neither a candidate for p nor p'
        if (mPreparedPrime && compareBallots(ballot, *mPreparedPrime) <= 0)
        {
            continue;
        }

        if (mPrepared)
        {
            // if ballot is already covered by p, skip
            if (areBallotsLessAndCompatible(ballot, *mPrepared))
            {
                continue;
            }
            // otherwise, there is a chance it increases p'
        }

        bool accepted = federatedAccept(
            // checks if any node is voting for this ballot
            [&ballot](ICPStatement const& st) {
                bool res;

                switch (st.pledges.type())
                {
                case ICP_ST_PREPARE:
                {
                    auto const& p = st.pledges.prepare();
                    res = areBallotsLessAndCompatible(ballot, p.ballot);
                }
                break;
                case ICP_ST_CONFIRM:
                {
                    auto const& c = st.pledges.confirm();
                    res = areBallotsCompatible(ballot, c.ballot);
                }
                break;
                case ICP_ST_EXTERNALIZE:
                {
                    auto const& e = st.pledges.externalize();
                    res = areBallotsCompatible(ballot, e.commit);
                }
                break;
                default:
                    res = false;
                    dbgAbort();
                }

                return res;
            },
            std::bind(&BallotProtocol::hasPreparedBallot, ballot, _1));
        if (accepted)
        {
            return setAcceptPrepared(ballot);
        }
    }

    return false;
}

bool
BallotProtocol::setAcceptPrepared(ICPBallot const& ballot)
{
    if (Logging::logTrace("ICP"))
        CLOG(TRACE, "ICP") << "BallotProtocol::setAcceptPrepared"
                           << " i: " << mSlot.getSlotIndex()
                           << " b: " << mSlot.getICP().ballotToStr(ballot);

    // update our state
    bool didWork = setPrepared(ballot);

    // check if we also need to clear 'c'
    if (mCommit && mHighBallot)
    {
        if ((mPrepared &&
             areBallotsLessAndIncompatible(*mHighBallot, *mPrepared)) ||
            (mPreparedPrime &&
             areBallotsLessAndIncompatible(*mHighBallot, *mPreparedPrime)))
        {
            dbgAssert(mPhase == ICP_PHASE_PREPARE);
            mCommit.reset();
            didWork = true;
        }
    }

    if (didWork)
    {
        mSlot.getICPDriver().acceptedBallotPrepared(mSlot.getSlotIndex(),
                                                    ballot);
        emitCurrentStateStatement();
    }

    return didWork;
}

bool
BallotProtocol::attemptConfirmPrepared(ICPStatement const& hint)
{
    if (mPhase != ICP_PHASE_PREPARE)
    {
        return false;
    }

    // check if we could accept this ballot as prepared
    if (!mPrepared)
    {
        return false;
    }

    auto candidates = getPrepareCandidates(hint);

    // see if we can accept any of the candidates, starting with the highest
    ICPBallot newH;
    bool newHfound = false;
    auto cur = candidates.rbegin();
    for (; cur != candidates.rend(); cur++)
    {
        ICPBallot ballot = *cur;

        // only consider it if we can potentially raise h
        if (mHighBallot && compareBallots(*mHighBallot, ballot) >= 0)
        {
            break;
        }

        bool ratified = federatedRatify(
            std::bind(&BallotProtocol::hasPreparedBallot, ballot, _1));
        if (ratified)
        {
            newH = ballot;
            newHfound = true;
            break;
        }
    }

    bool res = false;

    if (newHfound)
    {
        ICPBallot newC;
        // now, look for newC (left as 0 if no update)
        // step (3) from the paper
        ICPBallot b = mCurrentBallot ? *mCurrentBallot : ICPBallot();
        if (!mCommit &&
            (!mPrepared || !areBallotsLessAndIncompatible(newH, *mPrepared)) &&
            (!mPreparedPrime ||
             !areBallotsLessAndIncompatible(newH, *mPreparedPrime)))
        {
            // continue where we left off (cur is at newH at this point)
            for (; cur != candidates.rend(); cur++)
            {
                ICPBallot ballot = *cur;
                if (compareBallots(ballot, b) < 0)
                {
                    break;
                }
                // c and h must be compatible
                if (!areBallotsLessAndCompatible(*cur, newH))
                {
                    continue;
                }
                bool ratified = federatedRatify(
                    std::bind(&BallotProtocol::hasPreparedBallot, ballot, _1));
                if (ratified)
                {
                    newC = ballot;
                }
                else
                {
                    break;
                }
            }
        }
        res = setConfirmPrepared(newC, newH);
    }
    return res;
}

bool
BallotProtocol::commitPredicate(ICPBallot const& ballot, Interval const& check,
                                ICPStatement const& st)
{
    bool res = false;
    auto const& pl = st.pledges;
    switch (pl.type())
    {
    case ICP_ST_PREPARE:
        break;
    case ICP_ST_CONFIRM:
    {
        auto const& c = pl.confirm();
        if (areBallotsCompatible(ballot, c.ballot))
        {
            res = c.nCommit <= check.first && check.second <= c.nH;
        }
    }
    break;
    case ICP_ST_EXTERNALIZE:
    {
        auto const& e = pl.externalize();
        if (areBallotsCompatible(ballot, e.commit))
        {
            res = e.commit.counter <= check.first;
        }
    }
    break;
    default:
        dbgAbort();
    }
    return res;
}

bool
BallotProtocol::setConfirmPrepared(ICPBallot const& newC, ICPBallot const& newH)
{
    if (Logging::logTrace("ICP"))
        CLOG(TRACE, "ICP") << "BallotProtocol::setConfirmPrepared"
                           << " i: " << mSlot.getSlotIndex()
                           << " h: " << mSlot.getICP().ballotToStr(newH);

    bool didWork = false;

    // remember newH's value
    mValueOverride = std::make_unique<Value>(newH.value);

    // we don't set c/h if we're not on a compatible ballot
    if (!mCurrentBallot || areBallotsCompatible(*mCurrentBallot, newH))
    {
        if (!mHighBallot || compareBallots(newH, *mHighBallot) > 0)
        {
            didWork = true;
            mHighBallot = std::make_unique<ICPBallot>(newH);
        }

        if (newC.counter != 0)
        {
            dbgAssert(!mCommit);
            mCommit = std::make_unique<ICPBallot>(newC);
            didWork = true;
        }

        if (didWork)
        {
            mSlot.getICPDriver().confirmedBallotPrepared(mSlot.getSlotIndex(),
                                                         newH);
        }
    }

    // always perform step (8) with the computed value of h
    didWork = updateCurrentIfNeeded(newH) || didWork;

    if (didWork)
    {
        emitCurrentStateStatement();
    }

    return didWork;
}

void
BallotProtocol::findExtendedInterval(Interval& candidate,
                                     std::set<uint32> const& boundaries,
                                     std::function<bool(Interval const&)> pred)
{
    // iterate through interesting boundaries, starting from the top
    for (auto it = boundaries.rbegin(); it != boundaries.rend(); it++)
    {
        uint32 b = *it;

        Interval cur;
        if (candidate.first == 0)
        {
            // first, find the high bound
            cur = Interval(b, b);
        }
        else if (b > candidate.second) // invalid
        {
            continue;
        }
        else
        {
            cur.first = b;
            cur.second = candidate.second;
        }

        if (pred(cur))
        {
            candidate = cur;
        }
        else if (candidate.first != 0)
        {
            // could not extend further
            break;
        }
    }
}

std::set<uint32>
BallotProtocol::getCommitBoundariesFromStatements(ICPBallot const& ballot)
{
    std::set<uint32> res;
    for (auto const& env : mLatestEnvelopes)
    {
        auto const& pl = env.second.statement.pledges;
        switch (pl.type())
        {
        case ICP_ST_PREPARE:
        {
            auto const& p = pl.prepare();
            if (areBallotsCompatible(ballot, p.ballot))
            {
                if (p.nC)
                {
                    res.emplace(p.nC);
                    res.emplace(p.nH);
                }
            }
        }
        break;
        case ICP_ST_CONFIRM:
        {
            auto const& c = pl.confirm();
            if (areBallotsCompatible(ballot, c.ballot))
            {
                res.emplace(c.nCommit);
                res.emplace(c.nH);
            }
        }
        break;
        case ICP_ST_EXTERNALIZE:
        {
            auto const& e = pl.externalize();
            if (areBallotsCompatible(ballot, e.commit))
            {
                res.emplace(e.commit.counter);
                res.emplace(e.nH);
                res.emplace(UINT32_MAX);
            }
        }
        break;
        default:
            dbgAbort();
        }
    }
    return res;
}

bool
BallotProtocol::attemptAcceptCommit(ICPStatement const& hint)
{
    if (mPhase != ICP_PHASE_PREPARE && mPhase != ICP_PHASE_CONFIRM)
    {
        return false;
    }

    // extracts value from hint
    // note: ballot.counter is only used for logging purpose as we're looking at
    // possible value to commit
    ICPBallot ballot;
    switch (hint.pledges.type())
    {
    case ICPStatementType::ICP_ST_PREPARE:
    {
        auto const& prep = hint.pledges.prepare();
        if (prep.nC != 0)
        {
            ballot = ICPBallot(prep.nH, prep.ballot.value);
        }
        else
        {
            return false;
        }
    }
    break;
    case ICPStatementType::ICP_ST_CONFIRM:
    {
        auto const& con = hint.pledges.confirm();
        ballot = ICPBallot(con.nH, con.ballot.value);
    }
    break;
    case ICPStatementType::ICP_ST_EXTERNALIZE:
    {
        auto const& ext = hint.pledges.externalize();
        ballot = ICPBallot(ext.nH, ext.commit.value);
        break;
    }
    default:
        abort();
    };

    if (mPhase == ICP_PHASE_CONFIRM)
    {
        if (!areBallotsCompatible(ballot, *mHighBallot))
        {
            return false;
        }
    }

    auto pred = [&ballot, this](Interval const& cur) -> bool {
        return federatedAccept(
            [&](ICPStatement const& st) -> bool {
                bool res = false;
                auto const& pl = st.pledges;
                switch (pl.type())
                {
                case ICP_ST_PREPARE:
                {
                    auto const& p = pl.prepare();
                    if (areBallotsCompatible(ballot, p.ballot))
                    {
                        if (p.nC != 0)
                        {
                            res = p.nC <= cur.first && cur.second <= p.nH;
                        }
                    }
                }
                break;
                case ICP_ST_CONFIRM:
                {
                    auto const& c = pl.confirm();
                    if (areBallotsCompatible(ballot, c.ballot))
                    {
                        res = c.nCommit <= cur.first;
                    }
                }
                break;
                case ICP_ST_EXTERNALIZE:
                {
                    auto const& e = pl.externalize();
                    if (areBallotsCompatible(ballot, e.commit))
                    {
                        res = e.commit.counter <= cur.first;
                    }
                }
                break;
                default:
                    dbgAbort();
                }
                return res;
            },
            std::bind(&BallotProtocol::commitPredicate, ballot, cur, _1));
    };

    // build the boundaries to scan
    std::set<uint32> boundaries = getCommitBoundariesFromStatements(ballot);

    if (boundaries.empty())
    {
        return false;
    }

    // now, look for the high interval
    Interval candidate;

    findExtendedInterval(candidate, boundaries, pred);

    bool res = false;

    if (candidate.first != 0)
    {
        if (mPhase != ICP_PHASE_CONFIRM ||
            candidate.second > mHighBallot->counter)
        {
            ICPBallot c = ICPBallot(candidate.first, ballot.value);
            ICPBallot h = ICPBallot(candidate.second, ballot.value);
            res = setAcceptCommit(c, h);
        }
    }

    return res;
}

bool
BallotProtocol::setAcceptCommit(ICPBallot const& c, ICPBallot const& h)
{
    if (Logging::logTrace("ICP"))
        CLOG(TRACE, "ICP") << "BallotProtocol::setAcceptCommit"
                           << " i: " << mSlot.getSlotIndex()
                           << " new c: " << mSlot.getICP().ballotToStr(c)
                           << " new h: " << mSlot.getICP().ballotToStr(h);

    bool didWork = false;

    // remember h's value
    mValueOverride = std::make_unique<Value>(h.value);

    if (!mHighBallot || !mCommit || compareBallots(*mHighBallot, h) != 0 ||
        compareBallots(*mCommit, c) != 0)
    {
        mCommit = std::make_unique<ICPBallot>(c);
        mHighBallot = std::make_unique<ICPBallot>(h);

        didWork = true;
    }

    if (mPhase == ICP_PHASE_PREPARE)
    {
        mPhase = ICP_PHASE_CONFIRM;
        if (mCurrentBallot && !areBallotsLessAndCompatible(h, *mCurrentBallot))
        {
            bumpToBallot(h, false);
        }
        mPreparedPrime.reset();

        didWork = true;
    }

    if (didWork)
    {
        updateCurrentIfNeeded(*mHighBallot);

        mSlot.getICPDriver().acceptedCommit(mSlot.getSlotIndex(), h);
        emitCurrentStateStatement();
    }

    return didWork;
}

static uint32
statementBallotCounter(ICPStatement const& st)
{
    switch (st.pledges.type())
    {
    case ICP_ST_PREPARE:
        return st.pledges.prepare().ballot.counter;
    case ICP_ST_CONFIRM:
        return st.pledges.confirm().ballot.counter;
    case ICP_ST_EXTERNALIZE:
        return UINT32_MAX;
    default:
        // Should never be called with ICP_ST_NOMINATE.
        abort();
    }
}

static bool
hasVBlockingSubsetStrictlyAheadOf(std::shared_ptr<LocalNode> localNode,
                                  std::map<NodeID, ICPEnvelope> const& map,
                                  uint32_t n)
{
    return LocalNode::isVBlocking(
        localNode->getQuorumSet(), map,
        [&](ICPStatement const& st) { return statementBallotCounter(st) > n; });
}

// Step 9 from the paper (Feb 2016):
//
//   If ∃ S ⊆ M such that the set of senders {v_m | m ∈ S} is v-blocking
//   and ∀m ∈ S, b_m.n > b_v.n, then set b <- <n, z> where n is the lowest
//   counter for which no such S exists.
//
// a.k.a 4th rule for setting ballot.counter in the internet-draft (v03):
//
//   If nodes forming a blocking threshold all have ballot.counter values
//   greater than the local ballot.counter, then the local node immediately
//   cancels any pending timer, increases ballot.counter to the lowest
//   value such that this is no longer the case, and if appropriate
//   according to the rules above arms a new timer. Note that the blocking
//   threshold may include ballots from ICPCommit messages as well as
//   ICPExternalize messages, which implicitly have an infinite ballot
//   counter.

bool
BallotProtocol::attemptBump()
{
    if (mPhase == ICP_PHASE_PREPARE || mPhase == ICP_PHASE_CONFIRM)
    {

        // First check to see if this condition applies at all. If there
        // is no v-blocking set ahead of the local node, there's nothing
        // to do, return early.
        auto localNode = getLocalNode();
        uint32 localCounter = mCurrentBallot ? mCurrentBallot->counter : 0;
        if (!hasVBlockingSubsetStrictlyAheadOf(localNode, mLatestEnvelopes,
                                               localCounter))
        {
            return false;
        }

        // Collect all possible counters we might need to advance to.
        std::set<uint32> allCounters;
        for (auto const& e : mLatestEnvelopes)
        {
            uint32_t c = statementBallotCounter(e.second.statement);
            if (c > localCounter)
                allCounters.insert(c);
        }

        // If we got to here, implicitly there _was_ a v-blocking subset
        // with counters above the local counter; we just need to find a
        // minimal n at which that's no longer true. So check them in
        // order, starting from the smallest.
        for (uint32_t n : allCounters)
        {
            if (!hasVBlockingSubsetStrictlyAheadOf(localNode, mLatestEnvelopes,
                                                   n))
            {
                // Move to n.
                return abandonBallot(n);
            }
        }
    }
    return false;
}

bool
BallotProtocol::attemptConfirmCommit(ICPStatement const& hint)
{
    if (mPhase != ICP_PHASE_CONFIRM)
    {
        return false;
    }

    if (!mHighBallot || !mCommit)
    {
        return false;
    }

    // extracts value from hint
    // note: ballot.counter is only used for logging purpose
    ICPBallot ballot;
    switch (hint.pledges.type())
    {
    case ICPStatementType::ICP_ST_PREPARE:
    {
        return false;
    }
    break;
    case ICPStatementType::ICP_ST_CONFIRM:
    {
        auto const& con = hint.pledges.confirm();
        ballot = ICPBallot(con.nH, con.ballot.value);
    }
    break;
    case ICPStatementType::ICP_ST_EXTERNALIZE:
    {
        auto const& ext = hint.pledges.externalize();
        ballot = ICPBallot(ext.nH, ext.commit.value);
        break;
    }
    default:
        abort();
    };

    if (!areBallotsCompatible(ballot, *mCommit))
    {
        return false;
    }

    std::set<uint32> boundaries = getCommitBoundariesFromStatements(ballot);
    Interval candidate;

    auto pred = [&ballot, this](Interval const& cur) -> bool {
        return federatedRatify(
            std::bind(&BallotProtocol::commitPredicate, ballot, cur, _1));
    };

    findExtendedInterval(candidate, boundaries, pred);

    bool res = candidate.first != 0;
    if (res)
    {
        ICPBallot c = ICPBallot(candidate.first, ballot.value);
        ICPBallot h = ICPBallot(candidate.second, ballot.value);
        return setConfirmCommit(c, h);
    }
    return res;
}

bool
BallotProtocol::setConfirmCommit(ICPBallot const& c, ICPBallot const& h)
{
    if (Logging::logTrace("ICP"))
        CLOG(TRACE, "ICP") << "BallotProtocol::setConfirmCommit"
                           << " i: " << mSlot.getSlotIndex()
                           << " new c: " << mSlot.getICP().ballotToStr(c)
                           << " new h: " << mSlot.getICP().ballotToStr(h);

    mCommit = std::make_unique<ICPBallot>(c);
    mHighBallot = std::make_unique<ICPBallot>(h);
    updateCurrentIfNeeded(*mHighBallot);

    mPhase = ICP_PHASE_EXTERNALIZE;

    emitCurrentStateStatement();

    mSlot.stopNomination();

    mSlot.getICPDriver().valueExternalized(mSlot.getSlotIndex(),
                                           mCommit->value);

    return true;
}

bool
BallotProtocol::hasPreparedBallot(ICPBallot const& ballot,
                                  ICPStatement const& st)
{
    bool res;

    switch (st.pledges.type())
    {
    case ICP_ST_PREPARE:
    {
        auto const& p = st.pledges.prepare();
        res =
            (p.prepared && areBallotsLessAndCompatible(ballot, *p.prepared)) ||
            (p.preparedPrime &&
             areBallotsLessAndCompatible(ballot, *p.preparedPrime));
    }
    break;
    case ICP_ST_CONFIRM:
    {
        auto const& c = st.pledges.confirm();
        ICPBallot prepared(c.nPrepared, c.ballot.value);
        res = areBallotsLessAndCompatible(ballot, prepared);
    }
    break;
    case ICP_ST_EXTERNALIZE:
    {
        auto const& e = st.pledges.externalize();
        res = areBallotsCompatible(ballot, e.commit);
    }
    break;
    default:
        res = false;
        dbgAbort();
    }

    return res;
}

Hash
BallotProtocol::getCompanionQuorumSetHashFromStatement(ICPStatement const& st)
{
    Hash h;
    switch (st.pledges.type())
    {
    case ICP_ST_PREPARE:
        h = st.pledges.prepare().quorumSetHash;
        break;
    case ICP_ST_CONFIRM:
        h = st.pledges.confirm().quorumSetHash;
        break;
    case ICP_ST_EXTERNALIZE:
        h = st.pledges.externalize().commitQuorumSetHash;
        break;
    default:
        dbgAbort();
    }
    return h;
}

ICPBallot
BallotProtocol::getWorkingBallot(ICPStatement const& st)
{
    ICPBallot res;
    switch (st.pledges.type())
    {
    case ICP_ST_PREPARE:
        res = st.pledges.prepare().ballot;
        break;
    case ICP_ST_CONFIRM:
    {
        auto const& con = st.pledges.confirm();
        res = ICPBallot(con.nCommit, con.ballot.value);
    }
    break;
    case ICP_ST_EXTERNALIZE:
        res = st.pledges.externalize().commit;
        break;
    default:
        dbgAbort();
    }
    return res;
}

bool
BallotProtocol::setPrepared(ICPBallot const& ballot)
{
    bool didWork = false;

    // p and p' are the two higest prepared and incompatible ballots
    if (mPrepared)
    {
        int comp = compareBallots(*mPrepared, ballot);
        if (comp < 0)
        {
            // as we're replacing p, we see if we should also replace p'
            if (!areBallotsCompatible(*mPrepared, ballot))
            {
                mPreparedPrime = std::make_unique<ICPBallot>(*mPrepared);
            }
            mPrepared = std::make_unique<ICPBallot>(ballot);
            didWork = true;
        }
        else if (comp > 0)
        {
            // check if we should update only p', this happens
            // either p' was NULL
            // or p' gets replaced by ballot
            //      (p' < ballot and ballot is incompatible with p)
            // note, the later check is here out of paranoia as this function is
            // not called with a value that would not allow us to make progress

            if (!mPreparedPrime ||
                ((compareBallots(*mPreparedPrime, ballot) < 0) &&
                 !areBallotsCompatible(*mPrepared, ballot)))
            {
                mPreparedPrime = std::make_unique<ICPBallot>(ballot);
                didWork = true;
            }
        }
    }
    else
    {
        mPrepared = std::make_unique<ICPBallot>(ballot);
        didWork = true;
    }
    return didWork;
}

int
BallotProtocol::compareBallots(std::unique_ptr<ICPBallot> const& b1,
                               std::unique_ptr<ICPBallot> const& b2)
{
    int res;
    if (b1 && b2)
    {
        res = compareBallots(*b1, *b2);
    }
    else if (b1 && !b2)
    {
        res = 1;
    }
    else if (!b1 && b2)
    {
        res = -1;
    }
    else
    {
        res = 0;
    }
    return res;
}

int
BallotProtocol::compareBallots(ICPBallot const& b1, ICPBallot const& b2)
{
    if (b1.counter < b2.counter)
    {
        return -1;
    }
    else if (b2.counter < b1.counter)
    {
        return 1;
    }
    // ballots are also strictly ordered by value
    if (b1.value < b2.value)
    {
        return -1;
    }
    else if (b2.value < b1.value)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

bool
BallotProtocol::areBallotsCompatible(ICPBallot const& b1, ICPBallot const& b2)
{
    return b1.value == b2.value;
}

bool
BallotProtocol::areBallotsLessAndIncompatible(ICPBallot const& b1,
                                              ICPBallot const& b2)
{
    return (compareBallots(b1, b2) <= 0) && !areBallotsCompatible(b1, b2);
}

bool
BallotProtocol::areBallotsLessAndCompatible(ICPBallot const& b1,
                                            ICPBallot const& b2)
{
    return (compareBallots(b1, b2) <= 0) && areBallotsCompatible(b1, b2);
}

void
BallotProtocol::setStateFromEnvelope(ICPEnvelope const& e)
{
    if (mCurrentBallot)
    {
        throw std::runtime_error(
            "Cannot set state after starting ballot protocol");
    }

    recordEnvelope(e);

    mLastEnvelope = std::make_shared<ICPEnvelope>(e);
    mLastEnvelopeEmit = mLastEnvelope;

    auto const& pl = e.statement.pledges;

    switch (pl.type())
    {
    case ICPStatementType::ICP_ST_PREPARE:
    {
        auto const& prep = pl.prepare();
        auto const& b = prep.ballot;
        bumpToBallot(b, true);
        if (prep.prepared)
        {
            mPrepared = std::make_unique<ICPBallot>(*prep.prepared);
        }
        if (prep.preparedPrime)
        {
            mPreparedPrime = std::make_unique<ICPBallot>(*prep.preparedPrime);
        }
        if (prep.nH)
        {
            mHighBallot = std::make_unique<ICPBallot>(prep.nH, b.value);
        }
        if (prep.nC)
        {
            mCommit = std::make_unique<ICPBallot>(prep.nC, b.value);
        }
        mPhase = ICP_PHASE_PREPARE;
    }
    break;
    case ICPStatementType::ICP_ST_CONFIRM:
    {
        auto const& c = pl.confirm();
        auto const& v = c.ballot.value;
        bumpToBallot(c.ballot, true);
        mPrepared = std::make_unique<ICPBallot>(c.nPrepared, v);
        mHighBallot = std::make_unique<ICPBallot>(c.nH, v);
        mCommit = std::make_unique<ICPBallot>(c.nCommit, v);
        mPhase = ICP_PHASE_CONFIRM;
    }
    break;
    case ICPStatementType::ICP_ST_EXTERNALIZE:
    {
        auto const& ext = pl.externalize();
        auto const& v = ext.commit.value;
        bumpToBallot(ICPBallot(UINT32_MAX, v), true);
        mPrepared = std::make_unique<ICPBallot>(UINT32_MAX, v);
        mHighBallot = std::make_unique<ICPBallot>(ext.nH, v);
        mCommit = std::make_unique<ICPBallot>(ext.commit);
        mPhase = ICP_PHASE_EXTERNALIZE;
    }
    break;
    default:
        dbgAbort();
    }
}

std::vector<ICPEnvelope>
BallotProtocol::getCurrentState() const
{
    std::vector<ICPEnvelope> res;
    res.reserve(mLatestEnvelopes.size());
    for (auto const& n : mLatestEnvelopes)
    {
        // only return messages for self if the slot is fully validated
        if (!(n.first == mSlot.getICP().getLocalNodeID()) ||
            mSlot.isFullyValidated())
        {
            res.emplace_back(n.second);
        }
    }
    return res;
}

ICPEnvelope const*
BallotProtocol::getLatestMessage(NodeID const& id) const
{
    auto it = mLatestEnvelopes.find(id);
    if (it != mLatestEnvelopes.end())
    {
        return &it->second;
    }
    return nullptr;
}

std::vector<ICPEnvelope>
BallotProtocol::getExternalizingState() const
{
    std::vector<ICPEnvelope> res;
    if (mPhase == ICP_PHASE_EXTERNALIZE)
    {
        res.reserve(mLatestEnvelopes.size());
        for (auto const& n : mLatestEnvelopes)
        {
            if (!(n.first == mSlot.getICP().getLocalNodeID()))
            {
                // good approximation: statements with the value that
                // externalized
                // we could filter more using mConfirmedPrepared as well
                if (areBallotsCompatible(getWorkingBallot(n.second.statement),
                                         *mCommit))
                {
                    res.emplace_back(n.second);
                }
            }
            else if (mSlot.isFullyValidated())
            {
                // only return messages for self if the slot is fully validated
                res.emplace_back(n.second);
            }
        }
    }
    return res;
}

void
BallotProtocol::advanceSlot(ICPStatement const& hint)
{
    mCurrentMessageLevel++;
    if (Logging::logTrace("ICP"))
        CLOG(TRACE, "ICP") << "BallotProtocol::advanceSlot "
                           << mCurrentMessageLevel << " " << getLocalState();

    if (mCurrentMessageLevel >= MAX_ADVANCE_SLOT_RECURSION)
    {
        throw std::runtime_error(
            "maximum number of transitions reached in advanceSlot");
    }

    // attempt* methods will queue up messages, causing advanceSlot to be
    // called recursively

    // done in order so that we follow the steps from the white paper in
    // order
    // allowing the state to be updated properly

    bool didWork = false;

    didWork = attemptAcceptPrepared(hint) || didWork;

    didWork = attemptConfirmPrepared(hint) || didWork;

    didWork = attemptAcceptCommit(hint) || didWork;

    didWork = attemptConfirmCommit(hint) || didWork;

    // only bump after we're done with everything else
    if (mCurrentMessageLevel == 1)
    {
        bool didBump = false;
        do
        {
            // attemptBump may invoke advanceSlot recursively
            didBump = attemptBump();
            didWork = didBump || didWork;
        } while (didBump);

        checkHeardFromQuorum();
    }

    if (Logging::logTrace("ICP"))
        CLOG(TRACE, "ICP") << "BallotProtocol::advanceSlot "
                           << mCurrentMessageLevel << " - exiting "
                           << getLocalState();

    --mCurrentMessageLevel;

    if (didWork)
    {
        sendLatestEnvelope();
    }
}

ICPDriver::ValidationLevel
BallotProtocol::validateValues(ICPStatement const& st)
{
    std::set<Value> values;
    switch (st.pledges.type())
    {
    case ICPStatementType::ICP_ST_PREPARE:
    {
        auto const& prep = st.pledges.prepare();
        auto const& b = prep.ballot;
        if (b.counter != 0)
        {
            values.insert(prep.ballot.value);
        }
        if (prep.prepared)
        {
            values.insert(prep.prepared->value);
        }
    }
    break;
    case ICPStatementType::ICP_ST_CONFIRM:
        values.insert(st.pledges.confirm().ballot.value);
        break;
    case ICPStatementType::ICP_ST_EXTERNALIZE:
        values.insert(st.pledges.externalize().commit.value);
        break;
    default:
        // This shouldn't happen
        return ICPDriver::kInvalidValue;
    }
    ICPDriver::ValidationLevel res = ICPDriver::kFullyValidatedValue;
    for (auto const& v : values)
    {
        auto tr =
            mSlot.getICPDriver().validateValue(mSlot.getSlotIndex(), v, false);
        if (tr != ICPDriver::kFullyValidatedValue)
        {
            if (tr == ICPDriver::kInvalidValue)
            {
                res = ICPDriver::kInvalidValue;
            }
            else
            {
                res = ICPDriver::kMaybeValidValue;
            }
        }
    }
    return res;
}

void
BallotProtocol::sendLatestEnvelope()
{
    // emit current envelope if needed
    if (mCurrentMessageLevel == 0 && mLastEnvelope && mSlot.isFullyValidated())
    {
        if (!mLastEnvelopeEmit || mLastEnvelope != mLastEnvelopeEmit)
        {
            mLastEnvelopeEmit = mLastEnvelope;
            mSlot.getICPDriver().emitEnvelope(*mLastEnvelopeEmit);
        }
    }
}

const char* BallotProtocol::phaseNames[ICP_PHASE_NUM] = {"PREPARE", "FINISH",
                                                         "EXTERNALIZE"};

Json::Value
BallotProtocol::getJsonInfo()
{
    Json::Value ret;
    ret["heard"] = mHeardFromQuorum;
    ret["ballot"] = mSlot.getICP().ballotToStr(mCurrentBallot);
    ret["phase"] = phaseNames[mPhase];

    ret["state"] = getLocalState();
    return ret;
}

Json::Value
BallotProtocol::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys)
{
    Json::Value ret;
    auto& phase = ret["phase"];

    // find the state of the node `id`
    ICPBallot b;
    Hash qSetHash;

    auto stateit = mLatestEnvelopes.find(id);
    if (stateit == mLatestEnvelopes.end())
    {
        phase = "unknown";
        if (id == mSlot.getLocalNode()->getNodeID())
        {
            qSetHash = mSlot.getLocalNode()->getQuorumSetHash();
        }
    }
    else
    {
        auto const& st = stateit->second.statement;

        switch (st.pledges.type())
        {
        case ICPStatementType::ICP_ST_PREPARE:
            phase = "PREPARE";
            b = st.pledges.prepare().ballot;
            break;
        case ICPStatementType::ICP_ST_CONFIRM:
            phase = "CONFIRM";
            b = st.pledges.confirm().ballot;
            break;
        case ICPStatementType::ICP_ST_EXTERNALIZE:
            phase = "EXTERNALIZE";
            b = st.pledges.externalize().commit;
            break;
        default:
            dbgAbort();
        }
        // use the companion set here even for externalize to capture
        // the view of the quorum set during consensus
        qSetHash = mSlot.getCompanionQuorumSetHashFromStatement(st);
    }

    Json::Value& disagree = ret["disagree"];
    Json::Value& missing = ret["missing"];
    Json::Value& delayed = ret["delayed"];

    int n_missing = 0, n_disagree = 0, n_delayed = 0;

    int agree = 0;
    auto qSet = mSlot.getICPDriver().getQSet(qSetHash);
    if (!qSet)
    {
        phase = "expired";
        return ret;
    }
    LocalNode::forAllNodes(*qSet, [&](NodeID const& n) {
        auto it = mLatestEnvelopes.find(n);
        if (it == mLatestEnvelopes.end())
        {
            if (!summary)
            {
                missing.append(mSlot.getICPDriver().toStrKey(n, fullKeys));
            }
            n_missing++;
        }
        else
        {
            auto& st = it->second.statement;
            if (areBallotsCompatible(getWorkingBallot(st), b))
            {
                agree++;
                auto t = st.pledges.type();
                if (!(t == ICPStatementType::ICP_ST_EXTERNALIZE ||
                      (t == ICPStatementType::ICP_ST_CONFIRM &&
                       st.pledges.confirm().ballot.counter == UINT32_MAX)))
                {
                    if (!summary)
                    {
                        delayed.append(
                            mSlot.getICPDriver().toStrKey(n, fullKeys));
                    }
                    n_delayed++;
                }
            }
            else
            {
                if (!summary)
                {
                    disagree.append(mSlot.getICPDriver().toStrKey(n, fullKeys));
                }
                n_disagree++;
            }
        }
    });
    if (summary)
    {
        missing = n_missing;
        disagree = n_disagree;
        delayed = n_delayed;
    }

    auto f = LocalNode::findClosestVBlocking(*qSet, mLatestEnvelopes,
                                             [&](ICPStatement const& st) {
                                                 return areBallotsCompatible(
                                                     getWorkingBallot(st), b);
                                             },
                                             &id);
    ret["fail_at"] = static_cast<int>(f.size());

    if (!summary)
    {
        auto& f_ex = ret["fail_with"];
        for (auto const& n : f)
        {
            f_ex.append(mSlot.getICPDriver().toStrKey(n, fullKeys));
        }
        ret["value"] = getLocalNode()->toJson(*qSet, fullKeys);
    }

    ret["hash"] = hexAbbrev(qSetHash);
    ret["agree"] = agree;

    return ret;
}

std::string
BallotProtocol::getLocalState() const
{
    std::ostringstream oss;

    oss << "i: " << mSlot.getSlotIndex() << " | " << phaseNames[mPhase]
        << " | b: " << mSlot.getICP().ballotToStr(mCurrentBallot)
        << " | p: " << mSlot.getICP().ballotToStr(mPrepared)
        << " | p': " << mSlot.getICP().ballotToStr(mPreparedPrime)
        << " | h: " << mSlot.getICP().ballotToStr(mHighBallot)
        << " | c: " << mSlot.getICP().ballotToStr(mCommit)
        << " | M: " << mLatestEnvelopes.size();
    return oss.str();
}

std::shared_ptr<LocalNode>
BallotProtocol::getLocalNode()
{
    return mSlot.getICP().getLocalNode();
}

bool
BallotProtocol::federatedAccept(StatementPredicate voted,
                                StatementPredicate accepted)
{
    return mSlot.federatedAccept(voted, accepted, mLatestEnvelopes);
}

bool
BallotProtocol::federatedRatify(StatementPredicate voted)
{
    return mSlot.federatedRatify(voted, mLatestEnvelopes);
}

void
BallotProtocol::checkHeardFromQuorum()
{
    // this method is safe to call regardless of the transitions of the other
    // nodes on the network:
    // we guarantee that other nodes can only transition to higher counters
    // (messages are ignored upstream)
    // therefore the local node will not flip flop between "seen" and "not seen"
    // for a given counter on the local node
    if (mCurrentBallot)
    {
        if (LocalNode::isQuorum(
                getLocalNode()->getQuorumSet(), mLatestEnvelopes,
                std::bind(&Slot::getQuorumSetFromStatement, &mSlot, _1),
                [&](ICPStatement const& st) {
                    bool res;
                    if (st.pledges.type() == ICP_ST_PREPARE)
                    {
                        res = mCurrentBallot->counter <=
                              st.pledges.prepare().ballot.counter;
                    }
                    else
                    {
                        res = true;
                    }
                    return res;
                }))
        {
            bool oldHQ = mHeardFromQuorum;
            mHeardFromQuorum = true;
            if (!oldHQ)
            {
                // if we transition from not heard -> heard, we start the timer
                mSlot.getICPDriver().ballotDidHearFromQuorum(
                    mSlot.getSlotIndex(), *mCurrentBallot);
                if (mPhase != ICP_PHASE_EXTERNALIZE)
                {
                    startBallotProtocolTimer();
                }
            }
            if (mPhase == ICP_PHASE_EXTERNALIZE)
            {
                stopBallotProtocolTimer();
            }
        }
        else
        {
            mHeardFromQuorum = false;
            stopBallotProtocolTimer();
        }
    }
}
}
