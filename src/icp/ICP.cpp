// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "icp/ICP.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "icp/LocalNode.h"
#include "icp/Slot.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <lib/json/json.h>

namespace iotchain
{

ICP::ICP(ICPDriver& driver, NodeID const& nodeID, bool isValidator,
         ICPQuorumSet const& qSetLocal)
    : mDriver(driver)
{
    mLocalNode =
        std::make_shared<LocalNode>(nodeID, isValidator, qSetLocal, this);
}

ICP::EnvelopeState
ICP::receiveEnvelope(ICPEnvelope const& envelope)
{
    uint64 slotIndex = envelope.statement.slotIndex;
    return getSlot(slotIndex, true)->processEnvelope(envelope, false);
}

bool
ICP::nominate(uint64 slotIndex, Value const& value, Value const& previousValue)
{
    dbgAssert(isValidator());
    return getSlot(slotIndex, true)->nominate(value, previousValue, false);
}

void
ICP::stopNomination(uint64 slotIndex)
{
    auto s = getSlot(slotIndex, false);
    if (s)
    {
        s->stopNomination();
    }
}

void
ICP::updateLocalQuorumSet(ICPQuorumSet const& qSet)
{
    mLocalNode->updateQuorumSet(qSet);
}

ICPQuorumSet const&
ICP::getLocalQuorumSet()
{
    return mLocalNode->getQuorumSet();
}

NodeID const&
ICP::getLocalNodeID()
{
    return mLocalNode->getNodeID();
}

void
ICP::purgeSlots(uint64 maxSlotIndex)
{
    auto it = mKnownSlots.begin();
    while (it != mKnownSlots.end())
    {
        if (it->first < maxSlotIndex)
        {
            it = mKnownSlots.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

std::shared_ptr<LocalNode>
ICP::getLocalNode()
{
    return mLocalNode;
}

std::shared_ptr<Slot>
ICP::getSlot(uint64 slotIndex, bool create)
{
    std::shared_ptr<Slot> res;
    auto it = mKnownSlots.find(slotIndex);
    if (it == mKnownSlots.end())
    {
        if (create)
        {
            res = std::make_shared<Slot>(slotIndex, *this);
            mKnownSlots[slotIndex] = res;
        }
    }
    else
    {
        res = it->second;
    }
    return res;
}

Json::Value
ICP::getJsonInfo(size_t limit, bool fullKeys)
{
    Json::Value ret;
    auto it = mKnownSlots.rbegin();
    while (it != mKnownSlots.rend() && limit-- != 0)
    {
        auto& slot = *(it->second);
        ret[std::to_string(slot.getSlotIndex())] = slot.getJsonInfo(fullKeys);
        it++;
    }

    return ret;
}

Json::Value
ICP::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys,
                       uint64 index)
{
    Json::Value ret;
    if (index == 0)
    {
        for (auto& item : mKnownSlots)
        {
            auto& slot = *item.second;
            ret = slot.getJsonQuorumInfo(id, summary, fullKeys);
            ret["ledger"] = static_cast<Json::UInt64>(slot.getSlotIndex());
        }
    }
    else
    {
        auto s = getSlot(index, false);
        if (s)
        {
            ret = s->getJsonQuorumInfo(id, summary, fullKeys);
            ret["ledger"] = static_cast<Json::UInt64>(index);
        }
    }
    return ret;
}

bool
ICP::isValidator()
{
    return mLocalNode->isValidator();
}

bool
ICP::isSlotFullyValidated(uint64 slotIndex)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        return slot->isFullyValidated();
    }
    else
    {
        return false;
    }
}

size_t
ICP::getKnownSlotsCount() const
{
    return mKnownSlots.size();
}

size_t
ICP::getCumulativeStatemtCount() const
{
    size_t c = 0;
    for (auto const& s : mKnownSlots)
    {
        c += s.second->getStatementCount();
    }
    return c;
}

std::vector<ICPEnvelope>
ICP::getLatestMessagesSend(uint64 slotIndex)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        return slot->getLatestMessagesSend();
    }
    else
    {
        return std::vector<ICPEnvelope>();
    }
}

void
ICP::setStateFromEnvelope(uint64 slotIndex, ICPEnvelope const& e)
{
    auto slot = getSlot(slotIndex, true);
    slot->setStateFromEnvelope(e);
}

bool
ICP::empty() const
{
    return mKnownSlots.empty();
}

uint64
ICP::getLowSlotIndex() const
{
    assert(!empty());
    return mKnownSlots.begin()->first;
}

uint64
ICP::getHighSlotIndex() const
{
    assert(!empty());
    auto it = mKnownSlots.end();
    it--;
    return it->first;
}

std::vector<ICPEnvelope>
ICP::getCurrentState(uint64 slotIndex)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        return slot->getCurrentState();
    }
    else
    {
        return std::vector<ICPEnvelope>();
    }
}

ICPEnvelope const*
ICP::getLatestMessage(NodeID const& id)
{
    for (auto it = mKnownSlots.rbegin(); it != mKnownSlots.rend(); it++)
    {
        auto slot = it->second;
        auto res = slot->getLatestMessage(id);
        if (res != nullptr)
        {
            return res;
        }
    }
    return nullptr;
}

std::vector<ICPEnvelope>
ICP::getExternalizingState(uint64 slotIndex)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        return slot->getExternalizingState();
    }
    else
    {
        return std::vector<ICPEnvelope>();
    }
}

std::string
ICP::getValueString(Value const& v) const
{
    return mDriver.getValueString(v);
}

std::string
ICP::ballotToStr(ICPBallot const& ballot) const
{
    std::ostringstream oss;

    oss << "(" << ballot.counter << "," << getValueString(ballot.value) << ")";
    return oss.str();
}

std::string
ICP::ballotToStr(std::unique_ptr<ICPBallot> const& ballot) const
{
    std::string res;
    if (ballot)
    {
        res = ballotToStr(*ballot);
    }
    else
    {
        res = "(<null_ballot>)";
    }
    return res;
}

std::string
ICP::envToStr(ICPEnvelope const& envelope, bool fullKeys) const
{
    return envToStr(envelope.statement, fullKeys);
}

std::string
ICP::envToStr(ICPStatement const& st, bool fullKeys) const
{
    std::ostringstream oss;

    Hash const& qSetHash = Slot::getCompanionQuorumSetHashFromStatement(st);

    std::string nodeId = mDriver.toStrKey(st.nodeID, fullKeys);

    oss << "{ENV@" << nodeId << " | "
        << " i: " << st.slotIndex;
    switch (st.pledges.type())
    {
    case ICPStatementType::ICP_ST_PREPARE:
    {
        auto const& p = st.pledges.prepare();
        oss << " | PREPARE"
            << " | D: " << hexAbbrev(qSetHash)
            << " | b: " << ballotToStr(p.ballot)
            << " | p: " << ballotToStr(p.prepared)
            << " | p': " << ballotToStr(p.preparedPrime) << " | c.n: " << p.nC
            << " | h.n: " << p.nH;
    }
    break;
    case ICPStatementType::ICP_ST_CONFIRM:
    {
        auto const& c = st.pledges.confirm();
        oss << " | CONFIRM"
            << " | D: " << hexAbbrev(qSetHash)
            << " | b: " << ballotToStr(c.ballot) << " | p.n: " << c.nPrepared
            << " | c.n: " << c.nCommit << " | h.n: " << c.nH;
    }
    break;
    case ICPStatementType::ICP_ST_EXTERNALIZE:
    {
        auto const& ex = st.pledges.externalize();
        oss << " | EXTERNALIZE"
            << " | c: " << ballotToStr(ex.commit) << " | h.n: " << ex.nH
            << " | (lastD): " << hexAbbrev(qSetHash);
    }
    break;
    case ICPStatementType::ICP_ST_NOMINATE:
    {
        auto const& nom = st.pledges.nominate();
        oss << " | NOMINATE"
            << " | D: " << hexAbbrev(qSetHash) << " | X: {";
        bool first = true;
        for (auto const& v : nom.votes)
        {
            if (!first)
            {
                oss << " ,";
            }
            oss << "'" << getValueString(v) << "'";
            first = false;
        }
        oss << "}"
            << " | Y: {";
        first = true;
        for (auto const& a : nom.accepted)
        {
            if (!first)
            {
                oss << " ,";
            }
            oss << "'" << getValueString(a) << "'";
            first = false;
        }
        oss << "}";
    }
    break;
    }

    oss << " }";
    return oss.str();
}
}
