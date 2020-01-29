#pragma once

// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <set>

#include "crypto/SecretKey.h"
#include "lib/json/json-forwards.h"
#include "icp/ICPDriver.h"

namespace iotchain
{
class Node;
class Slot;
class LocalNode;
typedef std::shared_ptr<ICPQuorumSet> ICPQuorumSetPtr;

class ICP
{
    ICPDriver& mDriver;

  public:
    ICP(ICPDriver& driver, NodeID const& nodeID, bool isValidator,
        ICPQuorumSet const& qSetLocal);

    ICPDriver&
    getDriver()
    {
        return mDriver;
    }
    ICPDriver const&
    getDriver() const
    {
        return mDriver;
    }

    enum EnvelopeState
    {
        INVALID, // the envelope is considered invalid
        VALID    // the envelope is valid
    };

    // this is the main entry point of the ICP library
    // it processes the envelope, updates the internal state and
    // invokes the appropriate methods
    EnvelopeState receiveEnvelope(ICPEnvelope const& envelope);

    // Submit a value to consider for slotIndex
    // previousValue is the value from slotIndex-1
    bool nominate(uint64 slotIndex, Value const& value,
                  Value const& previousValue);

    // stops nomination for a slot
    void stopNomination(uint64 slotIndex);

    // Local QuorumSet interface (can be dynamically updated)
    void updateLocalQuorumSet(ICPQuorumSet const& qSet);
    ICPQuorumSet const& getLocalQuorumSet();

    // Local nodeID getter
    NodeID const& getLocalNodeID();

    // returns the local node descriptor
    std::shared_ptr<LocalNode> getLocalNode();

    Json::Value getJsonInfo(size_t limit, bool fullKeys = false);

    // summary: only return object counts
    // index = 0 for returning information for all slots
    Json::Value getJsonQuorumInfo(NodeID const& id, bool summary,
                                  bool fullKeys = false, uint64 index = 0);

    // Purges all data relative to all the slots whose slotIndex is smaller
    // than the specified `maxSlotIndex`.
    void purgeSlots(uint64 maxSlotIndex);

    // Returns whether the local node is a validator.
    bool isValidator();

    // returns the validation state of the given slot
    bool isSlotFullyValidated(uint64 slotIndex);

    // Helpers for monitoring and reporting the internal memory-usage of the ICP
    // protocol to system metric reporters.
    size_t getKnownSlotsCount() const;
    size_t getCumulativeStatemtCount() const;

    // returns the latest messages sent for the given slot
    std::vector<ICPEnvelope> getLatestMessagesSend(uint64 slotIndex);

    // forces the state to match the one in the envelope
    // this is used when rebuilding the state after a crash for example
    void setStateFromEnvelope(uint64 slotIndex, ICPEnvelope const& e);

    // check if we are holding some slots
    bool empty() const;
    // return lowest slot index value
    uint64 getLowSlotIndex() const;
    // return highest slot index value
    uint64 getHighSlotIndex() const;

    // returns all messages for the slot
    std::vector<ICPEnvelope> getCurrentState(uint64 slotIndex);

    // returns the latest message from a node
    // or nullptr if not found
    ICPEnvelope const* getLatestMessage(NodeID const& id);

    // returns messages that contributed to externalizing the slot
    // (or empty if the slot didn't externalize)
    std::vector<ICPEnvelope> getExternalizingState(uint64 slotIndex);

    // ** helper methods to stringify ballot for logging
    std::string getValueString(Value const& v) const;
    std::string ballotToStr(ICPBallot const& ballot) const;
    std::string ballotToStr(std::unique_ptr<ICPBallot> const& ballot) const;
    std::string envToStr(ICPEnvelope const& envelope,
                         bool fullKeys = false) const;
    std::string envToStr(ICPStatement const& st, bool fullKeys = false) const;

  protected:
    std::shared_ptr<LocalNode> mLocalNode;
    std::map<uint64, std::shared_ptr<Slot>> mKnownSlots;

    // Slot getter
    std::shared_ptr<Slot> getSlot(uint64 slotIndex, bool create);

    friend class TestICP;
};
}
