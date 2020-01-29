#pragma once

// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include <memory>
#include <set>
#include <vector>

#include "icp/ICP.h"
#include "util/HashOfHash.h"

namespace iotchain
{
/**
 * This is one Node in the iotchain network
 */
class LocalNode
{
  protected:
    const NodeID mNodeID;
    const bool mIsValidator;
    ICPQuorumSet mQSet;
    Hash mQSetHash;

    // alternative qset used during externalize {{mNodeID}}
    Hash gSingleQSetHash;                      // hash of the singleton qset
    std::shared_ptr<ICPQuorumSet> mSingleQSet; // {{mNodeID}}

    ICP* mICP;

  public:
    LocalNode(NodeID const& nodeID, bool isValidator, ICPQuorumSet const& qSet,
              ICP* icp);

    NodeID const& getNodeID();

    void updateQuorumSet(ICPQuorumSet const& qSet);

    ICPQuorumSet const& getQuorumSet();
    Hash const& getQuorumSetHash();
    bool isValidator();

    // returns the quorum set {{X}}
    static ICPQuorumSetPtr getSingletonQSet(NodeID const& nodeID);

    // runs proc over all nodes contained in qset
    static void forAllNodes(ICPQuorumSet const& qset,
                            std::function<void(NodeID const&)> proc);

    // returns the weight of the node within the qset
    // normalized between 0-UINT64_MAX
    static uint64 getNodeWeight(NodeID const& nodeID, ICPQuorumSet const& qset);

    // Tests this node against nodeSet for the specified qSethash.
    static bool isQuorumSlice(ICPQuorumSet const& qSet,
                              std::vector<NodeID> const& nodeSet);
    static bool isVBlocking(ICPQuorumSet const& qSet,
                            std::vector<NodeID> const& nodeSet);

    // Tests this node against a map of nodeID -> T for the specified qSetHash.

    // `isVBlocking` tests if the filtered nodes V are a v-blocking set for
    // this node.
    static bool
    isVBlocking(ICPQuorumSet const& qSet,
                std::map<NodeID, ICPEnvelope> const& map,
                std::function<bool(ICPStatement const&)> const& filter =
                    [](ICPStatement const&) { return true; });

    // `isQuorum` tests if the filtered nodes V form a quorum
    // (meaning for each v \in V there is q \in Q(v)
    // included in V and we have quorum on V for qSetHash). `qfun` extracts the
    // ICPQuorumSetPtr from the ICPStatement for its associated node in map
    // (required for transitivity)
    static bool
    isQuorum(ICPQuorumSet const& qSet, std::map<NodeID, ICPEnvelope> const& map,
             std::function<ICPQuorumSetPtr(ICPStatement const&)> const& qfun,
             std::function<bool(ICPStatement const&)> const& filter =
                 [](ICPStatement const&) { return true; });

    // computes the distance to the set of v-blocking sets given
    // a set of nodes that agree (but can fail)
    // excluded, if set will be skipped altogether
    static std::vector<NodeID>
    findClosestVBlocking(ICPQuorumSet const& qset,
                         std::set<NodeID> const& nodes, NodeID const* excluded);

    static std::vector<NodeID> findClosestVBlocking(
        ICPQuorumSet const& qset, std::map<NodeID, ICPEnvelope> const& map,
        std::function<bool(ICPStatement const&)> const& filter =
            [](ICPStatement const&) { return true; },
        NodeID const* excluded = nullptr);

    static Json::Value toJson(ICPQuorumSet const& qSet,
                              std::function<std::string(PublicKey const&)> r);

    Json::Value toJson(ICPQuorumSet const& qSet, bool fullKeys) const;
    std::string to_string(ICPQuorumSet const& qSet) const;

    static uint64 computeWeight(uint64 m, uint64 total, uint64 threshold);

  protected:
    // returns a quorum set {{ nodeID }}
    static ICPQuorumSet buildSingletonQSet(NodeID const& nodeID);

    // called recursively
    static bool isQuorumSliceInternal(ICPQuorumSet const& qset,
                                      std::vector<NodeID> const& nodeSet);
    static bool isVBlockingInternal(ICPQuorumSet const& qset,
                                    std::vector<NodeID> const& nodeSet);
};
}
