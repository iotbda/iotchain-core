#include "lib/catch.hpp"
#include "icp/LocalNode.h"
#include "icp/ICP.h"
#include "icp/Slot.h"
#include "simulation/Simulation.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

namespace iotchain
{
bool
isNear(uint64 r, double target)
{
    double v = (double)r / (double)UINT64_MAX;
    return (std::abs(v - target) < .01);
}

TEST_CASE("nomination weight", "[icp]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);

    ICPQuorumSet qSet;
    qSet.threshold = 3;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);

    uint64 result = LocalNode::getNodeWeight(v2NodeID, qSet);

    REQUIRE(isNear(result, .75));

    result = LocalNode::getNodeWeight(v4NodeID, qSet);
    REQUIRE(result == 0);

    ICPQuorumSet iQSet;
    iQSet.threshold = 1;
    iQSet.validators.push_back(v4NodeID);
    iQSet.validators.push_back(v5NodeID);
    qSet.innerSets.push_back(iQSet);

    result = LocalNode::getNodeWeight(v4NodeID, qSet);

    REQUIRE(isNear(result, .6 * .5));
}

class TestNominationICP : public ICPDriver
{
  public:
    ICP mICP;
    TestNominationICP(NodeID const& nodeID, ICPQuorumSet const& qSetLocal)
        : mICP(*this, nodeID, true, qSetLocal)
    {
        auto localQSet =
            std::make_shared<ICPQuorumSet>(mICP.getLocalQuorumSet());
        storeQuorumSet(localQSet);
    }

    void
    signEnvelope(ICPEnvelope&) override
    {
    }

    void
    storeQuorumSet(ICPQuorumSetPtr qSet)
    {
        Hash qSetHash = sha256(xdr::xdr_to_opaque(*qSet.get()));
        mQuorumSets[qSetHash] = qSet;
    }

    ICPDriver::ValidationLevel
    validateValue(uint64 slotIndex, Value const& value,
                  bool nomination) override
    {
        return ICPDriver::kFullyValidatedValue;
    }

    ICPQuorumSetPtr
    getQSet(Hash const& qSetHash) override
    {
        if (mQuorumSets.find(qSetHash) != mQuorumSets.end())
        {

            return mQuorumSets[qSetHash];
        }
        return ICPQuorumSetPtr();
    }

    void
    emitEnvelope(ICPEnvelope const& envelope) override
    {
    }

    Value
    combineCandidates(uint64 slotIndex,
                      std::set<Value> const& candidates) override
    {
        return {};
    }

    void
    setupTimer(uint64 slotIndex, int timerID, std::chrono::milliseconds timeout,
               std::function<void()> cb) override
    {
    }

    std::map<Hash, ICPQuorumSetPtr> mQuorumSets;

    Value const&
    getLatestCompositeCandidate(uint64 slotIndex)
    {
        static Value const emptyValue{};
        return emptyValue;
    }
};

class NominationTestHandler : public NominationProtocol
{
  public:
    NominationTestHandler(Slot& s) : NominationProtocol(s)
    {
    }

    void
    setPreviousValue(Value const& v)
    {
        mPreviousValue = v;
    }

    void
    setRoundNumber(int32 n)
    {
        mRoundNumber = n;
    }

    void
    updateRoundLeaders()
    {
        NominationProtocol::updateRoundLeaders();
    }

    std::set<NodeID>&
    getRoundLeaders()
    {
        return mRoundLeaders;
    }

    uint64
    getNodePriority(NodeID const& nodeID, ICPQuorumSet const& qset)
    {
        return NominationProtocol::getNodePriority(nodeID, qset);
    }
};

static ICPQuorumSet
makeQSet(std::vector<NodeID> const& nodeIDs, int threshold, int total,
         int offset)
{
    ICPQuorumSet qSet;
    qSet.threshold = threshold;
    for (int i = 0; i < total; i++)
    {
        qSet.validators.push_back(nodeIDs[i + offset]);
    }
    return qSet;
}

// this test case display statistical information on the priority function used
// by nomination
TEST_CASE("nomination weight stats", "[icp][!hide]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);
    SIMULATION_CREATE_NODE(6);

    std::vector<NodeID> nodeIDs = {v0NodeID, v1NodeID, v2NodeID, v3NodeID,
                                   v4NodeID, v5NodeID, v6NodeID};

    int const totalSlots = 1000;
    int const maxRoundPerSlot = 5; // 5 -> 15 seconds
    int const totalRounds = totalSlots * maxRoundPerSlot;

    auto runTests = [&](ICPQuorumSet qSet) {
        std::map<NodeID, int> wins;

        TestNominationICP nomICP(v0NodeID, qSet);
        for (int s = 0; s < totalSlots; s++)
        {
            Slot slot(s, nomICP.mICP);

            NominationTestHandler nom(slot);

            Value v;
            v.emplace_back(uint8_t(s)); // anything will do as a value

            nom.setPreviousValue(v);

            for (int i = 0; i < maxRoundPerSlot; i++)
            {
                nom.setRoundNumber(i);
                nom.updateRoundLeaders();
                auto& l = nom.getRoundLeaders();
                REQUIRE(!l.empty());
                for (auto& w : l)
                {
                    wins[w]++;
                }
            }
        }
        return wins;
    };

    SECTION("flat quorum")
    {
        auto flatTest = [&](int threshold, int total) {
            auto qSet = makeQSet(nodeIDs, threshold, total, 0);

            auto wins = runTests(qSet);

            for (auto& w : wins)
            {
                double stats = double(w.second * 100) / double(totalRounds);
                CLOG(INFO, "ICP") << "Got " << stats
                                  << ((v0NodeID == w.first) ? " LOCAL" : "");
            }
        };

        SECTION("3 out of 5")
        {
            flatTest(3, 5);
        }
        SECTION("2 out of 3")
        {
            flatTest(2, 3);
        }
    }
    SECTION("hierarchy")
    {
        auto qSet = makeQSet(nodeIDs, 3, 4, 0);

        auto qSetInner = makeQSet(nodeIDs, 2, 3, 4);
        qSet.innerSets.emplace_back(qSetInner);

        auto wins = runTests(qSet);

        for (auto& w : wins)
        {
            double stats = double(w.second * 100) / double(totalRounds);
            bool outer =
                std::any_of(qSet.validators.begin(), qSet.validators.end(),
                            [&](auto const& k) { return k == w.first; });
            CLOG(INFO, "ICP")
                << "Got " << stats << " "
                << ((v0NodeID == w.first) ? "LOCAL"
                                          : (outer ? "OUTER" : "INNER"));
        }
    }
}

TEST_CASE("nomination two nodes win stats", "[icp][!hide]")
{
    int const nbRoundsForStats = 9;
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);
    SIMULATION_CREATE_NODE(6);

    std::vector<NodeID> nodeIDs = {v0NodeID, v1NodeID, v2NodeID, v3NodeID,
                                   v4NodeID, v5NodeID, v6NodeID};

    int const totalIter = 10000;

    // maxRounds is the number of rounds to evaluate in a row
    // the iteration is considered successful if validators could
    // agree on what to nominate before maxRounds is reached
    auto nominationLeaders = [&](int maxRounds, ICPQuorumSet qSetNode0,
                                 ICPQuorumSet qSetNode1) {
        TestNominationICP nomICP0(v0NodeID, qSetNode0);
        Slot slot0(0, nomICP0.mICP);
        NominationTestHandler nom0(slot0);

        TestNominationICP nomICP1(v1NodeID, qSetNode1);
        Slot slot1(0, nomICP1.mICP);
        NominationTestHandler nom1(slot1);

        int tot = 0;
        for (int g = 0; g < totalIter; g++)
        {
            Value v;
            v.emplace_back(uint8_t(g));
            nom0.setPreviousValue(v);
            nom1.setPreviousValue(v);

            bool res = true;

            bool v0Voted = false;
            bool v1Voted = false;

            int r = 0;
            do
            {
                nom0.setRoundNumber(r);
                nom1.setRoundNumber(r);
                nom0.updateRoundLeaders();
                nom1.updateRoundLeaders();

                auto& l0 = nom0.getRoundLeaders();
                REQUIRE(!l0.empty());
                auto& l1 = nom1.getRoundLeaders();
                REQUIRE(!l1.empty());

                auto updateVoted = [&](auto const& id, auto const& leaders,
                                       bool& voted) {
                    if (!voted)
                    {
                        voted = std::find(leaders.begin(), leaders.end(), id) !=
                                leaders.end();
                    }
                };

                // checks if id voted (any past round, including this one)
                // AND id is a leader this round
                auto findNode = [](auto const& id, bool idVoted,
                                   auto const& otherLeaders) {
                    bool r = (idVoted && std::find(otherLeaders.begin(),
                                                   otherLeaders.end(),
                                                   id) != otherLeaders.end());
                    return r;
                };

                updateVoted(v0NodeID, l0, v0Voted);
                updateVoted(v1NodeID, l1, v1Voted);

                // either both vote for v0 or both vote for v1
                res = findNode(v0NodeID, v0Voted, l1);
                res = res || findNode(v1NodeID, v1Voted, l0);
            } while (!res && ++r < maxRounds);

            tot += res ? 1 : 0;
        }
        return tot;
    };

    SECTION("flat quorum")
    {
        // test using the same quorum on all nodes
        auto flatTest = [&](int threshold, int total) {
            auto qSet = makeQSet(nodeIDs, threshold, total, 0);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet, qSet);
                double stats = double(tot * 100) / double(totalIter);
                CLOG(INFO, "ICP")
                    << "Win rate for " << maxRounds << " : " << stats;
            }
        };

        SECTION("3 out of 5")
        {
            flatTest(3, 5);
        }
        SECTION("2 out of 3")
        {
            flatTest(2, 3);
        }
    }

    SECTION("hierarchy")
    {
        SECTION("same qSet")
        {
            auto qSet = makeQSet(nodeIDs, 3, 4, 0);

            auto qSetInner = makeQSet(nodeIDs, 2, 3, 4);
            qSet.innerSets.emplace_back(qSetInner);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet, qSet);
                double stats = double(tot * 100) / double(totalIter);
                CLOG(INFO, "ICP")
                    << "Win rate for " << maxRounds << " : " << stats;
            }
        }
        SECTION("v0 is inner node for v1")
        {
            auto qSet0 = makeQSet(nodeIDs, 3, 4, 0);
            auto qSetInner0 = makeQSet(nodeIDs, 2, 3, 4);
            qSet0.innerSets.emplace_back(qSetInner0);

            // v1's qset: we move v0 into the inner set
            auto qSet1 = qSet0;
            REQUIRE(qSet1.validators[0] == v0NodeID);
            std::swap(qSet1.validators[0], qSet1.innerSets[0].validators[0]);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet0, qSet1);
                double stats = double(tot * 100) / double(totalIter);
                CLOG(INFO, "ICP")
                    << "Win rate for " << maxRounds << " : " << stats;
            }
        }
    }
}
}
