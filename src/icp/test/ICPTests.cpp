// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0
#include "util/asio.h"

#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "lib/catch.hpp"
#include "icp/LocalNode.h"
#include "icp/ICP.h"
#include "icp/Slot.h"
#include "simulation/Simulation.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "util/format.h"
#include "xdrpp/marshal.h"
#include "xdrpp/printer.h"

namespace iotchain
{

// x < y < z < zz
// k can be anything
static Value xValue, yValue, zValue, zzValue, kValue;

static void
setupValues()
{
    std::vector<Value> v;
    std::string d = fmt::format("SEED_VALUE_DATA_{}", std::rand());
    for (int i = 0; i < 4; i++)
    {
        auto h = sha256(fmt::format("{}/{}", d, i));
        v.emplace_back(xdr::xdr_to_opaque(h));
    }
    std::sort(v.begin(), v.end());
    xValue = v[0];
    yValue = v[1];
    zValue = v[2];
    zzValue = v[3];

    // kValue is independent
    auto kHash = sha256(d);
    kValue = xdr::xdr_to_opaque(kHash);
}

class TestICP : public ICPDriver
{
  public:
    ICP mICP;

    TestICP(NodeID const& nodeID, ICPQuorumSet const& qSetLocal,
            bool isValidator = true)
        : mICP(*this, nodeID, isValidator, qSetLocal)
    {
        mPriorityLookup = [&](NodeID const& n) {
            return (n == mICP.getLocalNodeID()) ? 1000 : 1;
        };

        mHashValueCalculator = [&](Value const& v) { return 0; };

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

    void
    ballotDidHearFromQuorum(uint64 slotIndex, ICPBallot const& ballot) override
    {
        mHeardFromQuorums[slotIndex].push_back(ballot);
    }

    void
    valueExternalized(uint64 slotIndex, Value const& value) override
    {
        if (mExternalizedValues.find(slotIndex) != mExternalizedValues.end())
        {
            throw std::out_of_range("Value already externalized");
        }
        mExternalizedValues[slotIndex] = value;
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
        mEnvs.push_back(envelope);
    }

    // used to test BallotProtocol and bypass nomination
    bool
    bumpState(uint64 slotIndex, Value const& v)
    {
        return mICP.getSlot(slotIndex, true)->bumpState(v, true);
    }

    bool
    nominate(uint64 slotIndex, Value const& value, bool timedout)
    {
        return mICP.getSlot(slotIndex, true)->nominate(value, value, timedout);
    }

    // only used by nomination protocol
    Value
    combineCandidates(uint64 slotIndex,
                      std::set<Value> const& candidates) override
    {
        REQUIRE(candidates == mExpectedCandidates);
        REQUIRE(!mCompositeValue.empty());

        return mCompositeValue;
    }

    std::set<Value> mExpectedCandidates;
    Value mCompositeValue;

    // override the internal hashing scheme in order to make tests
    // more predictable.
    uint64
    computeHashNode(uint64 slotIndex, Value const& prev, bool isPriority,
                    int32_t roundNumber, NodeID const& nodeID) override
    {
        uint64 res;
        if (isPriority)
        {
            res = mPriorityLookup(nodeID);
        }
        else
        {
            res = 0;
        }
        return res;
    }

    // override the value hashing, to make tests more predictable.
    uint64
    computeValueHash(uint64 slotIndex, Value const& prev, int32_t roundNumber,
                     Value const& value) override
    {
        return mHashValueCalculator(value);
    }

    std::function<uint64(NodeID const&)> mPriorityLookup;
    std::function<uint64(Value const&)> mHashValueCalculator;

    std::map<Hash, ICPQuorumSetPtr> mQuorumSets;
    std::vector<ICPEnvelope> mEnvs;
    std::map<uint64, Value> mExternalizedValues;
    std::map<uint64, std::vector<ICPBallot>> mHeardFromQuorums;

    struct TimerData
    {
        std::chrono::milliseconds mAbsoluteTimeout;
        std::function<void()> mCallback;
    };
    std::map<int, TimerData> mTimers;
    std::chrono::milliseconds mCurrentTimerOffset{0};

    void
    setupTimer(uint64 slotIndex, int timerID, std::chrono::milliseconds timeout,
               std::function<void()> cb) override
    {
        mTimers[timerID] =
            TimerData{mCurrentTimerOffset +
                          (cb ? timeout : std::chrono::milliseconds::zero()),
                      cb};
    }

    TimerData
    getBallotProtocolTimer()
    {
        return mTimers[Slot::BALLOT_PROTOCOL_TIMER];
    }

    // pretends the time moved forward
    std::chrono::milliseconds
    bumpTimerOffset()
    {
        // increase by more than the maximum timeout
        mCurrentTimerOffset += std::chrono::hours(5);
        return mCurrentTimerOffset;
    }

    // returns true if a ballot protocol timer exists (in the past or future)
    bool
    hasBallotTimer()
    {
        return !!getBallotProtocolTimer().mCallback;
    }

    // returns true if the ballot protocol timer is scheduled in the future
    // false if scheduled in the past
    // this method is mostly used to verify that the timer *would* have fired
    bool
    hasBallotTimerUpcoming()
    {
        // timer must be scheduled in the past or future
        REQUIRE(hasBallotTimer());
        return mCurrentTimerOffset < getBallotProtocolTimer().mAbsoluteTimeout;
    }

    Value const&
    getLatestCompositeCandidate(uint64 slotIndex)
    {
        return mICP.getSlot(slotIndex, true)->getLatestCompositeCandidate();
    }

    void
    receiveEnvelope(ICPEnvelope const& envelope)
    {
        mICP.receiveEnvelope(envelope);
    }

    Slot&
    getSlot(uint64 index)
    {
        return *mICP.getSlot(index, false);
    }

    std::vector<ICPEnvelope>
    getEntireState(uint64 index)
    {
        auto v = mICP.getSlot(index, false)->getEntireCurrentState();
        return v;
    }

    ICPEnvelope
    getCurrentEnvelope(uint64 index, NodeID const& id)
    {
        auto r = getEntireState(index);
        auto it = std::find_if(r.begin(), r.end(), [&](ICPEnvelope const& e) {
            return e.statement.nodeID == id;
        });
        if (it != r.end())
        {
            return *it;
        }
        throw std::runtime_error("not found");
    }

    std::set<NodeID>
    getNominationLeaders(uint64 slotIndex)
    {
        return mICP.getSlot(slotIndex, false)->getNominationLeaders();
    }
};

static ICPEnvelope
makeEnvelope(SecretKey const& secretKey, uint64 slotIndex,
             ICPStatement const& statement)
{
    ICPEnvelope envelope;
    envelope.statement = statement;
    envelope.statement.nodeID = secretKey.getPublicKey();
    envelope.statement.slotIndex = slotIndex;

    envelope.signature = secretKey.sign(xdr::xdr_to_opaque(envelope.statement));

    return envelope;
}

static ICPEnvelope
makeExternalize(SecretKey const& secretKey, Hash const& qSetHash,
                uint64 slotIndex, ICPBallot const& commitBallot, uint32 nH)
{
    ICPStatement st;
    st.pledges.type(ICP_ST_EXTERNALIZE);
    auto& ext = st.pledges.externalize();
    ext.commit = commitBallot;
    ext.nH = nH;
    ext.commitQuorumSetHash = qSetHash;

    return makeEnvelope(secretKey, slotIndex, st);
}

static ICPEnvelope
makeConfirm(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
            uint32 prepareCounter, ICPBallot const& b, uint32 nC, uint32 nH)
{
    ICPStatement st;
    st.pledges.type(ICP_ST_CONFIRM);
    auto& con = st.pledges.confirm();
    con.ballot = b;
    con.nPrepared = prepareCounter;
    con.nCommit = nC;
    con.nH = nH;
    con.quorumSetHash = qSetHash;

    return makeEnvelope(secretKey, slotIndex, st);
}

static ICPEnvelope
makePrepare(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
            ICPBallot const& ballot, ICPBallot* prepared = nullptr,
            uint32 nC = 0, uint32 nH = 0, ICPBallot* preparedPrime = nullptr)
{
    ICPStatement st;
    st.pledges.type(ICP_ST_PREPARE);
    auto& p = st.pledges.prepare();
    p.ballot = ballot;
    p.quorumSetHash = qSetHash;
    if (prepared)
    {
        p.prepared.activate() = *prepared;
    }

    p.nC = nC;
    p.nH = nH;

    if (preparedPrime)
    {
        p.preparedPrime.activate() = *preparedPrime;
    }

    return makeEnvelope(secretKey, slotIndex, st);
}

static ICPEnvelope
makeNominate(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
             std::vector<Value> votes, std::vector<Value> accepted)
{
    std::sort(votes.begin(), votes.end());
    std::sort(accepted.begin(), accepted.end());

    ICPStatement st;
    st.pledges.type(ICP_ST_NOMINATE);
    auto& nom = st.pledges.nominate();
    nom.quorumSetHash = qSetHash;
    for (auto const& v : votes)
    {
        nom.votes.emplace_back(v);
    }
    for (auto const& a : accepted)
    {
        nom.accepted.emplace_back(a);
    }
    return makeEnvelope(secretKey, slotIndex, st);
}

void
verifyPrepare(ICPEnvelope const& actual, SecretKey const& secretKey,
              Hash const& qSetHash, uint64 slotIndex, ICPBallot const& ballot,
              ICPBallot* prepared = nullptr, uint32 nC = 0, uint32 nH = 0,
              ICPBallot* preparedPrime = nullptr)
{
    auto exp = makePrepare(secretKey, qSetHash, slotIndex, ballot, prepared, nC,
                           nH, preparedPrime);
    REQUIRE(exp.statement == actual.statement);
}

void
verifyConfirm(ICPEnvelope const& actual, SecretKey const& secretKey,
              Hash const& qSetHash, uint64 slotIndex, uint32 nPrepared,
              ICPBallot const& b, uint32 nC, uint32 nH)
{
    auto exp =
        makeConfirm(secretKey, qSetHash, slotIndex, nPrepared, b, nC, nH);
    REQUIRE(exp.statement == actual.statement);
}

void
verifyExternalize(ICPEnvelope const& actual, SecretKey const& secretKey,
                  Hash const& qSetHash, uint64 slotIndex,
                  ICPBallot const& commit, uint32 nH)
{
    auto exp = makeExternalize(secretKey, qSetHash, slotIndex, commit, nH);
    REQUIRE(exp.statement == actual.statement);
}

void
verifyNominate(ICPEnvelope const& actual, SecretKey const& secretKey,
               Hash const& qSetHash, uint64 slotIndex, std::vector<Value> votes,
               std::vector<Value> accepted)
{
    auto exp = makeNominate(secretKey, qSetHash, slotIndex, votes, accepted);
    REQUIRE(exp.statement == actual.statement);
}

TEST_CASE("vblocking and quorum", "[icp]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);

    ICPQuorumSet qSet;
    qSet.threshold = 3;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);

    std::vector<NodeID> nodeSet;
    nodeSet.push_back(v0NodeID);

    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == false);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == false);

    nodeSet.push_back(v2NodeID);

    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == false);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);

    nodeSet.push_back(v3NodeID);
    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == true);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);

    nodeSet.push_back(v1NodeID);
    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == true);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);
}

TEST_CASE("v blocking distance", "[icp]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);
    SIMULATION_CREATE_NODE(6);
    SIMULATION_CREATE_NODE(7);

    ICPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    auto check = [&](ICPQuorumSet const& qSetCheck, std::set<NodeID> const& s,
                     int expected) {
        auto r = LocalNode::findClosestVBlocking(qSetCheck, s, nullptr);
        REQUIRE(expected == r.size());
    };

    std::set<NodeID> good;
    good.insert(v0NodeID);

    // already v-blocking
    check(qSet, good, 0);

    good.insert(v1NodeID);
    // either v0 or v1
    check(qSet, good, 1);

    good.insert(v2NodeID);
    // any 2 of v0..v2
    check(qSet, good, 2);

    ICPQuorumSet qSubSet1;
    qSubSet1.threshold = 1;
    qSubSet1.validators.push_back(v3NodeID);
    qSubSet1.validators.push_back(v4NodeID);
    qSubSet1.validators.push_back(v5NodeID);
    qSet.innerSets.push_back(qSubSet1);

    good.insert(v3NodeID);
    // any 3 of v0..v3
    check(qSet, good, 3);

    good.insert(v4NodeID);
    // v0..v2
    check(qSet, good, 3);

    qSet.threshold = 1;
    // v0..v4
    check(qSet, good, 5);

    good.insert(v5NodeID);
    // v0..v5
    check(qSet, good, 6);

    ICPQuorumSet qSubSet2;
    qSubSet2.threshold = 2;
    qSubSet2.validators.push_back(v6NodeID);
    qSubSet2.validators.push_back(v7NodeID);

    qSet.innerSets.push_back(qSubSet2);
    // v0..v5
    check(qSet, good, 6);

    good.insert(v6NodeID);
    // v0..v5
    check(qSet, good, 6);

    good.insert(v7NodeID);
    // v0..v5 and one of 6,7
    check(qSet, good, 7);

    qSet.threshold = 4;
    // v6, v7
    check(qSet, good, 2);

    qSet.threshold = 3;
    // v0..v2
    check(qSet, good, 3);

    qSet.threshold = 2;
    // v0..v2 and one of v6,v7
    check(qSet, good, 4);
}

typedef std::function<ICPEnvelope(SecretKey const& sk)> genEnvelope;

using namespace std::placeholders;

static genEnvelope
makePrepareGen(Hash const& qSetHash, ICPBallot const& ballot,
               ICPBallot* prepared = nullptr, uint32 nC = 0, uint32 nH = 0,
               ICPBallot* preparedPrime = nullptr)
{
    return std::bind(makePrepare, _1, std::cref(qSetHash), 0, std::cref(ballot),
                     prepared, nC, nH, preparedPrime);
}

static genEnvelope
makeConfirmGen(Hash const& qSetHash, uint32 prepareCounter, ICPBallot const& b,
               uint32 nC, uint32 nH)
{
    return std::bind(makeConfirm, _1, std::cref(qSetHash), 0, prepareCounter,
                     std::cref(b), nC, nH);
}

static genEnvelope
makeExternalizeGen(Hash const& qSetHash, ICPBallot const& commitBallot,
                   uint32 nH)
{
    return std::bind(makeExternalize, _1, std::cref(qSetHash), 0,
                     std::cref(commitBallot), nH);
}

TEST_CASE("ballot protocol core5", "[icp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);

    // we need 5 nodes to avoid sharing various thresholds:
    // v-blocking set size: 2
    // threshold: 4 = 3 + self or 4 others
    ICPQuorumSet qSet;
    qSet.threshold = 4;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);
    qSet.validators.push_back(v4NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestICP icp(v0SecretKey.getPublicKey(), qSet);

    icp.storeQuorumSet(std::make_shared<ICPQuorumSet>(qSet));
    uint256 qSetHash0 = icp.mICP.getLocalNode()->getQuorumSetHash();

    REQUIRE(xValue < yValue);
    REQUIRE(yValue < zValue);
    REQUIRE(zValue < zzValue);

    CLOG(INFO, "ICP") << "";
    CLOG(INFO, "ICP") << "BEGIN TEST";

    auto recvVBlockingChecks = [&](genEnvelope gen, bool withChecks) {
        ICPEnvelope e1 = gen(v1SecretKey);
        ICPEnvelope e2 = gen(v2SecretKey);

        icp.bumpTimerOffset();

        // nothing should happen with first message
        size_t i = icp.mEnvs.size();
        icp.receiveEnvelope(e1);
        if (withChecks)
        {
            REQUIRE(icp.mEnvs.size() == i);
        }
        i++;
        icp.receiveEnvelope(e2);
        if (withChecks)
        {
            REQUIRE(icp.mEnvs.size() == i);
        }
    };

    auto recvVBlocking = std::bind(recvVBlockingChecks, _1, true);

    auto recvQuorumChecksEx = [&](genEnvelope gen, bool withChecks,
                                  bool delayedQuorum, bool checkUpcoming) {
        ICPEnvelope e1 = gen(v1SecretKey);
        ICPEnvelope e2 = gen(v2SecretKey);
        ICPEnvelope e3 = gen(v3SecretKey);
        ICPEnvelope e4 = gen(v4SecretKey);

        icp.bumpTimerOffset();

        icp.receiveEnvelope(e1);
        icp.receiveEnvelope(e2);
        size_t i = icp.mEnvs.size() + 1;
        icp.receiveEnvelope(e3);
        if (withChecks && !delayedQuorum)
        {
            REQUIRE(icp.mEnvs.size() == i);
        }
        if (checkUpcoming && !delayedQuorum)
        {
            REQUIRE(icp.hasBallotTimerUpcoming());
        }
        // nothing happens with an extra vote (unless we're in delayedQuorum)
        icp.receiveEnvelope(e4);
        if (withChecks && delayedQuorum)
        {
            REQUIRE(icp.mEnvs.size() == i);
        }
        if (checkUpcoming && delayedQuorum)
        {
            REQUIRE(icp.hasBallotTimerUpcoming());
        }
    };
    // doesn't check timers
    auto recvQuorumChecks = std::bind(recvQuorumChecksEx, _1, _2, _3, false);
    // checks enabled, no delayed quorum
    auto recvQuorumEx = std::bind(recvQuorumChecksEx, _1, true, false, _2);
    // checks enabled, no delayed quorum, no check timers
    auto recvQuorum = std::bind(recvQuorumEx, _1, false);

    auto nodesAllPledgeToCommit = [&]() {
        ICPBallot b(1, xValue);
        ICPEnvelope prepare1 = makePrepare(v1SecretKey, qSetHash, 0, b);
        ICPEnvelope prepare2 = makePrepare(v2SecretKey, qSetHash, 0, b);
        ICPEnvelope prepare3 = makePrepare(v3SecretKey, qSetHash, 0, b);
        ICPEnvelope prepare4 = makePrepare(v4SecretKey, qSetHash, 0, b);

        REQUIRE(icp.bumpState(0, xValue));
        REQUIRE(icp.mEnvs.size() == 1);

        verifyPrepare(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, b);

        icp.receiveEnvelope(prepare1);
        REQUIRE(icp.mEnvs.size() == 1);
        REQUIRE(icp.mHeardFromQuorums[0].size() == 0);

        icp.receiveEnvelope(prepare2);
        REQUIRE(icp.mEnvs.size() == 1);
        REQUIRE(icp.mHeardFromQuorums[0].size() == 0);

        icp.receiveEnvelope(prepare3);
        REQUIRE(icp.mEnvs.size() == 2);
        REQUIRE(icp.mHeardFromQuorums[0].size() == 1);
        REQUIRE(icp.mHeardFromQuorums[0][0] == b);

        // We have a quorum including us

        verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, b, &b);

        icp.receiveEnvelope(prepare4);
        REQUIRE(icp.mEnvs.size() == 2);

        ICPEnvelope prepared1 = makePrepare(v1SecretKey, qSetHash, 0, b, &b);
        ICPEnvelope prepared2 = makePrepare(v2SecretKey, qSetHash, 0, b, &b);
        ICPEnvelope prepared3 = makePrepare(v3SecretKey, qSetHash, 0, b, &b);
        ICPEnvelope prepared4 = makePrepare(v4SecretKey, qSetHash, 0, b, &b);

        icp.receiveEnvelope(prepared4);
        icp.receiveEnvelope(prepared3);
        REQUIRE(icp.mEnvs.size() == 2);

        icp.receiveEnvelope(prepared2);
        REQUIRE(icp.mEnvs.size() == 3);

        // confirms prepared
        verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, b, &b, b.counter,
                      b.counter);

        // extra statement doesn't do anything
        icp.receiveEnvelope(prepared1);
        REQUIRE(icp.mEnvs.size() == 3);
    };

    SECTION("bumpState x")
    {
        REQUIRE(icp.bumpState(0, xValue));
        REQUIRE(icp.mEnvs.size() == 1);

        ICPBallot expectedBallot(1, xValue);

        verifyPrepare(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, expectedBallot);
    }

    SECTION("start <1,x>")
    {
        // no timer is set
        REQUIRE(!icp.hasBallotTimer());

        Value const& aValue = xValue;
        Value const& bValue = zValue;
        Value const& midValue = yValue;
        Value const& bigValue = zzValue;

        ICPBallot A1(1, aValue);
        ICPBallot B1(1, bValue);
        ICPBallot Mid1(1, midValue);
        ICPBallot Big1(1, bigValue);

        ICPBallot A2 = A1;
        A2.counter++;

        ICPBallot A3 = A2;
        A3.counter++;

        ICPBallot A4 = A3;
        A4.counter++;

        ICPBallot A5 = A4;
        A5.counter++;

        ICPBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

        ICPBallot B2 = B1;
        B2.counter++;

        ICPBallot B3 = B2;
        B3.counter++;

        ICPBallot Mid2 = Mid1;
        Mid2.counter++;

        ICPBallot Big2 = Big1;
        Big2.counter++;

        REQUIRE(icp.bumpState(0, aValue));
        REQUIRE(icp.mEnvs.size() == 1);
        REQUIRE(!icp.hasBallotTimer());

        SECTION("prepared A1")
        {
            recvQuorumEx(makePrepareGen(qSetHash, A1), true);

            REQUIRE(icp.mEnvs.size() == 2);
            verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &A1);

            SECTION("bump prepared A2")
            {
                // bump to (2,a)

                icp.bumpTimerOffset();
                REQUIRE(icp.bumpState(0, aValue));
                REQUIRE(icp.mEnvs.size() == 3);
                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, A2, &A1);
                REQUIRE(!icp.hasBallotTimer());

                recvQuorumEx(makePrepareGen(qSetHash, A2), true);
                REQUIRE(icp.mEnvs.size() == 4);
                verifyPrepare(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, A2, &A2);

                SECTION("Confirm prepared A2")
                {
                    recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                    REQUIRE(icp.mEnvs.size() == 5);
                    verifyPrepare(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &A2, 2, 2);
                    REQUIRE(!icp.hasBallotTimerUpcoming());

                    SECTION("Accept commit")
                    {
                        SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            REQUIRE(icp.mEnvs.size() == 6);
                            verifyConfirm(icp.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                            REQUIRE(!icp.hasBallotTimerUpcoming());

                            SECTION("Quorum prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2));
                                REQUIRE(icp.mEnvs.size() == 7);
                                verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 2, A3, 2, 2);
                                REQUIRE(!icp.hasBallotTimer());

                                recvQuorumEx(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2),
                                    true);
                                REQUIRE(icp.mEnvs.size() == 8);
                                verifyConfirm(icp.mEnvs[7], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);

                                SECTION("Accept more commit A3")
                                {
                                    recvQuorum(makePrepareGen(qSetHash, A3, &A3,
                                                              2, 3));
                                    REQUIRE(icp.mEnvs.size() == 9);
                                    verifyConfirm(icp.mEnvs[8], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 3);
                                    REQUIRE(!icp.hasBallotTimerUpcoming());

                                    REQUIRE(icp.mExternalizedValues.size() ==
                                            0);

                                    SECTION("Quorum externalize A3")
                                    {
                                        recvQuorum(makeConfirmGen(qSetHash, 3,
                                                                  A3, 2, 3));
                                        REQUIRE(icp.mEnvs.size() == 10);
                                        verifyExternalize(icp.mEnvs[9],
                                                          v0SecretKey,
                                                          qSetHash0, 0, A2, 3);
                                        REQUIRE(!icp.hasBallotTimer());

                                        REQUIRE(
                                            icp.mExternalizedValues.size() ==
                                            1);
                                        REQUIRE(icp.mExternalizedValues[0] ==
                                                aValue);
                                    }
                                }
                                SECTION("v-blocking accept more A3")
                                {
                                    SECTION("Confirm A3")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, A3, 2, 3));
                                        REQUIRE(icp.mEnvs.size() == 9);
                                        verifyConfirm(icp.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, 3, A3, 2,
                                                      3);
                                        REQUIRE(!icp.hasBallotTimerUpcoming());
                                    }
                                    SECTION("Externalize A3")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, A2, 3));
                                        REQUIRE(icp.mEnvs.size() == 9);
                                        verifyConfirm(icp.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, UINT32_MAX,
                                                      AInf, 2, UINT32_MAX);
                                        REQUIRE(!icp.hasBallotTimer());
                                    }
                                    SECTION("other nodes moved to c=A4 h=A5")
                                    {
                                        SECTION("Confirm A4..5")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, A5, 4, 5));
                                            REQUIRE(icp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                icp.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, 3, A5, 4, 5);
                                            REQUIRE(!icp.hasBallotTimer());
                                        }
                                        SECTION("Externalize A4..5")
                                        {
                                            recvVBlocking(makeExternalizeGen(
                                                qSetHash, A4, 5));
                                            REQUIRE(icp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                icp.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, UINT32_MAX, AInf,
                                                4, UINT32_MAX);
                                            REQUIRE(!icp.hasBallotTimer());
                                        }
                                    }
                                }
                            }
                            SECTION("v-blocking prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A3, 2, 2));
                                REQUIRE(icp.mEnvs.size() == 7);
                                verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!icp.hasBallotTimer());
                            }
                            SECTION("v-blocking prepared A3+B3")
                            {
                                recvVBlocking(makePrepareGen(qSetHash, A3, &B3,
                                                             2, 2, &A3));
                                REQUIRE(icp.mEnvs.size() == 7);
                                verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!icp.hasBallotTimer());
                            }
                            SECTION("v-blocking confirm A3")
                            {
                                recvVBlocking(
                                    makeConfirmGen(qSetHash, 3, A3, 2, 2));
                                REQUIRE(icp.mEnvs.size() == 7);
                                verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!icp.hasBallotTimer());
                            }
                            SECTION("Hang - does not switch to B in CONFIRM")
                            {
                                SECTION("Network EXTERNALIZE")
                                {
                                    // externalize messages have a counter at
                                    // infinite
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 3));
                                    REQUIRE(icp.mEnvs.size() == 7);
                                    verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 2, AInf, 2, 2);
                                    REQUIRE(!icp.hasBallotTimer());

                                    // stuck
                                    recvQuorumChecks(
                                        makeExternalizeGen(qSetHash, B2, 3),
                                        false, false);
                                    REQUIRE(icp.mEnvs.size() == 7);
                                    REQUIRE(icp.mExternalizedValues.size() ==
                                            0);
                                    // timer scheduled as there is a quorum
                                    // with (2, *)
                                    REQUIRE(icp.hasBallotTimerUpcoming());
                                }
                                SECTION("Network CONFIRMS other ballot")
                                {
                                    SECTION("at same counter")
                                    {
                                        // nothing should happen here, in
                                        // particular, node should not attempt
                                        // to switch 'p'
                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B2, 2,
                                                           3),
                                            false, false);
                                        REQUIRE(icp.mEnvs.size() == 6);
                                        REQUIRE(
                                            icp.mExternalizedValues.size() ==
                                            0);
                                        REQUIRE(!icp.hasBallotTimerUpcoming());
                                    }
                                    SECTION("at a different counter")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, B3, 3, 3));
                                        REQUIRE(icp.mEnvs.size() == 7);
                                        verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                                      qSetHash0, 0, 2, A3, 2,
                                                      2);
                                        REQUIRE(!icp.hasBallotTimer());

                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B3, 3,
                                                           3),
                                            false, false);
                                        REQUIRE(icp.mEnvs.size() == 7);
                                        REQUIRE(
                                            icp.mExternalizedValues.size() ==
                                            0);
                                        // timer scheduled as there is a quorum
                                        // with (3, *)
                                        REQUIRE(icp.hasBallotTimerUpcoming());
                                    }
                                }
                            }
                        }
                        SECTION("v-blocking")
                        {
                            SECTION("CONFIRM")
                            {
                                SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                    REQUIRE(!icp.hasBallotTimerUpcoming());
                                }
                                SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                    REQUIRE(!icp.hasBallotTimer());
                                }
                                SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                    REQUIRE(!icp.hasBallotTimerUpcoming());
                                }
                            }
                            SECTION("EXTERNALIZE")
                            {
                                SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  AInf, 2, UINT32_MAX);
                                    REQUIRE(!icp.hasBallotTimer());
                                }
                                SECTION("EXTERNALIZE B2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  BInf, 2, UINT32_MAX);
                                    REQUIRE(!icp.hasBallotTimer());
                                }
                            }
                        }
                    }
                    SECTION("get conflicting prepared B")
                    {
                        SECTION("same counter")
                        {
                            recvVBlocking(makePrepareGen(qSetHash, B2, &B2));
                            REQUIRE(icp.mEnvs.size() == 6);
                            verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A2, &B2, 0, 2, &A2);
                            REQUIRE(!icp.hasBallotTimerUpcoming());

                            recvQuorum(makePrepareGen(qSetHash, B2, &B2, 2, 2));
                            REQUIRE(icp.mEnvs.size() == 7);
                            verifyConfirm(icp.mEnvs[6], v0SecretKey, qSetHash0,
                                          0, 2, B2, 2, 2);
                            REQUIRE(!icp.hasBallotTimerUpcoming());
                        }
                        SECTION("higher counter")
                        {
                            recvVBlocking(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2));
                            REQUIRE(icp.mEnvs.size() == 6);
                            verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A3, &B2, 0, 2, &A2);
                            REQUIRE(!icp.hasBallotTimer());

                            recvQuorumChecksEx(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2), true,
                                true, true);
                            REQUIRE(icp.mEnvs.size() == 7);
                            verifyConfirm(icp.mEnvs[6], v0SecretKey, qSetHash0,
                                          0, 3, B3, 2, 2);
                        }
                    }
                }
                SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared B2
                    recvVBlocking(makePrepareGen(qSetHash, B2, &B2, 0, 0, &A2));
                    REQUIRE(icp.mEnvs.size() == 5);
                    verifyPrepare(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &B2, 0, 0, &A2);
                    REQUIRE(!icp.hasBallotTimerUpcoming());

                    SECTION("mixed A2")
                    {
                        // causes h=A2
                        // but c = 0, as p >!~ h
                        icp.bumpTimerOffset();
                        icp.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(icp.mEnvs.size() == 6);
                        verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      A2, &B2, 0, 2, &A2);
                        REQUIRE(!icp.hasBallotTimerUpcoming());

                        icp.bumpTimerOffset();
                        icp.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(icp.mEnvs.size() == 6);
                        REQUIRE(!icp.hasBallotTimerUpcoming());
                    }
                    SECTION("mixed B2")
                    {
                        // causes h=B2, c=B2
                        icp.bumpTimerOffset();
                        icp.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(icp.mEnvs.size() == 6);
                        verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);
                        REQUIRE(!icp.hasBallotTimerUpcoming());

                        icp.bumpTimerOffset();
                        icp.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(icp.mEnvs.size() == 6);
                        REQUIRE(!icp.hasBallotTimerUpcoming());
                    }
                }
            }
            SECTION("switch prepared B1 from A1")
            {
                // (p,p') = (B1, A1) [ from (A1, null) ]
                recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
                REQUIRE(icp.mEnvs.size() == 3);
                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, A1, &B1,
                              0, 0, &A1);
                REQUIRE(!icp.hasBallotTimerUpcoming());

                // v-blocking with n=2 -> bump n
                recvVBlocking(makePrepareGen(qSetHash, B2));
                REQUIRE(icp.mEnvs.size() == 4);
                verifyPrepare(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, A2, &B1,
                              0, 0, &A1);

                // move to (p,p') = (B2, A1) [update p from B1 -> B2]
                recvVBlocking(makePrepareGen(qSetHash, B2, &B2));
                REQUIRE(icp.mEnvs.size() == 5);
                verifyPrepare(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, A2, &B2,
                              0, 0, &A1);
                REQUIRE(
                    !icp.hasBallotTimer()); // no quorum (other nodes on (A,1))

                SECTION("v-blocking switches to previous value of p")
                {
                    // v-blocking with n=3 -> bump n
                    recvVBlocking(makePrepareGen(qSetHash, B3));
                    REQUIRE(icp.mEnvs.size() == 6);
                    verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0, 0, A3,
                                  &B2, 0, 0, &A1);
                    REQUIRE(!icp.hasBallotTimer()); // no quorum (other nodes on
                                                    // (A,1))

                    // vBlocking set says "B1" is prepared - but we already have
                    // p=B2
                    recvVBlockingChecks(makePrepareGen(qSetHash, B3, &B1),
                                        false);
                    REQUIRE(icp.mEnvs.size() == 6);
                    REQUIRE(!icp.hasBallotTimer());
                }
                SECTION("switch p' to Mid2")
                {
                    // (p,p') = (B2, Mid2)
                    recvVBlocking(
                        makePrepareGen(qSetHash, B2, &B2, 0, 0, &Mid2));
                    REQUIRE(icp.mEnvs.size() == 6);
                    verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0, 0, A2,
                                  &B2, 0, 0, &Mid2);
                    REQUIRE(!icp.hasBallotTimer());
                }
                SECTION("switch again Big2")
                {
                    // both p and p' get updated
                    // (p,p') = (Big2, B2)
                    recvVBlocking(
                        makePrepareGen(qSetHash, B2, &Big2, 0, 0, &B2));
                    REQUIRE(icp.mEnvs.size() == 6);
                    verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0, 0, A2,
                                  &Big2, 0, 0, &B2);
                    REQUIRE(!icp.hasBallotTimer());
                }
            }
            SECTION("switch prepare B1")
            {
                recvQuorumChecks(makePrepareGen(qSetHash, B1), true, true);
                REQUIRE(icp.mEnvs.size() == 3);
                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, A1, &B1,
                              0, 0, &A1);
                REQUIRE(!icp.hasBallotTimerUpcoming());
            }
            SECTION("prepare higher counter (v-blocking)")
            {
                recvVBlocking(makePrepareGen(qSetHash, B2));
                REQUIRE(icp.mEnvs.size() == 3);
                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, A2, &A1);
                REQUIRE(!icp.hasBallotTimer());

                // more timeout from vBlocking set
                recvVBlocking(makePrepareGen(qSetHash, B3));
                REQUIRE(icp.mEnvs.size() == 4);
                verifyPrepare(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, A3, &A1);
                REQUIRE(!icp.hasBallotTimer());
            }
        }
        SECTION("prepared B (v-blocking)")
        {
            recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
            REQUIRE(icp.mEnvs.size() == 2);
            verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
            REQUIRE(!icp.hasBallotTimer());
        }
        SECTION("prepare B (quorum)")
        {
            recvQuorumChecksEx(makePrepareGen(qSetHash, B1), true, true, true);
            REQUIRE(icp.mEnvs.size() == 2);
            verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
        }
        SECTION("confirm (v-blocking)")
        {
            SECTION("via CONFIRM")
            {
                icp.bumpTimerOffset();
                icp.receiveEnvelope(
                    makeConfirm(v1SecretKey, qSetHash, 0, 3, A3, 3, 3));
                icp.receiveEnvelope(
                    makeConfirm(v2SecretKey, qSetHash, 0, 4, A4, 2, 4));
                REQUIRE(icp.mEnvs.size() == 2);
                verifyConfirm(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, 3, A3, 3,
                              3);
                REQUIRE(!icp.hasBallotTimer());
            }
            SECTION("via EXTERNALIZE")
            {
                icp.receiveEnvelope(
                    makeExternalize(v1SecretKey, qSetHash, 0, A2, 4));
                icp.receiveEnvelope(
                    makeExternalize(v2SecretKey, qSetHash, 0, A3, 5));
                REQUIRE(icp.mEnvs.size() == 2);
                verifyConfirm(icp.mEnvs[1], v0SecretKey, qSetHash0, 0,
                              UINT32_MAX, AInf, 3, UINT32_MAX);
                REQUIRE(!icp.hasBallotTimer());
            }
        }
    }

    // this is the same test suite than "start <1,x>" with the exception that
    // some transitions are not possible as x < z - so instead we verify that
    // nothing happens
    SECTION("start <1,z>")
    {
        // no timer is set
        REQUIRE(!icp.hasBallotTimer());

        Value const& aValue = zValue;
        Value const& bValue = xValue;

        ICPBallot A1(1, aValue);
        ICPBallot B1(1, bValue);

        ICPBallot A2 = A1;
        A2.counter++;

        ICPBallot A3 = A2;
        A3.counter++;

        ICPBallot A4 = A3;
        A4.counter++;

        ICPBallot A5 = A4;
        A5.counter++;

        ICPBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

        ICPBallot B2 = B1;
        B2.counter++;

        ICPBallot B3 = B2;
        B3.counter++;

        REQUIRE(icp.bumpState(0, aValue));
        REQUIRE(icp.mEnvs.size() == 1);
        REQUIRE(!icp.hasBallotTimer());

        SECTION("prepared A1")
        {
            recvQuorumEx(makePrepareGen(qSetHash, A1), true);

            REQUIRE(icp.mEnvs.size() == 2);
            verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &A1);

            SECTION("bump prepared A2")
            {
                // bump to (2,a)

                icp.bumpTimerOffset();
                REQUIRE(icp.bumpState(0, aValue));
                REQUIRE(icp.mEnvs.size() == 3);
                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, A2, &A1);
                REQUIRE(!icp.hasBallotTimer());

                recvQuorumEx(makePrepareGen(qSetHash, A2), true);
                REQUIRE(icp.mEnvs.size() == 4);
                verifyPrepare(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, A2, &A2);

                SECTION("Confirm prepared A2")
                {
                    recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                    REQUIRE(icp.mEnvs.size() == 5);
                    verifyPrepare(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &A2, 2, 2);
                    REQUIRE(!icp.hasBallotTimerUpcoming());

                    SECTION("Accept commit")
                    {
                        SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            REQUIRE(icp.mEnvs.size() == 6);
                            verifyConfirm(icp.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                            REQUIRE(!icp.hasBallotTimerUpcoming());

                            SECTION("Quorum prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2));
                                REQUIRE(icp.mEnvs.size() == 7);
                                verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 2, A3, 2, 2);
                                REQUIRE(!icp.hasBallotTimer());

                                recvQuorumEx(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2),
                                    true);
                                REQUIRE(icp.mEnvs.size() == 8);
                                verifyConfirm(icp.mEnvs[7], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);

                                SECTION("Accept more commit A3")
                                {
                                    recvQuorum(makePrepareGen(qSetHash, A3, &A3,
                                                              2, 3));
                                    REQUIRE(icp.mEnvs.size() == 9);
                                    verifyConfirm(icp.mEnvs[8], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 3);
                                    REQUIRE(!icp.hasBallotTimerUpcoming());

                                    REQUIRE(icp.mExternalizedValues.size() ==
                                            0);

                                    SECTION("Quorum externalize A3")
                                    {
                                        recvQuorum(makeConfirmGen(qSetHash, 3,
                                                                  A3, 2, 3));
                                        REQUIRE(icp.mEnvs.size() == 10);
                                        verifyExternalize(icp.mEnvs[9],
                                                          v0SecretKey,
                                                          qSetHash0, 0, A2, 3);
                                        REQUIRE(!icp.hasBallotTimer());

                                        REQUIRE(
                                            icp.mExternalizedValues.size() ==
                                            1);
                                        REQUIRE(icp.mExternalizedValues[0] ==
                                                aValue);
                                    }
                                }
                                SECTION("v-blocking accept more A3")
                                {
                                    SECTION("Confirm A3")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, A3, 2, 3));
                                        REQUIRE(icp.mEnvs.size() == 9);
                                        verifyConfirm(icp.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, 3, A3, 2,
                                                      3);
                                        REQUIRE(!icp.hasBallotTimerUpcoming());
                                    }
                                    SECTION("Externalize A3")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, A2, 3));
                                        REQUIRE(icp.mEnvs.size() == 9);
                                        verifyConfirm(icp.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, UINT32_MAX,
                                                      AInf, 2, UINT32_MAX);
                                        REQUIRE(!icp.hasBallotTimer());
                                    }
                                    SECTION("other nodes moved to c=A4 h=A5")
                                    {
                                        SECTION("Confirm A4..5")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, A5, 4, 5));
                                            REQUIRE(icp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                icp.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, 3, A5, 4, 5);
                                            REQUIRE(!icp.hasBallotTimer());
                                        }
                                        SECTION("Externalize A4..5")
                                        {
                                            recvVBlocking(makeExternalizeGen(
                                                qSetHash, A4, 5));
                                            REQUIRE(icp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                icp.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, UINT32_MAX, AInf,
                                                4, UINT32_MAX);
                                            REQUIRE(!icp.hasBallotTimer());
                                        }
                                    }
                                }
                            }
                            SECTION("v-blocking prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A3, 2, 2));
                                REQUIRE(icp.mEnvs.size() == 7);
                                verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!icp.hasBallotTimer());
                            }
                            SECTION("v-blocking prepared A3+B3")
                            {
                                recvVBlocking(makePrepareGen(qSetHash, A3, &A3,
                                                             2, 2, &B3));
                                REQUIRE(icp.mEnvs.size() == 7);
                                verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!icp.hasBallotTimer());
                            }
                            SECTION("v-blocking confirm A3")
                            {
                                recvVBlocking(
                                    makeConfirmGen(qSetHash, 3, A3, 2, 2));
                                REQUIRE(icp.mEnvs.size() == 7);
                                verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!icp.hasBallotTimer());
                            }
                            SECTION("Hang - does not switch to B in CONFIRM")
                            {
                                SECTION("Network EXTERNALIZE")
                                {
                                    // externalize messages have a counter at
                                    // infinite
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 3));
                                    REQUIRE(icp.mEnvs.size() == 7);
                                    verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 2, AInf, 2, 2);
                                    REQUIRE(!icp.hasBallotTimer());

                                    // stuck
                                    recvQuorumChecks(
                                        makeExternalizeGen(qSetHash, B2, 3),
                                        false, false);
                                    REQUIRE(icp.mEnvs.size() == 7);
                                    REQUIRE(icp.mExternalizedValues.size() ==
                                            0);
                                    // timer scheduled as there is a quorum
                                    // with (inf, *)
                                    REQUIRE(icp.hasBallotTimerUpcoming());
                                }
                                SECTION("Network CONFIRMS other ballot")
                                {
                                    SECTION("at same counter")
                                    {
                                        // nothing should happen here, in
                                        // particular, node should not attempt
                                        // to switch 'p'
                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B2, 2,
                                                           3),
                                            false, false);
                                        REQUIRE(icp.mEnvs.size() == 6);
                                        REQUIRE(
                                            icp.mExternalizedValues.size() ==
                                            0);
                                        REQUIRE(!icp.hasBallotTimerUpcoming());
                                    }
                                    SECTION("at a different counter")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, B3, 3, 3));
                                        REQUIRE(icp.mEnvs.size() == 7);
                                        verifyConfirm(icp.mEnvs[6], v0SecretKey,
                                                      qSetHash0, 0, 2, A3, 2,
                                                      2);
                                        REQUIRE(!icp.hasBallotTimer());

                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B3, 3,
                                                           3),
                                            false, false);
                                        REQUIRE(icp.mEnvs.size() == 7);
                                        REQUIRE(
                                            icp.mExternalizedValues.size() ==
                                            0);
                                        // timer scheduled as there is a quorum
                                        // with (3, *)
                                        REQUIRE(icp.hasBallotTimerUpcoming());
                                    }
                                }
                            }
                        }
                        SECTION("v-blocking")
                        {
                            SECTION("CONFIRM")
                            {
                                SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                    REQUIRE(!icp.hasBallotTimerUpcoming());
                                }
                                SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                    REQUIRE(!icp.hasBallotTimer());
                                }
                                SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                    REQUIRE(!icp.hasBallotTimerUpcoming());
                                }
                            }
                            SECTION("EXTERNALIZE")
                            {
                                SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  AInf, 2, UINT32_MAX);
                                    REQUIRE(!icp.hasBallotTimer());
                                }
                                SECTION("EXTERNALIZE B2")
                                {
                                    // can switch to B2 with externalize (higher
                                    // counter)
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    REQUIRE(icp.mEnvs.size() == 6);
                                    verifyConfirm(icp.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  BInf, 2, UINT32_MAX);
                                    REQUIRE(!icp.hasBallotTimer());
                                }
                            }
                        }
                    }
                    SECTION("get conflicting prepared B")
                    {
                        SECTION("same counter")
                        {
                            // messages are ignored as B2 < A2
                            recvQuorumChecks(makePrepareGen(qSetHash, B2, &B2),
                                             false, false);
                            REQUIRE(icp.mEnvs.size() == 5);
                            REQUIRE(!icp.hasBallotTimerUpcoming());
                        }
                        SECTION("higher counter")
                        {
                            recvVBlocking(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2));
                            REQUIRE(icp.mEnvs.size() == 6);
                            // A2 > B2 -> p = A2, p'=B2
                            verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A3, &A2, 2, 2, &B2);
                            REQUIRE(!icp.hasBallotTimer());

                            // node is trying to commit A2=<2,y> but rest
                            // of its quorum is trying to commit B2
                            // we end up with a delayed quorum
                            recvQuorumChecksEx(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2), true,
                                true, true);
                            REQUIRE(icp.mEnvs.size() == 7);
                            verifyConfirm(icp.mEnvs[6], v0SecretKey, qSetHash0,
                                          0, 3, B3, 2, 2);
                        }
                    }
                }
                SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared B2
                    recvVBlocking(makePrepareGen(qSetHash, A2, &A2, 0, 0, &B2));
                    REQUIRE(icp.mEnvs.size() == 5);
                    verifyPrepare(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &A2, 0, 0, &B2);
                    REQUIRE(!icp.hasBallotTimerUpcoming());

                    SECTION("mixed A2")
                    {
                        // causes h=A2, c=A2
                        icp.bumpTimerOffset();
                        icp.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(icp.mEnvs.size() == 6);
                        verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      A2, &A2, 2, 2, &B2);
                        REQUIRE(!icp.hasBallotTimerUpcoming());

                        icp.bumpTimerOffset();
                        icp.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(icp.mEnvs.size() == 6);
                        REQUIRE(!icp.hasBallotTimerUpcoming());
                    }
                    SECTION("mixed B2")
                    {
                        // causes computed_h=B2 ~ not set as h ~!= b
                        // -> noop
                        icp.bumpTimerOffset();
                        icp.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, A2, &B2));

                        REQUIRE(icp.mEnvs.size() == 5);
                        REQUIRE(!icp.hasBallotTimerUpcoming());

                        icp.bumpTimerOffset();
                        icp.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(icp.mEnvs.size() == 5);
                        REQUIRE(!icp.hasBallotTimerUpcoming());
                    }
                }
            }
            SECTION("switch prepared B1 from A1")
            {
                // can't switch to B1
                recvQuorumChecks(makePrepareGen(qSetHash, B1, &B1), false,
                                 false);
                REQUIRE(icp.mEnvs.size() == 2);
                REQUIRE(!icp.hasBallotTimerUpcoming());
            }
            SECTION("switch prepare B1")
            {
                // doesn't switch as B1 < A1
                recvQuorumChecks(makePrepareGen(qSetHash, B1), false, false);
                REQUIRE(icp.mEnvs.size() == 2);
                REQUIRE(!icp.hasBallotTimerUpcoming());
            }
            SECTION("prepare higher counter (v-blocking)")
            {
                recvVBlocking(makePrepareGen(qSetHash, B2));
                REQUIRE(icp.mEnvs.size() == 3);
                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, A2, &A1);
                REQUIRE(!icp.hasBallotTimer());

                // more timeout from vBlocking set
                recvVBlocking(makePrepareGen(qSetHash, B3));
                REQUIRE(icp.mEnvs.size() == 4);
                verifyPrepare(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, A3, &A1);
                REQUIRE(!icp.hasBallotTimer());
            }
        }
        SECTION("prepared B (v-blocking)")
        {
            recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
            REQUIRE(icp.mEnvs.size() == 2);
            verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
            REQUIRE(!icp.hasBallotTimer());
        }
        SECTION("prepare B (quorum)")
        {
            recvQuorumChecksEx(makePrepareGen(qSetHash, B1), true, true, true);
            REQUIRE(icp.mEnvs.size() == 2);
            verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
        }
        SECTION("confirm (v-blocking)")
        {
            SECTION("via CONFIRM")
            {
                icp.bumpTimerOffset();
                icp.receiveEnvelope(
                    makeConfirm(v1SecretKey, qSetHash, 0, 3, A3, 3, 3));
                icp.receiveEnvelope(
                    makeConfirm(v2SecretKey, qSetHash, 0, 4, A4, 2, 4));
                REQUIRE(icp.mEnvs.size() == 2);
                verifyConfirm(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, 3, A3, 3,
                              3);
                REQUIRE(!icp.hasBallotTimer());
            }
            SECTION("via EXTERNALIZE")
            {
                icp.receiveEnvelope(
                    makeExternalize(v1SecretKey, qSetHash, 0, A2, 4));
                icp.receiveEnvelope(
                    makeExternalize(v2SecretKey, qSetHash, 0, A3, 5));
                REQUIRE(icp.mEnvs.size() == 2);
                verifyConfirm(icp.mEnvs[1], v0SecretKey, qSetHash0, 0,
                              UINT32_MAX, AInf, 3, UINT32_MAX);
                REQUIRE(!icp.hasBallotTimer());
            }
        }
    }

    // this is the same test suite than "start <1,x>" but only keeping
    // the transitions that are observable when starting from empty
    SECTION("start from pristine")
    {
        Value const& aValue = xValue;
        Value const& bValue = zValue;

        ICPBallot A1(1, aValue);
        ICPBallot B1(1, bValue);

        ICPBallot A2 = A1;
        A2.counter++;

        ICPBallot A3 = A2;
        A3.counter++;

        ICPBallot A4 = A3;
        A4.counter++;

        ICPBallot A5 = A4;
        A5.counter++;

        ICPBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

        ICPBallot B2 = B1;
        B2.counter++;

        ICPBallot B3 = B2;
        B3.counter++;

        REQUIRE(icp.mEnvs.size() == 0);

        SECTION("prepared A1")
        {
            recvQuorumChecks(makePrepareGen(qSetHash, A1), false, false);
            REQUIRE(icp.mEnvs.size() == 0);

            SECTION("bump prepared A2")
            {
                SECTION("Confirm prepared A2")
                {
                    recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                        false);
                    REQUIRE(icp.mEnvs.size() == 0);

                    SECTION("Quorum A2")
                    {
                        recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                            false);
                        REQUIRE(icp.mEnvs.size() == 0);
                        recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                        REQUIRE(icp.mEnvs.size() == 1);
                        verifyPrepare(icp.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                      A2, &A2, 1, 2);
                    }
                    SECTION("Quorum B2")
                    {
                        recvVBlockingChecks(makePrepareGen(qSetHash, B2, &B2),
                                            false);
                        REQUIRE(icp.mEnvs.size() == 0);
                        recvQuorum(makePrepareGen(qSetHash, B2, &B2));
                        REQUIRE(icp.mEnvs.size() == 1);
                        verifyPrepare(icp.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);
                    }
                    SECTION("Accept commit")
                    {
                        SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            REQUIRE(icp.mEnvs.size() == 1);
                            verifyConfirm(icp.mEnvs[0], v0SecretKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                        }
                        SECTION("Quorum B2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, B2, &B2, 2, 2));
                            REQUIRE(icp.mEnvs.size() == 1);
                            verifyConfirm(icp.mEnvs[0], v0SecretKey, qSetHash0,
                                          0, 2, B2, 2, 2);
                        }
                        SECTION("v-blocking")
                        {
                            SECTION("CONFIRM")
                            {
                                SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    REQUIRE(icp.mEnvs.size() == 1);
                                    verifyConfirm(icp.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                }
                                SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    REQUIRE(icp.mEnvs.size() == 1);
                                    verifyConfirm(icp.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                }
                                SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    REQUIRE(icp.mEnvs.size() == 1);
                                    verifyConfirm(icp.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                }
                            }
                            SECTION("EXTERNALIZE")
                            {
                                SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    REQUIRE(icp.mEnvs.size() == 1);
                                    verifyConfirm(icp.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  AInf, 2, UINT32_MAX);
                                }
                                SECTION("EXTERNALIZE B2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    REQUIRE(icp.mEnvs.size() == 1);
                                    verifyConfirm(icp.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  BInf, 2, UINT32_MAX);
                                }
                            }
                        }
                    }
                }
                SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared A2
                    // causes p=A2
                    recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                        false);
                    REQUIRE(icp.mEnvs.size() == 0);

                    // a few nodes prepared B2
                    // causes p=B2, p'=A2
                    recvVBlockingChecks(
                        makePrepareGen(qSetHash, A2, &B2, 0, 0, &A2), false);
                    REQUIRE(icp.mEnvs.size() == 0);

                    SECTION("mixed A2")
                    {
                        // causes h=A2
                        // but c = 0, as p >!~ h
                        icp.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(icp.mEnvs.size() == 1);
                        verifyPrepare(icp.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                      A2, &B2, 0, 2, &A2);

                        icp.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(icp.mEnvs.size() == 1);
                    }
                    SECTION("mixed B2")
                    {
                        // causes h=B2, c=B2
                        icp.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(icp.mEnvs.size() == 1);
                        verifyPrepare(icp.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);

                        icp.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(icp.mEnvs.size() == 1);
                    }
                }
            }
            SECTION("switch prepared B1")
            {
                recvVBlockingChecks(makePrepareGen(qSetHash, B1, &B1), false);
                REQUIRE(icp.mEnvs.size() == 0);
            }
        }
        SECTION("prepared B (v-blocking)")
        {
            recvVBlockingChecks(makePrepareGen(qSetHash, B1, &B1), false);
            REQUIRE(icp.mEnvs.size() == 0);
        }
        SECTION("confirm (v-blocking)")
        {
            SECTION("via CONFIRM")
            {
                icp.receiveEnvelope(
                    makeConfirm(v1SecretKey, qSetHash, 0, 3, A3, 3, 3));
                icp.receiveEnvelope(
                    makeConfirm(v2SecretKey, qSetHash, 0, 4, A4, 2, 4));
                REQUIRE(icp.mEnvs.size() == 1);
                verifyConfirm(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, 3, A3, 3,
                              3);
            }
            SECTION("via EXTERNALIZE")
            {
                icp.receiveEnvelope(
                    makeExternalize(v1SecretKey, qSetHash, 0, A2, 4));
                icp.receiveEnvelope(
                    makeExternalize(v2SecretKey, qSetHash, 0, A3, 5));
                REQUIRE(icp.mEnvs.size() == 1);
                verifyConfirm(icp.mEnvs[0], v0SecretKey, qSetHash0, 0,
                              UINT32_MAX, AInf, 3, UINT32_MAX);
            }
        }
    }

    SECTION("normal round (1,x)")
    {
        nodesAllPledgeToCommit();
        REQUIRE(icp.mEnvs.size() == 3);

        ICPBallot b(1, xValue);

        // bunch of prepare messages with "commit b"
        ICPEnvelope preparedC1 =
            makePrepare(v1SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        ICPEnvelope preparedC2 =
            makePrepare(v2SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        ICPEnvelope preparedC3 =
            makePrepare(v3SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        ICPEnvelope preparedC4 =
            makePrepare(v4SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);

        // those should not trigger anything just yet
        icp.receiveEnvelope(preparedC1);
        icp.receiveEnvelope(preparedC2);
        REQUIRE(icp.mEnvs.size() == 3);

        // this should cause the node to accept 'commit b' (quorum)
        // and therefore send a "CONFIRM" message
        icp.receiveEnvelope(preparedC3);
        REQUIRE(icp.mEnvs.size() == 4);

        verifyConfirm(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, 1, b, b.counter,
                      b.counter);

        // bunch of confirm messages
        ICPEnvelope confirm1 = makeConfirm(v1SecretKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        ICPEnvelope confirm2 = makeConfirm(v2SecretKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        ICPEnvelope confirm3 = makeConfirm(v3SecretKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        ICPEnvelope confirm4 = makeConfirm(v4SecretKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);

        // those should not trigger anything just yet
        icp.receiveEnvelope(confirm1);
        icp.receiveEnvelope(confirm2);
        REQUIRE(icp.mEnvs.size() == 4);

        icp.receiveEnvelope(confirm3);
        // this causes our node to
        // externalize (confirm commit c)
        REQUIRE(icp.mEnvs.size() == 5);

        // The slot should have externalized the value
        REQUIRE(icp.mExternalizedValues.size() == 1);
        REQUIRE(icp.mExternalizedValues[0] == xValue);

        verifyExternalize(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, b,
                          b.counter);

        // extra vote should not do anything
        icp.receiveEnvelope(confirm4);
        REQUIRE(icp.mEnvs.size() == 5);
        REQUIRE(icp.mExternalizedValues.size() == 1);

        // duplicate should just no-op
        icp.receiveEnvelope(confirm2);
        REQUIRE(icp.mEnvs.size() == 5);
        REQUIRE(icp.mExternalizedValues.size() == 1);

        SECTION("bumpToBallot prevented once committed")
        {
            ICPBallot b2;
            SECTION("bumpToBallot prevented once committed (by value)")
            {
                b2 = ICPBallot(1, zValue);
            }
            SECTION("bumpToBallot prevented once committed (by counter)")
            {
                b2 = ICPBallot(2, xValue);
            }
            SECTION(
                "bumpToBallot prevented once committed (by value and counter)")
            {
                b2 = ICPBallot(2, zValue);
            }

            ICPEnvelope confirm1b2, confirm2b2, confirm3b2, confirm4b2;
            confirm1b2 = makeConfirm(v1SecretKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm2b2 = makeConfirm(v2SecretKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm3b2 = makeConfirm(v3SecretKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm4b2 = makeConfirm(v4SecretKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);

            icp.receiveEnvelope(confirm1b2);
            icp.receiveEnvelope(confirm2b2);
            icp.receiveEnvelope(confirm3b2);
            icp.receiveEnvelope(confirm4b2);
            REQUIRE(icp.mEnvs.size() == 5);
            REQUIRE(icp.mExternalizedValues.size() == 1);
        }
    }

    SECTION("range check")
    {
        nodesAllPledgeToCommit();
        REQUIRE(icp.mEnvs.size() == 3);

        ICPBallot b(1, xValue);

        // bunch of prepare messages with "commit b"
        ICPEnvelope preparedC1 =
            makePrepare(v1SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        ICPEnvelope preparedC2 =
            makePrepare(v2SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        ICPEnvelope preparedC3 =
            makePrepare(v3SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        ICPEnvelope preparedC4 =
            makePrepare(v4SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);

        // those should not trigger anything just yet
        icp.receiveEnvelope(preparedC1);
        icp.receiveEnvelope(preparedC2);
        REQUIRE(icp.mEnvs.size() == 3);

        // this should cause the node to accept 'commit b' (quorum)
        // and therefore send a "CONFIRM" message
        icp.receiveEnvelope(preparedC3);
        REQUIRE(icp.mEnvs.size() == 4);

        verifyConfirm(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, 1, b, b.counter,
                      b.counter);

        // bunch of confirm messages with different ranges
        ICPBallot b5(5, xValue);
        ICPEnvelope confirm1 = makeConfirm(v1SecretKey, qSetHash, 0, 4,
                                           ICPBallot(4, xValue), 2, 4);
        ICPEnvelope confirm2 = makeConfirm(v2SecretKey, qSetHash, 0, 6,
                                           ICPBallot(6, xValue), 2, 6);
        ICPEnvelope confirm3 = makeConfirm(v3SecretKey, qSetHash, 0, 5,
                                           ICPBallot(5, xValue), 3, 5);
        ICPEnvelope confirm4 = makeConfirm(v4SecretKey, qSetHash, 0, 6,
                                           ICPBallot(6, xValue), 3, 6);

        // this should not trigger anything just yet
        icp.receiveEnvelope(confirm1);

        // v-blocking
        //   * b gets bumped to (4,x)
        //   * p gets bumped to (4,x)
        //   * (c,h) gets bumped to (2,4)
        icp.receiveEnvelope(confirm2);
        REQUIRE(icp.mEnvs.size() == 5);
        verifyConfirm(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, 4,
                      ICPBallot(4, xValue), 2, 4);

        // this causes to externalize
        // range is [3,4]
        icp.receiveEnvelope(confirm4);
        REQUIRE(icp.mEnvs.size() == 6);

        // The slot should have externalized the value
        REQUIRE(icp.mExternalizedValues.size() == 1);
        REQUIRE(icp.mExternalizedValues[0] == xValue);

        verifyExternalize(icp.mEnvs[5], v0SecretKey, qSetHash0, 0,
                          ICPBallot(3, xValue), 4);
    }

    SECTION("timeout when h is set -> stay locked on h")
    {
        ICPBallot bx(1, xValue);
        REQUIRE(icp.bumpState(0, xValue));
        REQUIRE(icp.mEnvs.size() == 1);

        // v-blocking -> prepared
        // quorum -> confirm prepared
        recvQuorum(makePrepareGen(qSetHash, bx, &bx));
        REQUIRE(icp.mEnvs.size() == 3);
        verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, bx, &bx,
                      bx.counter, bx.counter);

        // now, see if we can timeout and move to a different value
        REQUIRE(icp.bumpState(0, yValue));
        REQUIRE(icp.mEnvs.size() == 4);
        ICPBallot newbx(2, xValue);
        verifyPrepare(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, newbx, &bx,
                      bx.counter, bx.counter);
    }
    SECTION("timeout when h exists but can't be set -> vote for h")
    {
        // start with (1,y)
        ICPBallot by(1, yValue);
        REQUIRE(icp.bumpState(0, yValue));
        REQUIRE(icp.mEnvs.size() == 1);

        ICPBallot bx(1, xValue);
        // but quorum goes with (1,x)
        // v-blocking -> prepared
        recvVBlocking(makePrepareGen(qSetHash, bx, &bx));
        REQUIRE(icp.mEnvs.size() == 2);
        verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, by, &bx);
        // quorum -> confirm prepared (no-op as b > h)
        recvQuorumChecks(makePrepareGen(qSetHash, bx, &bx), false, false);
        REQUIRE(icp.mEnvs.size() == 2);

        REQUIRE(icp.bumpState(0, yValue));
        REQUIRE(icp.mEnvs.size() == 3);
        ICPBallot newbx(2, xValue);
        // on timeout:
        // * we should move to the quorum's h value
        // * c can't be set yet as b > h
        verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, newbx, &bx, 0,
                      bx.counter);
    }

    SECTION("timeout from multiple nodes")
    {
        REQUIRE(icp.bumpState(0, xValue));

        ICPBallot x1(1, xValue);

        REQUIRE(icp.mEnvs.size() == 1);
        verifyPrepare(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, x1);

        recvQuorum(makePrepareGen(qSetHash, x1));
        // quorum -> prepared (1,x)
        REQUIRE(icp.mEnvs.size() == 2);
        verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, x1, &x1);

        ICPBallot x2(2, xValue);
        // timeout from local node
        REQUIRE(icp.bumpState(0, xValue));
        // prepares (2,x)
        REQUIRE(icp.mEnvs.size() == 3);
        verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, x2, &x1);

        recvQuorum(makePrepareGen(qSetHash, x1, &x1));
        // quorum -> set nH=1
        REQUIRE(icp.mEnvs.size() == 4);
        verifyPrepare(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, x2, &x1, 0, 1);
        REQUIRE(icp.mEnvs.size() == 4);

        recvVBlocking(makePrepareGen(qSetHash, x2, &x2, 1, 1));
        // v-blocking prepared (2,x) -> prepared (2,x)
        REQUIRE(icp.mEnvs.size() == 5);
        verifyPrepare(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, x2, &x2, 0, 1);

        recvQuorum(makePrepareGen(qSetHash, x2, &x2, 1, 1));
        // quorum (including us) confirms (2,x) prepared -> set h=c=x2
        // we also get extra message: a quorum not including us confirms (1,x)
        // prepared
        //  -> we confirm c=h=x1
        REQUIRE(icp.mEnvs.size() == 7);
        verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0, 0, x2, &x2, 2, 2);
        verifyConfirm(icp.mEnvs[6], v0SecretKey, qSetHash0, 0, 2, x2, 1, 1);
    }

    SECTION("timeout after prepare, receive old messages to prepare")
    {
        REQUIRE(icp.bumpState(0, xValue));

        ICPBallot x1(1, xValue);

        REQUIRE(icp.mEnvs.size() == 1);
        verifyPrepare(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, x1);

        icp.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, x1));
        icp.receiveEnvelope(makePrepare(v2SecretKey, qSetHash, 0, x1));
        icp.receiveEnvelope(makePrepare(v3SecretKey, qSetHash, 0, x1));

        // quorum -> prepared (1,x)
        REQUIRE(icp.mEnvs.size() == 2);
        verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, x1, &x1);

        ICPBallot x2(2, xValue);
        // timeout from local node
        REQUIRE(icp.bumpState(0, xValue));
        // prepares (2,x)
        REQUIRE(icp.mEnvs.size() == 3);
        verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, x2, &x1);

        ICPBallot x3(3, xValue);
        // timeout again
        REQUIRE(icp.bumpState(0, xValue));
        // prepares (3,x)
        REQUIRE(icp.mEnvs.size() == 4);
        verifyPrepare(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, x3, &x1);

        // other nodes moved on with x2
        icp.receiveEnvelope(
            makePrepare(v1SecretKey, qSetHash, 0, x2, &x2, 1, 2));
        icp.receiveEnvelope(
            makePrepare(v2SecretKey, qSetHash, 0, x2, &x2, 1, 2));
        // v-blocking -> prepared x2
        REQUIRE(icp.mEnvs.size() == 5);
        verifyPrepare(icp.mEnvs[4], v0SecretKey, qSetHash0, 0, x3, &x2);

        icp.receiveEnvelope(
            makePrepare(v3SecretKey, qSetHash, 0, x2, &x2, 1, 2));
        // quorum -> set nH=2
        REQUIRE(icp.mEnvs.size() == 6);
        verifyPrepare(icp.mEnvs[5], v0SecretKey, qSetHash0, 0, x3, &x2, 0, 2);
    }

    SECTION("non validator watching the network")
    {
        SIMULATION_CREATE_NODE(NV);
        TestICP icpNV(vNVSecretKey.getPublicKey(), qSet, false);
        icpNV.storeQuorumSet(std::make_shared<ICPQuorumSet>(qSet));
        uint256 qSetHashNV = icpNV.mICP.getLocalNode()->getQuorumSetHash();

        ICPBallot b(1, xValue);
        REQUIRE(icpNV.bumpState(0, xValue));
        REQUIRE(icpNV.mEnvs.size() == 0);
        verifyPrepare(icpNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey,
                      qSetHashNV, 0, b);
        auto ext1 = makeExternalize(v1SecretKey, qSetHash, 0, b, 1);
        auto ext2 = makeExternalize(v2SecretKey, qSetHash, 0, b, 1);
        auto ext3 = makeExternalize(v3SecretKey, qSetHash, 0, b, 1);
        auto ext4 = makeExternalize(v4SecretKey, qSetHash, 0, b, 1);
        icpNV.receiveEnvelope(ext1);
        icpNV.receiveEnvelope(ext2);
        icpNV.receiveEnvelope(ext3);
        REQUIRE(icpNV.mEnvs.size() == 0);
        verifyConfirm(icpNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey,
                      qSetHashNV, 0, UINT32_MAX, ICPBallot(UINT32_MAX, xValue),
                      1, UINT32_MAX);
        icpNV.receiveEnvelope(ext4);
        REQUIRE(icpNV.mEnvs.size() == 0);
        verifyExternalize(icpNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey,
                          qSetHashNV, 0, b, UINT32_MAX);
        REQUIRE(icpNV.mExternalizedValues[0] == xValue);
    }

    SECTION("restore ballot protocol")
    {
        TestICP icp2(v0SecretKey.getPublicKey(), qSet);
        icp2.storeQuorumSet(std::make_shared<ICPQuorumSet>(qSet));
        ICPBallot b(2, xValue);
        SECTION("prepare")
        {
            icp2.mICP.setStateFromEnvelope(
                0, makePrepare(v0SecretKey, qSetHash0, 0, b));
        }
        SECTION("confirm")
        {
            icp2.mICP.setStateFromEnvelope(
                0, makeConfirm(v0SecretKey, qSetHash0, 0, 2, b, 1, 2));
        }
        SECTION("externalize")
        {
            icp2.mICP.setStateFromEnvelope(
                0, makeExternalize(v0SecretKey, qSetHash0, 0, b, 2));
        }
    }
}

TEST_CASE("ballot protocol core3", "[icp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    // core3 has an edge case where v-blocking and quorum can be the same
    // v-blocking set size: 2
    // threshold: 2 = 1 + self or 2 others
    ICPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestICP icp(v0SecretKey.getPublicKey(), qSet);

    icp.storeQuorumSet(std::make_shared<ICPQuorumSet>(qSet));
    uint256 qSetHash0 = icp.mICP.getLocalNode()->getQuorumSetHash();

    REQUIRE(xValue < yValue);
    REQUIRE(yValue < zValue);

    auto recvQuorumChecksEx2 = [&](genEnvelope gen, bool withChecks,
                                   bool delayedQuorum, bool checkUpcoming,
                                   bool minQuorum) {
        ICPEnvelope e1 = gen(v1SecretKey);
        ICPEnvelope e2 = gen(v2SecretKey);

        icp.bumpTimerOffset();

        size_t i = icp.mEnvs.size() + 1;
        icp.receiveEnvelope(e1);
        if (withChecks && !delayedQuorum)
        {
            REQUIRE(icp.mEnvs.size() == i);
        }
        if (checkUpcoming)
        {
            REQUIRE(icp.hasBallotTimerUpcoming());
        }
        if (!minQuorum)
        {
            // nothing happens with an extra vote (unless we're in
            // delayedQuorum)
            icp.receiveEnvelope(e2);
            if (withChecks)
            {
                REQUIRE(icp.mEnvs.size() == i);
            }
        }
    };
    auto recvQuorumChecksEx =
        std::bind(recvQuorumChecksEx2, _1, _2, _3, _4, false);
    auto recvQuorumChecks = std::bind(recvQuorumChecksEx, _1, _2, _3, false);
    auto recvQuorumEx = std::bind(recvQuorumChecksEx, _1, true, false, _2);
    auto recvQuorum = std::bind(recvQuorumEx, _1, false);

    // no timer is set
    REQUIRE(!icp.hasBallotTimer());

    Value const& aValue = zValue;
    Value const& bValue = xValue;

    ICPBallot A1(1, aValue);
    ICPBallot B1(1, bValue);

    ICPBallot A2 = A1;
    A2.counter++;

    ICPBallot A3 = A2;
    A3.counter++;

    ICPBallot A4 = A3;
    A4.counter++;

    ICPBallot A5 = A4;
    A5.counter++;

    ICPBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

    ICPBallot B2 = B1;
    B2.counter++;

    ICPBallot B3 = B2;
    B3.counter++;

    REQUIRE(icp.bumpState(0, aValue));
    REQUIRE(icp.mEnvs.size() == 1);
    REQUIRE(!icp.hasBallotTimer());

    SECTION("prepared B1 (quorum votes B1)")
    {
        icp.bumpTimerOffset();
        recvQuorumChecks(makePrepareGen(qSetHash, B1), true, true);
        REQUIRE(icp.mEnvs.size() == 2);
        verifyPrepare(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
        REQUIRE(icp.hasBallotTimerUpcoming());
        SECTION("quorum prepared B1")
        {
            icp.bumpTimerOffset();
            recvQuorumChecks(makePrepareGen(qSetHash, B1, &B1), false, false);
            REQUIRE(icp.mEnvs.size() == 2);
            // nothing happens:
            // computed_h = B1 (2)
            //    does not actually update h as b > computed_h
            //    also skips (3)
            REQUIRE(!icp.hasBallotTimerUpcoming());
            SECTION("quorum bumps to A1")
            {
                icp.bumpTimerOffset();
                recvQuorumChecksEx2(makePrepareGen(qSetHash, A1, &B1), false,
                                    false, false, true);

                REQUIRE(icp.mEnvs.size() == 3);
                // still does not set h as b > computed_h
                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0, A1, &A1,
                              0, 0, &B1);
                REQUIRE(!icp.hasBallotTimerUpcoming());

                icp.bumpTimerOffset();
                // quorum commits A1
                recvQuorumChecksEx2(
                    makePrepareGen(qSetHash, A2, &A1, 1, 1, &B1), false, false,
                    false, true);
                REQUIRE(icp.mEnvs.size() == 4);
                verifyConfirm(icp.mEnvs[3], v0SecretKey, qSetHash0, 0, 2, A1, 1,
                              1);
                REQUIRE(!icp.hasBallotTimerUpcoming());
            }
        }
    }
}

TEST_CASE("nomination tests core5", "[icp][nominationprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);

    // we need 5 nodes to avoid sharing various thresholds:
    // v-blocking set size: 2
    // threshold: 4 = 3 + self or 4 others
    ICPQuorumSet qSet;
    qSet.threshold = 4;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);
    qSet.validators.push_back(v4NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    REQUIRE(xValue < yValue);
    REQUIRE(yValue < zValue);

    auto checkLeaders = [&](TestICP& icp, std::set<NodeID> expectedLeaders) {
        auto l = icp.getNominationLeaders(0);
        REQUIRE(std::equal(l.begin(), l.end(), expectedLeaders.begin(),
                           expectedLeaders.end()));
    };

    SECTION("nomination - v0 is top")
    {
        TestICP icp(v0SecretKey.getPublicKey(), qSet);
        uint256 qSetHash0 = icp.mICP.getLocalNode()->getQuorumSetHash();
        icp.storeQuorumSet(std::make_shared<ICPQuorumSet>(qSet));

        SECTION("v0 starts to nominates xValue")
        {
            REQUIRE(icp.nominate(0, xValue, false));

            checkLeaders(icp, {v0SecretKey.getPublicKey()});

            SECTION("others nominate what v0 says (x) -> prepare x")
            {
                std::vector<Value> votes, accepted;
                votes.emplace_back(xValue);

                REQUIRE(icp.mEnvs.size() == 1);
                verifyNominate(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, votes,
                               accepted);

                ICPEnvelope nom1 =
                    makeNominate(v1SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope nom2 =
                    makeNominate(v2SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope nom3 =
                    makeNominate(v3SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope nom4 =
                    makeNominate(v4SecretKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                icp.receiveEnvelope(nom1);
                icp.receiveEnvelope(nom2);
                REQUIRE(icp.mEnvs.size() == 1);

                // this causes 'x' to be accepted (quorum)
                icp.receiveEnvelope(nom3);
                REQUIRE(icp.mEnvs.size() == 2);

                icp.mExpectedCandidates.emplace(xValue);
                icp.mCompositeValue = xValue;

                accepted.emplace_back(xValue);
                verifyNominate(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, votes,
                               accepted);

                // extra message doesn't do anything
                icp.receiveEnvelope(nom4);
                REQUIRE(icp.mEnvs.size() == 2);

                ICPEnvelope acc1 =
                    makeNominate(v1SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope acc2 =
                    makeNominate(v2SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope acc3 =
                    makeNominate(v3SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope acc4 =
                    makeNominate(v4SecretKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                icp.receiveEnvelope(acc1);
                icp.receiveEnvelope(acc2);
                REQUIRE(icp.mEnvs.size() == 2);

                icp.mCompositeValue = xValue;
                // this causes the node to send a prepare message (quorum)
                icp.receiveEnvelope(acc3);
                REQUIRE(icp.mEnvs.size() == 3);

                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0,
                              ICPBallot(1, xValue));

                icp.receiveEnvelope(acc4);
                REQUIRE(icp.mEnvs.size() == 3);

                std::vector<Value> votes2 = votes;
                votes2.emplace_back(yValue);

                SECTION(
                    "nominate x -> accept x -> prepare (x) ; others accepted y "
                    "-> update latest to (z=x+y)")
                {
                    ICPEnvelope acc1_2 =
                        makeNominate(v1SecretKey, qSetHash, 0, votes2, votes2);
                    ICPEnvelope acc2_2 =
                        makeNominate(v2SecretKey, qSetHash, 0, votes2, votes2);
                    ICPEnvelope acc3_2 =
                        makeNominate(v3SecretKey, qSetHash, 0, votes2, votes2);
                    ICPEnvelope acc4_2 =
                        makeNominate(v4SecretKey, qSetHash, 0, votes2, votes2);

                    icp.receiveEnvelope(acc1_2);
                    REQUIRE(icp.mEnvs.size() == 3);

                    // v-blocking
                    icp.receiveEnvelope(acc2_2);
                    REQUIRE(icp.mEnvs.size() == 4);
                    verifyNominate(icp.mEnvs[3], v0SecretKey, qSetHash0, 0,
                                   votes2, votes2);

                    icp.mExpectedCandidates.insert(yValue);
                    icp.mCompositeValue = kValue;
                    // this updates the composite value to use next time
                    // but does not prepare it
                    icp.receiveEnvelope(acc3_2);
                    REQUIRE(icp.mEnvs.size() == 4);

                    REQUIRE(icp.getLatestCompositeCandidate(0) == kValue);

                    icp.receiveEnvelope(acc4_2);
                    REQUIRE(icp.mEnvs.size() == 4);
                }
                SECTION("nomination - restored state")
                {
                    TestICP icp2(v0SecretKey.getPublicKey(), qSet);
                    icp2.storeQuorumSet(std::make_shared<ICPQuorumSet>(qSet));

                    // at this point
                    // votes = { x }
                    // accepted = { x }

                    // tests if nomination proceeds like normal
                    // nominates x
                    auto nominationRestore = [&]() {
                        // restores from the previous state
                        icp2.mICP.setStateFromEnvelope(
                            0, makeNominate(v0SecretKey, qSetHash0, 0, votes,
                                            accepted));
                        // tries to start nomination with yValue
                        REQUIRE(icp2.nominate(0, yValue, false));

                        checkLeaders(icp2, {v0SecretKey.getPublicKey()});

                        REQUIRE(icp2.mEnvs.size() == 1);
                        verifyNominate(icp2.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                       votes2, accepted);

                        // other nodes vote for 'x'
                        icp2.receiveEnvelope(nom1);
                        icp2.receiveEnvelope(nom2);
                        REQUIRE(icp2.mEnvs.size() == 1);
                        // 'x' is accepted (quorum)
                        // but because the restored state already included
                        // 'x' in the accepted set, no new message is emitted
                        icp2.receiveEnvelope(nom3);

                        icp2.mExpectedCandidates.emplace(xValue);
                        icp2.mCompositeValue = xValue;

                        // other nodes not emit 'x' as accepted
                        icp2.receiveEnvelope(acc1);
                        icp2.receiveEnvelope(acc2);
                        REQUIRE(icp2.mEnvs.size() == 1);

                        icp2.mCompositeValue = xValue;
                        // this causes the node to update its composite value to
                        // x
                        icp2.receiveEnvelope(acc3);
                    };

                    SECTION("ballot protocol not started")
                    {
                        nominationRestore();
                        // nomination ended up starting the ballot protocol
                        REQUIRE(icp2.mEnvs.size() == 2);

                        verifyPrepare(icp2.mEnvs[1], v0SecretKey, qSetHash0, 0,
                                      ICPBallot(1, xValue));
                    }
                    SECTION("ballot protocol started (on value k)")
                    {
                        icp2.mICP.setStateFromEnvelope(
                            0, makePrepare(v0SecretKey, qSetHash0, 0,
                                           ICPBallot(1, kValue)));
                        nominationRestore();
                        // nomination didn't do anything (already working on k)
                        REQUIRE(icp2.mEnvs.size() == 1);
                    }
                }
            }
            SECTION(
                "receive more messages, then v0 switches to a different leader")
            {
                ICPEnvelope nom1 =
                    makeNominate(v1SecretKey, qSetHash, 0, {kValue}, {});
                ICPEnvelope nom2 =
                    makeNominate(v2SecretKey, qSetHash, 0, {yValue}, {});

                // nothing more happens
                icp.receiveEnvelope(nom1);
                icp.receiveEnvelope(nom2);
                REQUIRE(icp.mEnvs.size() == 1);

                // switch leader to v1
                icp.mPriorityLookup = [&](NodeID const& n) {
                    return (n == v1NodeID) ? 1000 : 1;
                };
                REQUIRE(icp.nominate(0, xValue, true));
                REQUIRE(icp.mEnvs.size() == 2);

                std::vector<Value> votesXK;
                votesXK.emplace_back(xValue);
                votesXK.emplace_back(kValue);
                std::sort(votesXK.begin(), votesXK.end());

                verifyNominate(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, votesXK,
                               {});
            }
        }
        SECTION("self nominates 'x', others nominate y -> prepare y")
        {
            std::vector<Value> myVotes, accepted;
            myVotes.emplace_back(xValue);

            icp.mExpectedCandidates.emplace(xValue);
            icp.mCompositeValue = xValue;
            REQUIRE(icp.nominate(0, xValue, false));

            REQUIRE(icp.mEnvs.size() == 1);
            verifyNominate(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, myVotes,
                           accepted);

            std::vector<Value> votes;
            votes.emplace_back(yValue);

            std::vector<Value> acceptedY = accepted;

            acceptedY.emplace_back(yValue);

            SECTION("others only vote for y")
            {
                ICPEnvelope nom1 =
                    makeNominate(v1SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope nom2 =
                    makeNominate(v2SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope nom3 =
                    makeNominate(v3SecretKey, qSetHash, 0, votes, accepted);
                ICPEnvelope nom4 =
                    makeNominate(v4SecretKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                icp.receiveEnvelope(nom1);
                icp.receiveEnvelope(nom2);
                icp.receiveEnvelope(nom3);
                REQUIRE(icp.mEnvs.size() == 1);

                // 'y' is accepted (quorum)
                icp.receiveEnvelope(nom4);
                REQUIRE(icp.mEnvs.size() == 2);
                myVotes.emplace_back(yValue);
                verifyNominate(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, myVotes,
                               acceptedY);
            }
            SECTION("others accepted y")
            {
                ICPEnvelope acc1 =
                    makeNominate(v1SecretKey, qSetHash, 0, votes, acceptedY);
                ICPEnvelope acc2 =
                    makeNominate(v2SecretKey, qSetHash, 0, votes, acceptedY);
                ICPEnvelope acc3 =
                    makeNominate(v3SecretKey, qSetHash, 0, votes, acceptedY);
                ICPEnvelope acc4 =
                    makeNominate(v4SecretKey, qSetHash, 0, votes, acceptedY);

                icp.receiveEnvelope(acc1);
                REQUIRE(icp.mEnvs.size() == 1);

                // this causes 'y' to be accepted (v-blocking)
                icp.receiveEnvelope(acc2);
                REQUIRE(icp.mEnvs.size() == 2);

                myVotes.emplace_back(yValue);
                verifyNominate(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, myVotes,
                               acceptedY);

                icp.mExpectedCandidates.clear();
                icp.mExpectedCandidates.insert(yValue);
                icp.mCompositeValue = yValue;
                // this causes the node to send a prepare message (quorum)
                icp.receiveEnvelope(acc3);
                REQUIRE(icp.mEnvs.size() == 3);

                verifyPrepare(icp.mEnvs[2], v0SecretKey, qSetHash0, 0,
                              ICPBallot(1, yValue));

                icp.receiveEnvelope(acc4);
                REQUIRE(icp.mEnvs.size() == 3);
            }
        }
    }
    SECTION("v1 is top node")
    {
        TestICP icp(v0SecretKey.getPublicKey(), qSet);
        uint256 qSetHash0 = icp.mICP.getLocalNode()->getQuorumSetHash();
        icp.storeQuorumSet(std::make_shared<ICPQuorumSet>(qSet));

        icp.mPriorityLookup = [&](NodeID const& n) {
            return (n == v1NodeID) ? 1000 : 1;
        };

        std::vector<Value> votesX, votesY, votesK, votesXY, votesYK, votesXK,
            emptyV;
        votesX.emplace_back(xValue);
        votesY.emplace_back(yValue);
        votesK.emplace_back(kValue);

        votesXY.emplace_back(xValue);
        votesXY.emplace_back(yValue);

        votesYK.emplace_back(yValue);
        votesYK.emplace_back(kValue);
        std::sort(votesYK.begin(), votesYK.end());

        votesXK.emplace_back(xValue);
        votesXK.emplace_back(kValue);
        std::sort(votesXK.begin(), votesXK.end());

        std::vector<Value> valuesHash;
        valuesHash.emplace_back(xValue);
        valuesHash.emplace_back(yValue);
        valuesHash.emplace_back(kValue);
        std::sort(valuesHash.begin(), valuesHash.end());

        icp.mHashValueCalculator = [&](Value const& v) {
            auto pos = std::find(valuesHash.begin(), valuesHash.end(), v);
            if (pos == valuesHash.end())
            {
                abort();
            }
            return 1 + std::distance(valuesHash.begin(), pos);
        };

        ICPEnvelope nom1 =
            makeNominate(v1SecretKey, qSetHash, 0, votesXY, emptyV);
        ICPEnvelope nom2 =
            makeNominate(v2SecretKey, qSetHash, 0, votesXK, emptyV);

        SECTION("nomination waits for v1")
        {
            REQUIRE(!icp.nominate(0, xValue, false));

            checkLeaders(icp, {v1SecretKey.getPublicKey()});

            REQUIRE(icp.mEnvs.size() == 0);

            ICPEnvelope nom3 =
                makeNominate(v3SecretKey, qSetHash, 0, votesYK, emptyV);
            ICPEnvelope nom4 =
                makeNominate(v4SecretKey, qSetHash, 0, votesXK, emptyV);

            // nothing happens with non top nodes
            icp.receiveEnvelope(nom2);
            icp.receiveEnvelope(nom3);
            REQUIRE(icp.mEnvs.size() == 0);

            icp.receiveEnvelope(nom1);
            REQUIRE(icp.mEnvs.size() == 1);
            verifyNominate(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, votesY,
                           emptyV);

            icp.receiveEnvelope(nom4);
            REQUIRE(icp.mEnvs.size() == 1);

            SECTION("timeout -> pick another value from v1")
            {
                icp.mExpectedCandidates.emplace(xValue);
                icp.mCompositeValue = xValue;

                // note: value passed in here should be ignored
                REQUIRE(icp.nominate(0, kValue, true));
                // picks up 'x' from v1 (as we already have 'y')
                // which also happens to causes 'x' to be accepted
                REQUIRE(icp.mEnvs.size() == 2);
                verifyNominate(icp.mEnvs[1], v0SecretKey, qSetHash0, 0, votesXY,
                               votesX);
            }
        }
        SECTION("v1 dead, timeout")
        {
            REQUIRE(!icp.nominate(0, xValue, false));

            REQUIRE(icp.mEnvs.size() == 0);

            icp.receiveEnvelope(nom2);
            REQUIRE(icp.mEnvs.size() == 0);

            checkLeaders(icp, {v1SecretKey.getPublicKey()});

            SECTION("v0 is new top node")
            {
                icp.mPriorityLookup = [&](NodeID const& n) {
                    return (n == v0NodeID) ? 1000 : 1;
                };

                REQUIRE(icp.nominate(0, xValue, true));
                checkLeaders(icp, {v0SecretKey.getPublicKey(),
                                   v1SecretKey.getPublicKey()});

                REQUIRE(icp.mEnvs.size() == 1);
                verifyNominate(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, votesX,
                               emptyV);
            }
            SECTION("v2 is new top node")
            {
                icp.mPriorityLookup = [&](NodeID const& n) {
                    return (n == v2NodeID) ? 1000 : 1;
                };

                REQUIRE(icp.nominate(0, xValue, true));
                checkLeaders(icp, {v1SecretKey.getPublicKey(),
                                   v2SecretKey.getPublicKey()});

                REQUIRE(icp.mEnvs.size() == 1);
                // v2 votes for XK, but nomination only picks the highest value
                std::vector<Value> v2Top;
                v2Top.emplace_back(std::max(xValue, kValue));
                verifyNominate(icp.mEnvs[0], v0SecretKey, qSetHash0, 0, v2Top,
                               emptyV);
            }
            SECTION("v3 is new top node")
            {
                icp.mPriorityLookup = [&](NodeID const& n) {
                    return (n == v3NodeID) ? 1000 : 1;
                };
                // nothing happens, we don't have any message for v3
                REQUIRE(!icp.nominate(0, xValue, true));
                checkLeaders(icp, {v1SecretKey.getPublicKey(),
                                   v3SecretKey.getPublicKey()});

                REQUIRE(icp.mEnvs.size() == 0);
            }
        }
    }
}
}
