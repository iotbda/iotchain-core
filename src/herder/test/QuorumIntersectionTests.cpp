// Copyright 2016-2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "herder/QuorumIntersectionChecker.h"
#include "lib/catch.hpp"
#include "main/Config.h"
#include "icp/LocalNode.h"
#include "test/test.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "xdrpp/marshal.h"
#include <lib/util/format.h>
#include <xdrpp/autocheck.h>

using namespace iotchain;

using QS = ICPQuorumSet;
using VQ = xdr::xvector<QS>;
using VK = xdr::xvector<PublicKey>;
using std::make_shared;

TEST_CASE("quorum intersection basic 4-node", "[herder][quorumintersection]")
{
    QuorumTracker::QuorumMap qm;

    PublicKey pkA = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkB = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkC = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkD = SecretKey::pseudoRandomForTesting().getPublicKey();

    qm[pkA] = make_shared<QS>(2, VK({pkB, pkC, pkD}), VQ{});
    qm[pkB] = make_shared<QS>(2, VK({pkA, pkC, pkD}), VQ{});
    qm[pkC] = make_shared<QS>(2, VK({pkA, pkB, pkD}), VQ{});
    qm[pkD] = make_shared<QS>(2, VK({pkA, pkB, pkC}), VQ{});

    Config cfg(getTestConfig());
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 6-node with subquorums",
          "[herder][quorumintersection]")
{
    QuorumTracker::QuorumMap qm;

    PublicKey pkA = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkB = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkC = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkD = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkE = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkF = SecretKey::pseudoRandomForTesting().getPublicKey();

    ICPQuorumSet qsABC(2, VK({pkA, pkB, pkC}), VQ{});
    ICPQuorumSet qsABD(2, VK({pkA, pkB, pkD}), VQ{});
    ICPQuorumSet qsABE(2, VK({pkA, pkB, pkE}), VQ{});
    ICPQuorumSet qsABF(2, VK({pkA, pkB, pkF}), VQ{});

    ICPQuorumSet qsACD(2, VK({pkA, pkC, pkD}), VQ{});
    ICPQuorumSet qsACE(2, VK({pkA, pkC, pkE}), VQ{});
    ICPQuorumSet qsACF(2, VK({pkA, pkC, pkF}), VQ{});

    ICPQuorumSet qsADE(2, VK({pkA, pkD, pkE}), VQ{});
    ICPQuorumSet qsADF(2, VK({pkA, pkD, pkF}), VQ{});

    ICPQuorumSet qsBDC(2, VK({pkB, pkD, pkC}), VQ{});
    ICPQuorumSet qsBDE(2, VK({pkB, pkD, pkE}), VQ{});
    ICPQuorumSet qsCDE(2, VK({pkC, pkD, pkE}), VQ{});

    qm[pkA] = make_shared<QS>(2, VK{}, VQ({qsBDC, qsBDE, qsCDE}));
    qm[pkB] = make_shared<QS>(2, VK{}, VQ({qsACD, qsACE, qsACF}));
    qm[pkC] = make_shared<QS>(2, VK{}, VQ({qsABD, qsABE, qsABF}));
    qm[pkD] = make_shared<QS>(2, VK{}, VQ({qsABC, qsABE, qsABF}));
    qm[pkE] = make_shared<QS>(2, VK{}, VQ({qsABC, qsABD, qsABF}));
    qm[pkF] = make_shared<QS>(2, VK{}, VQ({qsABC, qsABD, qsABE}));

    Config cfg(getTestConfig());
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum non intersection basic 6-node",
          "[herder][quorumintersection]")
{
    QuorumTracker::QuorumMap qm;

    PublicKey pkA = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkB = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkC = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkD = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkE = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkF = SecretKey::pseudoRandomForTesting().getPublicKey();

    qm[pkA] = make_shared<QS>(2, VK({pkB, pkC, pkD, pkE, pkF}), VQ{});
    qm[pkB] = make_shared<QS>(2, VK({pkA, pkC, pkD, pkE, pkF}), VQ{});
    qm[pkC] = make_shared<QS>(2, VK({pkA, pkB, pkD, pkE, pkF}), VQ{});
    qm[pkD] = make_shared<QS>(2, VK({pkA, pkB, pkC, pkE, pkF}), VQ{});
    qm[pkE] = make_shared<QS>(2, VK({pkA, pkB, pkC, pkD, pkF}), VQ{});
    qm[pkF] = make_shared<QS>(2, VK({pkA, pkB, pkC, pkD, pkE}), VQ{});

    Config cfg(getTestConfig());
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(!qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum non intersection 6-node with subquorums",
          "[herder][quorumintersection]")
{
    QuorumTracker::QuorumMap qm;

    PublicKey pkA = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkB = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkC = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkD = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkE = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkF = SecretKey::pseudoRandomForTesting().getPublicKey();

    ICPQuorumSet qsABC(2, VK({pkA, pkB, pkC}), VQ{});
    ICPQuorumSet qsABD(2, VK({pkA, pkB, pkD}), VQ{});
    ICPQuorumSet qsABE(2, VK({pkA, pkB, pkE}), VQ{});
    ICPQuorumSet qsABF(2, VK({pkA, pkB, pkF}), VQ{});

    ICPQuorumSet qsACD(2, VK({pkA, pkC, pkD}), VQ{});
    ICPQuorumSet qsACE(2, VK({pkA, pkC, pkE}), VQ{});
    ICPQuorumSet qsACF(2, VK({pkA, pkC, pkF}), VQ{});

    ICPQuorumSet qsADE(2, VK({pkA, pkD, pkE}), VQ{});
    ICPQuorumSet qsADF(2, VK({pkA, pkD, pkF}), VQ{});

    ICPQuorumSet qsBDC(2, VK({pkB, pkD, pkC}), VQ{});
    ICPQuorumSet qsBDE(2, VK({pkB, pkD, pkE}), VQ{});
    ICPQuorumSet qsBDF(2, VK({pkB, pkD, pkF}), VQ{});
    ICPQuorumSet qsCDE(2, VK({pkC, pkD, pkE}), VQ{});
    ICPQuorumSet qsCDF(2, VK({pkC, pkD, pkF}), VQ{});

    qm[pkA] = make_shared<QS>(2, VK{}, VQ({qsABC, qsABD, qsABE}));
    qm[pkB] = make_shared<QS>(2, VK{}, VQ({qsBDC, qsABD, qsABF}));
    qm[pkC] = make_shared<QS>(2, VK{}, VQ({qsACD, qsACD, qsACF}));

    qm[pkD] = make_shared<QS>(2, VK{}, VQ({qsCDE, qsADE, qsBDE}));
    qm[pkE] = make_shared<QS>(2, VK{}, VQ({qsCDE, qsADE, qsBDE}));
    qm[pkF] = make_shared<QS>(2, VK{}, VQ({qsABF, qsADF, qsBDF}));

    Config cfg(getTestConfig());
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(!qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum plausible non intersection", "[herder][quorumintersection]")
{
    QuorumTracker::QuorumMap qm;

    PublicKey pkSDF1 = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkSDF2 = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkSDF3 = SecretKey::pseudoRandomForTesting().getPublicKey();

    PublicKey pkLOBSTR1 = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkLOBSTR2 = SecretKey::pseudoRandomForTesting().getPublicKey();

    PublicKey pkSatoshi1 = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkSatoshi2 = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkSatoshi3 = SecretKey::pseudoRandomForTesting().getPublicKey();

    PublicKey pkCOINQVEST1 = SecretKey::pseudoRandomForTesting().getPublicKey();
    PublicKey pkCOINQVEST2 = SecretKey::pseudoRandomForTesting().getPublicKey();

    Config cfg(getTestConfig());
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkSDF1)] = "SDF1";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkSDF2)] = "SDF2";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkSDF3)] = "SDF3";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkLOBSTR1)] = "LOBSTR1_Europe";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkLOBSTR2)] = "LOBSTR2_Europe";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkSatoshi1)] =
        "SatoshiPay_DE_Frankfurt";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkSatoshi2)] =
        "SatoshiPay_SG_Singapore";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkSatoshi3)] = "SatoshiPay_US_Iowa";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkCOINQVEST1)] = "COINQVEST_Germany";
    cfg.VALIDATOR_NAMES[KeyUtils::toStrKey(pkCOINQVEST2)] = "COINQVEST_Finland";

    // Some innersets used in quorums below.

    ICPQuorumSet qs1of2LOBSTR(1, VK({pkLOBSTR1, pkLOBSTR2}), VQ{});
    ICPQuorumSet qs1of2COINQVEST(1, VK({pkCOINQVEST1, pkCOINQVEST2}), VQ{});

    ICPQuorumSet qs2of3SDF(1, VK({pkSDF1, pkSDF2, pkSDF3}), VQ{});

    ICPQuorumSet qs2of3SatoshiPay(2, VK({pkSatoshi1, pkSatoshi2, pkSatoshi3}),
                                  VQ{});

    // All 3 SDF nodes get this:
    auto qsSDF = make_shared<QS>(3, VK({pkSDF1, pkSDF2, pkSDF3}),
                                 VQ({qs1of2LOBSTR, qs2of3SatoshiPay}));
    qm[pkSDF1] = qsSDF;
    qm[pkSDF2] = qsSDF;
    qm[pkSDF3] = qsSDF;

    // All SatoshiPay nodes get this:
    auto qsSatoshiPay =
        make_shared<QS>(4, VK({pkSatoshi1, pkSatoshi2, pkSatoshi3}),
                        VQ({qs2of3SDF, qs1of2LOBSTR, qs1of2COINQVEST}));
    qm[pkSatoshi1] = qsSatoshiPay;
    qm[pkSatoshi2] = qsSatoshiPay;
    qm[pkSatoshi3] = qsSatoshiPay;

    // All LOBSTR nodes get this:
    auto qsLOBSTR = make_shared<QS>(
        5, VK({pkSDF1, pkSDF2, pkSDF3, pkSatoshi1, pkSatoshi2, pkSatoshi3}),
        VQ{});
    qm[pkLOBSTR1] = qsLOBSTR;
    qm[pkLOBSTR2] = qsLOBSTR;

    // All COINQVEST nodes get this:
    auto qsCOINQVEST =
        make_shared<QS>(3, VK({pkCOINQVEST1, pkCOINQVEST2}),
                        VQ({qs2of3SDF, qs2of3SatoshiPay, qs1of2LOBSTR}));
    qm[pkCOINQVEST1] = qsCOINQVEST;
    qm[pkCOINQVEST2] = qsCOINQVEST;

    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(!qic->networkEnjoysQuorumIntersection());
}

uint32
roundUpPct(size_t n, size_t pct)
{
    return static_cast<uint32>(size_t(1) +
                               (((n * pct) - size_t(1)) / size_t(100)));
}

static xdr::xvector<xdr::xvector<PublicKey>>
generateOrgs(size_t n_orgs, std::vector<size_t> sizes = {3, 5})
{
    xdr::xvector<xdr::xvector<PublicKey>> ret;

    for (size_t i = 0; i < n_orgs; ++i)
    {
        ret.emplace_back();
        size_t n_nodes = sizes.at(i % sizes.size());
        for (size_t j = 0; j < n_nodes; ++j)
        {
            ret.back().emplace_back(
                SecretKey::pseudoRandomForTesting().getPublicKey());
        }
    }
    return ret;
}

static Config
configureShortNames(Config const& cfgIn,
                    xdr::xvector<xdr::xvector<PublicKey>> const& orgs)
{
    Config cfgOut(cfgIn);
    for (size_t i = 0; i < orgs.size(); ++i)
    {
        auto const& org = orgs.at(i);
        for (size_t j = 0; j < org.size(); ++j)
        {
            auto n = KeyUtils::toStrKey(org.at(j));
            auto s = fmt::format("org{}.n{}", i, j);
            cfgOut.VALIDATOR_NAMES[n] = s;
        }
    }
    return cfgOut;
}

static QuorumTracker::QuorumMap
interconnectOrgs(xdr::xvector<xdr::xvector<PublicKey>> const& orgs,
                 std::function<bool(size_t i, size_t j)> shouldDepend,
                 size_t ownThreshPct = 67, size_t innerThreshPct = 51)
{
    QuorumTracker::QuorumMap qm;
    xdr::xvector<ICPQuorumSet> emptySet;
    for (size_t i = 0; i < orgs.size(); ++i)
    {
        auto const& org = orgs.at(i);
        auto qs = std::make_shared<ICPQuorumSet>();
        qs->validators = org;
        for (auto const& pk : org)
        {
            qm[pk] = qs;
        }
        auto& depOrgs = qs->innerSets;
        for (size_t j = 0; j < orgs.size(); ++j)
        {
            if (i == j)
            {
                continue;
            }
            if (shouldDepend(i, j))
            {
                CLOG(DEBUG, "ICP") << "dep: org#" << i << " => org#" << j;
                auto& otherOrg = orgs.at(j);
                auto thresh = roundUpPct(otherOrg.size(), innerThreshPct);
                depOrgs.emplace_back(thresh, otherOrg, emptySet);
            }
        }
        qs->threshold = roundUpPct(qs->validators.size() + qs->innerSets.size(),
                                   ownThreshPct);
    }
    return qm;
}

static QuorumTracker::QuorumMap
interconnectOrgsUnidir(xdr::xvector<xdr::xvector<PublicKey>> const& orgs,
                       std::vector<std::pair<size_t, size_t>> edges,
                       size_t ownThreshPct = 67, size_t innerThreshPct = 51)
{
    return interconnectOrgs(orgs,
                            [&edges](size_t i, size_t j) {
                                for (auto const& e : edges)
                                {
                                    if (e.first == i && e.second == j)
                                    {
                                        return true;
                                    }
                                }
                                return false;
                            },
                            ownThreshPct, innerThreshPct);
}

static QuorumTracker::QuorumMap
interconnectOrgsBidir(xdr::xvector<xdr::xvector<PublicKey>> const& orgs,
                      std::vector<std::pair<size_t, size_t>> edges,
                      size_t ownThreshPct = 67, size_t innerThreshPct = 51)
{
    return interconnectOrgs(orgs,
                            [&edges](size_t i, size_t j) {
                                for (auto const& e : edges)
                                {
                                    if ((e.first == i && e.second == j) ||
                                        (e.first == j && e.second == i))
                                    {
                                        return true;
                                    }
                                }
                                return false;
                            },
                            ownThreshPct, innerThreshPct);
}

TEST_CASE("quorum intersection 4-org fully-connected, elide all minquorums",
          "[herder][quorumintersection]")
{
    // Generate a typical all-to-all multi-org graph that checks quickly: every
    // quorum is a fair bit larger than half the SCC, so it will actually trim
    // its search to nothing before bothering to look in detail at a single
    // min-quorum. This is a bit weird but, I think, correct.
    auto orgs = generateOrgs(4);
    auto qm = interconnectOrgs(orgs, [](size_t i, size_t j) { return true; });
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 3-org 3-node open line",
          "[herder][quorumintersection]")
{
    // Network: org0 <--> org1 <--> org2
    //
    // This fails to enjoy quorum intersection when the orgs each have 3
    // own-nodes: org0 or org2 at 67% need a 3/4 threshold (over their
    // validators and innersets), meaning either org can be satisfied by its own
    // nodes alone.
    auto orgs = generateOrgs(3, {3});
    auto qm = interconnectOrgsBidir(orgs, {{0, 1}, {1, 2}});
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(!qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 3-org 2-node open line",
          "[herder][quorumintersection]")
{
    // Network: org0 <--> org1 <--> org2
    //
    // This enjoys quorum intersection when the orgs each have 2 own-nodes: org0
    // and org2 at 67% need 3/3 nodes (including their 1 outgoing dependency),
    // meaning they have to agree with org1 to be satisfied.
    auto orgs = generateOrgs(3, {2});
    auto qm = interconnectOrgsBidir(orgs, {{0, 1}, {1, 2}});
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 3-org 3-node closed ring",
          "[herder][quorumintersection]")
{
    // Network: org0 <--> org1 <--> org2
    //           ^                   ^
    //           |                   |
    //           +-------------------+
    //
    // This enjoys quorum intersection when the orgs each have 3 own-nodes: any
    // org at 67% needs a 4/5 threshold (over its validators and innersets),
    // meaning the org must be agree with at least one neighbour org.
    auto orgs = generateOrgs(3, {3});
    auto qm = interconnectOrgsBidir(orgs, {{0, 1}, {1, 2}, {0, 2}});
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 3-org 3-node closed one-way ring",
          "[herder][quorumintersection]")
{
    // Network: org0 --> org1 --> org2
    //           ^                  |
    //           |                  |
    //           +------------------+
    //
    // This fails to enjoy quorum intersection when the orgs each have 3
    // own-nodes: any org at 67% needs a 3/4 threshold (over its validators and
    // innersets), meaning the org can be satisfied by its own nodes alone. This
    // is similar to the 3-org 3-node open line case.
    auto orgs = generateOrgs(3, {3});
    auto qm = interconnectOrgsUnidir(orgs, {
                                               {0, 1},
                                               {1, 2},
                                               {2, 0},
                                           });
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(!qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 3-org 2-node closed one-way ring",
          "[herder][quorumintersection]")
{
    // Network: org0 --> org1 --> org2
    //           ^                  |
    //           |                  |
    //           +------------------+
    //
    // This enjoys quorum intersection when the orgs each have 2 own-nodes: any
    // org at 67% needs a 3/3 threshold (over its validators and innersets),
    // meaning the org must be agree with at least one neighbour org. This is
    // similar to the 3-org 2-node open line case.
    auto orgs = generateOrgs(3, {2});
    auto qm = interconnectOrgsUnidir(orgs, {
                                               {0, 1},
                                               {1, 2},
                                               {2, 0},
                                           });
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 3-org 2-node 2-of-3 asymmetric",
          "[herder][quorumintersection]")
{
    //           +-------------------+
    //           |                   v
    // Network: org0 <--> org1 --> org2
    //           ^         ^         |
    //           |         |         |
    //           +---------+---------+
    //
    // This enjoys quorum intersection when the orgs each have 3 own-nodes: any
    // org at 67% needs a 4/5 threshold (over its validators and innersets),
    // meaning the org must be agree with at least one neighbour org. This is
    // similar to the 3-org 2-node closed ring case.
    auto orgs = generateOrgs(3, {3});
    auto qm = interconnectOrgsUnidir(orgs, {
                                               {0, 1},
                                               {0, 2},
                                               {1, 0},
                                               {1, 2},
                                               {2, 0},
                                               {2, 1},
                                           });
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 8-org core-and-periphery dangling",
          "[herder][quorumintersection]")
{
    // This configuration "looks kinda strong" -- there's a fully-connected
    // "core" org set and the "periphery" orgs are all set to 3/3 between their
    // own two nodes and the core org they're watching -- but it is still
    // capable of splitting in half because the core orgs' dependency on on
    // periphery orgs allows passing the core org's 5/7 threshold without
    // needing a majority of the core orgs. The core orgs can be satisfied by
    // their own 3 nodes + 1 other core node + 1 periphery org, which is enough
    // to cause the network to split in two 4-org / 10-node halves:
    //
    //    org4           org5
    //       \           /
    //        org0---org1
    //          | \ / |
    //          |  X  |
    //          | / \ |
    //        org2---org3
    //       /           \
    //    org6           org7
    //
    auto orgs = generateOrgs(8, {3, 3, 3, 3, 2, 2, 2, 2});
    auto qm = interconnectOrgsBidir(
        orgs,
        {// 4 core orgs 0, 1, 2, 3 (with 3 nodes each) which fully depend on one
         // another.
         {0, 1},
         {0, 2},
         {0, 3},
         {1, 2},
         {1, 3},
         {2, 3},
         // 4 "periphery" orgs (with 2 nodes each), each with bidirectional
         // trust with one core org, which is that core org's only paired
         // periphery.
         {0, 4},
         {1, 5},
         {2, 6},
         {3, 7}});
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(!qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 8-org core-and-periphery balanced",
          "[herder][quorumintersection]")
{
    // This configuration strengthens the previous just a bit by making each of
    // the core orgs have _two_ periphery relationships, in a specific
    // "balanced" pattern of peripheral dependency. The periphery nodes are
    // still able to be satisfied by 3/4 threshold so they can "go with" a core
    // node, but the core nodes have been pushed from 5/7 up to 6/8 which means
    // they need their own 3 nodes + 2 periphery orgs + 1 other core
    // org. Needing two periphery orgs means -- due to the balanced distribution
    // of core/periphery relationships -- that one of those periphery orgs spans
    // any possible split across the core, which means there's quorum
    // intersection in all cases.
    //
    //    org4--------   org5
    //       \        \  /|
    //        org0---org1 |
    //       /  | \ / |   |
    //      |   |  X  |   |
    //      |   | / \ |  /
    //      | org2---org3
    //      |/  \        \
    //    org6   --------org7
    //
    auto orgs = generateOrgs(8, {3, 3, 3, 3, 2, 2, 2, 2});
    auto qm = interconnectOrgsBidir(
        orgs,
        {// 4 core orgs 0, 1, 2, 3 (with 3 nodes each) which fully depend on one
         // another.
         {0, 1},
         {0, 2},
         {0, 3},
         {1, 2},
         {1, 3},
         {2, 3},
         // 4 "periphery" orgs (with 2 nodes each), each with bidirectional
         // trust with two core orgs, with each pair of core orgs having only
         // one peripheral org in common.
         {0, 4},
         {1, 4},
         {1, 5},
         {3, 5},
         {2, 6},
         {0, 6},
         {3, 7},
         {2, 7}});
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 8-org core-and-periphery unbalanced",
          "[herder][quorumintersection]")
{
    // This configuration weakens the previous again, just a _tiny_ bit,
    // by un-balancing the periphery-org structure. It's enough to re-introduce
    // the possibility of splitting though.
    //
    //            -------- org5
    //    org4---/----    /
    //       \  /     \  /
    //        org0---org1
    //          | \ / |
    //          |  X  |
    //          | / \ |
    //        org2---org3
    //       /  \     /  \
    //    org6---\----    \
    //            -------- org7
    //
    auto orgs = generateOrgs(8, {3, 3, 3, 3, 2, 2, 2, 2});
    auto qm = interconnectOrgsBidir(
        orgs,
        {// 4 core orgs 0, 1, 2, 3 (with 3 nodes each) which fully depend on one
         // another.
         {0, 1},
         {0, 2},
         {0, 3},
         {1, 2},
         {1, 3},
         {2, 3},
         // 4 "periphery" orgs (with 2 nodes each), each with bidirectional
         // trust with two core orgs, with two pairs of core orgs paired to
         // the same two peripherals.
         {0, 4},
         {1, 4},
         {0, 5},
         {1, 5},
         {2, 6},
         {3, 6},
         {2, 7},
         {3, 7}});
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(!qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection 6-org 1-node 4-null qsets",
          "[herder][quorumintersection]")
{
    // Generating the following topology with dependencies from the core nodes
    // org0..org1 bidirectionally to one another, but also one-way outwards to
    // some "unknown nodes" org2..org5, which we don't have qsets for.
    //
    //          org2       org4
    //           ^          ^
    //           |          |
    //          org0 <---> org1
    //           |          |
    //           v          v
    //          org3       org5
    //
    // We build this case to explore the correct inferred over-approximate qsets
    // for org2..org5. We know org0..org1 have threshold 67% = 3-of-4 (4 being
    // "self + 3 neighbours"); the current logic in the quorum intersection
    // checker (see buildGraph and convertICPQuorumSet) will treat this network
    // as _only_ having 2-nodes and will therefore declare it vacuously enjoying
    // quorum intersection due to being halted.
    //
    // (At other points in the design, and possibly again in the future if we
    // change our minds, we modeled this differently, treating the null-qset
    // nodes as either live-and-unknown, or byzantine; both of those cases
    // split.)

    auto orgs = generateOrgs(6, {1});
    auto qm = interconnectOrgsUnidir(orgs, {
                                               {0, 1},
                                               {1, 0},
                                               {0, 2},
                                               {0, 3},
                                               {1, 4},
                                               {1, 5},
                                           });

    // Mark the last 4 orgs as unknown.
    for (size_t i = 2; i < orgs.size(); ++i)
    {
        for (auto const& node : orgs.at(i))
        {
            qm[node] = nullptr;
        }
    }

    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
    REQUIRE(qic->getMaxQuorumsFound() == 0);
}

TEST_CASE("quorum intersection 4-org 1-node 4-null qsets",
          "[herder][quorumintersection]")
{
    // Generating the following topology with dependencies from the core nodes
    // org0..org1 bidirectionally to one another, but also one-way outwards to
    // some "unknown nodes" org2..org3, which we don't have qsets for.
    //
    //           +-> org2 <-+
    //           |          |
    //          org0 <--> org1
    //           |          |
    //           +-> org3 <-+
    //
    // As with the case before, this represents (to the quorum intersection
    // checker's eyes) a halted network which vacuously enjoys quorum
    // intersection.  But if we were using one of the other models for the
    // meaning of a null qset, it might be different: split in the byzantine
    // case, live and enjoying quorum intersection in the live-and-unknown case.

    auto orgs = generateOrgs(4, {1});
    auto qm = interconnectOrgsUnidir(orgs, {
                                               {0, 1},
                                               {1, 0},
                                               {0, 2},
                                               {0, 3},
                                               {1, 2},
                                               {1, 3},
                                           });

    // Mark the last 2 orgs as unknown.
    for (size_t i = 2; i < orgs.size(); ++i)
    {
        for (auto const& node : orgs.at(i))
        {
            qm[node] = nullptr;
        }
    }

    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
    REQUIRE(qic->getMaxQuorumsFound() == 0);
}

TEST_CASE("quorum intersection 6-org 3-node fully-connected",
          "[herder][quorumintersection]")
{
    auto orgs = generateOrgs(6, {3});
    auto qm = interconnectOrgs(orgs, [](size_t i, size_t j) { return true; });
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

TEST_CASE("quorum intersection scaling test",
          "[herder][quorumintersectionbench][!hide]")
{
    // Same as above but with 3-or-5-own-node orgs, so more possible nodes,
    // bigger search space for performance testing.
    auto orgs = generateOrgs(6);
    auto qm = interconnectOrgs(orgs, [](size_t i, size_t j) { return true; });
    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());
}

static void
debugQmap(Config const& cfg, QuorumTracker::QuorumMap const& qm)
{
    for (auto const& pair : qm)
    {
        if (pair.second)
        {
            auto str =
                LocalNode::toJson(*pair.second, [&cfg](PublicKey const& k) {
                    return cfg.toShortString(k);
                });
            CLOG(DEBUG, "ICP")
                << "qmap[" << cfg.toShortString(pair.first) << "] = " << str;
        }
        else
        {
            CLOG(DEBUG, "ICP")
                << "qmap[" << cfg.toShortString(pair.first) << "] = nullptr";
        }
    }
}

TEST_CASE("quorum intersection criticality",
          "[herder][quorumintersectioncriticality]")
{
    // An org is "critical" if the network splits when it is made "fickle".
    //
    // Fickleness means reducing a node's threshold to "2 of {self} + {others}"
    // where "{others}" is an innerset with threshold of 1 and containing the
    // set of nodes depending on self. This over-approximates "bad
    // configuration", is as bad as we can imagine making a configuration
    // without making the node actually byzantine.
    //
    // Here we build a graph with two main "groups" of orgs {0,1,2} and {4,5,6},
    // with a critical org3 that, under normal/good configuration, will be a
    // bridge between the groups.
    //
    // The {4,5,6} group is fully connected so can meet a 3-of-3 quorum on its
    // own (at 67%) but the {0,1,2} isn't fully connected: each node in it needs
    // the agreement of org3, and org3 itself requires 5/6 agreement, so will
    // always agree with both groups, bridging them.
    //
    // IOW, in "good" configuration, this graph enjoys quorum intersection.
    //
    // But if org3 becomes misconfigured (fickle) it can decide it has adequate
    // quorum with only the {0,1,2} group, splitting them off from the {4,5,6}
    // group, which will continue along on their own.
    //
    //
    //   org0 <-+  +-> org4 <-+
    //    ^     |  |    ^     |
    //    |     |  |    |     |
    //    v     v  v    v     |
    // org1 <-> org3   org5   |
    //    ^     ^  ^    ^     |
    //    |     |  |    |     |
    //    v     |  |    v     |
    //   org2 <-+  +-> org6 <-+
    //

    auto orgs = generateOrgs(7, {1});
    auto qm = interconnectOrgsBidir(orgs, {
                                              {0, 1},
                                              {1, 2},

                                              {4, 5},
                                              {4, 6},
                                              {5, 6},

                                              {0, 3},
                                              {1, 3},
                                              {2, 3},
                                              {4, 3},
                                              {6, 3},
                                          });

    Config cfg(getTestConfig());
    cfg = configureShortNames(cfg, orgs);
    debugQmap(cfg, qm);
    auto qic = QuorumIntersectionChecker::create(qm, cfg);
    REQUIRE(qic->networkEnjoysQuorumIntersection());

    auto groups =
        QuorumIntersectionChecker::getIntersectionCriticalGroups(qm, cfg);
    REQUIRE(groups.size() == 1);
    REQUIRE(groups == std::set<std::set<PublicKey>>{{orgs[3][0]}});
}
