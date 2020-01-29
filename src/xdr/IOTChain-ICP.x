// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

%#include "xdr/IOTChain-types.h"

namespace iotchain
{

typedef opaque Value<>;

struct ICPBallot
{
    uint32 counter; // n
    Value value;    // x
};

enum ICPStatementType
{
    ICP_ST_PREPARE = 0,
    ICP_ST_CONFIRM = 1,
    ICP_ST_EXTERNALIZE = 2,
    ICP_ST_NOMINATE = 3
};

struct ICPNomination
{
    Hash quorumSetHash; // D
    Value votes<>;      // X
    Value accepted<>;   // Y
};

struct ICPStatement
{
    NodeID nodeID;    // v
    uint64 slotIndex; // i

    union switch (ICPStatementType type)
    {
    case ICP_ST_PREPARE:
        struct
        {
            Hash quorumSetHash;       // D
            ICPBallot ballot;         // b
            ICPBallot* prepared;      // p
            ICPBallot* preparedPrime; // p'
            uint32 nC;                // c.n
            uint32 nH;                // h.n
        } prepare;
    case ICP_ST_CONFIRM:
        struct
        {
            ICPBallot ballot;   // b
            uint32 nPrepared;   // p.n
            uint32 nCommit;     // c.n
            uint32 nH;          // h.n
            Hash quorumSetHash; // D
        } confirm;
    case ICP_ST_EXTERNALIZE:
        struct
        {
            ICPBallot commit;         // c
            uint32 nH;                // h.n
            Hash commitQuorumSetHash; // D used before EXTERNALIZE
        } externalize;
    case ICP_ST_NOMINATE:
        ICPNomination nominate;
    }
    pledges;
};

struct ICPEnvelope
{
    ICPStatement statement;
    Signature signature;
};

// supports things like: A,B,C,(D,E,F),(G,H,(I,J,K,L))
// only allows 2 levels of nesting
struct ICPQuorumSet
{
    uint32 threshold;
    PublicKey validators<>;
    ICPQuorumSet innerSets<>;
};
}
