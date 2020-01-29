// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderUtils.h"
#include "icp/Slot.h"
#include "xdr/IOTChain-ledger.h"
#include <algorithm>
#include <xdrpp/marshal.h>

namespace iotchain
{

std::vector<Hash>
getTxSetHashes(ICPEnvelope const& envelope)
{
    auto values = getIOTChainValues(envelope.statement);
    auto result = std::vector<Hash>{};
    result.resize(values.size());

    std::transform(std::begin(values), std::end(values), std::begin(result),
                   [](IOTChainValue const& sv) { return sv.txSetHash; });

    return result;
}

std::vector<IOTChainValue>
getIOTChainValues(ICPStatement const& statement)
{
    auto values = Slot::getStatementValues(statement);
    auto result = std::vector<IOTChainValue>{};
    result.resize(values.size());

    std::transform(std::begin(values), std::end(values), std::begin(result),
                   [](Value const& v) {
                       auto wb = IOTChainValue{};
                       xdr::xdr_from_opaque(v, wb);
                       return wb;
                   });

    return result;
}
}
