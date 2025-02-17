#pragma once

// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "xdr/IOTChain-types.h"
#include <vector>

namespace iotchain
{

struct ICPEnvelope;
struct ICPStatement;
struct IOTChainValue;

std::vector<Hash> getTxSetHashes(ICPEnvelope const& envelope);
std::vector<IOTChainValue> getIOTChainValues(ICPStatement const& envelope);
}
