#pragma once

// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0
#include "bucket/Bucket.h"
#include "xdr/IOTChain-types.h"
#include <cstdint>
#include <iosfwd>
#include <vector>

namespace iotchain
{
// Key type for cache of merges-in-progress. These only exist to enable
// re-attaching a deserialized FutureBucket to a std::shared_future, or (if the
// merge is finished and has been promoted to a live bucket) to identify which
// _output_ was produced from a given set of _inptus_ so we can recreate a
// pre-resolved std::shared_future containing that output.
struct MergeKey
{
    MergeKey(uint32_t maxProtocolVersion, bool keepDeadEntries,
             std::shared_ptr<Bucket> const& inputCurr,
             std::shared_ptr<Bucket> const& inputSnap,
             std::vector<std::shared_ptr<Bucket>> const& inputShadows);

    MergeKey(uint32_t maxProtocolVersion, bool keepDeadEntries, Hash& inputCurr,
             Hash& inputSnap, std::vector<Hash> const& inputShadows);

    uint32_t mMaxProtocolVersion;
    bool mKeepDeadEntries;
    Hash mInputCurrBucket;
    Hash mInputSnapBucket;
    std::vector<Hash> mInputShadowBuckets;
    bool operator==(MergeKey const& other) const;
};

std::ostream& operator<<(std::ostream& out, MergeKey const& b);
}

namespace std
{
template <> struct hash<iotchain::MergeKey>
{
    size_t operator()(iotchain::MergeKey const& k) const noexcept;
};
}
