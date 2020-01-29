// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/MergeKey.h"
#include "crypto/Hex.h"
#include <sstream>

namespace iotchain
{

MergeKey::MergeKey(uint32_t maxProtocolVersion, bool keepDeadEntries,
                   std::shared_ptr<Bucket> const& inputCurr,
                   std::shared_ptr<Bucket> const& inputSnap,
                   std::vector<std::shared_ptr<Bucket>> const& inputShadows)
    : mMaxProtocolVersion(maxProtocolVersion)
    , mKeepDeadEntries(keepDeadEntries)
    , mInputCurrBucket(inputCurr->getHash())
    , mInputSnapBucket(inputSnap->getHash())
{
    mInputShadowBuckets.reserve(inputShadows.size());
    for (auto const& s : inputShadows)
    {
        mInputShadowBuckets.emplace_back(s->getHash());
    }
}

MergeKey::MergeKey(uint32_t maxProtocolVersion, bool keepDeadEntries,
                   Hash& inputCurr, Hash& inputSnap,
                   std::vector<Hash> const& inputShadows)
    : mMaxProtocolVersion(maxProtocolVersion)
    , mKeepDeadEntries(keepDeadEntries)
    , mInputCurrBucket(inputCurr)
    , mInputSnapBucket(inputSnap)
    , mInputShadowBuckets(inputShadows)
{
}

bool
MergeKey::operator==(MergeKey const& other) const
{
    return mMaxProtocolVersion == other.mMaxProtocolVersion &&
           mKeepDeadEntries == other.mKeepDeadEntries &&
           mInputCurrBucket == other.mInputCurrBucket &&
           mInputSnapBucket == other.mInputSnapBucket &&
           mInputShadowBuckets == other.mInputShadowBuckets;
}

std::ostream&
operator<<(std::ostream& out, MergeKey const& b)
{
    out << "[curr=" << hexAbbrev(b.mInputCurrBucket)
        << ", snap=" << hexAbbrev(b.mInputSnapBucket) << ", shadows=[";
    bool first = true;
    for (auto const& s : b.mInputShadowBuckets)
    {
        if (!first)
        {
            out << ", ";
        }
        first = false;
        out << hexAbbrev(s);
    }
    out << "]]";
    return out;
}
}

namespace std
{
size_t
hash<iotchain::MergeKey>::operator()(iotchain::MergeKey const& key) const noexcept
{
    std::ostringstream oss;
    oss << key.mMaxProtocolVersion << ',' << key.mKeepDeadEntries << ','
        << iotchain::binToHex(key.mInputCurrBucket) << ','
        << iotchain::binToHex(key.mInputSnapBucket);
    for (auto const& e : key.mInputShadowBuckets)
    {
        oss << iotchain::binToHex(e) << ',';
    }
    std::hash<std::string> h;
    return h(oss.str());
}
}
