#pragma once

// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/ByteSliceHasher.h"
#include "xdr/IOTChain-ledger.h"
#include <functional>

// implements a default hasher for "LedgerKey"
namespace std
{
template <> class hash<iotchain::LedgerKey>
{
  public:
    size_t
    operator()(iotchain::LedgerKey const& lk) const
    {
        size_t res;
        switch (lk.type())
        {
        case iotchain::ACCOUNT:
            res = iotchain::shortHash::computeHash(
                iotchain::ByteSlice(lk.account().accountID.ed25519().data(), 8));
            break;
        case iotchain::TRUSTLINE:
        {
            auto& tl = lk.trustLine();
            res = iotchain::shortHash::computeHash(
                iotchain::ByteSlice(tl.accountID.ed25519().data(), 8));
            switch (lk.trustLine().asset.type())
            {
            case iotchain::ASSET_TYPE_NATIVE:
                break;
            case iotchain::ASSET_TYPE_CREDIT_ALPHANUM4:
            {
                auto& tl4 = tl.asset.alphaNum4();
                res ^= iotchain::shortHash::computeHash(
                    iotchain::ByteSlice(tl4.issuer.ed25519().data(), 8));
                res ^= tl4.assetCode[0];
                break;
            }
            case iotchain::ASSET_TYPE_CREDIT_ALPHANUM12:
            {
                auto& tl12 = tl.asset.alphaNum12();
                res ^= iotchain::shortHash::computeHash(
                    iotchain::ByteSlice(tl12.issuer.ed25519().data(), 8));
                res ^= tl12.assetCode[0];
                break;
            }
            default:
                abort();
            }
            break;
        }
        case iotchain::DATA:
            res = iotchain::shortHash::computeHash(
                iotchain::ByteSlice(lk.data().accountID.ed25519().data(), 8));
            res ^= iotchain::shortHash::computeHash(iotchain::ByteSlice(
                lk.data().dataName.data(), lk.data().dataName.size()));
            break;
        case iotchain::OFFER:
            res = iotchain::shortHash::computeHash(iotchain::ByteSlice(
                &lk.offer().offerID, sizeof(lk.offer().offerID)));
            break;
        default:
            abort();
        }
        return res;
    }
};
}
