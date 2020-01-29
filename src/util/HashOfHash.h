#pragma once
#include <xdr/IOTChain-types.h>

namespace std
{
template <> struct hash<iotchain::uint256>
{
    size_t operator()(iotchain::uint256 const& x) const noexcept;
};
}
