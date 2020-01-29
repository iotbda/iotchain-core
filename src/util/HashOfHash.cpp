#include "HashOfHash.h"
#include "crypto/ByteSliceHasher.h"

namespace std
{

size_t
hash<iotchain::uint256>::operator()(iotchain::uint256 const& x) const noexcept
{
    size_t res =
        iotchain::shortHash::computeHash(iotchain::ByteSlice(x.data(), 8));

    return res;
}
}
