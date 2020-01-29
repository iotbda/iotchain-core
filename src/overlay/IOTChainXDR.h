#pragma once
#include "xdr/IOTChain-ledger-entries.h"
#include "xdr/IOTChain-ledger.h"
#include "xdr/IOTChain-overlay.h"
#include "xdr/IOTChain-transaction.h"
#include "xdr/IOTChain-types.h"

namespace iotchain
{

std::string xdr_printer(const PublicKey& pk);
}
