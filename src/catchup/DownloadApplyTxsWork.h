// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "ledger/LedgerRange.h"
#include "util/XDRStream.h"
#include "work/BatchWork.h"
#include "xdr/IOTChain-ledger.h"

namespace medida
{
class Meter;
}

namespace iotchain
{

class TmpDir;
struct LedgerHeaderHistoryEntry;

class DownloadApplyTxsWork : public BatchWork
{
    LedgerRange const mRange;
    TmpDir const& mDownloadDir;
    LedgerHeaderHistoryEntry& mLastApplied;
    uint32_t mCheckpointToQueue;
    std::shared_ptr<BasicWork> mLastYieldedWork;

  public:
    DownloadApplyTxsWork(Application& app, TmpDir const& downloadDir,
                         LedgerRange const& range,
                         LedgerHeaderHistoryEntry& lastApplied);

  protected:
    bool hasNext() const override;
    std::shared_ptr<BasicWork> yieldMoreWork() override;
    void resetIter() override;
    void onSuccess() override;
};
}