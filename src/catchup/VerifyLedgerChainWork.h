// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "history/HistoryManager.h"
#include "ledger/LedgerRange.h"
#include "work/Work.h"

namespace medida
{
class Meter;
}

namespace iotchain
{

class TmpDir;
struct LedgerHeaderHistoryEntry;

// This class verifies ledger chain of a given range by checking the hashes.
// Note that verification is done starting with the latest checkpoint in the
// range, and working its way backwards to the beginning of the range.
class VerifyLedgerChainWork : public BasicWork
{
    TmpDir const& mDownloadDir;
    LedgerRange const mRange;
    uint32_t mCurrCheckpoint;
    LedgerNumHashPair const& mLastClosed;
    LedgerNumHashPair const mTrustedEndLedger;

    // First ledger of last verified checkpoint. Needed for a checkpoint that
    // is being verified: last ledger in current checkpoint must agree with
    // mVerifiedAhead
    LedgerNumHashPair mVerifiedAhead;

    // First ledger in the range
    LedgerHeaderHistoryEntry mVerifiedLedgerRangeStart{};

    medida::Meter& mVerifyLedgerSuccess;
    medida::Meter& mVerifyLedgerChainSuccess;
    medida::Meter& mVerifyLedgerChainFailure;

    HistoryManager::LedgerVerificationStatus verifyHistoryOfSingleCheckpoint();

  public:
    VerifyLedgerChainWork(Application& app, TmpDir const& downloadDir,
                          LedgerRange range,
                          LedgerNumHashPair const& lastClosedLedger,
                          LedgerNumHashPair ledgerRangeEnd);
    ~VerifyLedgerChainWork() override = default;
    std::string getStatus() const override;

    LedgerHeaderHistoryEntry
    getVerifiedLedgerRangeStart()
    {
        return mVerifiedLedgerRangeStart;
    }

  protected:
    void onReset() override;

    BasicWork::State onRun() override;
    bool
    onAbort() override
    {
        return true;
    };
};
}
