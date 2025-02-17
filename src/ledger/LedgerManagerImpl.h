#pragma once

// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0
#include "util/asio.h"

#include "history/HistoryManager.h"
#include "ledger/LedgerManager.h"
#include "ledger/SyncingLedgerChain.h"
#include "main/PersistentState.h"
#include "transactions/TransactionFrame.h"
#include "xdr/IOTChain-ledger.h"
#include <string>

/*
Holds the current ledger
Applies the tx set to the last ledger to get the next one
Hands the old ledger off to the history
*/

namespace medida
{
class Timer;
class Counter;
class Histogram;
}

namespace iotchain
{
class AbstractLedgerTxn;
class Application;
class Database;
class LedgerTxnHeader;

class LedgerManagerImpl : public LedgerManager
{
    LedgerHeaderHistoryEntry mLastClosedLedger;

  protected:
    Application& mApp;

  private:
    medida::Timer& mTransactionApply;
    medida::Histogram& mTransactionCount;
    medida::Histogram& mOperationCount;
    medida::Counter& mInternalErrorCount;
    medida::Timer& mLedgerClose;
    medida::Timer& mLedgerAgeClosed;
    medida::Counter& mLedgerAge;
    medida::Counter& mPrefetchHitRate;
    VirtualClock::time_point mLastClose;

    std::unique_ptr<VirtualClock::time_point> mStartCatchup;
    medida::Timer& mCatchupDuration;

    medida::Counter& mSyncingLedgersSize;
    uint32_t mCatchupTriggerLedger{0};

    CatchupState mCatchupState{CatchupState::NONE};

    void addToSyncingLedgers(LedgerCloseData const& ledgerData);
    void startCatchupIf(uint32_t lastReceivedLedgerSeq);

    void historyCaughtup(CatchupWork::ProgressState progressState,
                         LedgerHeaderHistoryEntry const& lastClosed,
                         CatchupConfiguration::Mode catchupMode);

    void processFeesSeqNums(std::vector<TransactionFramePtr>& txs,
                            AbstractLedgerTxn& ltxOuter, int64_t baseFee);

    void applyTransactions(std::vector<TransactionFramePtr>& txs,
                           AbstractLedgerTxn& ltx,
                           TransactionResultSet& txResultSet);

    void ledgerClosed(AbstractLedgerTxn& ltx);

    void storeCurrentLedger(LedgerHeader const& header);
    void prefetchTransactionData(std::vector<TransactionFramePtr>& txs);
    void prefetchTxSourceIds(std::vector<TransactionFramePtr>& txs);

    enum class CloseLedgerIfResult
    {
        CLOSED,
        TOO_OLD,
        TOO_NEW
    };
    CloseLedgerIfResult closeLedgerIf(LedgerCloseData const& ledgerData);

    State mState;
    void setState(State s);

  protected:
    virtual void transferLedgerEntriesToBucketList(AbstractLedgerTxn& ltx,
                                                   uint32_t ledgerSeq,
                                                   uint32_t ledgerVers);

    SyncingLedgerChain mSyncingLedgers;

    void applyBufferedLedgers();
    void setCatchupState(CatchupState s);
    void advanceLedgerPointers(LedgerHeader const& header);

    void initializeCatchup(LedgerCloseData const& ledgerData);
    void continueCatchup(LedgerCloseData const& ledgerData);
    void finalizeCatchup(LedgerCloseData const& ledgerData);
    void logTxApplyMetrics(AbstractLedgerTxn& ltx, size_t numTxs,
                           size_t numOps);

  public:
    LedgerManagerImpl(Application& app);

    void bootstrap() override;
    State getState() const override;
    CatchupState getCatchupState() const override;
    std::string getStateHuman() const override;

    void valueExternalized(LedgerCloseData const& ledgerData) override;

    uint32_t getLastMaxTxSetSize() const override;
    int64_t getLastMinBalance(uint32_t ownerCount) const override;
    uint32_t getLastReserve() const override;
    uint32_t getLastTxFee() const override;

    uint32_t getLastClosedLedgerNum() const override;
    uint64_t secondsSinceLastLedgerClose() const override;
    void syncMetrics() override;

    void startNewLedger(LedgerHeader const& genesisLedger);
    void startNewLedger() override;
    void loadLastKnownLedger(
        std::function<void(asio::error_code const& ec)> handler) override;

    LedgerHeaderHistoryEntry const& getLastClosedLedgerHeader() const override;

    HistoryArchiveState getLastClosedLedgerHAS() override;

    Database& getDatabase() override;

    void startCatchup(CatchupConfiguration configuration) override;

    void closeLedger(LedgerCloseData const& ledgerData) override;
    void deleteOldEntries(Database& db, uint32_t ledgerSeq,
                          uint32_t count) override;
};
}
