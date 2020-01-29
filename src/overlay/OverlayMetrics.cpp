#include "overlay/OverlayMetrics.h"
#include "main/Application.h"

#include "medida/meter.h"
#include "medida/metrics_registry.h"
#include "medida/timer.h"

namespace iotchain
{

OverlayMetrics::OverlayMetrics(Application& app)
    : mMessageRead(
          app.getMetrics().NewMeter({"overlay", "message", "read"}, "message"))
    , mMessageWrite(
          app.getMetrics().NewMeter({"overlay", "message", "write"}, "message"))
    , mByteRead(app.getMetrics().NewMeter({"overlay", "byte", "read"}, "byte"))
    , mByteWrite(
          app.getMetrics().NewMeter({"overlay", "byte", "write"}, "byte"))
    , mErrorRead(
          app.getMetrics().NewMeter({"overlay", "error", "read"}, "error"))
    , mErrorWrite(
          app.getMetrics().NewMeter({"overlay", "error", "write"}, "error"))
    , mTimeoutIdle(
          app.getMetrics().NewMeter({"overlay", "timeout", "idle"}, "timeout"))
    , mTimeoutStraggler(app.getMetrics().NewMeter(
          {"overlay", "timeout", "straggler"}, "timeout"))

    , mRecvErrorTimer(app.getMetrics().NewTimer({"overlay", "recv", "error"}))
    , mRecvHelloTimer(app.getMetrics().NewTimer({"overlay", "recv", "hello"}))
    , mRecvAuthTimer(app.getMetrics().NewTimer({"overlay", "recv", "auth"}))
    , mRecvDontHaveTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "dont-have"}))
    , mRecvGetPeersTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "get-peers"}))
    , mRecvPeersTimer(app.getMetrics().NewTimer({"overlay", "recv", "peers"}))
    , mRecvGetTxSetTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "get-txset"}))
    , mRecvTxSetTimer(app.getMetrics().NewTimer({"overlay", "recv", "txset"}))
    , mRecvTransactionTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "transaction"}))
    , mRecvGetICPQuorumSetTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "get-icp-qset"}))
    , mRecvICPQuorumSetTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "icp-qset"}))
    , mRecvICPMessageTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "icp-message"}))
    , mRecvGetICPStateTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "get-icp-state"}))

    , mRecvICPPrepareTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "icp-prepare"}))
    , mRecvICPConfirmTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "icp-confirm"}))
    , mRecvICPNominateTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "icp-nominate"}))
    , mRecvICPExternalizeTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "icp-externalize"}))

    , mSendErrorMeter(
          app.getMetrics().NewMeter({"overlay", "send", "error"}, "message"))
    , mSendHelloMeter(
          app.getMetrics().NewMeter({"overlay", "send", "hello"}, "message"))
    , mSendAuthMeter(
          app.getMetrics().NewMeter({"overlay", "send", "auth"}, "message"))
    , mSendDontHaveMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "dont-have"}, "message"))
    , mSendGetPeersMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "get-peers"}, "message"))
    , mSendPeersMeter(
          app.getMetrics().NewMeter({"overlay", "send", "peers"}, "message"))
    , mSendGetTxSetMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "get-txset"}, "message"))
    , mSendTransactionMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "transaction"}, "message"))
    , mSendTxSetMeter(
          app.getMetrics().NewMeter({"overlay", "send", "txset"}, "message"))
    , mSendGetICPQuorumSetMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "get-icp-qset"}, "message"))
    , mSendICPQuorumSetMeter(
          app.getMetrics().NewMeter({"overlay", "send", "icp-qset"}, "message"))
    , mSendICPMessageSetMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "icp-message"}, "message"))
    , mSendGetICPStateMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "get-icp-state"}, "message"))
    , mMessagesBroadcast(app.getMetrics().NewMeter(
          {"overlay", "message", "broadcast"}, "message"))
    , mPendingPeersSize(
          app.getMetrics().NewCounter({"overlay", "connection", "pending"}))
    , mAuthenticatedPeersSize(app.getMetrics().NewCounter(
          {"overlay", "connection", "authenticated"}))

    , mUniqueFloodBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "flood", "unique-recv"}, "byte"))
    , mDuplicateFloodBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "flood", "duplicate-recv"}, "byte"))
    , mUniqueFetchBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "fetch", "unique-recv"}, "byte"))
    , mDuplicateFetchBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "fetch", "duplicate-recv"}, "byte"))
{
}
}
