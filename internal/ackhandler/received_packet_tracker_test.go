package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestReceivedPacketTrackerGenerateACKs(t *testing.T) {
	tracker := newReceivedPacketTracker()

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(3), protocol.ECNNon, true))
	ack := tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 3}}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(4), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 4}}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(1), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 3, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	// non-ack-eliciting packets don't trigger ACKs
	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(10), protocol.ECNNon, false))
	require.Nil(t, tracker.GetAckFrame())

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(11), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 11},
		{Smallest: 3, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, ack.AckRanges)
}

func TestAppDataReceivedPacketTrackerECN(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, 0)

	require.NoError(t, tr.ReceivedPacket(0, protocol.ECT0, monotime.Now(), true))
	pn := protocol.PacketNumber(1)
	for range 2 {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECT1, monotime.Now(), true))
		pn++
	}
	for range 3 {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNCE, monotime.Now(), true))
		pn++
	}
	ack := tr.GetAckFrame(monotime.Now(), false)
	require.Equal(t, uint64(1), ack.ECT0)
	require.Equal(t, uint64(2), ack.ECT1)
	require.Equal(t, uint64(3), ack.ECNCE)
}

func TestAppDataReceivedPacketTrackerAckEverySecondPacket(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, 0)
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))

	for p := protocol.PacketNumber(1); p <= 20; p++ {
		require.NoError(t, tr.ReceivedPacket(p, protocol.ECNNon, monotime.Now(), true))
		switch p % 2 {
		case 0:
			require.NotNil(t, tr.GetAckFrame(monotime.Now(), true))
		case 1:
			require.Nil(t, tr.GetAckFrame(monotime.Now(), true))
		}
	}
}

func TestAppDataReceivedPacketTrackerAlarmTimeout(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, 0)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, false))
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))
	require.Zero(t, tr.GetAlarmTimeout())

	rcvTime := now.Add(10 * time.Millisecond)
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, rcvTime, true))
	require.Equal(t, rcvTime.Add(protocol.MaxAckDelay), tr.GetAlarmTimeout())
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))

	// no timeout after the ACK has been dequeued
	require.NotNil(t, tr.GetAckFrame(monotime.Now(), false))
	require.Zero(t, tr.GetAlarmTimeout())
}

func TestAppDataReceivedPacketTrackerQueuesECNCE(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, 0)

	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNCE, monotime.Now(), true))
	ack := tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, protocol.PacketNumber(1), ack.LargestAcked())
	require.EqualValues(t, 1, ack.ECNCE)
}

func TestAppDataReceivedPacketTrackerMissingPackets(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, 0)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))

	require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))
	ack := tr.GetAckFrame(now, true) // ACK: 0 and 5, missing: 1, 2, 3, 4
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 5, Largest: 5}, {Smallest: 0, Largest: 0}}, ack.AckRanges)

	// now receive one of the missing packets
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now, true))
	ack = tr.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 5, Largest: 5},
		{Smallest: 3, Largest: 3},
		{Smallest: 0, Largest: 0},
	}, ack.AckRanges)

	require.NoError(t, tr.ReceivedPacket(6, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
	require.NoError(t, tr.ReceivedPacket(8, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
}

func TestAppDataReceivedPacketTrackerDelayTime(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, 0)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now.Add(-1337*time.Millisecond), true))
	ack := tr.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.Equal(t, 1337*time.Millisecond, ack.DelayTime)

	// don't use a negative delay time
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now.Add(time.Hour), true))
	ack = tr.GetAckFrame(now, false)
	require.NotNil(t, ack)
	require.Zero(t, ack.DelayTime)
}

func TestAppDataReceivedPacketTrackerIgnoreBelow(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, 0)

	tr.IgnoreBelow(4)
	// check that packets below 7 are considered duplicates
	require.True(t, tr.IsPotentiallyDuplicate(3))
	require.False(t, tr.IsPotentiallyDuplicate(4))

	for i := 5; i <= 10; i++ {
		require.NoError(t, tr.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, monotime.Now(), true))
	}
	ack := tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 5, Largest: 10}}, ack.AckRanges)

	tr.IgnoreBelow(7)

	require.NoError(t, tr.ReceivedPacket(11, protocol.ECNNon, monotime.Now(), true))
	require.NoError(t, tr.ReceivedPacket(12, protocol.ECNNon, monotime.Now(), true))
	ack = tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 7, Largest: 12}}, ack.AckRanges)

	// make sure that old packets are not accepted
	require.ErrorContains(t,
		tr.ReceivedPacket(4, protocol.ECNNon, monotime.Now(), true),
		"receivedPacketTracker BUG: ReceivedPacket called for old / duplicate packet 4",
	)
}

// TestAppDataReceivedPacketTrackerGapSettle verifies that when AckGapSettleDelay
// is set, a newly-detected missing-packet gap doesn't immediately produce a
// gap-revealing ACK; instead the ACK is held for up to the settle window. If
// the gap fills during the window, no gap is ever reported to the peer. If it
// doesn't fill, the ACK ships after the settle window expires.
func TestAppDataReceivedPacketTrackerGapSettle(t *testing.T) {
	t.Run("gap fills within settle window — no gap-revealing ACK", func(t *testing.T) {
		settle := 2 * time.Millisecond
		tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, settle)
		now := monotime.Now()

		// First two packets in order — the every-2-packets rule queues a
		// clean ACK that we drain. This establishes lastAck so the next
		// out-of-order packet's gap registers as a "new missing" event.
		require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
		require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
		ack := tr.GetAckFrame(now, true)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, ack.AckRanges)

		// Packet 5 arrives, opening a gap at 3-4. Without gap-settle, this
		// would queue an immediate ACK. With settle enabled, no ACK should
		// be available yet.
		require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))
		require.Nil(t, tr.GetAckFrame(now, true))
		require.Equal(t, now.Add(settle), tr.GetAlarmTimeout())

		// 4 arrives 1ms later (still inside the settle window). It fills
		// the highest gap; 3 is still missing. hasNewMissingPackets stays
		// true (3 < largestObserved-reorderingThreshold), so suppression
		// continues.
		require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now.Add(time.Millisecond), true))
		require.Nil(t, tr.GetAckFrame(now.Add(time.Millisecond), true))

		// 3 arrives at 1.5ms — gap fully closed. The suppression clears on
		// the next ReceivedPacket call's hasNewMissingPackets check. The
		// pending ACK can flow but it's now a clean range.
		require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now.Add(1500*time.Microsecond), true))

		// After settle window expires, an ACK can be drained. It must NOT
		// contain a gap.
		ack = tr.GetAckFrame(now.Add(settle+time.Millisecond), false)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 5}}, ack.AckRanges,
			"the gap filled before the settle window expired, so the ACK must be a clean range")
	})

	t.Run("gap persists past settle window — ACK ships with gap", func(t *testing.T) {
		settle := 2 * time.Millisecond
		tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, settle)
		now := monotime.Now()

		require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
		require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
		require.NotNil(t, tr.GetAckFrame(now, true))

		// Open a gap at 3-4 by receiving 5.
		require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))

		// During the settle window the gap-revealing ACK is suppressed.
		require.Nil(t, tr.GetAckFrame(now.Add(time.Millisecond), true))

		// After the settle window expires, the ACK ships with the gap.
		ack := tr.GetAckFrame(now.Add(settle+time.Microsecond), true)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{
			{Smallest: 5, Largest: 5},
			{Smallest: 1, Largest: 2},
		}, ack.AckRanges)
	})

	t.Run("settle = 0 preserves current immediate-ACK behavior", func(t *testing.T) {
		tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, 0)
		now := monotime.Now()

		require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
		require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
		require.NotNil(t, tr.GetAckFrame(now, true))

		// Open a gap; with settle disabled the ACK is queued immediately.
		require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))
		ack := tr.GetAckFrame(now, true)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{
			{Smallest: 5, Largest: 5},
			{Smallest: 1, Largest: 2},
		}, ack.AckRanges)
	})

	t.Run("settle window does not delay normal ACKs that arrive before any gap", func(t *testing.T) {
		settle := 2 * time.Millisecond
		tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, settle)
		now := monotime.Now()

		// Two in-order packets must still trigger the standard every-2
		// ACK — settle only affects gap-revealing ACKs.
		require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
		require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
		ack := tr.GetAckFrame(now, true)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, ack.AckRanges)
	})

	t.Run("packets-threshold trigger during settle does not leak the gap", func(t *testing.T) {
		settle := 5 * time.Millisecond
		tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, settle)
		now := monotime.Now()

		require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
		require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
		require.NotNil(t, tr.GetAckFrame(now, true))

		// Open a single persistent gap at 3 by receiving 4.
		require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now, true))
		require.Nil(t, tr.GetAckFrame(now, true))

		// More in-order packets arrive, contiguous with 4, so no NEW gap
		// opens (only the original gap at 3 remains). Packets-threshold
		// (every 2 ack-eliciting) would normally trigger an immediate
		// ACK, but settle suppression must hold until the window
		// expires — otherwise the gap-revealing ACK leaks early.
		require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now.Add(time.Millisecond), true))
		require.NoError(t, tr.ReceivedPacket(6, protocol.ECNNon, now.Add(time.Millisecond), true))
		require.Nil(t, tr.GetAckFrame(now.Add(time.Millisecond), true),
			"settle window must suppress all ACKs that would expose the unfilled gap")

		// Once the window expires, the ACK ships with the unfilled gap
		// at 3.
		ack := tr.GetAckFrame(now.Add(settle+time.Microsecond), true)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{
			{Smallest: 4, Largest: 6},
			{Smallest: 1, Largest: 2},
		}, ack.AckRanges)
	})

	t.Run("overlapping gaps: new gap during settle refreshes the window", func(t *testing.T) {
		settle := 2 * time.Millisecond
		tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, settle)
		now := monotime.Now()

		require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
		require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
		require.NotNil(t, tr.GetAckFrame(now, true))

		// Gap A: packet 5 arrives at t=0 (PNs 3,4 missing). Settle armed
		// until t=2ms.
		require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))
		require.Nil(t, tr.GetAckFrame(now, true))

		// Gap B: packet 8 arrives at t=1ms (PNs 6,7 newly missing). With
		// the prior, buggy implementation the settle would not refresh
		// because ackQueued was already set by the packets-threshold —
		// the window would expire at t=2ms while gap B had only had 1ms
		// of settle. The fix refreshes settle to t=1+2=3ms regardless
		// of ackQueued.
		require.NoError(t, tr.ReceivedPacket(8, protocol.ECNNon, now.Add(time.Millisecond), true))

		// Fill gap A at t=1.5ms — but gap B remains open. Suppression
		// must continue.
		require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now.Add(1500*time.Microsecond), true))
		require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now.Add(1500*time.Microsecond), true))

		// At t=2.5ms, gap A's original window has expired but gap B's
		// refreshed window (until t=3ms) still suppresses.
		require.Nil(t, tr.GetAckFrame(now.Add(2500*time.Microsecond), true),
			"gap B's refreshed settle must still suppress the ACK past gap A's original expiry")

		// Fill gap B at t=2.6ms — all gaps now closed. The suppression
		// clears on this ReceivedPacket call.
		require.NoError(t, tr.ReceivedPacket(6, protocol.ECNNon, now.Add(2600*time.Microsecond), true))
		require.NoError(t, tr.ReceivedPacket(7, protocol.ECNNon, now.Add(2600*time.Microsecond), true))

		// The ACK can now ship and must be a clean range covering 1-8.
		ack := tr.GetAckFrame(now.Add(2600*time.Microsecond), false)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 8}}, ack.AckRanges,
			"both gaps filled within their (possibly refreshed) settle windows, so the ACK must be clean")
	})

	t.Run("overlapping gaps: latest gap settle expires with both gaps still open", func(t *testing.T) {
		settle := 2 * time.Millisecond
		tr := newAppDataReceivedPacketTracker(utils.DefaultLogger, settle)
		now := monotime.Now()

		require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
		require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
		require.NotNil(t, tr.GetAckFrame(now, true))

		// Two overlapping gaps that never fill: gap A at PN 3 (opened by
		// packet 4 at t=0), gap B at PN 5 (opened by packet 6 at t=1ms).
		// Refreshed settle window ends at t=3ms.
		require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now, true))
		require.NoError(t, tr.ReceivedPacket(6, protocol.ECNNon, now.Add(time.Millisecond), true))

		// Before the refreshed settle expires, the ACK stays suppressed.
		require.Nil(t, tr.GetAckFrame(now.Add(2*time.Millisecond+500*time.Microsecond), true))

		// After the refreshed window expires, the ACK ships with both
		// gaps reported.
		ack := tr.GetAckFrame(now.Add(3*time.Millisecond+time.Microsecond), true)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{
			{Smallest: 6, Largest: 6},
			{Smallest: 4, Largest: 4},
			{Smallest: 1, Largest: 2},
		}, ack.AckRanges)
	})
}
