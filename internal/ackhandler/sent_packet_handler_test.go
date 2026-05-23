package ackhandler

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type customFrameHandler struct {
	onLost, onAcked func(wire.Frame)
}

func (h *customFrameHandler) OnLost(f wire.Frame) {
	if h.onLost != nil {
		h.onLost(f)
	}
}

func (h *customFrameHandler) OnAcked(f wire.Frame) {
	if h.onAcked != nil {
		h.onAcked(f)
	}
}

type packetTracker struct {
	Acked []protocol.PacketNumber
	Lost  []protocol.PacketNumber
}

func (t *packetTracker) Reset() {
	t.Acked = nil
	t.Lost = nil
}

func (t *packetTracker) NewPingFrame(pn protocol.PacketNumber) Frame {
	return Frame{
		Frame: &wire.PingFrame{},
		Handler: &customFrameHandler{
			onAcked: func(wire.Frame) { t.Acked = append(t.Acked, pn) },
			onLost:  func(wire.Frame) { t.Lost = append(t.Lost, pn) },
		},
	}
}

func (h *sentPacketHandler) getBytesInFlight() protocol.ByteCount {
	return h.bytesInFlight
}

func ackRanges(pns ...protocol.PacketNumber) []wire.AckRange {
	return appendAckRanges(nil, pns...)
}

func appendAckRanges(ranges []wire.AckRange, pns ...protocol.PacketNumber) []wire.AckRange {
	if len(pns) == 0 {
		return ranges
	}
	slices.Sort(pns)
	slices.Reverse(pns)

	start := pns[0]
	for i := 1; i < len(pns); i++ {
		if pns[i-1]-pns[i] > 1 {
			ranges = append(ranges, wire.AckRange{Smallest: pns[i-1], Largest: start})
			start = pns[i]
		}
	}
	return append(ranges, wire.AckRange{Smallest: pns[len(pns)-1], Largest: start})
}

func TestAckRanges(t *testing.T) {
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 1}}, ackRanges(1))
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, ackRanges(1, 2))
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 3}}, ackRanges(1, 2, 3))
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 3}}, ackRanges(3, 2, 1))
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 3}}, ackRanges(1, 3, 2))

	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 3}, {Smallest: 1, Largest: 1}}, ackRanges(1, 3))
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 4}, {Smallest: 1, Largest: 1}}, ackRanges(1, 3, 4))
	require.Equal(t, []wire.AckRange{{Smallest: 5, Largest: 6}, {Smallest: 0, Largest: 2}}, ackRanges(0, 1, 2, 5, 6))
}

func TestSentPacketHandlerSendAndAcknowledge(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testSentPacketHandlerSendAndAcknowledge(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testSentPacketHandlerSendAndAcknowledge(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testSentPacketHandlerSendAndAcknowledge(t, protocol.Encryption1RTT)
	})
}

func testSentPacketHandlerSendAndAcknowledge(t *testing.T, encLevel protocol.EncryptionLevel) {
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	var packets packetTracker
	var pns []protocol.PacketNumber
	now := monotime.Now()
	for i := range 10 {
		e := encLevel
		// also send some 0-RTT packets to make sure they're acknowledged in the same packet number space
		if encLevel == protocol.Encryption1RTT && i < 5 {
			e = protocol.Encryption0RTT
		}
		pn := sph.PopPacketNumber(e)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, e, protocol.ECNNon, 1200, false, false)
		pns = append(pns, pn)
	}

	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2], pns[3], pns[4], pns[7], pns[8], pns[9])},
		encLevel,
		monotime.Now(),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1], pns[2], pns[3], pns[4], pns[7], pns[8], pns[9]}, packets.Acked)

	// ACKs that don't acknowledge new packets are ok
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[1], pns[2], pns[3])},
		encLevel,
		monotime.Now(),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1], pns[2], pns[3], pns[4], pns[7], pns[8], pns[9]}, packets.Acked)

	// ACKs that don't acknowledge packets that we didn't send are not ok
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[7], pns[8], pns[9], pns[9]+1)},
		encLevel,
		monotime.Now(),
	)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "received ACK for an unsent packet")
}

func TestSentPacketHandlerAcknowledgeSkippedPacket(t *testing.T) {
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	now := monotime.Now()
	lastPN := protocol.InvalidPacketNumber
	skippedPN := protocol.InvalidPacketNumber
	for {
		pn, _ := sph.PeekPacketNumber(protocol.Encryption1RTT)
		require.Equal(t, pn, sph.PopPacketNumber(protocol.Encryption1RTT))
		if pn > lastPN+1 {
			skippedPN = pn - 1
		}
		if pn >= 1e6 {
			t.Fatal("expected a skipped packet number")
		}
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
		lastPN = pn
		if skippedPN != protocol.InvalidPacketNumber {
			break
		}
	}

	_, err := sph.ReceivedAck(&wire.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: 0, Largest: lastPN}},
	}, protocol.Encryption1RTT, monotime.Now())
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, fmt.Sprintf("received an ACK for skipped packet number: %d (1-RTT)", skippedPN))
}

func TestSentPacketHandlerRTTAckEliciting(t *testing.T) {
	var eventRecorder events.Recorder

	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		&eventRecorder,
		utils.DefaultLogger,
		0,
		0,
	)

	getPacketsInFlight := func() int {
		evs := eventRecorder.Events(qlog.MetricsUpdated{})
		return evs[len(evs)-1].(qlog.MetricsUpdated).PacketsInFlight
	}
	getBytesInFlight := func() int {
		evs := eventRecorder.Events(qlog.MetricsUpdated{})
		return evs[len(evs)-1].(qlog.MetricsUpdated).BytesInFlight
	}

	sendPacket := func(t *testing.T, ti monotime.Time, size protocol.ByteCount, ackEliciting bool) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		var frames []Frame
		if ackEliciting {
			frames = []Frame{{Frame: &wire.PingFrame{}}}
		}
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, frames, protocol.Encryption1RTT, protocol.ECNNon, size, false, false)
		return pn
	}

	ackPackets := func(t *testing.T, ti monotime.Time, pns ...protocol.PacketNumber) {
		t.Helper()
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns...)}, protocol.Encryption1RTT, ti)
		require.NoError(t, err)
	}

	now := monotime.Now()
	pn1 := sendPacket(t, now, 1200, true)
	require.Equal(t, 1, getPacketsInFlight())
	require.Equal(t, 1200, getBytesInFlight())
	pn2 := sendPacket(t, now, 1100, false)
	// Sending a non-ack-eliciting packet doesn't change bytes or packets in flight.
	// Non-ack-eliciting packets are not included in congestion control.
	require.Equal(t, 1, getPacketsInFlight())
	require.Equal(t, 1200, getBytesInFlight())
	pn3 := sendPacket(t, now, 1000, true)
	require.Equal(t, 2, getPacketsInFlight())
	require.Equal(t, 2200, getBytesInFlight())
	// the RTT is recorded, since the largest acknowledged packet is ack-eliciting
	now = now.Add(200 * time.Millisecond)
	ackPackets(t, now, pn1, pn2, pn3)
	require.Equal(t, 200*time.Millisecond, rttStats.LatestRTT())
	require.Zero(t, getPacketsInFlight())
	require.Zero(t, getBytesInFlight())

	pn4 := sendPacket(t, now, 1200, false)
	// non-ack-eliciting packets don't trigger metrics updates
	require.Zero(t, getPacketsInFlight())
	require.Zero(t, getBytesInFlight())
	pn5 := sendPacket(t, now, 500, false)
	require.Zero(t, getPacketsInFlight())
	require.Zero(t, getBytesInFlight())
	now = now.Add(500 * time.Millisecond)
	// only non-ack-eliciting packets are newly acknowledged, so the RTT is not updated
	ackPackets(t, now, pn2, pn3, pn4, pn5)
	require.Equal(t, 200*time.Millisecond, rttStats.LatestRTT())

	pn6 := sendPacket(t, now, 1400, true)
	require.Equal(t, 1, getPacketsInFlight())
	require.Equal(t, 1400, getBytesInFlight())
	pn7 := sendPacket(t, now, 1100, false)
	// non-ack-eliciting packet doesn't change metrics
	require.Equal(t, 1, getPacketsInFlight())
	require.Equal(t, 1400, getBytesInFlight())
	now = now.Add(800 * time.Millisecond)
	// largest acknowledged packet is not ack-eliciting, but one new ack-eliciting
	// packet was acknowledged, so the RTT is updated
	ackPackets(t, now, pn6, pn7)
	require.Equal(t, 800*time.Millisecond, rttStats.LatestRTT())
	require.Zero(t, getPacketsInFlight())
	require.Zero(t, getBytesInFlight())
}

func TestSentPacketHandlerRTTAcrossPacketNumberSpaces(t *testing.T) {
	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	sendPacket := func(t *testing.T, ti monotime.Time, encLevel protocol.EncryptionLevel) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(encLevel)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, encLevel, protocol.ECNNon, 1200, false, false)
		return pn
	}

	ackPackets := func(t *testing.T, ti monotime.Time, encLevel protocol.EncryptionLevel, pns ...protocol.PacketNumber) {
		t.Helper()
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns...)}, encLevel, ti)
		require.NoError(t, err)
	}

	now := monotime.Now()
	initial1 := sendPacket(t, now, protocol.EncryptionInitial)
	handshake1 := sendPacket(t, now.Add(time.Second), protocol.EncryptionHandshake)
	initial2 := sendPacket(t, now.Add(2*time.Second), protocol.EncryptionInitial)
	handshake2 := sendPacket(t, now.Add(2*time.Second), protocol.EncryptionHandshake)

	ackPackets(t, now.Add(3*time.Second), protocol.EncryptionInitial, initial1, initial2)
	require.Equal(t, time.Second, rttStats.LatestRTT())

	// No RTT measurement, since the second initial packet was sent after the first handshake packet.
	ackPackets(t, now.Add(4*time.Second), protocol.EncryptionHandshake, handshake1)
	require.Equal(t, time.Second, rttStats.LatestRTT())

	// This causes an RTT measurement, since the second handshake packet was sent last.
	ackPackets(t, now.Add(5*time.Second), protocol.EncryptionHandshake, handshake1, handshake2)
	require.Equal(t, 3*time.Second, rttStats.LatestRTT())
}

func TestSentPacketHandlerRTTAckDelays(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testSentPacketHandlerRTTAckDelays(t, protocol.EncryptionInitial, false)
	})
	t.Run("Handshake", func(t *testing.T) {
		testSentPacketHandlerRTTAckDelays(t, protocol.EncryptionHandshake, false)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testSentPacketHandlerRTTAckDelays(t, protocol.Encryption1RTT, true)
	})
}

func testSentPacketHandlerRTTAckDelays(t *testing.T, encLevel protocol.EncryptionLevel, usesAckDelay bool) {
	expectedRTTStats := utils.NewRTTStats()
	expectedRTTStats.SetMaxAckDelay(time.Second)
	rttStats := utils.NewRTTStats()
	rttStats.SetMaxAckDelay(time.Second)
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(encLevel)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, encLevel, protocol.ECNNon, 1200, false, false)
		return pn
	}

	ackPacket := func(pn protocol.PacketNumber, ti monotime.Time, d time.Duration) {
		t.Helper()
		_, err := sph.ReceivedAck(&wire.AckFrame{DelayTime: d, AckRanges: ackRanges(pn)}, encLevel, ti)
		require.NoError(t, err)
	}

	var packets []protocol.PacketNumber
	now := monotime.Now()
	// send some packets and receive ACKs with 0 ack delay
	for range 5 {
		packets = append(packets, sendPacket(t, now))
	}
	for i := range 5 {
		expectedRTTStats.UpdateRTT(time.Duration(i+1)*time.Second, 0)
		now = now.Add(time.Second)
		ackPacket(packets[i], now, 0)
		require.Equal(t, expectedRTTStats.SmoothedRTT(), rttStats.SmoothedRTT())
		require.Equal(t, time.Second, rttStats.MinRTT())
		require.Equal(t, time.Duration(i+1)*time.Second, rttStats.LatestRTT())
	}
	packets = packets[:0]

	// send some more packets and receive ACKs with non-zero ack delay
	for range 5 {
		packets = append(packets, sendPacket(t, now))
	}
	expectedRTTStatsNoAckDelay := expectedRTTStats.Clone()
	for i := range 5 {
		const ackDelay = 500 * time.Millisecond
		expectedRTTStats.UpdateRTT(time.Duration(i+1)*time.Second, ackDelay)
		expectedRTTStatsNoAckDelay.UpdateRTT(time.Duration(i+1)*time.Second, 0)
		now = now.Add(time.Second)
		ackPacket(packets[i], now, ackDelay)
		if usesAckDelay {
			require.Equal(t, expectedRTTStats.SmoothedRTT(), rttStats.SmoothedRTT())
		} else {
			require.Equal(t, expectedRTTStatsNoAckDelay.SmoothedRTT(), rttStats.SmoothedRTT())
		}
	}
	packets = packets[:0]
	// make sure that taking ack delay into account actually changes the RTT,
	// otherwise the test is not meaningful
	require.NotEqual(t, expectedRTTStats.SmoothedRTT(), expectedRTTStatsNoAckDelay.SmoothedRTT())

	// Send two more packets, and acknowledge them in opposite order.
	// This tests that the RTT is updated even if the ACK doesn't increase the largest acked.
	packets = append(packets, sendPacket(t, now))
	packets = append(packets, sendPacket(t, now))
	ackPacket(packets[1], now.Add(time.Second), 0)
	rtt := rttStats.SmoothedRTT()
	ackPacket(packets[0], now.Add(10*time.Second), 0)
	require.NotEqual(t, rtt, rttStats.SmoothedRTT())

	// Send one more packet, and send where the largest acked is acknowledged twice.
	pn := sendPacket(t, now)
	ackPacket(pn, now.Add(time.Second), 0)
	rtt = rttStats.SmoothedRTT()
	ackPacket(pn, now.Add(10*time.Second), 0)
	require.Equal(t, rtt, rttStats.SmoothedRTT())
}

func TestSentPacketHandlerAmplificationLimitServer(t *testing.T) {
	t.Run("address validated", func(t *testing.T) {
		testSentPacketHandlerAmplificationLimitServer(t, true)
	})
	t.Run("address not validated", func(t *testing.T) {
		testSentPacketHandlerAmplificationLimitServer(t, false)
	})
}

func testSentPacketHandlerAmplificationLimitServer(t *testing.T, addressValidated bool) {
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		addressValidated,
		false,
		nil,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	if addressValidated {
		require.Equal(t, SendAny, sph.SendMode(monotime.Now()))
		return
	}

	// no data received yet, so we can't send any packet yet
	require.Equal(t, SendNone, sph.SendMode(monotime.Now()))
	require.Zero(t, sph.GetLossDetectionTimeout())

	// Receive 1000 bytes from the client.
	// As long as we haven't sent out 3x the amount of bytes received, we can send out new packets,
	// even if we go above the 3x limit by sending the last packet.
	sph.ReceivedBytes(1000, monotime.Now())
	for i := range 4 {
		require.Equal(t, SendAny, sph.SendMode(monotime.Now()))
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		sph.SentPacket(monotime.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 999, false, false)
		if i != 3 {
			require.NotZero(t, sph.GetLossDetectionTimeout())
		}
	}
	require.Equal(t, SendNone, sph.SendMode(monotime.Now()))
	// no need to set a loss detection timer, as we're blocked by the amplification limit
	require.Zero(t, sph.GetLossDetectionTimeout())

	// receiving more data allows us to send out more packets
	sph.ReceivedBytes(1000, monotime.Now())
	require.NotZero(t, sph.GetLossDetectionTimeout())
	for range 3 {
		require.Equal(t, SendAny, sph.SendMode(monotime.Now()))
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		sph.SentPacket(monotime.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)
	}
	require.Equal(t, SendNone, sph.SendMode(monotime.Now()))
	require.Zero(t, sph.GetLossDetectionTimeout())

	// receiving an Initial packet doesn't validate the client's address
	sph.ReceivedPacket(protocol.EncryptionInitial, monotime.Now())
	require.Equal(t, SendNone, sph.SendMode(monotime.Now()))
	require.Zero(t, sph.GetLossDetectionTimeout())

	// receiving a Handshake packet validates the client's address
	sph.ReceivedPacket(protocol.EncryptionHandshake, monotime.Now())
	require.Equal(t, SendAny, sph.SendMode(monotime.Now()))
	require.NotZero(t, sph.GetLossDetectionTimeout())
}

func TestSentPacketHandlerAmplificationLimitClient(t *testing.T) {
	t.Run("handshake ACK", func(t *testing.T) {
		testSentPacketHandlerAmplificationLimitClient(t, false)
	})

	t.Run("drop Handshake without ACK", func(t *testing.T) {
		testSentPacketHandlerAmplificationLimitClient(t, true)
	})
}

func testSentPacketHandlerAmplificationLimitClient(t *testing.T, dropHandshake bool) {
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	require.Equal(t, SendAny, sph.SendMode(monotime.Now()))
	pn := sph.PopPacketNumber(protocol.EncryptionInitial)
	sph.SentPacket(monotime.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 999, false, false)
	// it's not surprising that the loss detection timer is set, as this packet might be lost...
	require.NotZero(t, sph.GetLossDetectionTimeout())
	// ... but it's still set after receiving an ACK for this packet,
	// since we might need to unblock the server's amplification limit
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, monotime.Now())
	require.NoError(t, err)
	require.NotZero(t, sph.GetLossDetectionTimeout())
	require.Equal(t, SendAny, sph.SendMode(monotime.Now()))

	// when the timer expires, we should send a PTO packet
	sph.OnLossDetectionTimeout(monotime.Now())
	require.Equal(t, SendPTOInitial, sph.SendMode(monotime.Now()))
	require.NotZero(t, sph.GetLossDetectionTimeout())

	if dropHandshake {
		// dropping the handshake packet number space completes the handshake,
		// even if no ACK for a handshake packet was received
		sph.DropPackets(protocol.EncryptionHandshake, monotime.Now())
		require.Zero(t, sph.GetLossDetectionTimeout())
		return
	}

	// once the Initial packet number space is dropped, we need to send a Handshake PTO packet,
	// even if we haven't sent any packet in the Handshake packet number space yet
	sph.DropPackets(protocol.EncryptionInitial, monotime.Now())
	require.NotZero(t, sph.GetLossDetectionTimeout())
	sph.OnLossDetectionTimeout(monotime.Now())
	require.Equal(t, SendPTOHandshake, sph.SendMode(monotime.Now()))

	// receiving an ACK for a handshake packet shows that the server completed address validation
	pn = sph.PopPacketNumber(protocol.EncryptionHandshake)
	sph.SentPacket(monotime.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionHandshake, protocol.ECNNon, 999, false, false)
	require.NotZero(t, sph.GetLossDetectionTimeout())
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionHandshake, monotime.Now())
	require.NoError(t, err)
	require.Zero(t, sph.GetLossDetectionTimeout())
}

func TestSentPacketHandlerDelayBasedLossDetection(t *testing.T) {
	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time, isPathMTUProbePacket bool) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, isPathMTUProbePacket, false)
		return pn
	}

	const rtt = time.Second
	now := monotime.Now()
	t1 := now.Add(-rtt)
	t2 := now.Add(-10 * time.Millisecond)
	// Send 3 packets
	pn1 := sendPacket(t, t1, false)
	pn2 := sendPacket(t, t2, false)
	// Also send a Path MTU probe packet.
	// We expect the same loss recovery logic to be applied to it.
	pn3 := sendPacket(t, t2, true)
	pn4 := sendPacket(t, now, false)

	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn4)},
		protocol.EncryptionInitial,
		now.Add(time.Second),
	)
	require.NoError(t, err)
	// make sure that the RTT is actually 1s
	require.Equal(t, rtt, rttStats.SmoothedRTT())
	require.Equal(t, []protocol.PacketNumber{pn4}, packets.Acked)
	// only the first packet was lost
	require.Equal(t, []protocol.PacketNumber{pn1}, packets.Lost)
	// ... but we armed a timer to declare packet 2 lost after 9/8 RTTs
	require.Equal(t, t2.Add(time.Second*9/8), sph.GetLossDetectionTimeout())

	sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout().Add(-time.Microsecond))
	require.Len(t, packets.Lost, 1)
	sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout())
	require.Equal(t, []protocol.PacketNumber{pn1, pn2, pn3}, packets.Lost)
}

func TestSentPacketHandlerPacketBasedLossDetection(t *testing.T) {
	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	var packets packetTracker
	now := monotime.Now()
	var pns []protocol.PacketNumber
	for range 5 {
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)
		pns = append(pns, pn)
	}

	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[3])},
		protocol.EncryptionInitial,
		now.Add(time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[3]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[0]}, packets.Lost)

	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[4])},
		protocol.EncryptionInitial,
		now.Add(time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[3], pns[4]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)
}

func TestSentPacketHandlerPTO(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testSentPacketHandlerPTO(t, protocol.EncryptionInitial, SendPTOInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testSentPacketHandlerPTO(t, protocol.EncryptionHandshake, SendPTOHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testSentPacketHandlerPTO(t, protocol.Encryption1RTT, SendPTOAppData)
	})
}

func testSentPacketHandlerPTO(t *testing.T, encLevel protocol.EncryptionLevel, ptoMode SendMode) {
	var packets packetTracker
	var eventRecorder events.Recorder

	rttStats := utils.NewRTTStats()
	rttStats.SetMaxAckDelay(25 * time.Millisecond)
	rttStats.UpdateRTT(500*time.Millisecond, 0)
	rttStats.UpdateRTT(1000*time.Millisecond, 0)
	rttStats.UpdateRTT(1500*time.Millisecond, 0)
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		&eventRecorder,
		utils.DefaultLogger,
		0,
		0,
	)

	// in the application-data packet number space, the PTO is only set
	if encLevel == protocol.Encryption1RTT {
		sph.DropPackets(protocol.EncryptionInitial, monotime.Now())
		sph.DropPackets(protocol.EncryptionHandshake, monotime.Now())
	}

	sendPacket := func(t *testing.T, ti monotime.Time, ackEliciting bool, ptoCount uint) protocol.PacketNumber {
		t.Helper()

		pn := sph.PopPacketNumber(encLevel)
		if ackEliciting {
			sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, encLevel, protocol.ECNNon, 1000, false, false)
			require.Equal(t,
				[]qlogwriter.Event{
					qlog.LossTimerUpdated{
						Type:      qlog.LossTimerUpdateTypeSet,
						TimerType: qlog.TimerTypePTO,
						EncLevel:  encLevel,
						Time:      ti.ToTime().Add(rttStats.PTO(encLevel == protocol.Encryption1RTT) << ptoCount),
					},
				},
				eventRecorder.Events(qlog.LossTimerUpdated{}),
			)
			eventRecorder.Clear()
		} else {
			sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, nil, encLevel, protocol.ECNNon, 1000, true, false)
			require.Empty(t, eventRecorder.Events(qlog.LossTimerUpdated{}))
		}
		return pn
	}

	now := monotime.Now()
	sendTimes := []monotime.Time{
		now,
		now.Add(100 * time.Millisecond),
		now.Add(200 * time.Millisecond),
		now.Add(300 * time.Millisecond),
	}
	var pns []protocol.PacketNumber
	// send packet 0, 1, 2, 3
	for i := range 3 {
		pns = append(pns, sendPacket(t, sendTimes[i], true, 0))
	}
	pns = append(pns, sendPacket(t, sendTimes[3], false, 0))

	// The PTO includes the max_ack_delay only for the application-data packet number space.
	// Make sure that the value is actually different, so this test is meaningful.
	require.NotEqual(t, rttStats.PTO(true), rttStats.PTO(false))

	timeout := sph.GetLossDetectionTimeout()
	// the PTO is based on the *last* ack-eliciting packet
	require.Equal(t, sendTimes[2].Add(rttStats.PTO(encLevel == protocol.Encryption1RTT)), timeout)

	eventRecorder.Clear()
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeExpired,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  encLevel,
			},
			qlog.PTOCountUpdated{PTOCount: 1},
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeSet,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  encLevel,
				Time:      sendTimes[2].Add(2 * rttStats.PTO(encLevel == protocol.Encryption1RTT)).ToTime(),
			},
		},
		eventRecorder.Events(qlog.PTOCountUpdated{}, qlog.LossTimerUpdated{}),
	)
	// PTO timer expiration doesn't declare packets lost
	require.Empty(t, packets.Lost)

	now = timeout
	require.Equal(t, ptoMode, sph.SendMode(now))
	// queue a probe packet
	require.True(t, sph.QueueProbePacket(encLevel))
	require.True(t, sph.QueueProbePacket(encLevel))
	require.True(t, sph.QueueProbePacket(encLevel))
	// there are only two ack-eliciting packets that could be queued
	require.False(t, sph.QueueProbePacket(encLevel))
	// Queueing probe packets currently works by declaring them lost.
	// We shouldn't do this, but this is how the code is currently written.
	require.Equal(t, pns[:3], packets.Lost)
	packets.Lost = packets.Lost[:0]

	eventRecorder.Clear()

	// send packet 4 and 6 as probe packets
	// 5 doesn't count, since it's not an ack-eliciting packet
	sendTimes = append(sendTimes, now.Add(100*time.Millisecond))
	sendTimes = append(sendTimes, now.Add(200*time.Millisecond))
	sendTimes = append(sendTimes, now.Add(300*time.Millisecond))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[4])) // first probe packet
	pns = append(pns, sendPacket(t, sendTimes[4], true, 1))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[5])) // next probe packet
	pns = append(pns, sendPacket(t, sendTimes[5], false, 1))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[6])) // non-ack-eliciting packet didn't count as a probe packet
	pns = append(pns, sendPacket(t, sendTimes[6], true, 1))
	require.Equal(t, SendAny, sph.SendMode(sendTimes[6])) // enough probe packets sent

	timeout = sph.GetLossDetectionTimeout()
	// exponential backoff
	require.Equal(t, sendTimes[6].Add(2*rttStats.PTO(encLevel == protocol.Encryption1RTT)), timeout)
	now = timeout

	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeExpired,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  encLevel,
			},
			qlog.PTOCountUpdated{PTOCount: 2},
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeSet,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  encLevel,
				Time:      sendTimes[6].Add(4 * rttStats.PTO(encLevel == protocol.Encryption1RTT)).ToTime(),
			},
		},
		eventRecorder.Events(qlog.LossTimerUpdated{}, qlog.PTOCountUpdated{}),
	)
	eventRecorder.Clear()
	// PTO timer expiration doesn't declare packets lost
	require.Empty(t, packets.Lost)

	// send packet 7, 8 as probe packets
	sendTimes = append(sendTimes, now.Add(100*time.Millisecond))
	sendTimes = append(sendTimes, now.Add(200*time.Millisecond))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[7])) // first probe packet
	pns = append(pns, sendPacket(t, sendTimes[7], true, 2))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[8])) // next probe packet
	pns = append(pns, sendPacket(t, sendTimes[8], true, 2))
	require.Equal(t, SendAny, sph.SendMode(sendTimes[8])) // enough probe packets sent

	timeout = sph.GetLossDetectionTimeout()

	// exponential backoff, again
	require.Equal(t, sendTimes[8].Add(4*rttStats.PTO(encLevel == protocol.Encryption1RTT)), timeout)

	eventRecorder.Clear()

	// Receive an ACK for packet 7.
	// This now declares packets lost, and leads to arming of a timer for packet 8.
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[7])},
		encLevel,
		sendTimes[7].Add(time.Microsecond),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[7]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[4], pns[6]}, packets.Lost)
	require.Len(t, eventRecorder.Events(qlog.PacketLost{}), 2)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PTOCountUpdated{PTOCount: 0},
		},
		eventRecorder.Events(qlog.PTOCountUpdated{})[:1],
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeSet,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  encLevel,
				Time:      sendTimes[8].Add(rttStats.PTO(encLevel == protocol.Encryption1RTT)).ToTime(),
			},
		},
		eventRecorder.Events(qlog.LossTimerUpdated{}),
	)
	require.Contains(t, packets.Acked, pns[7])

	// The PTO timer is now set for the last remaining packet (8),
	// with no exponential backoff.
	require.Equal(t, sendTimes[8].Add(rttStats.PTO(encLevel == protocol.Encryption1RTT)), sph.GetLossDetectionTimeout())

	// Acknowledge the last packet (8).
	// This should cancel the loss detection timer since there are no more outstanding packets.
	eventRecorder.Clear()
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[8])},
		encLevel,
		sendTimes[8].Add(time.Second),
	)
	require.NoError(t, err)
	require.Contains(t, packets.Acked, pns[8])

	// The loss detection timer should be cancelled since there are no more outstanding packets.
	require.True(t, sph.GetLossDetectionTimeout().IsZero())
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.LossTimerUpdated{Type: qlog.LossTimerUpdateTypeCancelled},
		},
		eventRecorder.Events(qlog.LossTimerUpdated{}),
	)
}

func TestSentPacketHandlerPacketNumberSpacesPTO(t *testing.T) {
	rttStats := utils.NewRTTStats()
	const rtt = time.Second
	rttStats.UpdateRTT(rtt, 0)
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	sendPacket := func(t *testing.T, ti monotime.Time, encLevel protocol.EncryptionLevel) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(encLevel)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, encLevel, protocol.ECNNon, 1000, false, false)
		return pn
	}

	var initialPNs, handshakePNs [4]protocol.PacketNumber
	var initialTimes, handshakeTimes [4]monotime.Time
	now := monotime.Now()
	initialPNs[0] = sendPacket(t, now, protocol.EncryptionInitial)
	initialTimes[0] = now
	now = now.Add(100 * time.Millisecond)
	handshakePNs[0] = sendPacket(t, now, protocol.EncryptionHandshake)
	handshakeTimes[0] = now
	now = now.Add(100 * time.Millisecond)
	initialPNs[1] = sendPacket(t, now, protocol.EncryptionInitial)
	initialTimes[1] = now
	now = now.Add(100 * time.Millisecond)
	handshakePNs[1] = sendPacket(t, now, protocol.EncryptionHandshake)
	handshakeTimes[1] = now
	require.Equal(t, protocol.ByteCount(4000), sph.(*sentPacketHandler).getBytesInFlight())

	// the PTO is the earliest time of the PTO times for both packet number spaces,
	// i.e. the 2nd Initial packet sent
	timeout := sph.GetLossDetectionTimeout()
	require.Equal(t, initialTimes[1].Add(rttStats.PTO(false)), timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOInitial, sph.SendMode(timeout))
	// send a PTO probe packet (Initial)
	now = timeout.Add(100 * time.Millisecond)
	initialPNs[2] = sendPacket(t, now, protocol.EncryptionInitial)
	initialTimes[2] = now

	// the earliest PTO time is now the 2nd Handshake packet
	timeout = sph.GetLossDetectionTimeout()
	// pto_count is a global property, so there's now an exponential backoff
	require.Equal(t, handshakeTimes[1].Add(2*rttStats.PTO(false)), timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOHandshake, sph.SendMode(timeout))
	// send a PTO probe packet (Handshake)
	now = timeout.Add(100 * time.Millisecond)
	handshakePNs[2] = sendPacket(t, now, protocol.EncryptionHandshake)
	handshakeTimes[2] = now

	// the earliest PTO time is now the 3rd Initial packet
	timeout = sph.GetLossDetectionTimeout()
	require.Equal(t, initialTimes[2].Add(4*rttStats.PTO(false)), timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOInitial, sph.SendMode(timeout))

	// drop the Initial packet number space
	now = timeout.Add(100 * time.Millisecond)
	require.Equal(t, protocol.ByteCount(6000), sph.(*sentPacketHandler).getBytesInFlight())
	sph.DropPackets(protocol.EncryptionInitial, now)
	require.Equal(t, protocol.ByteCount(3000), sph.(*sentPacketHandler).getBytesInFlight())

	// Since the Initial packets are gone:
	// * the earliest PTO time is now based on the 3rd Handshake packet
	// * the PTO count is reset to 0
	timeout = sph.GetLossDetectionTimeout()
	require.Equal(t, handshakeTimes[2].Add(rttStats.PTO(false)), timeout)

	// send a 1-RTT packet
	now = timeout.Add(100 * time.Millisecond)
	sendTime := now
	sendPacket(t, now, protocol.Encryption1RTT)

	// until handshake confirmation, the PTO timer is based on the Handshake packet number space
	require.Equal(t, timeout, sph.GetLossDetectionTimeout())
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOHandshake, sph.SendMode(now))

	// Drop Handshake packet number space.
	// This confirms the handshake, and the PTO timer is now based on the 1-RTT packet number space.
	sph.DropPackets(protocol.EncryptionHandshake, now)
	require.Equal(t, sendTime.Add(rttStats.PTO(false)), sph.GetLossDetectionTimeout())
}

func TestSentPacketHandler0RTT(t *testing.T) {
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	var appDataPackets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time, encLevel protocol.EncryptionLevel) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(encLevel)
		var frames []Frame
		if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
			frames = []Frame{appDataPackets.NewPingFrame(pn)}
		} else {
			frames = []Frame{{Frame: &wire.PingFrame{}}}
		}
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, frames, encLevel, protocol.ECNNon, 1000, false, false)
		return pn
	}

	now := monotime.Now()
	sendPacket(t, now, protocol.Encryption0RTT)
	sendPacket(t, now.Add(100*time.Millisecond), protocol.EncryptionHandshake)
	sendPacket(t, now.Add(200*time.Millisecond), protocol.Encryption0RTT)
	sendPacket(t, now.Add(300*time.Millisecond), protocol.Encryption1RTT)
	sendPacket(t, now.Add(400*time.Millisecond), protocol.Encryption1RTT)
	require.Equal(t, protocol.ByteCount(5000), sph.(*sentPacketHandler).getBytesInFlight())

	// The PTO timer is based on the Handshake packet number space, not the 0-RTT packets
	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOHandshake, sph.SendMode(timeout))

	now = timeout.Add(100 * time.Millisecond)
	sph.DropPackets(protocol.Encryption0RTT, now)
	require.Equal(t, protocol.ByteCount(3000), sph.(*sentPacketHandler).getBytesInFlight())
	// 0-RTT are discarded, not lost
	require.Empty(t, appDataPackets.Lost)
}

func TestSentPacketHandlerCongestion(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cong := mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)
	sph.(*sentPacketHandler).congestion = cong

	var packets packetTracker
	// Send the first 5 packets: not congestion-limited, not pacing-limited.
	// The 2nd packet is a Path MTU Probe packet.
	now := monotime.Now()
	var bytesInFlight protocol.ByteCount
	var pns []protocol.PacketNumber
	var sendTimes []monotime.Time
	for i := range 5 {
		gomock.InOrder(
			cong.EXPECT().CanSend(bytesInFlight).Return(true),
			cong.EXPECT().HasPacingBudget(now).Return(true),
		)
		require.Equal(t, SendAny, sph.SendMode(now))
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		bytesInFlight += 1000
		cong.EXPECT().OnPacketSent(now, bytesInFlight, pn, protocol.ByteCount(1000), true)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, i == 1, false)
		pns = append(pns, pn)
		sendTimes = append(sendTimes, now)
		now = now.Add(100 * time.Millisecond)
	}

	// try to send another packet: not congestion-limited, but pacing-limited
	now = now.Add(100 * time.Millisecond)
	gomock.InOrder(
		cong.EXPECT().CanSend(bytesInFlight).Return(true),
		cong.EXPECT().HasPacingBudget(now).Return(false),
	)
	require.Equal(t, SendPacingLimited, sph.SendMode(now))
	// the connection would call TimeUntilSend, to find out when a new packet can be sent again
	pacingDeadline := now.Add(500 * time.Millisecond)
	cong.EXPECT().TimeUntilSend(bytesInFlight).Return(pacingDeadline)
	require.Equal(t, pacingDeadline, sph.TimeUntilSend())

	// try to send another packet, but now we're congestion limited
	now = now.Add(100 * time.Millisecond)
	cong.EXPECT().CanSend(bytesInFlight).Return(false)
	require.Equal(t, SendAck, sph.SendMode(now)) // ACKs are allowed even if congestion limited

	// Receive an ACK for packet 3 and 4 (which declares the 1st and 2nd packet lost).
	// However, since the 2nd packet was a Path MTU probe packet, it won't get reported
	// to the congestion controller.
	ackTime := sendTimes[3].Add(time.Second)
	gomock.InOrder(
		cong.EXPECT().MaybeExitSlowStart(),
		cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(1000), protocol.ByteCount(5000)),
		cong.EXPECT().OnPacketAcked(pns[2], protocol.ByteCount(1000), protocol.ByteCount(5000), ackTime),
		cong.EXPECT().OnPacketAcked(pns[3], protocol.ByteCount(1000), protocol.ByteCount(5000), ackTime),
	)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[2], pns[3])}, protocol.EncryptionInitial, ackTime)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[2], pns[3]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)

	// Now receive a (delayed) ACK for the 1st packet.
	// Since this packet was already lost, we don't expect any calls to the congestion controller.
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[0])}, protocol.EncryptionInitial, ackTime)
	require.NoError(t, err)

	// we should now have a PTO timer armed for the 4th packet
	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOInitial, sph.SendMode(timeout))

	// send another packet to check that bytes_in_flight was correctly adjusted
	now = timeout.Add(100 * time.Millisecond)
	pn := sph.PopPacketNumber(protocol.EncryptionInitial)
	cong.EXPECT().OnPacketSent(now, protocol.ByteCount(2000), pn, protocol.ByteCount(1000), true)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)
}

func TestSentPacketHandlerRetry(t *testing.T) {
	t.Run("long RTT measurement", func(t *testing.T) {
		testSentPacketHandlerRetry(t, time.Second, time.Second)
	})

	// The estimated RTT should be at least 5ms, even if the RTT measurement is very short.
	t.Run("short RTT measurement", func(t *testing.T) {
		testSentPacketHandlerRetry(t, minRTTAfterRetry/3, minRTTAfterRetry)
	})
}

func testSentPacketHandlerRetry(t *testing.T, rtt, expectedRTT time.Duration) {
	var initialPackets, appDataPackets packetTracker

	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	start := monotime.Now()
	now := start
	var initialPNs, appDataPNs []protocol.PacketNumber
	// send 2 initial and 2 0-RTT packets
	for range 2 {
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		initialPNs = append(initialPNs, pn)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{initialPackets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)
		now = now.Add(100 * time.Millisecond)

		pn = sph.PopPacketNumber(protocol.Encryption0RTT)
		appDataPNs = append(appDataPNs, pn)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{appDataPackets.NewPingFrame(pn)}, protocol.Encryption0RTT, protocol.ECNNon, 1000, false, false)
		now = now.Add(100 * time.Millisecond)
	}
	require.Equal(t, protocol.ByteCount(4000), sph.(*sentPacketHandler).getBytesInFlight())
	require.NotZero(t, sph.GetLossDetectionTimeout())

	sph.ResetForRetry(start.Add(rtt))
	// receiving a Retry cancels all timers
	require.Zero(t, sph.GetLossDetectionTimeout())
	// all packets sent so far are declared lost
	require.Equal(t, []protocol.PacketNumber{initialPNs[0], initialPNs[1]}, initialPackets.Lost)
	require.Equal(t, []protocol.PacketNumber{appDataPNs[0], appDataPNs[1]}, appDataPackets.Lost)
	require.False(t, sph.QueueProbePacket(protocol.EncryptionInitial))
	require.False(t, sph.QueueProbePacket(protocol.Encryption0RTT))
	// the RTT measurement is taken from the first packet sent
	require.Equal(t, expectedRTT, rttStats.SmoothedRTT())
	require.Zero(t, sph.(*sentPacketHandler).getBytesInFlight())

	// packet numbers continue increasing
	initialPN, _ := sph.PeekPacketNumber(protocol.EncryptionInitial)
	require.Greater(t, initialPN, initialPNs[1])
	appDataPN, _ := sph.PeekPacketNumber(protocol.Encryption0RTT)
	require.Greater(t, appDataPN, appDataPNs[1])
}

func TestSentPacketHandlerRetryAfterPTO(t *testing.T) {
	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	var packets packetTracker
	start := monotime.Now()
	now := start
	pn1 := sph.PopPacketNumber(protocol.EncryptionInitial)
	sph.SentPacket(now, pn1, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn1)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)

	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOInitial, sph.SendMode(timeout))
	require.True(t, sph.QueueProbePacket(protocol.EncryptionInitial))

	// send a retransmission for the first packet
	now = timeout.Add(100 * time.Millisecond)
	pn2 := sph.PopPacketNumber(protocol.EncryptionInitial)
	sph.SentPacket(now, pn2, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn2)}, protocol.EncryptionInitial, protocol.ECNNon, 900, false, false)

	const rtt = time.Second
	sph.ResetForRetry(now.Add(rtt))

	require.Equal(t, []protocol.PacketNumber{pn1, pn2}, packets.Lost)
	// no RTT measurement is taken, since the PTO timer fired
	require.Equal(t, utils.DefaultInitialRTT, rttStats.SmoothedRTT())
}

func TestSentPacketHandlerECN(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cong := mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
	cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	cong.EXPECT().OnPacketAcked(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	cong.EXPECT().MaybeExitSlowStart().AnyTimes()
	ecnHandler := NewMockECNHandler(mockCtrl)
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)
	sph.(*sentPacketHandler).ecnTracker = ecnHandler
	sph.(*sentPacketHandler).congestion = cong

	// ECN marks on non-1-RTT packets are ignored
	sph.SentPacket(monotime.Now(), sph.PopPacketNumber(protocol.EncryptionInitial), protocol.InvalidPacketNumber, nil, nil, protocol.EncryptionInitial, protocol.ECT1, 1200, false, false)
	sph.SentPacket(monotime.Now(), sph.PopPacketNumber(protocol.EncryptionHandshake), protocol.InvalidPacketNumber, nil, nil, protocol.EncryptionHandshake, protocol.ECT0, 1200, false, false)
	sph.SentPacket(monotime.Now(), sph.PopPacketNumber(protocol.Encryption0RTT), protocol.InvalidPacketNumber, nil, nil, protocol.Encryption0RTT, protocol.ECNCE, 1200, false, false)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time, ecn protocol.ECN) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		ecnHandler.EXPECT().SentPacket(pn, ecn)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, ecn, 1200, false, false)
		return pn
	}

	pns := make([]protocol.PacketNumber, 4)
	now := monotime.Now()
	pns[0] = sendPacket(t, now, protocol.ECT1)
	now = now.Add(time.Second)
	pns[1] = sendPacket(t, now, protocol.ECT0)
	pns[2] = sendPacket(t, now, protocol.ECT0)
	pns[3] = sendPacket(t, now, protocol.ECT0)

	// Receive an ACK with a short RTT, such that the first packet is lost.
	cong.EXPECT().OnCongestionEvent(gomock.Any(), gomock.Any(), gomock.Any())
	ecnHandler.EXPECT().LostPacket(pns[0])
	ecnHandler.EXPECT().HandleNewlyAcked(gomock.Any(), int64(10), int64(11), int64(12)).DoAndReturn(func(packets []packetWithPacketNumber, _, _, _ int64) bool {
		require.Len(t, packets, 2)
		require.Equal(t, pns[2], packets[0].PacketNumber)
		require.Equal(t, pns[3], packets[1].PacketNumber)
		return false
	})
	_, err := sph.ReceivedAck(
		&wire.AckFrame{
			AckRanges: ackRanges(pns[2], pns[3]),
			ECT0:      10,
			ECT1:      11,
			ECNCE:     12,
		},
		protocol.Encryption1RTT,
		now.Add(100*time.Millisecond),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0]}, packets.Lost)

	// The second packet is still outstanding.
	// Receive a (delayed) ACK for it.
	// Since the new ECN counts were already reported, ECN marks on this ACK frame are ignored.
	// pns[0] is in the lost-packet tracker (CongestionInformed=true). The new
	// RTT sample on this ACK pushes 3*PTO above pns[0]'s age, so the tracker
	// cleanup ages it out — that triggers AbandonSpuriousLossUndo since the
	// loss can no longer be confirmed spurious by a later ACK.
	lostPN0 := pns[0]
	cong.EXPECT().AbandonSpuriousLossUndo(lostPN0)
	now = now.Add(100 * time.Millisecond)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[1])}, protocol.Encryption1RTT, now)
	require.NoError(t, err)

	// Send two more packets, and receive an ACK for the second one.
	pns = pns[:2]
	pns[0] = sendPacket(t, now, protocol.ECT1)
	pns[1] = sendPacket(t, now, protocol.ECT1)
	ecnHandler.EXPECT().HandleNewlyAcked(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(packets []packetWithPacketNumber, _, _, _ int64) bool {
			require.Len(t, packets, 1)
			require.Equal(t, pns[1], packets[0].PacketNumber)
			return false
		},
	)
	now = now.Add(100 * time.Millisecond)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[1])}, protocol.Encryption1RTT, now)
	require.NoError(t, err)
	// Receiving an ACK that covers both packets doesn't cause the ECN marks to be reported,
	// since the largest acked didn't increase.
	now = now.Add(100 * time.Millisecond)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1])}, protocol.Encryption1RTT, now)
	require.NoError(t, err)

	// Send another packet, and have the ECN handler report congestion.
	// This needs to be reported to the congestion controller.
	pns = pns[:1]
	now = now.Add(time.Second)
	pns[0] = sendPacket(t, now, protocol.ECT1)

	gomock.InOrder(
		ecnHandler.EXPECT().HandleNewlyAcked(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true),
		cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(0), gomock.Any()),
	)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[0])}, protocol.Encryption1RTT, now.Add(100*time.Millisecond))
	require.NoError(t, err)
}

func TestSentPacketHandlerPathProbe(t *testing.T) {
	const rtt = 10 * time.Millisecond // RTT of the original path
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(rtt, 0)

	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)
	sph.DropPackets(protocol.EncryptionInitial, monotime.Now())
	sph.DropPackets(protocol.EncryptionHandshake, monotime.Now())

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time, isPathProbe bool) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, isPathProbe)
		return pn
	}

	// send 5 packets: 2 non-probe packets, 1 probe packet, 2 non-probe packets
	now := monotime.Now()
	var pns [5]protocol.PacketNumber
	pns[0] = sendPacket(t, now, false)
	now = now.Add(rtt)
	pns[1] = sendPacket(t, now, false)
	pns[2] = sendPacket(t, now, true)
	pathProbeTimeout := now.Add(pathProbePacketLossTimeout)
	now = now.Add(rtt)
	pns[3] = sendPacket(t, now, false)
	now = now.Add(rtt)
	pns[4] = sendPacket(t, now, false)
	require.Less(t, sph.GetLossDetectionTimeout(), pathProbeTimeout)

	now = now.Add(100 * time.Millisecond)
	// make sure that this ACK doesn't declare the path probe packet lost
	require.Greater(t, pathProbeTimeout, now)
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[3], pns[4])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[3], pns[4]}, packets.Acked)
	// despite having been sent at the same time, the probe packet was not lost
	require.Equal(t, []protocol.PacketNumber{pns[1]}, packets.Lost)

	// the timeout is now based on the probe packet
	timeout := sph.GetLossDetectionTimeout()
	require.Equal(t, pathProbeTimeout, timeout)
	require.Zero(t, sph.(*sentPacketHandler).getBytesInFlight())
	pn1 := sendPacket(t, now, false)
	pn2 := sendPacket(t, now, false)
	require.Equal(t, protocol.ByteCount(2400), sph.(*sentPacketHandler).getBytesInFlight())

	// send one more non-probe packet
	pn := sendPacket(t, now, false)
	// the timeout is now based on this packet
	require.Less(t, sph.GetLossDetectionTimeout(), pathProbeTimeout)
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[2], pn)},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)

	packets.Lost = packets.Lost[:0]
	sph.MigratedPath(now, 1200)
	require.Zero(t, sph.(*sentPacketHandler).getBytesInFlight())
	require.Equal(t, utils.DefaultInitialRTT, rttStats.SmoothedRTT())
	require.Equal(t, []protocol.PacketNumber{pn1, pn2}, packets.Lost)
}

func TestSentPacketHandlerPathProbeAckAndLoss(t *testing.T) {
	const rtt = 10 * time.Millisecond // RTT of the original path
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(rtt, 0)

	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)
	sph.DropPackets(protocol.EncryptionInitial, monotime.Now())
	sph.DropPackets(protocol.EncryptionHandshake, monotime.Now())

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time, isPathProbe bool) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, isPathProbe)
		return pn
	}

	now := monotime.Now()
	pn1 := sendPacket(t, now, true)
	t1 := now
	now = now.Add(100 * time.Millisecond)
	_ = sendPacket(t, now, true)
	t2 := now
	now = now.Add(100 * time.Millisecond)
	pn3 := sendPacket(t, now, true)

	now = now.Add(100 * time.Millisecond)
	require.Equal(t, t1.Add(pathProbePacketLossTimeout), sph.GetLossDetectionTimeout())
	require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
	require.Equal(t, []protocol.PacketNumber{pn1}, packets.Lost)
	packets.Lost = packets.Lost[:0]

	// receive a delayed ACK for the path probe packet
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn1, pn3)},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pn3}, packets.Acked)
	require.Empty(t, packets.Lost)

	require.Equal(t, t2.Add(pathProbePacketLossTimeout), sph.GetLossDetectionTimeout())
}

// The packet tracking logic is pretty complex.
// We test it with a randomized approach, to make sure that it doesn't panic under any circumstances.
func TestSentPacketHandlerRandomized(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	for i := range 5 {
		t.Run(fmt.Sprintf("run %d (seed %d)", i+1, seed), func(t *testing.T) {
			testSentPacketHandlerRandomized(t, seed)
		})
		seed++
	}
}

func testSentPacketHandlerRandomized(t *testing.T, seed uint64) {
	var b [32]byte
	binary.BigEndian.PutUint64(b[:], seed)
	r := rand.New(rand.NewChaCha8(b))

	rttStats := utils.NewRTTStats()
	rtt := []time.Duration{10 * time.Millisecond, 100 * time.Millisecond, 1000 * time.Millisecond}[r.IntN(3)]
	t.Logf("rtt: %dms", rtt.Milliseconds())
	rttStats.UpdateRTT(rtt, 0) // RTT of the original path

	randDuration := func(min, max time.Duration) time.Duration {
		return time.Duration(rand.Int64N(int64(max-min))) + min
	}

	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)
	sph.DropPackets(protocol.EncryptionInitial, monotime.Now())
	sph.DropPackets(protocol.EncryptionHandshake, monotime.Now())

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time, isPathProbe bool) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, isPathProbe)
		return pn
	}

	now := monotime.Now()
	start := now
	var pns []protocol.PacketNumber
	for range 4 {
		isProbe := r.Int()%2 == 0
		pn := sendPacket(t, now, isProbe)
		t.Logf("t=%dms: sending packet %d (probe packet: %t)", now.Sub(start).Milliseconds(), pn, isProbe)
		pns = append(pns, pn)
		now = now.Add(randDuration(0, 500*time.Millisecond))
		if r.Int()%3 == 0 {
			sph.OnLossDetectionTimeout(now)
			t.Logf("t=%dms: loss detection timeout (lost: %v)", now.Sub(start).Milliseconds(), packets.Lost)
			packets.Reset()
			now = now.Add(randDuration(0, 500*time.Millisecond))
		}
		if r.Int()%3 == 0 {
			// acknowledge up to 2 random packet numbers from the pns slice
			var ackPns []protocol.PacketNumber
			if len(pns) > 0 {
				numToAck := min(1+r.IntN(2), len(pns))
				for range numToAck {
					ackPns = append(ackPns, pns[r.IntN(len(pns))])
				}
			}
			if len(ackPns) > 1 {
				slices.Sort(ackPns)
				ackPns = slices.Compact(ackPns)
			}
			sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(ackPns...)}, protocol.Encryption1RTT, now)
			t.Logf("t=%dms: received ACK for packets %v (acked: %v, lost: %v)", now.Sub(start).Milliseconds(), ackPns, packets.Acked, packets.Lost)
			packets.Reset()
			now = now.Add(randDuration(0, 500*time.Millisecond))
		}
		if r.Int()%10 == 0 {
			sph.MigratedPath(now, 1200)
			now = now.Add(randDuration(0, 500*time.Millisecond))
		}
	}
	t.Logf("t=%dms: loss detection timeout (lost: %v)", now.Sub(start).Milliseconds(), packets.Lost)
	sph.OnLossDetectionTimeout(now)
}

func TestSentPacketHandlerSpuriousLoss(t *testing.T) {
	const rtt = time.Second

	var eventRecorder events.Recorder

	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		&eventRecorder,
		utils.DefaultLogger,
		0,
		0,
	)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 20 {
		pns = append(pns, sendPacket(t, now))
		now = now.Add(10 * time.Millisecond)
	}

	now = start.Add(rtt)
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[6])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[6]}, packets.Acked)
	// pns[4] and pns[5] are not yet declared lost
	require.Equal(t, []protocol.PacketNumber{pns[1], pns[2], pns[3]}, packets.Lost)

	packets.Reset()
	eventRecorder.Clear()

	const secondAckDelay = 50 * time.Millisecond

	now = now.Add(secondAckDelay)
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2], pns[3], pns[4], pns[5], pns[6], pns[12], pns[16])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[4], pns[5], pns[12], pns[16]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[7], pns[8], pns[9], pns[10], pns[11], pns[13]}, packets.Lost)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.SpuriousLoss{
				EncryptionLevel:  protocol.Encryption1RTT,
				PacketNumber:     pns[1],
				PacketReordering: 16 - 1,
				TimeReordering:   rtt + secondAckDelay - 10*time.Millisecond,
			},
			qlog.SpuriousLoss{
				EncryptionLevel:  protocol.Encryption1RTT,
				PacketNumber:     pns[2],
				PacketReordering: 16 - 2,
				TimeReordering:   rtt + secondAckDelay - 20*time.Millisecond,
			},
			qlog.SpuriousLoss{
				EncryptionLevel:  protocol.Encryption1RTT,
				PacketNumber:     pns[3],
				PacketReordering: 16 - 3,
				TimeReordering:   rtt + secondAckDelay - 30*time.Millisecond,
			},
		},
		eventRecorder.Events(qlog.SpuriousLoss{}),
	)
	eventRecorder.Clear()

	now = now.Add(secondAckDelay)
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2], pns[3], pns[4], pns[5], pns[6], pns[7], pns[8], pns[9], pns[10], pns[16], pns[17], pns[18])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[4], pns[5], pns[12], pns[16], pns[17], pns[18]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[7], pns[8], pns[9], pns[10], pns[11], pns[13], pns[14], pns[15]}, packets.Lost)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.SpuriousLoss{
				EncryptionLevel:  protocol.Encryption1RTT,
				PacketNumber:     pns[7],
				PacketReordering: 18 - 7,
				TimeReordering:   rtt + 2*secondAckDelay - 70*time.Millisecond,
			},
			qlog.SpuriousLoss{
				EncryptionLevel:  protocol.Encryption1RTT,
				PacketNumber:     pns[8],
				PacketReordering: 18 - 8,
				TimeReordering:   rtt + 2*secondAckDelay - 80*time.Millisecond,
			},
			qlog.SpuriousLoss{
				EncryptionLevel:  protocol.Encryption1RTT,
				PacketNumber:     pns[9],
				PacketReordering: 18 - 9,
				TimeReordering:   rtt + 2*secondAckDelay - 90*time.Millisecond,
			},
			qlog.SpuriousLoss{
				EncryptionLevel:  protocol.Encryption1RTT,
				PacketNumber:     pns[10],
				PacketReordering: 18 - 10,
				TimeReordering:   rtt + 2*secondAckDelay - 100*time.Millisecond,
			},
		},
		eventRecorder.Events(qlog.SpuriousLoss{}),
	)
}

// newMockedSPH wires a SentPacketHandler whose congestion controller is a
// gomock mock, returning both the SPH and the mock.
// TestSentPacketHandlerPacketThresholdClampedToMinimum verifies that
// LossDetectionPacketThreshold values below RFC 9002 §6.1.1's minimum (3)
// are silently clamped to the default, so a misconfigured caller can't drive
// non-compliant, overly-aggressive loss detection.
func TestSentPacketHandlerPacketThresholdClampedToMinimum(t *testing.T) {
	for _, requested := range []int{-1, 0, 1, 2} {
		t.Run(fmt.Sprintf("requested=%d", requested), func(t *testing.T) {
			sph := NewSentPacketHandler(
				0,
				1200,
				utils.NewRTTStats(),
				&utils.ConnectionStats{},
				true,
				false,
				nil,
				protocol.PerspectiveClient,
				nil,
				utils.DefaultLogger,
				requested,
				0,
			)
			require.Equal(t, defaultPacketThreshold, sph.(*sentPacketHandler).packetThreshold,
				"below-minimum packet threshold must be clamped to default")
		})
	}

	// Values at or above the minimum must be honored as-is.
	for _, requested := range []int{3, 5, 15, 100} {
		t.Run(fmt.Sprintf("requested=%d", requested), func(t *testing.T) {
			sph := NewSentPacketHandler(
				0,
				1200,
				utils.NewRTTStats(),
				&utils.ConnectionStats{},
				true,
				false,
				nil,
				protocol.PerspectiveClient,
				nil,
				utils.DefaultLogger,
				requested,
				0,
			)
			require.Equal(t, requested, sph.(*sentPacketHandler).packetThreshold,
				"at-or-above-minimum packet threshold must be honored")
		})
	}
}

// TestSentPacketHandlerTimeThresholdRejectsNonFiniteOrNonPositive verifies
// that LossDetectionTimeThreshold values that are non-positive (zero, the
// "unset" value, or negative) or non-finite (NaN, ±Inf) fall back to the
// RFC 9002 default. Without this guard, NaN and +Inf would survive the
// "<= 0" check (all comparisons with NaN are false; +Inf is not <= 0) and
// poison the timeThreshold*maxRTT product in detectLostPackets — silently
// inverting the intended relaxation into a 1-tick loss delay.
func TestSentPacketHandlerTimeThresholdRejectsNonFiniteOrNonPositive(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested float64
	}{
		{"unset (zero)", 0},
		{"negative", -1.0},
		{"NaN", math.NaN()},
		{"PosInf", math.Inf(+1)},
		{"NegInf", math.Inf(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sph := NewSentPacketHandler(
				0,
				1200,
				utils.NewRTTStats(),
				&utils.ConnectionStats{},
				true,
				false,
				nil,
				protocol.PerspectiveClient,
				nil,
				utils.DefaultLogger,
				0,
				tc.requested,
			)
			require.Equal(t, float64(defaultTimeThreshold), sph.(*sentPacketHandler).timeThreshold,
				"non-positive or non-finite time threshold must fall back to default")
		})
	}

	// Finite positive values must be honored as-is, including very large
	// ones (the overflow guard sits at the use site, not at setup).
	for _, requested := range []float64{0.5, 1.0, 9.0 / 8, 2.0, 10.0, 1e9} {
		t.Run(fmt.Sprintf("requested=%g", requested), func(t *testing.T) {
			sph := NewSentPacketHandler(
				0,
				1200,
				utils.NewRTTStats(),
				&utils.ConnectionStats{},
				true,
				false,
				nil,
				protocol.PerspectiveClient,
				nil,
				utils.DefaultLogger,
				0,
				requested,
			)
			require.Equal(t, requested, sph.(*sentPacketHandler).timeThreshold,
				"finite positive time threshold must be honored as-is")
		})
	}
}

// TestSentPacketHandlerTimeThresholdNoOverflow verifies that detectLostPackets
// caps lossDelay before BOTH the float→Duration conversion AND any monotime
// arithmetic on it. A pathologically large finite product would otherwise
// break two independent operations:
//   (1) The float→Duration conversion itself: Go's implementation-defined
//       overflow yields math.MinInt64, which max(..., TimerGranularity)
//       silently turns into a 1-tick loss delay.
//   (2) p.SendTime.Add(lossDelay): even a finite lossDelay near
//       math.MaxInt64 wraps the sum past int64 into the past, parking
//       pnSpace.lossTime in the past so the loss timer fires immediately
//       on every ACK instead of deferring time-based loss detection.
//
// We assert (1) by checking that the older packet is NOT time-lost despite
// being far older than a 1-tick lossDelay would imply, and (2) by checking
// that the loss-detection alarm ends up strictly after rcvTime.
func TestSentPacketHandlerTimeThresholdNoOverflow(t *testing.T) {
	// 1e15 * a typical RTT in nanoseconds (~1e9) = 1e24, well past int64's
	// ~9.2e18 max.
	const hugeThreshold = 1e15

	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		hugeThreshold,
	)

	var packets packetTracker
	start := monotime.Now()
	pns := make([]protocol.PacketNumber, 2)
	for i := range pns {
		pns[i] = sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(start, pns[i], protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pns[i])},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
	}

	// ACK pns[1] one second later. detectLostPackets runs with
	// huge timeThreshold * ~1s RTT — must NOT collapse to ~1ms loss delay,
	// AND must produce a loss timer in the future (not wrapped into the past).
	rcvTime := start.Add(time.Second)
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[1])},
		protocol.Encryption1RTT,
		rcvTime,
	)
	require.NoError(t, err)
	require.NotContains(t, packets.Lost, pns[0],
		"with a huge time threshold, the older packet must not be time-lost; "+
			"a 1ms collapsed lossDelay would have declared it lost")
	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout, "an outstanding ack-eliciting packet must arm the loss timer")
	require.True(t, timeout.After(rcvTime),
		"loss-detection alarm must be in the future, not wrapped into the past via overflow; "+
			"alarm=%d rcvTime=%d", int64(timeout), int64(rcvTime))
}

func newMockedSPH(t *testing.T) (SentPacketHandler, *mocks.MockSendAlgorithmWithDebugInfos) {
	t.Helper()
	cong := mocks.NewMockSendAlgorithmWithDebugInfos(gomock.NewController(t))
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)
	sph.(*sentPacketHandler).congestion = cong
	return sph, cong
}

// TestSentPacketHandlerSpuriousLossSkipsMTUProbe verifies that when an
// MTU-probe packet (whose original loss was never reported to congestion
// control) is later retroactively acked, OnSpuriousLoss is NOT called for
// it. Calling it would decrement a sibling cutback's epoch counter in the
// CC and could cause an unrelated, genuine cut to be incorrectly undone.
//
// Setup mirrors TestSentPacketHandlerSpuriousLoss: small inter-send gaps
// plus a long ACK delay keep the measured RTT large, so the 3*PTO
// DeleteBefore window doesn't prune the lost-packet entries before the
// follow-up ACK retroactively covers them.
func TestSentPacketHandlerSpuriousLossSkipsMTUProbe(t *testing.T) {
	sph, cong := newMockedSPH(t)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time, mtuProbe bool) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		cong.EXPECT().OnPacketSent(ti, gomock.Any(), pn, protocol.ByteCount(1000), true)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pn)},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, mtuProbe, false)
		return pn
	}

	// pns[0] is an MTU probe; the rest are normal ack-eliciting packets.
	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for i := range 7 {
		pns = append(pns, sendPacket(t, now, i == 0))
		now = now.Add(10 * time.Millisecond)
	}

	// First ACK covers only pns[6]. Reordering threshold (default 3)
	// declares pns[0..3] lost. pns[0] is the MTU probe — no OnCongestionEvent
	// is fired for it; pns[1] triggers the cut, pns[2] and pns[3] fold into
	// the same epoch.
	ackTime := start.Add(time.Second)
	cong.EXPECT().MaybeExitSlowStart()
	cong.EXPECT().OnCongestionEvent(pns[1], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnCongestionEvent(pns[2], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnCongestionEvent(pns[3], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnPacketAcked(pns[6], protocol.ByteCount(1000), gomock.Any(), ackTime)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[6])}, protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.ElementsMatch(t, []protocol.PacketNumber{pns[0], pns[1], pns[2], pns[3]}, packets.Lost)

	// Send one fresh packet after the cutback.
	postCut := sendPacket(t, ackTime.Add(10*time.Millisecond), false)

	// Second ACK covers pns[0..6] and postCut, retroactively acking every
	// packet that was declared lost in the first ACK. detectSpuriousLosses
	// must call OnSpuriousLoss for pns[1..3] (their losses were counted) but
	// NOT for pns[0] (its loss was never counted — it's an MTU probe).
	ackTime2 := ackTime.Add(50 * time.Millisecond)
	cong.EXPECT().MaybeExitSlowStart()
	cong.EXPECT().OnSpuriousLoss(pns[1])
	cong.EXPECT().OnSpuriousLoss(pns[2])
	cong.EXPECT().OnSpuriousLoss(pns[3])
	// pns[0..3] and pns[6] are already out of history; pns[4], pns[5], and
	// postCut are the fresh acks that drive OnPacketAcked.
	cong.EXPECT().OnPacketAcked(pns[4], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	cong.EXPECT().OnPacketAcked(pns[5], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	cong.EXPECT().OnPacketAcked(postCut, protocol.ByteCount(1000), gomock.Any(), ackTime2)
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2], pns[3], pns[4], pns[5], pns[6], postCut)},
		protocol.Encryption1RTT, ackTime2,
	)
	require.NoError(t, err)
	// gomock fails the test at cleanup if OnSpuriousLoss(pns[0]) was called.
}

// TestSentPacketHandlerSpuriousLossBeforeAckGrowth verifies that, within a
// single ReceivedAck call, OnSpuriousLoss fires BEFORE the OnPacketAcked
// calls for packets sent after the (now-undone) cutback. If the order were
// reversed, OnPacketAcked could exit recovery and grow cwnd first, and the
// subsequent undo would overwrite that newer state with the stale pre-cut
// snapshot — effectively rewinding cwnd and Cubic state.
func TestSentPacketHandlerSpuriousLossBeforeAckGrowth(t *testing.T) {
	sph, cong := newMockedSPH(t)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		cong.EXPECT().OnPacketSent(ti, gomock.Any(), pn, protocol.ByteCount(1000), true)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pn)},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 5 {
		pns = append(pns, sendPacket(t, now))
		now = now.Add(10 * time.Millisecond)
	}

	// First ACK covers only pns[4]; pns[0] and pns[1] are declared lost via
	// the reordering threshold (Difference >= 3). pns[0] triggers the cut.
	ackTime := start.Add(time.Second)
	cong.EXPECT().MaybeExitSlowStart()
	cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnCongestionEvent(pns[1], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnPacketAcked(pns[4], protocol.ByteCount(1000), gomock.Any(), ackTime)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.ElementsMatch(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)

	// Send a fresh packet AFTER the cutback (its PN > largestSentAtLastCutback).
	postCut := sendPacket(t, ackTime.Add(10*time.Millisecond))

	// Second ACK retroactively covers pns[0] and pns[1] (driving the spurious-
	// loss undo) and freshly acks pns[2], pns[3], and postCut. The undo MUST
	// happen before the per-packet ACK growth — assert via gomock.InOrder.
	ackTime2 := ackTime.Add(50 * time.Millisecond)
	cong.EXPECT().MaybeExitSlowStart()
	postCutAck := cong.EXPECT().OnPacketAcked(postCut, protocol.ByteCount(1000), gomock.Any(), ackTime2)
	gomock.InOrder(cong.EXPECT().OnSpuriousLoss(pns[0]), postCutAck)
	gomock.InOrder(cong.EXPECT().OnSpuriousLoss(pns[1]), postCutAck)
	cong.EXPECT().OnPacketAcked(pns[2], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	cong.EXPECT().OnPacketAcked(pns[3], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2], pns[3], pns[4], postCut)},
		protocol.Encryption1RTT, ackTime2,
	)
	require.NoError(t, err)
}

// TestSentPacketHandlerSpuriousLossBeforeFreshLoss verifies that, within a
// single ReceivedAck call, OnSpuriousLoss for a retroactively-acked older
// packet fires BEFORE OnCongestionEvent for losses freshly detected by the
// same ACK. If the order were reversed, the fresh OnCongestionEvent would
// overwrite the pre-cut snapshot with the already-reduced cwnd; the later
// OnSpuriousLoss for the older packet would then look stale (predates the
// new snapshot's epoch) and bail out — leaving the false cut in place AND
// applying the fresh cut on top, double-cutting cwnd.
func TestSentPacketHandlerSpuriousLossBeforeFreshLoss(t *testing.T) {
	sph, cong := newMockedSPH(t)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		cong.EXPECT().OnPacketSent(ti, gomock.Any(), pn, protocol.ByteCount(1000), true)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pn)},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	// Send 11 packets back-to-back so the second ACK can leave gaps among
	// post-cut packets to drive a fresh reordering loss.
	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 11 {
		pns = append(pns, sendPacket(t, now))
		now = now.Add(10 * time.Millisecond)
	}

	// First ACK covers pns[4] only. pns[0] and pns[1] are declared lost via
	// the reordering threshold (Difference(4, 0)=4, Difference(4, 1)=3).
	// pns[0] triggers the cut; pns[1] folds into the same epoch.
	ackTime := start.Add(time.Second)
	cong.EXPECT().MaybeExitSlowStart()
	cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnCongestionEvent(pns[1], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnPacketAcked(pns[4], protocol.ByteCount(1000), gomock.Any(), ackTime)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.ElementsMatch(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)

	// Second ACK simultaneously:
	//   (a) retroactively covers pns[0] and pns[1] (proving the original cut
	//       spurious), and
	//   (b) raises largestAcked to pns[10], leaving pns[5..7] as gaps with
	//       Difference >= 3 — fresh reordering losses.
	// With the fix, detectSpuriousLosses runs before detectLostPackets, so
	// both OnSpuriousLoss calls must precede every fresh OnCongestionEvent.
	ackTime2 := ackTime.Add(50 * time.Millisecond)
	cong.EXPECT().MaybeExitSlowStart()
	spur0 := cong.EXPECT().OnSpuriousLoss(pns[0])
	spur1 := cong.EXPECT().OnSpuriousLoss(pns[1])
	freshCut5 := cong.EXPECT().OnCongestionEvent(pns[5], protocol.ByteCount(1000), gomock.Any())
	freshCut6 := cong.EXPECT().OnCongestionEvent(pns[6], protocol.ByteCount(1000), gomock.Any())
	freshCut7 := cong.EXPECT().OnCongestionEvent(pns[7], protocol.ByteCount(1000), gomock.Any())
	gomock.InOrder(spur0, freshCut5)
	gomock.InOrder(spur0, freshCut6)
	gomock.InOrder(spur0, freshCut7)
	gomock.InOrder(spur1, freshCut5)
	gomock.InOrder(spur1, freshCut6)
	gomock.InOrder(spur1, freshCut7)
	cong.EXPECT().OnPacketAcked(pns[2], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	cong.EXPECT().OnPacketAcked(pns[3], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	cong.EXPECT().OnPacketAcked(pns[8], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	cong.EXPECT().OnPacketAcked(pns[9], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	cong.EXPECT().OnPacketAcked(pns[10], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(
			pns[0], pns[1], pns[2], pns[3], pns[4],
			pns[8], pns[9], pns[10],
		)},
		protocol.Encryption1RTT, ackTime2,
	)
	require.NoError(t, err)
}

// TestSentPacketHandlerSpuriousLossWhenAckOnlyCoversLostPackets verifies that
// an ACK whose ranges cover ONLY previously-declared-lost packets (no
// in-flight ones) still drives OnSpuriousLoss. Such an ACK produces an empty
// ackedPackets list because declared-lost packets are no longer in
// pnSpace.history; without the early-detect ordering, ReceivedAck would
// return at the len(ackedPackets)==0 early return and never notify the
// congestion controller of the undo.
func TestSentPacketHandlerSpuriousLossWhenAckOnlyCoversLostPackets(t *testing.T) {
	sph, cong := newMockedSPH(t)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		cong.EXPECT().OnPacketSent(ti, gomock.Any(), pn, protocol.ByteCount(1000), true)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pn)},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 5 {
		pns = append(pns, sendPacket(t, now))
		now = now.Add(10 * time.Millisecond)
	}

	// First ACK covers pns[4] only; pns[0] and pns[1] are reordering-lost.
	ackTime := start.Add(time.Second)
	cong.EXPECT().MaybeExitSlowStart()
	cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnCongestionEvent(pns[1], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnPacketAcked(pns[4], protocol.ByteCount(1000), gomock.Any(), ackTime)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.ElementsMatch(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)

	// Second ACK covers ONLY [pns[0], pns[1], pns[4]] — pns[4] was already
	// acked in the first ACK (gone from history) and pns[0..1] were declared
	// lost (gone from history). pns[2..3] are still in flight but the ACK
	// leaves them in the gap. detectAndRemoveAckedPackets therefore returns
	// an empty ackedPackets list — but OnSpuriousLoss for pns[0..1] still
	// has to fire.
	ackTime2 := ackTime.Add(50 * time.Millisecond)
	cong.EXPECT().OnSpuriousLoss(pns[0])
	cong.EXPECT().OnSpuriousLoss(pns[1])
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[4])},
		protocol.Encryption1RTT, ackTime2,
	)
	require.NoError(t, err)
	// gomock fails the test at cleanup if any additional unexpected mock
	// call fired (e.g. MaybeExitSlowStart, OnPacketAcked, OnCongestionEvent).
}

// TestSentPacketHandlerSpuriousOnlyAckRunsPostAckCleanup verifies that an
// ACK whose only effect is to confirm a previously-declared-lost packet as
// spurious (detectAndRemoveAckedPackets surfaces nothing because the PN was
// removed from history at loss-declaration time) still runs the post-ACK
// cleanup — particularly the PTO backoff reset. Returning early on empty
// ackedPackets would leave ptoCount stuck at whatever value the prior PTO
// firings inflated it to, even though the path is healthy enough to deliver
// a late ACK for an ack-eliciting packet (and the cwnd cut was already
// undone via OnSpuriousLoss earlier in the same ReceivedAck call).
func TestSentPacketHandlerSpuriousOnlyAckRunsPostAckCleanup(t *testing.T) {
	sph, cong := newMockedSPH(t)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		cong.EXPECT().OnPacketSent(ti, gomock.Any(), pn, protocol.ByteCount(1000), true)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pn)},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 5 {
		pns = append(pns, sendPacket(t, now))
		now = now.Add(10 * time.Millisecond)
	}

	// First ACK covers pns[4]: pns[0] and pns[1] are declared lost. This ACK
	// also marks peerCompletedAddressValidation, which gates the post-ACK
	// ptoCount reset on subsequent ACKs.
	ackTime := start.Add(time.Second)
	cong.EXPECT().MaybeExitSlowStart()
	cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnCongestionEvent(pns[1], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnPacketAcked(pns[4], protocol.ByteCount(1000), gomock.Any(), ackTime)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.ElementsMatch(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)

	// Simulate PTO backoff accumulated from earlier probe timeouts. The
	// spurious-only ACK below must clear this — any acknowledgment of an
	// ack-eliciting packet (even a retroactive one) is forward progress that
	// RFC 9002 §6.2.1 says resets the backoff factor.
	sph.(*sentPacketHandler).ptoCount = 3

	// Second ACK covers only pns[0] — already declared lost, gone from
	// history, so detectAndRemoveAckedPackets returns empty. The early
	// return would have skipped the ptoCount reset; the fix routes through
	// the post-ACK cleanup because detectSpuriousLosses found something.
	ackTime2 := ackTime.Add(50 * time.Millisecond)
	cong.EXPECT().OnSpuriousLoss(pns[0])
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0])},
		protocol.Encryption1RTT, ackTime2,
	)
	require.NoError(t, err)
	require.Zero(t, sph.(*sentPacketHandler).ptoCount,
		"spurious-only ACK must reset PTO backoff via the post-ACK cleanup")
}

// TestSentPacketHandlerSpuriousLossOnReorderedAck verifies that an ACK
// whose LargestAcked is BELOW the current pnSpace.largestAcked still drives
// OnSpuriousLoss for ranges that retroactively cover previously-declared-
// lost packets. This is the "reordered ACK at the sender" case: ACK A is
// sent first, ACK B is sent later (and seen first), then A arrives. A's
// LargestAcked is older than B's, but A's ranges may include declared-lost
// packets that detectAndRemoveAckedPackets won't surface (those PNs are
// gone from pnSpace.history). Gating detectSpuriousLosses on
// largestAcked >= pnSpace.largestAcked would silently drop the undo for
// every spurious-loss confirmation that arrives in such a reordered ACK.
func TestSentPacketHandlerSpuriousLossOnReorderedAck(t *testing.T) {
	sph, cong := newMockedSPH(t)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		cong.EXPECT().OnPacketSent(ti, gomock.Any(), pn, protocol.ByteCount(1000), true)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pn)},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 5 {
		pns = append(pns, sendPacket(t, now))
		now = now.Add(10 * time.Millisecond)
	}

	// First ACK covers pns[4] only; pns[0] and pns[1] are declared lost via
	// the reordering threshold.
	ackTime := start.Add(time.Second)
	cong.EXPECT().MaybeExitSlowStart()
	cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnCongestionEvent(pns[1], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnPacketAcked(pns[4], protocol.ByteCount(1000), gomock.Any(), ackTime)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.ElementsMatch(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)

	// Reordered ACK arrives second: LargestAcked = pns[0] (well below the
	// current pnSpace.largestAcked of pns[4]), with a range covering only
	// pns[0]. detectAndRemoveAckedPackets will return empty (pns[0] is gone
	// from history), but detectSpuriousLosses must still fire OnSpuriousLoss
	// for pns[0]. pns[1] is in lostPackets too but isn't in this ACK's
	// ranges, so it stays.
	ackTime2 := ackTime.Add(50 * time.Millisecond)
	cong.EXPECT().OnSpuriousLoss(pns[0])
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0])},
		protocol.Encryption1RTT, ackTime2,
	)
	require.NoError(t, err)
}

// TestSentPacketHandlerLostPacketTrackerCapacityEvictionAbandonsUndo verifies
// that when detectLostPackets adds a counted loss while the lost-packet
// tracker is at capacity, the evicted oldest entry drives
// AbandonSpuriousLossUndo. The lossesInEpoch counter the controller bumped
// for the evicted PN cannot be decremented by a future ACK (the entry is
// gone), so leaving the snapshot in place would strand the undo above zero
// and silently disable it for the current epoch.
func TestSentPacketHandlerLostPacketTrackerCapacityEvictionAbandonsUndo(t *testing.T) {
	sph, cong := newMockedSPH(t)
	// Shrink the tracker so we can demonstrate eviction with only a few
	// losses instead of >64.
	sph.(*sentPacketHandler).lostPackets = *newLostPacketTracker(2)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		cong.EXPECT().OnPacketSent(ti, gomock.Any(), pn, protocol.ByteCount(1000), true)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pn)},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 6 {
		pns = append(pns, sendPacket(t, now))
		now = now.Add(10 * time.Millisecond)
	}

	cong.EXPECT().MaybeExitSlowStart().AnyTimes()

	// First ACK covers pns[3]: pns[0] is declared lost via reordering threshold
	// (Difference(3, 0) = 3).
	ackTime := start.Add(time.Second)
	cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnPacketAcked(pns[3], protocol.ByteCount(1000), gomock.Any(), ackTime)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[3])}, protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)

	// Second ACK extends largest to pns[4]: pns[1] becomes lost. Tracker now
	// holds [pns[0], pns[1]] — at capacity.
	ackTime2 := ackTime.Add(10 * time.Millisecond)
	cong.EXPECT().OnCongestionEvent(pns[1], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().OnPacketAcked(pns[4], protocol.ByteCount(1000), gomock.Any(), ackTime2)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[3], pns[4])}, protocol.Encryption1RTT, ackTime2)
	require.NoError(t, err)

	// Third ACK extends largest to pns[5]: pns[2] is declared lost. Add to
	// the tracker overflows capacity, evicting pns[0] (the oldest and
	// counted) — that must drive AbandonSpuriousLossUndo(pns[0]) so the
	// controller doesn't keep counting it.
	ackTime3 := ackTime2.Add(10 * time.Millisecond)
	cong.EXPECT().OnCongestionEvent(pns[2], protocol.ByteCount(1000), gomock.Any())
	cong.EXPECT().AbandonSpuriousLossUndo(pns[0])
	cong.EXPECT().OnPacketAcked(pns[5], protocol.ByteCount(1000), gomock.Any(), ackTime3)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[3], pns[4], pns[5])}, protocol.Encryption1RTT, ackTime3)
	require.NoError(t, err)
}

// TestSentPacketHandlerMigratedPathClearsLostPackets verifies that
// MigratedPath drops the spurious-loss tracker alongside the fresh
// congestion controller. Without this, a pre-migration entry with
// CongestionInformed=true could later trigger OnSpuriousLoss on the new
// cubicSender — whose snapshot starts from InvalidPacketNumber, so the
// old (large positive) PN looks "in-epoch" against any new-path cut and
// can undo it.
func TestSentPacketHandlerMigratedPathClearsLostPackets(t *testing.T) {
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)

	var packets packetTracker
	sendPacket := func(t *testing.T, ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{packets.NewPingFrame(pn)},
			protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 5 {
		pns = append(pns, sendPacket(t, now))
		now = now.Add(10 * time.Millisecond)
	}

	// First ACK covers pns[4] only — pns[0..1] are declared lost via the
	// reordering threshold and added to lostPackets with
	// CongestionInformed=true (ack-eliciting, non-MTU-probe).
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[4])},
		protocol.Encryption1RTT,
		start.Add(time.Second),
	)
	require.NoError(t, err)
	require.ElementsMatch(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)
	sphInternal := sph.(*sentPacketHandler)
	require.NotZero(t, len(sphInternal.lostPackets.lostPackets),
		"sanity: pre-migration losses should populate the spurious-loss tracker")

	// Path migration. The spurious-loss tracker must be dropped — otherwise
	// an ACK arriving on the new path that retroactively covers pns[0] or
	// pns[1] would call OnSpuriousLoss on the freshly created cubicSender
	// (whose largestSentAtLastCutback starts at InvalidPacketNumber) and
	// could undo an unrelated new-path cut.
	sph.MigratedPath(start.Add(2*time.Second), 1200)
	require.Zero(t, len(sphInternal.lostPackets.lostPackets),
		"MigratedPath must drop the pre-migration spurious-loss-tracker entries")
}

func BenchmarkSendAndAcknowledge(b *testing.B) {
	b.Run("ack every: 2, in flight: 0", func(b *testing.B) {
		benchmarkSendAndAcknowledge(b, 2, 0)
	})
	b.Run("ack every: 10, in flight: 100", func(b *testing.B) {
		benchmarkSendAndAcknowledge(b, 10, 100)
	})
	b.Run("ack every: 100, in flight: 1000", func(b *testing.B) {
		benchmarkSendAndAcknowledge(b, 100, 1000)
	})
}

func benchmarkSendAndAcknowledge(b *testing.B, ackEvery, inFlight int) {
	b.ReportAllocs()

	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
		0,
		0,
	)
	now := monotime.Now()
	sph.DropPackets(protocol.EncryptionInitial, now)
	sph.DropPackets(protocol.EncryptionHandshake, now)

	streamFrames := []StreamFrame{{Frame: &wire.StreamFrame{}}}

	pns := make([]protocol.PacketNumber, 0, ackEvery+inFlight)

	var counter int
	ranges := make([]wire.AckRange, 0, ackEvery)
	for b.Loop() {
		counter++
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(
			now,
			pn,
			protocol.InvalidPacketNumber,
			streamFrames,
			nil,
			protocol.Encryption1RTT,
			protocol.ECNNon,
			1200,
			false, false,
		)
		now = now.Add(time.Millisecond)
		pns = append(pns, pn)

		if counter > inFlight && counter%ackEvery == 0 {
			sph.ReceivedAck(
				&wire.AckFrame{AckRanges: appendAckRanges(ranges, pns[:ackEvery]...)},
				protocol.Encryption1RTT,
				now,
			)
			pns = append(pns[:0], pns[ackEvery:]...)
			ranges = ranges[:0]
		}
	}
}
