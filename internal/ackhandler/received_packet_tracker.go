package ackhandler

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

const reorderingThreshold = 1

// The receivedPacketTracker tracks packets for the Initial and Handshake packet number space.
// Every received packet is acknowledged immediately.
type receivedPacketTracker struct {
	ect0, ect1, ecnce uint64

	packetHistory receivedPacketHistory

	lastAck   *wire.AckFrame
	hasNewAck bool // true as soon as we received an ack-eliciting new packet
}

func newReceivedPacketTracker() *receivedPacketTracker {
	return &receivedPacketTracker{packetHistory: *newReceivedPacketHistory()}
}

func (h *receivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, ackEliciting bool) error {
	if isNew := h.packetHistory.ReceivedPacket(pn); !isNew {
		return fmt.Errorf("receivedPacketTracker BUG: ReceivedPacket called for old / duplicate packet %d", pn)
	}

	//nolint:exhaustive // Only need to count ECT(0), ECT(1) and ECN-CE.
	switch ecn {
	case protocol.ECT0:
		h.ect0++
	case protocol.ECT1:
		h.ect1++
	case protocol.ECNCE:
		h.ecnce++
	}
	if !ackEliciting {
		return nil
	}
	h.hasNewAck = true
	return nil
}

func (h *receivedPacketTracker) GetAckFrame() *wire.AckFrame {
	if !h.hasNewAck {
		return nil
	}

	// This function always returns the same ACK frame struct, filled with the most recent values.
	ack := h.lastAck
	if ack == nil {
		ack = &wire.AckFrame{}
	}
	ack.Reset()
	ack.ECT0 = h.ect0
	ack.ECT1 = h.ect1
	ack.ECNCE = h.ecnce
	for r := range h.packetHistory.Backward() {
		ack.AckRanges = append(ack.AckRanges, wire.AckRange{Smallest: r.Start, Largest: r.End})
	}

	h.lastAck = ack
	h.hasNewAck = false
	return ack
}

func (h *receivedPacketTracker) IsPotentiallyDuplicate(pn protocol.PacketNumber) bool {
	return h.packetHistory.IsPotentiallyDuplicate(pn)
}

// number of ack-eliciting packets received before sending an ACK
const packetsBeforeAck = 2

// The appDataReceivedPacketTracker tracks packets received in the Application Data packet number space.
// It waits until at least 2 packets were received before queueing an ACK, or until the max_ack_delay was reached.
type appDataReceivedPacketTracker struct {
	receivedPacketTracker

	largestObservedRcvdTime monotime.Time

	largestObserved protocol.PacketNumber
	ignoreBelow     protocol.PacketNumber

	maxAckDelay       time.Duration
	ackGapSettleDelay time.Duration // 0 = disabled (RFC-compliant immediate ACK on out-of-order)
	ackQueued         bool          // true if we need send a new ACK

	// ackGapSettleUntil suppresses ACK sending until this time when a new
	// missing-packet gap is first detected. If the gap fills before the
	// timer fires, no gap-revealing ACK is sent.
	ackGapSettleUntil monotime.Time
	// ackGapSettleArmedFor is the highest-PN missing packet that the
	// current settle window covers. Tracking this prevents an already-
	// armed gap from re-arming on every subsequent packet arrival; only
	// a newer (higher-PN) gap refreshes the window.
	ackGapSettleArmedFor protocol.PacketNumber

	ackElicitingPacketsReceivedSinceLastAck int
	ackAlarm                                monotime.Time

	logger utils.Logger
}

func newAppDataReceivedPacketTracker(logger utils.Logger, ackGapSettleDelay time.Duration) *appDataReceivedPacketTracker {
	h := &appDataReceivedPacketTracker{
		receivedPacketTracker: *newReceivedPacketTracker(),
		maxAckDelay:           protocol.MaxAckDelay,
		ackGapSettleDelay:     ackGapSettleDelay,
		ackGapSettleArmedFor:  protocol.InvalidPacketNumber,
		logger:                logger,
	}
	return h
}

func (h *appDataReceivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, rcvTime monotime.Time, ackEliciting bool) error {
	if err := h.receivedPacketTracker.ReceivedPacket(pn, ecn, ackEliciting); err != nil {
		return err
	}
	if pn >= h.largestObserved {
		h.largestObserved = pn
		h.largestObservedRcvdTime = rcvTime
	}
	if !ackEliciting {
		return nil
	}
	h.ackElicitingPacketsReceivedSinceLastAck++
	isMissing := h.isMissing(pn)

	// Track the gap-settle window independently of the rest of the queue
	// logic so that gaps opening after ackQueued is already set still get
	// their own settle protection. The new-vs-already-armed distinction
	// matters: a single unfilled gap should arm once, not re-arm on every
	// subsequent packet — otherwise the deadline drifts forward forever.
	h.updateGapSettle(rcvTime)

	queueReason := h.ackQueueReason(pn, ecn, isMissing)
	if !h.ackQueued && queueReason != ackReasonNone {
		if queueReason == ackReasonNewMissing && h.ackGapSettleDelay > 0 {
			// The settle window was armed above; don't queue the ACK yet.
			// GetAckFrame will refuse to ship anything until the window
			// expires (or the gap fills and clears the suppression).
		} else {
			h.ackQueued = true
			// Cancel the ack alarm, but keep the gap-settle wake-up if one
			// is pending — GetAckFrame will refuse to send until it
			// expires, and the connection still needs a timer to wake at
			// the right moment.
			if h.ackGapSettleUntil.IsZero() {
				h.ackAlarm = 0
			} else {
				h.ackAlarm = h.ackGapSettleUntil
			}
		}
	}
	if !h.ackQueued && h.ackAlarm.IsZero() {
		// No ACK queued, but we'll need to acknowledge the packet after max_ack_delay.
		h.ackAlarm = rcvTime.Add(h.maxAckDelay)
		if h.logger.Debug() {
			h.logger.Debugf("\tSetting ACK timer to max ack delay: %s", h.maxAckDelay)
		}
	}
	return nil
}

// IgnoreBelow sets a lower limit for acknowledging packets.
// Packets with packet numbers smaller than p will not be acked.
func (h *appDataReceivedPacketTracker) IgnoreBelow(pn protocol.PacketNumber) {
	if pn <= h.ignoreBelow {
		return
	}
	h.ignoreBelow = pn
	h.packetHistory.DeleteBelow(pn)
	if h.logger.Debug() {
		h.logger.Debugf("\tIgnoring all packets below %d.", pn)
	}
}

// isMissing says if a packet was reported missing in the last ACK.
func (h *appDataReceivedPacketTracker) isMissing(p protocol.PacketNumber) bool {
	if h.lastAck == nil || p < h.ignoreBelow {
		return false
	}
	return p < h.lastAck.LargestAcked() && !h.lastAck.AcksPacket(p)
}

// updateGapSettle arms, refreshes, or clears the gap-settle suppression
// window. The window is keyed to the highest-PN currently-missing packet:
//   - new highest missing PN > previously armed PN: arm/refresh, deadline =
//     rcvTime + ackGapSettleDelay.
//   - same as previously armed: do nothing (don't refresh — the gap has
//     already had its share of the settle window).
//   - no qualifying missing PN at all: clear the suppression.
//
// "Qualifying" mirrors hasNewMissingPackets: missing PN must be above
// reorderingThreshold below largestObserved, and not already reported
// missing in lastAck.
func (h *appDataReceivedPacketTracker) updateGapSettle(rcvTime monotime.Time) {
	if h.ackGapSettleDelay == 0 {
		return
	}
	if h.lastAck == nil || h.largestObserved < reorderingThreshold {
		return
	}
	highestMissing := h.packetHistory.HighestMissingUpTo(h.largestObserved - reorderingThreshold)
	qualifies := highestMissing != protocol.InvalidPacketNumber &&
		highestMissing >= h.lastAck.LargestAcked() &&
		highestMissing > h.lastAck.LargestAcked()-reorderingThreshold
	if !qualifies {
		if !h.ackGapSettleUntil.IsZero() {
			if h.logger.Debug() {
				h.logger.Debugf("\tGap filled before settle window expired; clearing suppression.")
			}
			h.ackGapSettleUntil = 0
			h.ackGapSettleArmedFor = protocol.InvalidPacketNumber
		}
		return
	}
	if highestMissing <= h.ackGapSettleArmedFor {
		// already armed for this gap (or a higher one we've since seen);
		// don't refresh — the existing deadline still bounds how long
		// this gap can be hidden from the peer.
		return
	}
	h.ackGapSettleArmedFor = highestMissing
	h.ackGapSettleUntil = rcvTime.Add(h.ackGapSettleDelay)
	if h.ackAlarm.IsZero() || h.ackGapSettleUntil.Before(h.ackAlarm) {
		h.ackAlarm = h.ackGapSettleUntil
	}
	if h.logger.Debug() {
		h.logger.Debugf("\tDeferring gap-revealing ACK (highest missing PN %d) for %s.",
			highestMissing, h.ackGapSettleDelay)
	}
}

func (h *appDataReceivedPacketTracker) hasNewMissingPackets() bool {
	if h.lastAck == nil {
		return false
	}
	if h.largestObserved < reorderingThreshold {
		return false
	}
	highestMissing := h.packetHistory.HighestMissingUpTo(h.largestObserved - reorderingThreshold)
	if highestMissing == protocol.InvalidPacketNumber {
		return false
	}
	if highestMissing < h.lastAck.LargestAcked() {
		// the packet was already reported missing in the last ACK
		return false
	}
	return highestMissing > h.lastAck.LargestAcked()-reorderingThreshold
}

// ackQueueReason explains why an ACK should be queued, or ackReasonNone if no
// reason applies. The distinction matters because ackReasonNewMissing may be
// deferred by the gap-settle window while the other reasons fire immediately.
type ackQueueReason int

const (
	ackReasonNone ackQueueReason = iota
	ackReasonWasMissing
	ackReasonPacketsThreshold
	ackReasonNewMissing
	ackReasonECNCE
)

func (h *appDataReceivedPacketTracker) ackQueueReason(pn protocol.PacketNumber, ecn protocol.ECN, wasMissing bool) ackQueueReason {
	// Send an ACK if this packet was reported missing in an ACK sent before.
	// Ack decimation with reordering relies on the timer to send an ACK, but if
	// missing packets we reported in the previous ACK, send an ACK immediately.
	if wasMissing {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d was missing before.", pn)
		}
		return ackReasonWasMissing
	}

	// send an ACK every 2 ack-eliciting packets
	if h.ackElicitingPacketsReceivedSinceLastAck >= packetsBeforeAck {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d packets were received after the last ACK (using initial threshold: %d).", h.ackElicitingPacketsReceivedSinceLastAck, packetsBeforeAck)
		}
		return ackReasonPacketsThreshold
	}

	// queue an ACK if there are new missing packets to report
	if h.hasNewMissingPackets() {
		h.logger.Debugf("\tQueuing ACK because there's a new missing packet to report.")
		return ackReasonNewMissing
	}

	// queue an ACK if the packet was ECN-CE marked
	if ecn == protocol.ECNCE {
		h.logger.Debugf("\tQueuing ACK because the packet was ECN-CE marked.")
		return ackReasonECNCE
	}
	return ackReasonNone
}

func (h *appDataReceivedPacketTracker) GetAckFrame(now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	// Suppress ACK sending entirely while inside the gap-settle window —
	// otherwise a packets-threshold or other trigger could leak the gap
	// before it has had a chance to fill. The window auto-clears when
	// the gap fills (in ReceivedPacket) or when this time passes.
	if !h.ackGapSettleUntil.IsZero() && now.Before(h.ackGapSettleUntil) {
		return nil
	}
	h.ackGapSettleUntil = 0
	h.ackGapSettleArmedFor = protocol.InvalidPacketNumber

	if onlyIfQueued && !h.ackQueued {
		if h.ackAlarm.IsZero() || h.ackAlarm.After(now) {
			return nil
		}
		if h.logger.Debug() && !h.ackAlarm.IsZero() {
			h.logger.Debugf("Sending ACK because the ACK timer expired.")
		}
	}
	ack := h.receivedPacketTracker.GetAckFrame()
	if ack == nil {
		return nil
	}
	ack.DelayTime = max(0, now.Sub(h.largestObservedRcvdTime))
	h.ackQueued = false
	h.ackAlarm = 0
	h.ackElicitingPacketsReceivedSinceLastAck = 0
	return ack
}

func (h *appDataReceivedPacketTracker) GetAlarmTimeout() monotime.Time { return h.ackAlarm }
