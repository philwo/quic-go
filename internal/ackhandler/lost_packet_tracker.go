package ackhandler

import (
	"iter"
	"slices"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

type lostPacket struct {
	PacketNumber protocol.PacketNumber
	SendTime     monotime.Time
	// CongestionInformed records whether the original loss declaration was
	// reported to the congestion controller via OnCongestionEvent. Only such
	// entries are eligible to drive OnSpuriousLoss; otherwise we'd decrement
	// an epoch counter for a loss the controller never counted, and risk
	// undoing an unrelated, genuine cutback.
	CongestionInformed bool
}

type lostPacketTracker struct {
	maxLength   int
	lostPackets []lostPacket
}

func newLostPacketTracker(maxLength int) *lostPacketTracker {
	return &lostPacketTracker{
		maxLength: maxLength,
		// Preallocate a small slice only.
		// Hopefully we won't lose many packets.
		lostPackets: make([]lostPacket, 0, 4),
	}
}

// Add appends a new entry. If the tracker is at capacity, the oldest entry
// is evicted and returned via (evicted, true) so the caller can react —
// notably, when a CongestionInformed eviction would otherwise strand the
// congestion controller's per-epoch undo counter.
func (t *lostPacketTracker) Add(p protocol.PacketNumber, sendTime monotime.Time, congestionInformed bool) (evicted lostPacket, didEvict bool) {
	if len(t.lostPackets) == t.maxLength {
		evicted = t.lostPackets[0]
		didEvict = true
		t.lostPackets = t.lostPackets[1:]
	}
	t.lostPackets = append(t.lostPackets, lostPacket{
		PacketNumber:       p,
		SendTime:           sendTime,
		CongestionInformed: congestionInformed,
	})
	return evicted, didEvict
}

// Delete deletes a packet from the lost packet tracker.
// This function is not optimized for performance if many packets are lost,
// but it is only used when a spurious loss is detected, which is rare.
func (t *lostPacketTracker) Delete(pn protocol.PacketNumber) {
	t.lostPackets = slices.DeleteFunc(t.lostPackets, func(p lostPacket) bool {
		return p.PacketNumber == pn
	})
}

func (t *lostPacketTracker) All() iter.Seq[lostPacket] {
	return func(yield func(lostPacket) bool) {
		for _, p := range t.lostPackets {
			if !yield(p) {
				return
			}
		}
	}
}

// DeleteBefore prunes entries older than ti and returns them so the caller
// can react to CongestionInformed evictions (the congestion controller's
// per-epoch undo counter must be cleared for any in-epoch entry that ages
// out without being confirmed spurious; otherwise the counter would be
// stranded above zero and block the undo permanently).
func (t *lostPacketTracker) DeleteBefore(ti monotime.Time) (evicted []lostPacket) {
	if len(t.lostPackets) == 0 {
		return nil
	}
	if !t.lostPackets[0].SendTime.Before(ti) {
		return nil
	}
	var idx int
	for ; idx < len(t.lostPackets); idx++ {
		if !t.lostPackets[idx].SendTime.Before(ti) {
			break
		}
	}
	evicted = slices.Clone(t.lostPackets[:idx])
	t.lostPackets = slices.Delete(t.lostPackets, 0, idx)
	return evicted
}
