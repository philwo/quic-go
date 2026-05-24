package ackhandler

import (
	"testing"
	"time"

	"github.com/philwo/quic-go/internal/monotime"
	"github.com/philwo/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func collectAll(lt *lostPacketTracker) map[protocol.PacketNumber]lostPacket {
	m := make(map[protocol.PacketNumber]lostPacket)
	for p := range lt.All() {
		m[p.PacketNumber] = p
	}
	return m
}

func TestLostPacketTracker(t *testing.T) {
	lt := newLostPacketTracker(4)

	start := monotime.Now()
	lt.Add(1, start, true)
	lt.Add(5, start.Add(time.Second), true)
	lt.Add(8, start.Add(2*time.Second), true)
	require.Equal(t, map[protocol.PacketNumber]lostPacket{
		1: {PacketNumber: 1, SendTime: start, CongestionInformed: true},
		5: {PacketNumber: 5, SendTime: start.Add(time.Second), CongestionInformed: true},
		8: {PacketNumber: 8, SendTime: start.Add(2 * time.Second), CongestionInformed: true},
	}, collectAll(lt))

	// Lose 2 more packets. The first one should be removed.
	lt.Add(10, start.Add(3*time.Second), true)
	lt.Add(11, start.Add(4*time.Second), true)
	require.Equal(t, map[protocol.PacketNumber]lostPacket{
		5:  {PacketNumber: 5, SendTime: start.Add(time.Second), CongestionInformed: true},
		8:  {PacketNumber: 8, SendTime: start.Add(2 * time.Second), CongestionInformed: true},
		10: {PacketNumber: 10, SendTime: start.Add(3 * time.Second), CongestionInformed: true},
		11: {PacketNumber: 11, SendTime: start.Add(4 * time.Second), CongestionInformed: true},
	}, collectAll(lt))

	lt.Delete(5)
	lt.Delete(10)
	require.Equal(t, map[protocol.PacketNumber]lostPacket{
		8:  {PacketNumber: 8, SendTime: start.Add(2 * time.Second), CongestionInformed: true},
		11: {PacketNumber: 11, SendTime: start.Add(4 * time.Second), CongestionInformed: true},
	}, collectAll(lt))
}

// TestLostPacketTrackerCongestionInformed verifies that the CongestionInformed
// flag is preserved per-entry. The sent_packet_handler relies on this flag to
// avoid notifying the congestion controller about spurious losses for packets
// that never triggered an OnCongestionEvent in the first place.
func TestLostPacketTrackerCongestionInformed(t *testing.T) {
	lt := newLostPacketTracker(4)
	start := monotime.Now()

	lt.Add(1, start, true)
	lt.Add(2, start.Add(time.Second), false)
	lt.Add(3, start.Add(2*time.Second), true)

	got := collectAll(lt)
	require.True(t, got[1].CongestionInformed)
	require.False(t, got[2].CongestionInformed)
	require.True(t, got[3].CongestionInformed)
}

// TestLostPacketTrackerAddReportsEviction verifies that Add returns the
// dropped oldest entry (including its CongestionInformed flag) when the
// tracker is at capacity, so callers can react. The sent-packet handler
// uses this to abandon the congestion controller's per-epoch undo state
// for a CongestionInformed loss that would otherwise be stranded.
func TestLostPacketTrackerAddReportsEviction(t *testing.T) {
	lt := newLostPacketTracker(2)

	start := monotime.Now()
	_, didEvict := lt.Add(1, start, true)
	require.False(t, didEvict, "no eviction below capacity")
	_, didEvict = lt.Add(2, start.Add(time.Second), false)
	require.False(t, didEvict, "no eviction at exactly capacity-1 entries")

	// Third add hits capacity; pn=1 (CongestionInformed) is evicted.
	evicted, didEvict := lt.Add(3, start.Add(2*time.Second), true)
	require.True(t, didEvict)
	require.Equal(t, lostPacket{PacketNumber: 1, SendTime: start, CongestionInformed: true}, evicted)

	// Fourth add evicts pn=2 (not CongestionInformed) — caller must know.
	evicted, didEvict = lt.Add(4, start.Add(3*time.Second), true)
	require.True(t, didEvict)
	require.Equal(t, lostPacket{PacketNumber: 2, SendTime: start.Add(time.Second), CongestionInformed: false}, evicted)
}

// TestLostPacketTrackerDeleteBeforeReportsEviction verifies that
// DeleteBefore returns the slice of pruned entries so the caller can
// notify the congestion controller about CongestionInformed entries that
// aged out without ever being confirmed spurious.
func TestLostPacketTrackerDeleteBeforeReportsEviction(t *testing.T) {
	lt := newLostPacketTracker(8)
	start := monotime.Now()
	lt.Add(1, start, true)
	lt.Add(2, start.Add(time.Second), false)
	lt.Add(3, start.Add(2*time.Second), true)
	lt.Add(4, start.Add(3*time.Second), true)

	// No-op prune returns nil.
	require.Nil(t, lt.DeleteBefore(start))

	// Prune everything strictly before start+2s — should drop pn=1 (counted)
	// and pn=2 (not counted) in age order.
	evicted := lt.DeleteBefore(start.Add(2 * time.Second))
	require.Equal(t, []lostPacket{
		{PacketNumber: 1, SendTime: start, CongestionInformed: true},
		{PacketNumber: 2, SendTime: start.Add(time.Second), CongestionInformed: false},
	}, evicted)
}

func TestLostPacketTrackerDeleteBefore(t *testing.T) {
	lt := newLostPacketTracker(4)

	trackedPackets := func(lt *lostPacketTracker) []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		for p := range lt.All() {
			pns = append(pns, p.PacketNumber)
		}
		return pns
	}

	start := monotime.Now()
	lt.Add(1, start, true)
	lt.Add(5, start.Add(time.Second), true)
	lt.Add(8, start.Add(2*time.Second), true)
	lt.Add(10, start.Add(3*time.Second), true)

	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start) // this should be a no-op
	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(2 * time.Second))
	require.Equal(t, []protocol.PacketNumber{8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Second * 5 / 2))
	require.Equal(t, []protocol.PacketNumber{10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Hour))
	require.Empty(t, trackedPackets(lt))
}
