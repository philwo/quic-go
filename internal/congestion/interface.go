package congestion

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// A SendAlgorithm performs congestion control
type SendAlgorithm interface {
	TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time
	HasPacingBudget(now monotime.Time) bool
	OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight protocol.ByteCount) bool
	MaybeExitSlowStart()
	OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time)
	OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount)
	// OnSpuriousLoss is called when a packet previously reported lost via
	// OnCongestionEvent turns out to have been delivered (it was ACKed
	// later than the loss detector's threshold allowed for). Implementations
	// should consider undoing the cwnd reduction taken at the time of the
	// original "loss," if it can be attributed to this packet's epoch.
	OnSpuriousLoss(number protocol.PacketNumber)
	// AbandonSpuriousLossUndo is called when the lost-packet tracker drops
	// an entry that had been reported to the congestion controller via
	// OnCongestionEvent, without that entry ever being confirmed spurious.
	// This happens on capacity eviction in the tracker and on 3*PTO age-out
	// pruning. Once such an entry is gone, no future ACK can drive
	// OnSpuriousLoss for it; an implementation that tracks per-epoch loss
	// counts toward an undo decision should treat the current epoch's
	// snapshot as no longer recoverable and discard it, so the cut stands.
	// Implementations may ignore calls whose packet number predates the
	// current epoch — such entries can't affect any active undo state.
	AbandonSpuriousLossUndo(number protocol.PacketNumber)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(protocol.ByteCount)
}

// A SendAlgorithmWithDebugInfos is a SendAlgorithm that exposes some debug infos
type SendAlgorithmWithDebugInfos interface {
	SendAlgorithm
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() protocol.ByteCount
}
