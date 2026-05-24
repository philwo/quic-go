package congestion

import (
	"fmt"

	"github.com/philwo/quic-go/internal/monotime"
	"github.com/philwo/quic-go/internal/protocol"
	"github.com/philwo/quic-go/internal/utils"
	"github.com/philwo/quic-go/qlog"
	"github.com/philwo/quic-go/qlogwriter"
)

const (
	// maxDatagramSize is the default maximum packet size used in the Linux TCP implementation.
	// Used in QUIC for congestion window computations in bytes.
	initialMaxDatagramSize     = protocol.ByteCount(protocol.InitialPacketSize)
	maxBurstPackets            = 3
	renoBeta                   = 0.7 // Reno backoff factor.
	minCongestionWindowPackets = 2
	initialCongestionWindow    = 32
)

type cubicSender struct {
	hybridSlowStart HybridSlowStart
	rttStats        *utils.RTTStats
	connStats       *utils.ConnectionStats
	cubic           *Cubic
	pacer           *pacer
	clock           Clock

	reno bool

	// Track the largest packet that has been sent.
	largestSentPacketNumber protocol.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber protocol.PacketNumber

	// Track the largest packet number outstanding when a CWND cutback occurs.
	largestSentAtLastCutback protocol.PacketNumber

	// Whether the last loss event caused us to exit slowstart.
	// Used for stats collection of slowstartPacketsLost
	lastCutbackExitedSlowstart bool

	// Congestion window in bytes.
	congestionWindow protocol.ByteCount

	// Slow start congestion window in bytes, aka ssthresh.
	slowStartThreshold protocol.ByteCount

	// ACK counter for the Reno implementation.
	numAckedPackets uint64

	initialCongestionWindow    protocol.ByteCount
	initialMaxCongestionWindow protocol.ByteCount

	maxDatagramSize protocol.ByteCount

	lastState qlog.CongestionState
	qlogger   qlogwriter.Recorder

	// preCutback is the cwnd state captured immediately before the most
	// recent loss-driven cutback. Used to undo the cutback if every
	// declared loss in the cutback's epoch is later detected as spurious.
	// nil once consumed or once a fresh cutback happens for a higher PN.
	preCutback *cwndSnapshot

	// lossesInEpoch counts the OnCongestionEvent calls within the current
	// cutback's epoch (the first call cuts cwnd; subsequent calls in the
	// same epoch are folded into a single loss event but still bump this
	// counter). OnSpuriousLoss decrements it; the undo only fires when it
	// reaches zero — i.e. every declared loss in the epoch was disproven.
	// This guards against undoing a cut where some sibling loss was real,
	// even when the trigger packet itself turns out to have been ACKed.
	lossesInEpoch int
}

// cwndSnapshot is a saved cubicSender state, used for spurious-loss undo.
type cwndSnapshot struct {
	congestionWindow           protocol.ByteCount
	slowStartThreshold         protocol.ByteCount
	largestSentAtLastCutback   protocol.PacketNumber
	lastCutbackExitedSlowstart bool
	// numAckedPackets carries Reno's accumulated additive-increase progress
	// (ACK credit toward the next CA cwnd increment). OnCongestionEvent
	// zeros it on every cut, so we must snapshot it pre-cut to restore the
	// credit when the cut turns out spurious.
	numAckedPackets uint64
	cubic           Cubic
	// clamped records whether the cut left cwnd numerically unchanged
	// (pre-cut cwnd was already at minCongestionWindow, so β*cwnd or the
	// Cubic reduction was clamped back up to min). It disambiguates the
	// two ways OnSpuriousLoss can see c.cwnd == s.congestionWindow:
	//   - clamped == true:  the cut never reduced cwnd, so numAckedPackets
	//     and the Cubic state were reset without any post-cut growth to
	//     preserve. The undo *must* restore them.
	//   - clamped == false: post-cut CA grew cwnd back to exactly the
	//     pre-cut value via fresh ACKs. numAckedPackets and Cubic now hold
	//     newer post-cut state that the undo must *not* overwrite.
	clamped bool
}

var (
	_ SendAlgorithm               = &cubicSender{}
	_ SendAlgorithmWithDebugInfos = &cubicSender{}
)

// NewCubicSender makes a new cubic sender
func NewCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	reno bool,
	qlogger qlogwriter.Recorder,
) *cubicSender {
	return newCubicSender(
		clock,
		rttStats,
		connStats,
		reno,
		initialMaxDatagramSize,
		initialCongestionWindow*initialMaxDatagramSize,
		protocol.MaxCongestionWindowPackets*initialMaxDatagramSize,
		qlogger,
	)
}

func newCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	reno bool,
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *cubicSender {
	c := &cubicSender{
		rttStats:                   rttStats,
		connStats:                  connStats,
		largestSentPacketNumber:    protocol.InvalidPacketNumber,
		largestAckedPacketNumber:   protocol.InvalidPacketNumber,
		largestSentAtLastCutback:   protocol.InvalidPacketNumber,
		initialCongestionWindow:    initialCongestionWindow,
		initialMaxCongestionWindow: initialMaxCongestionWindow,
		congestionWindow:           initialCongestionWindow,
		slowStartThreshold:         protocol.MaxByteCount,
		cubic:                      NewCubic(clock),
		clock:                      clock,
		reno:                       reno,
		qlogger:                    qlogger,
		maxDatagramSize:            initialMaxDatagramSize,
	}
	c.pacer = newPacer(c.BandwidthEstimate)
	if c.qlogger != nil {
		c.lastState = qlog.CongestionStateSlowStart
		c.qlogger.RecordEvent(qlog.CongestionStateUpdated{
			State: qlog.CongestionStateSlowStart,
		})
	}
	return c
}

// TimeUntilSend returns when the next packet should be sent.
func (c *cubicSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return c.pacer.TimeUntilSend()
}

func (c *cubicSender) HasPacingBudget(now monotime.Time) bool {
	return c.pacer.Budget(now) >= c.maxDatagramSize
}

func (c *cubicSender) maxCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * protocol.MaxCongestionWindowPackets
}

func (c *cubicSender) minCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * minCongestionWindowPackets
}

func (c *cubicSender) OnPacketSent(
	sentTime monotime.Time,
	_ protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	c.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	c.largestSentPacketNumber = packetNumber
	c.hybridSlowStart.OnPacketSent(packetNumber)
}

func (c *cubicSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < c.GetCongestionWindow()
}

func (c *cubicSender) InRecovery() bool {
	return c.largestAckedPacketNumber != protocol.InvalidPacketNumber && c.largestAckedPacketNumber <= c.largestSentAtLastCutback
}

func (c *cubicSender) InSlowStart() bool {
	return c.GetCongestionWindow() < c.slowStartThreshold
}

func (c *cubicSender) GetCongestionWindow() protocol.ByteCount {
	return c.congestionWindow
}

func (c *cubicSender) MaybeExitSlowStart() {
	if c.InSlowStart() &&
		c.hybridSlowStart.ShouldExitSlowStart(c.rttStats.LatestRTT(), c.rttStats.MinRTT(), c.GetCongestionWindow()/c.maxDatagramSize) {
		// exit slow start
		c.slowStartThreshold = c.congestionWindow
		c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	}
}

func (c *cubicSender) OnPacketAcked(
	ackedPacketNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	c.largestAckedPacketNumber = max(ackedPacketNumber, c.largestAckedPacketNumber)
	if c.InRecovery() {
		return
	}
	c.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, priorInFlight, eventTime)
	if c.InSlowStart() {
		// If hybridSlowStart's round-end completes CSS, exit slow start
		// immediately: subsequent per-packet OnPacketAcked calls within
		// this ReceivedAck (or in later reordered ACKs that don't update
		// RTT and therefore don't trigger MaybeExitSlowStart) would
		// otherwise still apply CSS-throttled growth past the CSS_ROUNDS
		// budget.
		if c.hybridSlowStart.OnPacketAcked(ackedPacketNumber) {
			c.slowStartThreshold = c.congestionWindow
			c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
		}
	}
}

func (c *cubicSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
	c.connStats.PacketsLost.Add(1)
	c.connStats.BytesLost.Add(uint64(lostBytes))

	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
	// already sent should be treated as a single loss event, since it's expected.
	if packetNumber <= c.largestSentAtLastCutback {
		// Same loss epoch — no further cut, but track this loss for the
		// spurious-loss undo counter so we don't wrongly undo when only
		// the trigger turns out to be spurious while a sibling was real.
		if c.preCutback != nil {
			c.lossesInEpoch++
		}
		return
	}
	// Snapshot pre-cut state for possible spurious-loss undo. A fresh cutback
	// supersedes any older snapshot — once we cut again, the prior cut's
	// "what would things look like if we hadn't cut" is no longer reachable.
	c.preCutback = &cwndSnapshot{
		congestionWindow:           c.congestionWindow,
		slowStartThreshold:         c.slowStartThreshold,
		largestSentAtLastCutback:   c.largestSentAtLastCutback,
		lastCutbackExitedSlowstart: c.lastCutbackExitedSlowstart,
		numAckedPackets:            c.numAckedPackets,
		cubic:                      *c.cubic,
	}
	c.lossesInEpoch = 1
	c.lastCutbackExitedSlowstart = c.InSlowStart()
	c.maybeQlogStateChange(qlog.CongestionStateRecovery)

	if c.reno {
		c.congestionWindow = protocol.ByteCount(float64(c.congestionWindow) * renoBeta)
	} else {
		c.congestionWindow = c.cubic.CongestionWindowAfterPacketLoss(c.congestionWindow)
	}
	if minCwnd := c.minCongestionWindow(); c.congestionWindow < minCwnd {
		c.congestionWindow = minCwnd
	}
	// Record whether the reduction was a no-op on cwnd (pre-cut already at
	// min, so the β / Cubic reduction got clamped back up). OnSpuriousLoss
	// uses this to distinguish the genuine "clamped cut" case — where
	// numAckedPackets and Cubic were reset without any cwnd movement and
	// the snapshot is the only place to recover them — from the "catch-up"
	// case where post-cut CA grew cwnd back to exactly the pre-cut value
	// and the live state now holds newer post-cut progress.
	c.preCutback.clamped = c.congestionWindow == c.preCutback.congestionWindow
	c.slowStartThreshold = c.congestionWindow
	c.largestSentAtLastCutback = c.largestSentPacketNumber
	// reset packet count from congestion avoidance mode. We start
	// counting again when we're out of recovery.
	c.numAckedPackets = 0
}

// OnSpuriousLoss undoes the cwnd reduction taken on the previous
// OnCongestionEvent only when *every* declared loss in the current cutback's
// epoch has been confirmed spurious. This avoids erasing a real congestion
// response when only some packets in the epoch were reordering false-
// positives and a sibling was a genuine loss.
func (c *cubicSender) OnSpuriousLoss(packetNumber protocol.PacketNumber) {
	s := c.preCutback
	if s == nil {
		return
	}
	// The current epoch covers (preCutback.largestSentAtLastCutback,
	// c.largestSentAtLastCutback]. A spurious packet outside that range
	// belongs to some earlier cut whose snapshot is gone, so can't be
	// used to undo the current cut.
	if packetNumber <= s.largestSentAtLastCutback {
		return
	}
	if c.lossesInEpoch > 0 {
		c.lossesInEpoch--
	}
	if c.lossesInEpoch > 0 {
		// Other losses in this epoch are still unresolved. If any of
		// them is genuine, the cut was deserved — wait for confirmation.
		return
	}
	// Always restore the epoch markers: ssthresh, largestSentAtLastCutback,
	// and the SS-exit flag. None of them accumulate value during post-cut
	// CA growth — only OnCongestionEvent moves them — so restoring them
	// never erases any post-cut work. Skipping them would leave the sender
	// stuck in CA at the post-cut ssthresh in two pathological cases:
	//   - Clamped cut: pre-cut cwnd was already at minCongestionWindow, so
	//     OnCongestionEvent didn't reduce cwnd numerically but DID set
	//     ssthresh to minCongestionWindow and bump largestSentAtLastCutback.
	//     The cwnd-restore gate below would skip everything (c.cwnd ==
	//     s.cwnd) and the spurious undo would have no observable effect.
	//   - Catch-up: post-cut ACKs grew cwnd past the pre-cut value via CA.
	//     The cwnd-restore gate skips the cwnd assignment (correct — we
	//     don't want to rewind growth), but we still want ssthresh back so
	//     subsequent growth is exponential SS, not the slow AIMD pace.
	c.slowStartThreshold = s.slowStartThreshold
	c.largestSentAtLastCutback = s.largestSentAtLastCutback
	c.lastCutbackExitedSlowstart = s.lastCutbackExitedSlowstart

	// Restore cwnd / Reno credit / Cubic state only when the live state
	// doesn't already reflect post-cut growth we'd otherwise discard:
	//   - c.cwnd < s.cwnd: post-cut CA hasn't caught up to the pre-cut
	//     value yet, so the snapshot's numAckedPackets/Cubic are still
	//     the most accurate pre-cut state.
	//   - s.clamped && c.cwnd == s.cwnd: the cut was a no-op on cwnd
	//     (pre-cut already at min), so the equality is "never moved"
	//     not "moved down and grew back". numAckedPackets and Cubic
	//     were reset by the cut without any post-cut activity to
	//     preserve — the snapshot is the only place those values still
	//     live. The cwnd assignment is a no-op here.
	// The equality case for a non-clamped cut is deliberately excluded:
	// it means post-cut CA grew cwnd back to exactly the pre-cut value
	// (Reno cwnd advances in MSS-sized steps, so landing on the snapshot
	// is plausible), and the live numAckedPackets / Cubic now carry
	// genuine post-cut progress.
	if c.congestionWindow < s.congestionWindow || (s.clamped && c.congestionWindow == s.congestionWindow) {
		c.congestionWindow = s.congestionWindow
		c.numAckedPackets = s.numAckedPackets
		*c.cubic = s.cubic
	}
	c.preCutback = nil
	if c.InSlowStart() {
		c.maybeQlogStateChange(qlog.CongestionStateSlowStart)
	} else {
		c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	}
}

// AbandonSpuriousLossUndo is called when a CongestionInformed entry leaves
// the lost-packet tracker without going through detectSpuriousLosses —
// either evicted on capacity in Add or aged out in DeleteBefore. The
// lossesInEpoch counter was incremented when OnCongestionEvent reported
// that loss; once the entry is gone, no future ACK can drive
// OnSpuriousLoss for it, and the counter would never reach zero, leaving
// the current epoch's undo permanently disabled. Dropping preCutback here
// makes subsequent OnSpuriousLoss calls bail out at the nil check rather
// than spinning on a counter that can never resolve, and lets the next
// genuine cut start with a clean snapshot.
//
// PNs that predate the current epoch (snapshot.largestSentAtLastCutback)
// belong to an older cutback whose snapshot is already gone, so dropping
// the current snapshot for them would be incorrect — skip them.
func (c *cubicSender) AbandonSpuriousLossUndo(packetNumber protocol.PacketNumber) {
	s := c.preCutback
	if s == nil {
		return
	}
	if packetNumber <= s.largestSentAtLastCutback {
		return
	}
	c.preCutback = nil
	c.lossesInEpoch = 0
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
func (c *cubicSender) maybeIncreaseCwnd(
	_ protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	// Do not increase the congestion window unless the sender is close to using
	// the current window.
	if !c.isCwndLimited(priorInFlight) {
		c.cubic.OnApplicationLimited()
		c.maybeQlogStateChange(qlog.CongestionStateApplicationLimited)
		return
	}
	if c.congestionWindow >= c.maxCongestionWindow() {
		return
	}
	if c.InSlowStart() {
		// Slow start (or HyStart++ CSS): increase cwnd by one MSS per ACK
		// in regular SS, by one MSS / CSS_GROWTH_DIVISOR in CSS.
		c.congestionWindow += c.maxDatagramSize / protocol.ByteCount(c.hybridSlowStart.GrowthDivisor())
		c.maybeQlogStateChange(qlog.CongestionStateSlowStart)
		return
	}
	// Congestion avoidance
	c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	if c.reno {
		// Classic Reno congestion avoidance.
		c.numAckedPackets++
		if c.numAckedPackets >= uint64(c.congestionWindow/c.maxDatagramSize) {
			c.congestionWindow += c.maxDatagramSize
			c.numAckedPackets = 0
		}
	} else {
		c.congestionWindow = min(
			c.maxCongestionWindow(),
			c.cubic.CongestionWindowAfterAck(ackedBytes, c.congestionWindow, c.rttStats.MinRTT(), eventTime),
		)
	}
}

func (c *cubicSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	congestionWindow := c.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return true
	}
	availableBytes := congestionWindow - bytesInFlight
	slowStartLimited := c.InSlowStart() && bytesInFlight > congestionWindow/2
	return slowStartLimited || availableBytes <= maxBurstPackets*c.maxDatagramSize
}

// BandwidthEstimate returns the current bandwidth estimate
func (c *cubicSender) BandwidthEstimate() Bandwidth {
	srtt := c.rttStats.SmoothedRTT()
	if srtt == 0 {
		// This should never happen, but if it does, avoid division by zero.
		srtt = protocol.TimerGranularity
	}
	return BandwidthFromDelta(c.GetCongestionWindow(), srtt)
}

// OnRetransmissionTimeout is called on an retransmission timeout
func (c *cubicSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	if !packetsRetransmitted {
		return
	}
	c.hybridSlowStart.Restart()
	c.cubic.Reset()
	c.slowStartThreshold = c.congestionWindow / 2
	c.congestionWindow = c.minCongestionWindow()
	// Drop any pre-RTO spurious-loss snapshot. A later OnSpuriousLoss for
	// a packet from the pre-RTO epoch would otherwise restore the
	// pre-RTO cwnd/ssthresh, undoing the RTO reset.
	c.preCutback = nil
	c.lossesInEpoch = 0
}

// OnConnectionMigration is called when the connection is migrated (?)
func (c *cubicSender) OnConnectionMigration() {
	c.hybridSlowStart.Restart()
	c.largestSentPacketNumber = protocol.InvalidPacketNumber
	c.largestAckedPacketNumber = protocol.InvalidPacketNumber
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	c.lastCutbackExitedSlowstart = false
	c.cubic.Reset()
	c.numAckedPackets = 0
	c.congestionWindow = c.initialCongestionWindow
	c.slowStartThreshold = c.initialMaxCongestionWindow
	// Drop any pre-migration spurious-loss snapshot. A later
	// OnSpuriousLoss for a packet from the pre-migration epoch would
	// otherwise restore the pre-migration cwnd/ssthresh, undoing the
	// migration reset that put cwnd back at the initial window.
	c.preCutback = nil
	c.lossesInEpoch = 0
}

func (c *cubicSender) maybeQlogStateChange(new qlog.CongestionState) {
	if c.qlogger == nil || new == c.lastState {
		return
	}
	c.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: new})
	c.lastState = new
}

func (c *cubicSender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < c.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", c.maxDatagramSize, s))
	}
	cwndIsMinCwnd := c.congestionWindow == c.minCongestionWindow()
	c.maxDatagramSize = s
	if cwndIsMinCwnd {
		c.congestionWindow = c.minCongestionWindow()
	}
	c.pacer.SetMaxDatagramSize(s)
}
