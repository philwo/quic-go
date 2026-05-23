package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

// HyStart++ parameters per RFC 9406.
const (
	// Minimum window before HyStart++ is allowed to act (in packets).
	hybridStartLowWindow = protocol.ByteCount(16)
	// Number of RTT samples required in a round before the inflation check fires.
	hybridStartMinSamples = uint32(8)
	// Bounds on the RTT-inflation threshold: clamp(LastRoundMinRTT/8, 4ms, 16ms).
	hybridStartDelayMinThresholdUs = int64(4000)
	hybridStartDelayMaxThresholdUs = int64(16000)
	// CSS: cwnd grows at 1/CSS_GROWTH_DIVISOR the regular slow-start rate.
	cssGrowthDivisor = 4
	// CSS: number of rounds spent in CSS before confirming exit to CA.
	cssRoundsCount = 5
)

type hybridSSState uint8

const (
	hybridSSNormal hybridSSState = iota
	hybridSSConservative
)

// HybridSlowStart implements HyStart++ (RFC 9406), an evolution of the
// original HyStart that adds a CSS (Conservative Slow Start) phase between
// regular slow start and congestion avoidance.
//
// When the current round's min RTT is found to be inflated relative to the
// previous round's min RTT, the algorithm enters CSS rather than immediately
// exiting to CA. In CSS, cwnd grows at 1/CSS_GROWTH_DIVISOR the regular rate
// for up to CSS_ROUNDS rounds. If inflation persists for the full CSS window
// the exit to CA is confirmed; if inflation goes away the algorithm returns
// to regular slow start. The effect is to absorb single-round RTT spikes
// that aren't real congestion, while still bounding cwnd's overshoot when
// they are.
type HybridSlowStart struct {
	endPacketNumber      protocol.PacketNumber
	lastSentPacketNumber protocol.PacketNumber

	state hybridSSState

	// Per-round bookkeeping.
	started            bool
	rttSampleCount     uint32
	currentRoundMinRTT time.Duration

	// Min RTT observed during the previous fully-completed round; used as
	// the baseline against which currentRoundMinRTT is compared. Zero until
	// at least one round has produced samples.
	lastRoundMinRTT time.Duration

	// CSS state.
	cssBaselineMinRTT time.Duration
	cssRoundsLeft     int

	// Set when CSS expires with persistent inflation; once true,
	// ShouldExitSlowStart returns true (gated only on cwnd >= lowWindow).
	hystartFound bool
}

// StartReceiveRound is called for the start of each receive round (burst).
// It promotes the just-completed round's minimum RTT into lastRoundMinRTT
// so that it can serve as the baseline for the new round.
func (s *HybridSlowStart) StartReceiveRound(lastSent protocol.PacketNumber) {
	s.endPacketNumber = lastSent
	if s.currentRoundMinRTT > 0 {
		s.lastRoundMinRTT = s.currentRoundMinRTT
	}
	s.currentRoundMinRTT = 0
	s.rttSampleCount = 0
	s.started = true
}

// IsEndOfRound returns true if this ack is past the last packet number of
// the current round.
func (s *HybridSlowStart) IsEndOfRound(ack protocol.PacketNumber) bool {
	return s.endPacketNumber < ack
}

// ShouldExitSlowStart processes one RTT sample (called per ACK) and returns
// true once HyStart++ has confirmed an exit to congestion avoidance — which
// happens only after CSS has run its full duration with persistent inflation.
//
// The minRTT parameter is no longer consulted (HyStart++ uses the previous
// round's min as baseline) but is preserved in the signature for source
// compatibility with the original HyStart caller.
func (s *HybridSlowStart) ShouldExitSlowStart(latestRTT, _ time.Duration, congestionWindow protocol.ByteCount) bool {
	if s.hystartFound {
		return congestionWindow >= hybridStartLowWindow
	}
	if !s.started {
		s.StartReceiveRound(s.lastSentPacketNumber)
	}
	s.rttSampleCount++
	if s.currentRoundMinRTT == 0 || s.currentRoundMinRTT > latestRTT {
		s.currentRoundMinRTT = latestRTT
	}
	// The inflation check only fires once we have N_RTT_SAMPLE samples and
	// a baseline from a previous round.
	if s.rttSampleCount != hybridStartMinSamples || s.lastRoundMinRTT == 0 {
		return false
	}

	threshUs := int64(s.lastRoundMinRTT/time.Microsecond) >> 3
	threshUs = min(threshUs, hybridStartDelayMaxThresholdUs)
	threshUs = max(threshUs, hybridStartDelayMinThresholdUs)
	rttThresh := time.Duration(threshUs) * time.Microsecond

	switch s.state {
	case hybridSSNormal:
		if s.currentRoundMinRTT >= s.lastRoundMinRTT+rttThresh {
			// Inflation detected — enter CSS to confirm rather than exit
			// straight to CA.
			s.state = hybridSSConservative
			s.cssBaselineMinRTT = s.currentRoundMinRTT
			s.cssRoundsLeft = cssRoundsCount
		}
	case hybridSSConservative:
		// In CSS, an RTT below the baseline means the inflation was a
		// transient (likely a single-packet delay spike); abandon CSS and
		// resume regular slow start.
		if s.currentRoundMinRTT < s.cssBaselineMinRTT {
			s.state = hybridSSNormal
			s.cssBaselineMinRTT = 0
			s.cssRoundsLeft = 0
		}
	}
	// Exit-to-CA confirmation happens at round end (OnPacketAcked) — not
	// here, so this sample alone never returns true.
	return false
}

// OnPacketSent is called when a packet is sent.
func (s *HybridSlowStart) OnPacketSent(packetNumber protocol.PacketNumber) {
	s.lastSentPacketNumber = packetNumber
}

// OnPacketAcked is called for each ACKed packet. At round boundaries, this
// drives the CSS round counter — exit to CA is confirmed once cssRoundsLeft
// reaches zero with state still in CSS.
func (s *HybridSlowStart) OnPacketAcked(ackedPacketNumber protocol.PacketNumber) {
	if !s.IsEndOfRound(ackedPacketNumber) {
		return
	}
	s.started = false
	if s.state == hybridSSConservative && s.cssRoundsLeft > 0 {
		s.cssRoundsLeft--
		if s.cssRoundsLeft == 0 {
			s.hystartFound = true
		}
	}
}

// InCSS reports whether HyStart++ is in Conservative Slow Start. Callers
// (cubicSender) use this to slow cwnd growth via GrowthDivisor.
func (s *HybridSlowStart) InCSS() bool { return s.state == hybridSSConservative }

// GrowthDivisor returns the divisor by which slow-start cwnd growth should
// be scaled down — 1 in regular SS, CSS_GROWTH_DIVISOR (=4) in CSS.
func (s *HybridSlowStart) GrowthDivisor() int {
	if s.state == hybridSSConservative {
		return cssGrowthDivisor
	}
	return 1
}

// Started reports whether a round is currently in progress.
func (s *HybridSlowStart) Started() bool { return s.started }

// Restart resets all HyStart++ state. Call on RTO, connection migration,
// or any other event that requires the slow-start phase to begin fresh.
func (s *HybridSlowStart) Restart() {
	s.started = false
	s.hystartFound = false
	s.state = hybridSSNormal
	s.currentRoundMinRTT = 0
	s.lastRoundMinRTT = 0
	s.cssBaselineMinRTT = 0
	s.cssRoundsLeft = 0
	s.rttSampleCount = 0
}
