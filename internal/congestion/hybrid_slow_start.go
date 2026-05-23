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

	// suppressBaselineUpdate defers the StartReceiveRound promotion of
	// currentRoundMinRTT into lastRoundMinRTT for one round. Set when the
	// inflation check fires in ShouldExitSlowStart but cwnd is still below
	// hybridStartLowWindow, so CSS entry would be illegal here. Without
	// this, the inflated currentRoundMinRTT would become lastRoundMinRTT
	// at round end and a persistently inflated following round would
	// compare against that already-inflated baseline and never enter CSS.
	// Cleared by StartReceiveRound after consulting it.
	suppressBaselineUpdate bool
}

// StartReceiveRound is called for the start of each receive round (burst).
// It promotes the just-completed round's minimum RTT into lastRoundMinRTT
// so that it can serve as the baseline for the new round, unless that
// promotion was suppressed (see suppressBaselineUpdate).
func (s *HybridSlowStart) StartReceiveRound(lastSent protocol.PacketNumber) {
	s.endPacketNumber = lastSent
	if s.currentRoundMinRTT > 0 && !s.suppressBaselineUpdate {
		s.lastRoundMinRTT = s.currentRoundMinRTT
	}
	s.suppressBaselineUpdate = false
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
	// The inflation check fires from the N_RTT_SAMPLE-th sample onward
	// (RFC 9406 §4.2 uses >=, not ==). Continuing to check on every
	// subsequent sample within the round matters in CSS: a later sample
	// can lower currentRoundMinRTT below cssBaselineMinRTT and prove the
	// inflation transient, so we must not miss it because it didn't
	// arrive exactly on sample #8.
	if s.rttSampleCount < hybridStartMinSamples || s.lastRoundMinRTT == 0 {
		return false
	}

	threshUs := int64(s.lastRoundMinRTT/time.Microsecond) >> 3
	threshUs = min(threshUs, hybridStartDelayMaxThresholdUs)
	threshUs = max(threshUs, hybridStartDelayMinThresholdUs)
	rttThresh := time.Duration(threshUs) * time.Microsecond
	inflated := s.currentRoundMinRTT >= s.lastRoundMinRTT+rttThresh

	switch s.state {
	case hybridSSNormal:
		// Gate CSS entry — but not inflation *detection* — on the same
		// lowWindow threshold that gates the final exit-to-CA
		// confirmation. Without the gate, a post-RTO start at the minimum
		// cwnd could enter CSS on the very first inflated sample and
		// immediately throttle slow-start growth by 4x, even though
		// HyStart++ is not supposed to act below this threshold. But we
		// still have to preserve the inflation signal: if we let the next
		// StartReceiveRound promote the inflated currentRoundMinRTT into
		// lastRoundMinRTT, a persistently inflated following round would
		// compare against the inflated baseline and never detect
		// inflation. Suppress that one promotion instead.
		//
		// Re-evaluate the suppress flag on every fired check rather than
		// only setting it. currentRoundMinRTT is monotonically decreasing
		// (it's a min over the round's samples), so a later sample within
		// the same low-cwnd round can drop it back below the inflation
		// threshold; the completed round is then no longer inflated and
		// the next StartReceiveRound must promote its (lower) MinRTT
		// normally. Holding the flag stale would otherwise leave the
		// baseline at an older, lower value and let a small RTT bump in
		// the following round trip the inflation check falsely.
		if congestionWindow < hybridStartLowWindow {
			s.suppressBaselineUpdate = inflated
			return false
		}
		// cwnd is at or above the lowWindow gate, so we are allowed to act
		// on inflation in this round. Clear any stale suppression left over
		// from an earlier sample of *this* round that fired the inflation
		// check while cwnd was still below the gate. Without this, a round
		// that crosses lowWindow mid-flight would (a) act on the inflation
		// here yet (b) still suppress the next StartReceiveRound's
		// baseline promotion — dropping the just-completed round's MinRTT
		// and leaving an older lower baseline that can falsely re-enter
		// CSS once the current round's CSS resolves.
		s.suppressBaselineUpdate = false
		if inflated {
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
// reaches zero with state still in CSS. Returns true if this ACK confirmed
// the HyStart++ exit, signalling the caller (cubicSender) to exit slow
// start immediately (ssthresh = cwnd, leave CSS). Without an immediate
// signal, any further per-packet OnPacketAcked calls before the next
// MaybeExitSlowStart — including reordered ACKs that don't update RTT —
// would still apply CSS-throttled growth past the CSS_ROUNDS budget.
//
// One ACK frame can ack multiple packets, all of which may have packet
// numbers past endPacketNumber. Without a guard, every such packet would
// fire the round-end handling (IsEndOfRound stays true until the next
// StartReceiveRound, which only happens once per ACK in ShouldExitSlowStart)
// and a single batched/delayed ACK could consume several CSS rounds at
// once, forcing a premature exit to CA. Gate the work on the first
// transition out of a started round.
func (s *HybridSlowStart) OnPacketAcked(ackedPacketNumber protocol.PacketNumber) (exitSlowStart bool) {
	if !s.IsEndOfRound(ackedPacketNumber) || !s.started {
		return false
	}
	s.started = false
	if s.state == hybridSSConservative && s.cssRoundsLeft > 0 {
		s.cssRoundsLeft--
		if s.cssRoundsLeft == 0 {
			s.hystartFound = true
			// Leave CSS now so GrowthDivisor returns 1 on any subsequent
			// per-packet OnPacketAcked call before MaybeExitSlowStart
			// runs and sets ssthresh.
			s.state = hybridSSNormal
			s.cssBaselineMinRTT = 0
			return true
		}
	}
	return false
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
