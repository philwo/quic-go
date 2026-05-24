package congestion

import (
	"testing"
	"time"

	"github.com/philwo/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestHybridSlowStartSimpleCase(t *testing.T) {
	slowStart := HybridSlowStart{}

	packetNumber := protocol.PacketNumber(1)
	endPacketNumber := protocol.PacketNumber(3)
	slowStart.StartReceiveRound(endPacketNumber)

	packetNumber++
	require.False(t, slowStart.IsEndOfRound(packetNumber))

	// Test duplicates.
	require.False(t, slowStart.IsEndOfRound(packetNumber))

	packetNumber++
	require.False(t, slowStart.IsEndOfRound(packetNumber))
	packetNumber++
	require.True(t, slowStart.IsEndOfRound(packetNumber))

	// Test without a new registered end_packet_number;
	packetNumber++
	require.True(t, slowStart.IsEndOfRound(packetNumber))

	endPacketNumber = 20
	slowStart.StartReceiveRound(endPacketNumber)
	for packetNumber < endPacketNumber {
		packetNumber++
		require.False(t, slowStart.IsEndOfRound(packetNumber))
	}
	packetNumber++
	require.True(t, slowStart.IsEndOfRound(packetNumber))
}

// finishRound feeds 8 RTT samples then signals end-of-round, simulating one
// full HyStart++ round at the given RTT. cwnd is just a placeholder above
// hybridStartLowWindow so the gating check doesn't suppress the result.
// Returns true if either an RTT-sample callback or the round-ending ACK
// reported the slow-start exit confirmation.
func finishRound(s *HybridSlowStart, rtt time.Duration) bool {
	var exit bool
	for range hybridStartMinSamples {
		if s.ShouldExitSlowStart(rtt, 0, 100) {
			exit = true
		}
	}
	// Advance the round.
	if s.OnPacketAcked(s.endPacketNumber + 1) {
		exit = true
	}
	return exit
}

// TestHybridSlowStartEntersCSSOnInflation verifies that a single inflated
// round causes a transition into CSS — not an immediate exit to CA.
func TestHybridSlowStartEntersCSSOnInflation(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond

	// Round 1: baseline. No baseline yet from a previous round, so no check.
	require.False(t, finishRound(&s, baseRTT))
	require.False(t, s.InCSS())

	// Round 2: inflated by 20ms (well over the clamped threshold of 7.5ms).
	require.False(t, finishRound(&s, baseRTT+20*time.Millisecond))
	require.True(t, s.InCSS(), "should have entered CSS after one inflated round")
	require.Equal(t, cssGrowthDivisor, s.GrowthDivisor())
}

// TestHybridSlowStartCSSExitsToCAAfterRounds verifies that CSS with persistent
// inflation eventually confirms the exit to congestion avoidance.
func TestHybridSlowStartCSSExitsToCAAfterRounds(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	const inflated = baseRTT + 20*time.Millisecond

	// Round 1: baseline.
	require.False(t, finishRound(&s, baseRTT))
	// Round 2: trigger CSS. Its OnPacketAcked counts as the first CSS round
	// (cssRoundsLeft 5→4).
	require.False(t, finishRound(&s, inflated))
	require.True(t, s.InCSS())

	// CSS_ROUNDS-1 more rounds at inflated RTT exhaust the budget. The last
	// of those rounds reports the exit confirmation immediately via
	// OnPacketAcked (and also leaves CSS state right away).
	for i := range cssRoundsCount - 1 {
		exit := finishRound(&s, inflated)
		if i < cssRoundsCount-2 {
			require.False(t, exit, "round %d in CSS should not exit yet", i)
			require.True(t, s.InCSS())
		} else {
			require.True(t, exit, "final CSS round should report exit to CA")
			require.False(t, s.InCSS(),
				"exit confirmation should also leave CSS state immediately")
		}
	}
}

// TestHybridSlowStartCSSCountsOneRoundPerBatchedAck verifies that a single
// ACK frame acknowledging multiple packets past endPacketNumber only counts
// as ONE CSS round, not one per acked packet. Without the started-flag
// gate in OnPacketAcked, IsEndOfRound stays true for every post-round-end
// packet in the same ACK (endPacketNumber only advances when the next
// ShouldExitSlowStart triggers a fresh StartReceiveRound), so a batched
// or delayed ACK could consume several of the five CSS rounds at once
// and force a premature exit to congestion avoidance.
func TestHybridSlowStartCSSCountsOneRoundPerBatchedAck(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	const inflated = baseRTT + 20*time.Millisecond
	const cwnd = protocol.ByteCount(100)

	require.False(t, finishRound(&s, baseRTT))  // round 1: baseline
	require.False(t, finishRound(&s, inflated)) // round 2: enter CSS
	require.True(t, s.InCSS())
	require.Equal(t, cssRoundsCount-1, s.cssRoundsLeft,
		"sanity: round 2 ended already counted one CSS round")

	// Simulate a round in CSS where the round-end ACK arrives as a single
	// frame acking three packets past endPacketNumber. ShouldExitSlowStart
	// is called once per ACK frame (drives the RTT samples); OnPacketAcked
	// is called once per acked packet — and all three packets have
	// PNs > endPacketNumber.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(inflated, 0, cwnd))
	}
	endPN := s.endPacketNumber
	s.OnPacketAcked(endPN + 1)
	s.OnPacketAcked(endPN + 2)
	s.OnPacketAcked(endPN + 3)

	// Exactly one CSS round consumed by this batched round-end, not three.
	require.Equal(t, cssRoundsCount-2, s.cssRoundsLeft,
		"one ACK frame past the round end must consume exactly one CSS round")
	require.True(t, s.InCSS(),
		"with %d CSS rounds still left, CSS must not have exited yet", cssRoundsCount-2)
	require.False(t, s.hystartFound,
		"hystartFound must not flip until cssRoundsLeft truly hits zero")
}

// TestHybridSlowStartCSSAbandonedOnRecovery verifies that if the RTT spike
// goes away mid-CSS, we return to regular slow start instead of exiting.
func TestHybridSlowStartCSSAbandonedOnRecovery(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	const inflated = baseRTT + 20*time.Millisecond

	require.False(t, finishRound(&s, baseRTT))     // round 1: baseline
	require.False(t, finishRound(&s, inflated))    // round 2: enter CSS
	require.True(t, s.InCSS())

	// RTT returns below the CSS baseline: CSS is abandoned.
	require.False(t, finishRound(&s, baseRTT))
	require.False(t, s.InCSS(), "CSS should have been abandoned when RTT recovered")
	require.Equal(t, 1, s.GrowthDivisor())
}

// TestHybridSlowStartNoExitWithoutInflation verifies the happy path — stable
// RTT across many rounds leaves us in regular slow start indefinitely.
func TestHybridSlowStartNoExitWithoutInflation(t *testing.T) {
	s := HybridSlowStart{}
	const rtt = 60 * time.Millisecond
	for range 10 {
		require.False(t, finishRound(&s, rtt))
		require.False(t, s.InCSS())
	}
}

// TestHybridSlowStartCSSRecoversAfterMinSamples verifies that CSS recovery
// keeps firing on every RTT sample past N_RTT_SAMPLE, not just the eighth.
// Per RFC 9406 §4.2 the inflation check uses >=, not ==; a CSS round whose
// recovering sample lands at #9+ must still abandon CSS.
func TestHybridSlowStartCSSRecoversAfterMinSamples(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	const inflated = baseRTT + 20*time.Millisecond
	const cwnd = protocol.ByteCount(100)

	require.False(t, finishRound(&s, baseRTT))  // round 1: baseline
	require.False(t, finishRound(&s, inflated)) // round 2: enter CSS
	require.True(t, s.InCSS())

	// Round 3 in CSS: feed the minimum-required 8 samples at the same RTT as
	// the CSS baseline (no recovery would be detected here either way), then
	// a 9th sample below the baseline. With the bug, the 9th-sample check is
	// skipped because rttSampleCount != hybridStartMinSamples; the test
	// would fail because CSS would persist.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(inflated, 0, cwnd))
	}
	require.True(t, s.InCSS(), "still in CSS after the first 8 samples")

	require.False(t, s.ShouldExitSlowStart(baseRTT, 0, cwnd))
	require.False(t, s.InCSS(),
		"sample past N_RTT_SAMPLE with RTT below the CSS baseline must abandon CSS")
	require.Equal(t, 1, s.GrowthDivisor())
}

// TestHybridSlowStartLowCwndGatesCSSEntry verifies that CSS entry honors the
// same lowWindow gate as the exit-to-CA confirmation. Even with clear RTT
// inflation, a cwnd below hybridStartLowWindow must NOT enter CSS — otherwise
// a post-RTO restart at the minimum cwnd would have its slow-start growth
// throttled by 4x before HyStart++ is supposed to act at all.
func TestHybridSlowStartLowCwndGatesCSSEntry(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	const inflated = baseRTT + 20*time.Millisecond
	const lowCwnd = hybridStartLowWindow - 1

	// Round 1 at low cwnd establishes the baseline.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(baseRTT, 0, lowCwnd))
	}
	s.OnPacketAcked(s.endPacketNumber + 1)

	// Round 2: inflated RTT at low cwnd. Inflation is real, but the gate
	// must prevent CSS entry; we should remain in normal slow start.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(inflated, 0, lowCwnd))
	}
	require.False(t, s.InCSS(), "low-cwnd gate must prevent CSS entry")
	require.Equal(t, 1, s.GrowthDivisor(),
		"GrowthDivisor must stay at 1 while below the lowWindow threshold")

	// Sanity: once cwnd crosses the threshold within a still-inflated round,
	// CSS entry is allowed.
	require.False(t, s.ShouldExitSlowStart(inflated, 0, hybridStartLowWindow))
	require.True(t, s.InCSS(),
		"with cwnd at the threshold and inflation, CSS entry should fire")
}

// TestHybridSlowStartLowCwndPreservesInflation verifies that an inflated
// round sampled below hybridStartLowWindow does NOT silently overwrite the
// next round's baseline with the already-inflated currentRoundMinRTT. The
// lowWindow gate prevents CSS *entry* (we can't act yet) but the inflation
// signal has to survive into the next round so a persistently inflated
// following round — above lowWindow — can still detect it. Without
// preservation, the next StartReceiveRound promotes the inflated RTT into
// lastRoundMinRTT, and the persistently inflated next round compares
// against the inflated baseline (no inflation detected) and never enters
// CSS.
func TestHybridSlowStartLowCwndPreservesInflation(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	const inflated = baseRTT + 20*time.Millisecond
	const lowCwnd = hybridStartLowWindow - 1

	// Round 1 at low cwnd at baseRTT — establishes a clean baseline of
	// baseRTT (no inflation detected since lastRoundMinRTT was 0).
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(baseRTT, 0, lowCwnd))
	}
	s.OnPacketAcked(s.endPacketNumber + 1)

	// Round 2 at low cwnd at inflated RTT. Inflation IS detected against
	// the round-1 baseline, but the lowWindow gate prevents CSS entry.
	// The fix preserves the signal by suppressing the baseline promotion
	// at the next StartReceiveRound.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(inflated, 0, lowCwnd))
	}
	require.False(t, s.InCSS(), "lowWindow gate must prevent CSS entry below threshold")
	s.OnPacketAcked(s.endPacketNumber + 1)

	// Round 3 at cwnd >= lowWindow, RTT still inflated. With the
	// preservation, lastRoundMinRTT is still baseRTT (round 1's value),
	// so the inflation check fires again and CSS entry succeeds. Without
	// it, lastRoundMinRTT would have been promoted to the inflated
	// value, the check would compare inflated vs inflated → no inflation
	// → no CSS entry.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(inflated, 0, hybridStartLowWindow))
	}
	require.True(t, s.InCSS(),
		"persistent inflation after crossing lowWindow must enter CSS — "+
			"the low-cwnd inflation signal must survive the round boundary")
}

// TestHybridSlowStartLowCwndClearsSuppressionWhenRecovered verifies that the
// low-window baseline-suppression flag tracks the *latest* inflation verdict
// within the round — not just "did we ever see inflation". currentRoundMinRTT
// is monotonically decreasing across the round; a later sample can drop it
// back below the inflation threshold, so the completed round is no longer
// inflated and StartReceiveRound must promote its (lower) MinRTT normally.
// Without the clear, the suppress flag would hold stale, the next round
// would compare against an older lower baseline, and a small RTT increase
// after crossing lowWindow could trip the inflation check and falsely
// enter CSS.
func TestHybridSlowStartLowCwndClearsSuppressionWhenRecovered(t *testing.T) {
	s := HybridSlowStart{}
	const lowCwnd = hybridStartLowWindow - 1
	const aboveLowCwnd = hybridStartLowWindow

	// Round 1 at low cwnd at 45ms — establishes lastRoundMinRTT = 45ms
	// (no inflation detected; lastRoundMinRTT was 0).
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(45*time.Millisecond, 0, lowCwnd))
	}
	s.OnPacketAcked(s.endPacketNumber + 1)

	// Round 2 at low cwnd:
	//   - Samples 1..8 at 70ms. The 8th sample fires the inflation check:
	//     70ms >= 45ms + clamp(45/8, 4, 16)ms = 45ms + 5.625ms → inflated.
	//     With my fix, suppressBaselineUpdate is set true.
	//   - Sample 9 at 50ms drops currentRoundMinRTT to 50ms. The check
	//     re-fires: 50ms < 45ms + 5.625ms = 50.625ms → NOT inflated. The
	//     fix must clear suppressBaselineUpdate here; without it, the
	//     flag stays true and the next StartReceiveRound skips promotion.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(70*time.Millisecond, 0, lowCwnd))
	}
	require.False(t, s.ShouldExitSlowStart(50*time.Millisecond, 0, lowCwnd))
	s.OnPacketAcked(s.endPacketNumber + 1)

	// Round 3 above lowWindow at 51ms. With the fix:
	//   lastRoundMinRTT = 50ms (round 2's actual MinRTT, promoted normally).
	//   Threshold = clamp(50/8, 4, 16)ms = 6.25ms. 51ms < 50ms + 6.25ms →
	//   no inflation → no CSS entry.
	// Without the fix:
	//   lastRoundMinRTT = 45ms (round 1's stale value, since round 2's
	//   promotion was suppressed). Threshold = 5.625ms. 51ms >= 45ms +
	//   5.625ms = 50.625ms → inflated → false CSS entry.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(51*time.Millisecond, 0, aboveLowCwnd))
	}
	require.False(t, s.InCSS(),
		"a small RTT increase after a recovered low-cwnd round must NOT enter CSS — "+
			"the stale older baseline would otherwise trip the inflation check")
}

// TestHybridSlowStartLowCwndClearsSuppressionAcrossThreshold verifies that
// when a low-cwnd inflated sample has already set suppressBaselineUpdate
// and then a later sample in the SAME round arrives with cwnd >=
// hybridStartLowWindow (acting on the inflation, e.g. by entering CSS),
// the suppression flag is cleared. Without the clear, the next
// StartReceiveRound would drop the just-completed (acted-upon) round's
// MinRTT and the *following* round would compare against a stale older
// baseline — leading to false CSS re-entry on a small RTT bump.
func TestHybridSlowStartLowCwndClearsSuppressionAcrossThreshold(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	const inflated = baseRTT + 20*time.Millisecond
	const lowCwnd = hybridStartLowWindow - 1
	const aboveLowCwnd = hybridStartLowWindow

	// Round 1 at low cwnd at baseRTT — establishes lastRoundMinRTT =
	// baseRTT (no inflation detected, lastRoundMinRTT was 0).
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(baseRTT, 0, lowCwnd))
	}
	s.OnPacketAcked(s.endPacketNumber + 1)

	// Round 2 starts at low cwnd, then cwnd crosses lowWindow mid-round:
	//   - Samples 1..8 at low cwnd at inflated RTT. The 8th sample fires
	//     the inflation check (cwnd < lowWindow path) and sets
	//     suppressBaselineUpdate = true.
	//   - Sample 9 in the same round at cwnd >= lowWindow, still inflated.
	//     Now we take the inflation-acted path and enter CSS. The fix
	//     clears suppressBaselineUpdate here; without it the flag stays
	//     true and the next StartReceiveRound drops round 2's MinRTT.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(inflated, 0, lowCwnd))
	}
	require.True(t, s.suppressBaselineUpdate,
		"sanity: low-cwnd inflated sample must set suppressBaselineUpdate")
	require.False(t, s.ShouldExitSlowStart(inflated, 0, aboveLowCwnd))
	require.True(t, s.InCSS(),
		"sanity: above-lowWindow inflated sample must enter CSS in the same round")
	require.False(t, s.suppressBaselineUpdate,
		"crossing the lowWindow gate within a round must clear stale suppression; "+
			"otherwise the just-completed (acted-upon) round's MinRTT is dropped, "+
			"leaving a stale older baseline that can re-enter CSS falsely")

	// End round 2; the next StartReceiveRound must promote round 2's
	// MinRTT (inflated) into lastRoundMinRTT — only possible if
	// suppressBaselineUpdate was correctly cleared above.
	s.OnPacketAcked(s.endPacketNumber + 1)
	s.ShouldExitSlowStart(baseRTT, 0, aboveLowCwnd) // triggers StartReceiveRound
	require.Equal(t, inflated, s.lastRoundMinRTT,
		"round 2's MinRTT must be promoted as the new baseline")
}

// TestHybridSlowStartCSSExitDoesNotApplyCSSGrowthAfter verifies that once
// OnPacketAcked confirms the HyStart++ exit (returns true), subsequent
// per-packet OnPacketAcked calls — e.g. batched ACKs or reordered ACKs
// that don't update RTT and therefore don't trigger MaybeExitSlowStart —
// do NOT re-apply CSS growth. The state must be hybridSSNormal and
// GrowthDivisor must return 1 immediately on the round-end exit
// transition.
func TestHybridSlowStartCSSExitDoesNotApplyCSSGrowthAfter(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	const inflated = baseRTT + 20*time.Millisecond

	// Round 1 baseline; round 2 enters CSS and counts as the first CSS
	// round (cssRoundsLeft 5→4).
	require.False(t, finishRound(&s, baseRTT))
	require.False(t, finishRound(&s, inflated))
	require.True(t, s.InCSS())
	require.Equal(t, cssGrowthDivisor, s.GrowthDivisor(),
		"sanity: CSS must throttle growth via GrowthDivisor=4")

	// Burn cssRoundsCount-2 more rounds in CSS without exhausting the
	// budget; each one decrements cssRoundsLeft and must keep us in CSS.
	for range cssRoundsCount - 2 {
		require.False(t, finishRound(&s, inflated))
		require.True(t, s.InCSS())
		require.Equal(t, cssGrowthDivisor, s.GrowthDivisor())
	}

	// The next round-ending ACK exhausts the CSS budget. OnPacketAcked
	// must return true (so cubicSender can exit slow start immediately)
	// AND drop the state out of CSS so any subsequent per-packet ACK in
	// the same ReceivedAck call (or in a later reordered ACK that doesn't
	// update RTT) won't keep applying CSS-throttled growth.
	for range hybridStartMinSamples {
		require.False(t, s.ShouldExitSlowStart(inflated, 0, 100))
	}
	require.True(t, s.OnPacketAcked(s.endPacketNumber+1),
		"the exit-confirming round-end ACK must signal the caller")
	require.False(t, s.InCSS(),
		"state must leave CSS immediately on exit confirmation")
	require.Equal(t, 1, s.GrowthDivisor(),
		"GrowthDivisor must return 1 immediately so further OnPacketAcked "+
			"calls don't apply CSS-throttled growth before MaybeExitSlowStart")
}

// TestHybridSlowStartRestart verifies Restart wipes all CSS bookkeeping.
func TestHybridSlowStartRestart(t *testing.T) {
	s := HybridSlowStart{}
	const baseRTT = 60 * time.Millisecond
	require.False(t, finishRound(&s, baseRTT))
	require.False(t, finishRound(&s, baseRTT+20*time.Millisecond))
	require.True(t, s.InCSS())

	s.Restart()
	require.False(t, s.InCSS())
	require.Equal(t, 1, s.GrowthDivisor())
	require.False(t, s.Started())
}
