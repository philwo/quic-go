package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

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
func finishRound(s *HybridSlowStart, rtt time.Duration) bool {
	var exit bool
	for range hybridStartMinSamples {
		if s.ShouldExitSlowStart(rtt, 0, 100) {
			exit = true
		}
	}
	// Advance the round.
	s.OnPacketAcked(s.endPacketNumber + 1)
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
	// Round 2: trigger CSS.
	require.False(t, finishRound(&s, inflated))
	require.True(t, s.InCSS())

	// CSS_ROUNDS more rounds at inflated RTT — the last one confirms exit.
	for i := range cssRoundsCount {
		exit := finishRound(&s, inflated)
		if i < cssRoundsCount-1 {
			require.False(t, exit, "round %d in CSS should not exit yet", i)
			require.True(t, s.InCSS())
		} else {
			require.True(t, exit, "CSS_ROUNDS-th round should exit to CA")
		}
	}
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
