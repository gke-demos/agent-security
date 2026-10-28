package evals

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gke-demos/agent-security/internal/aegis"
)

// ParseSSEStream parses a raw text/event-stream HTTP body into ordered TurnStreamEvent frames.
func ParseSSEStream(raw string) ([]aegis.TurnStreamEvent, error) {
	var events []aegis.TurnStreamEvent
	blocks := strings.Split(strings.TrimSpace(raw), "\n\n")
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		var eventHeader string
		var dataLine string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "event:") {
				eventHeader = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			}
		}
		if dataLine == "" {
			continue
		}
		var ev aegis.TurnStreamEvent
		if err := json.Unmarshal([]byte(dataLine), &ev); err != nil {
			return nil, fmt.Errorf("unmarshal SSE frame %q: %w", dataLine, err)
		}
		if eventHeader != "" && eventHeader != string(ev.Type) {
			return nil, fmt.Errorf("SSE frame header %q does not match payload type %q", eventHeader, ev.Type)
		}
		events = append(events, ev)
	}
	return events, nil
}

// ValidateTurnStreamInvariants verifies that an ordered slice of TurnStreamEvent frames
// obeys the AegisSRE SSE protocol invariants:
// 1. First event is turn.started
// 2. Final event is turn.completed with non-nil Turn
// 3. Number of boundary.step events equals len(turn.BoundaryTrace)
// 4. Number of wire.record events equals len(turn.WireRecords)
// 5. Number of a2ui.card events equals len(turn.Cards)
// 6. At least one text.delta event is emitted whenever turn.AssistantText is non-empty
func ValidateTurnStreamInvariants(events []aegis.TurnStreamEvent) (*aegis.TurnResult, error) {
	if len(events) < 2 {
		return nil, fmt.Errorf("expected at least 2 SSE events (turn.started and turn.completed), got %d", len(events))
	}
	if events[0].Type != aegis.TurnStreamEventStarted {
		return nil, fmt.Errorf("first SSE event = %q, want %q", events[0].Type, aegis.TurnStreamEventStarted)
	}
	last := events[len(events)-1]
	if last.Type != aegis.TurnStreamEventCompleted || last.Turn == nil {
		return nil, fmt.Errorf("last SSE event = %q (Turn=%v), want %q with non-nil Turn", last.Type, last.Turn != nil, aegis.TurnStreamEventCompleted)
	}

	var stepCount, wireCount, cardCount, deltaCount int
	for _, ev := range events {
		switch ev.Type {
		case aegis.TurnStreamEventBoundaryStep:
			if ev.Step == nil {
				return nil, fmt.Errorf("boundary.step frame has nil Step")
			}
			stepCount++
		case aegis.TurnStreamEventWireRecord:
			if ev.Record == nil {
				return nil, fmt.Errorf("wire.record frame has nil Record")
			}
			wireCount++
		case aegis.TurnStreamEventA2UICard:
			if ev.Card == nil {
				return nil, fmt.Errorf("a2ui.card frame has nil Card")
			}
			cardCount++
		case aegis.TurnStreamEventTextDelta:
			if strings.TrimSpace(ev.Delta) == "" {
				return nil, fmt.Errorf("text.delta frame has empty Delta")
			}
			deltaCount++
		}
	}

	if stepCount != len(last.Turn.BoundaryTrace) {
		return nil, fmt.Errorf("streamed boundary.step count = %d, want len(BoundaryTrace) = %d", stepCount, len(last.Turn.BoundaryTrace))
	}
	if wireCount != len(last.Turn.WireRecords) {
		return nil, fmt.Errorf("streamed wire.record count = %d, want len(WireRecords) = %d", wireCount, len(last.Turn.WireRecords))
	}
	if cardCount != len(last.Turn.Cards) {
		return nil, fmt.Errorf("streamed a2ui.card count = %d, want len(Cards) = %d", cardCount, len(last.Turn.Cards))
	}
	if strings.TrimSpace(last.Turn.AssistantText) != "" && deltaCount < 1 {
		return nil, fmt.Errorf("streamed text.delta count = %d, want >= 1 for non-empty AssistantText", deltaCount)
	}
	return last.Turn, nil
}
