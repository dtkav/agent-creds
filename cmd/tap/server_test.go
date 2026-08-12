package main

import (
	"testing"
	"time"
)

func TestGroupOperationsByAgentAndIdleGap(t *testing.T) {
	operation := func(
		id int64, agentID, agentName, start, end string, input, output int64,
	) Operation {
		return Operation{
			ID: id, Source: agentID, AgentID: agentID, AgentName: agentName,
			Provider: "openai", Operation: "responses", Model: "gpt-test",
			StartedAt:  "2026-01-01T00:" + start + "Z",
			EndedAt:    "2026-01-01T00:" + end + "Z",
			DurationMS: 1000, StatusCode: 200, Outcome: "success",
			InputTokens: input, OutputTokens: output,
		}
	}

	activities := groupOperations([]Operation{
		operation(4, "agent-a", "Dispatch", "02:00", "02:05", 40, 4),
		operation(3, "agent-a", "Dispatch", "00:40", "00:50", 30, 3),
		operation(2, "agent-b", "Merge Queue", "00:05", "00:06", 20, 2),
		operation(1, "agent-a", "Dispatch", "00:00", "00:10", 10, 1),
	}, 45*time.Second)

	if len(activities) != 3 {
		t.Fatalf("got %d activities, want 3: %+v", len(activities), activities)
	}
	latest := activities[0]
	if latest.AgentID != "agent-a" || latest.RequestCount != 1 || latest.ID != "agent-a:4" {
		t.Fatalf("unexpected latest activity: %+v", latest)
	}

	var grouped Activity
	for _, activity := range activities {
		if activity.ID == "agent-a:1" {
			grouped = activity
		}
	}
	if grouped.RequestCount != 2 {
		t.Fatalf("agent requests were not grouped: %+v", grouped)
	}
	if grouped.InputTokens != 40 || grouped.OutputTokens != 4 {
		t.Fatalf("token totals = %d/%d, want 40/4", grouped.InputTokens, grouped.OutputTokens)
	}
	if grouped.DurationMS != 50_000 {
		t.Fatalf("activity duration = %dms, want 50000ms", grouped.DurationMS)
	}
	if grouped.Operations[0].ID != 3 || grouped.Operations[1].ID != 1 {
		t.Fatalf("raw requests are not newest first: %+v", grouped.Operations)
	}
}

func TestGroupOperationsKeepsOverlappingRequestsTogether(t *testing.T) {
	activities := groupOperations([]Operation{
		{
			ID: 1, Source: "agent", Provider: "anthropic", Operation: "messages",
			StartedAt: "2026-01-01T00:00:00Z", EndedAt: "2026-01-01T00:02:00Z",
			Outcome: "success",
		},
		{
			ID: 2, Source: "agent", Provider: "anthropic", Operation: "messages",
			StartedAt: "2026-01-01T00:01:30Z", EndedAt: "2026-01-01T00:01:40Z",
			Outcome: "success",
		},
	}, 45*time.Second)

	if len(activities) != 1 || activities[0].RequestCount != 2 {
		t.Fatalf("overlapping requests should form one activity: %+v", activities)
	}
}
