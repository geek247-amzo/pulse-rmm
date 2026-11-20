package main

import "testing"

func TestPublicAgentWebSocketURL(t *testing.T) {
	for _, origin := range []string{"https://pulse.seunarain.co.za", "https://pulse.seunarain.co.za/"} {
		got, err := publicAgentWebSocketURL(origin)
		if err != nil || got != "wss://pulse.seunarain.co.za/ws/agent" {
			t.Fatalf("origin conversion failed: %v", err)
		}
	}
	for _, origin := range []string{"http://pulse.seunarain.co.za", "https://", "https://user:password@pulse.seunarain.co.za", "https://pulse.seunarain.co.za/path", "https://pulse.seunarain.co.za?token=x", "https://pulse.seunarain.co.za/#fragment"} {
		if _, err := publicAgentWebSocketURL(origin); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
}
