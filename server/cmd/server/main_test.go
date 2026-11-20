package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMetricHistoryIsBounded(t *testing.T) {
	s := NewDeviceStore(filepath.Join(t.TempDir(), "devices.json"))
	for i := 0; i < maxHistoryPerDevice+3; i++ {
		s.Update(&DeviceMetrics{DeviceID: "device-1", CPUPercent: float64(i)}, nil)
	}
	_, history, ok := s.GetDetail("device-1")
	if !ok || len(history) != maxHistoryPerDevice {
		t.Fatalf("history length = %d, expected %d", len(history), maxHistoryPerDevice)
	}
	if history[0].CPUPercent != 3 {
		t.Fatalf("oldest retained sample = %v, expected 3", history[0].CPUPercent)
	}
}

func TestCommandJobCompletionAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	s := NewDeviceStore(path)
	job := &CommandJob{ID: "job-1", DeviceID: "device-1", Command: "whoami", Status: "queued", CreatedAt: time.Now()}
	s.jobs[job.ID] = job
	s.CompleteJob("device-1", map[string]interface{}{"job_id": "job-1", "output": "operator", "error": ""})
	if job.Status != "completed" || job.Output != "operator" || job.FinishedAt.IsZero() {
		t.Fatalf("unexpected completed job: %+v", job)
	}
	if len(s.audit) != 1 {
		t.Fatalf("audit events = %d, expected 1", len(s.audit))
	}
	s.save()
	reloaded := NewDeviceStore(path)
	if reloaded.jobs[job.ID] == nil || reloaded.jobs[job.ID].Output != "operator" {
		t.Fatal("job result did not survive reload")
	}
}

func TestLegacyStoreLoadsAndUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	legacy := StoreDump{Devices: map[string]*DeviceMetrics{"old": {DeviceID: "old", Hostname: "legacy"}}, DeviceTokens: map[string]string{"old": "token"}, Tokens: map[string]*TokenRecord{}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := NewDeviceStore(path)
	if s.devices["old"] == nil || s.deviceTokens["old"] != "token" {
		t.Fatal("legacy JSON store did not load")
	}
	s.save()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("store permissions too broad: %o", info.Mode().Perm())
	}
}
