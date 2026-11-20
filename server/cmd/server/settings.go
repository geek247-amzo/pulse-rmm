package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type actorKey struct{}

type platformValues struct {
	OpenAIKey    string `json:"openai_key"`
	Model        string `json:"model"`
	RustDeskHost string `json:"rustdesk_host"`
	RustDeskKey  string `json:"rustdesk_key"`
}

type platformSettings struct {
	mu     sync.RWMutex
	path   string
	values platformValues
}

func loadPlatformSettings(cfg *Config) (*platformSettings, error) {
	host := os.Getenv("RUSTDESK_HOST")
	if host == "" {
		host = ""
	}
	key := os.Getenv("RUSTDESK_KEY")
	if key == "" {
		key = ""
	}
	model := cfg.OpenAIModel
	if model == "" {
		model = "gpt-4.1-mini"
	}
	s := &platformSettings{path: filepath.Join(cfg.DataDir, "platform-settings.json"), values: platformValues{cfg.OpenAIKey, model, host, key}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &s.values); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *platformSettings) current() platformValues {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.values
}

func (s *platformSettings) save(values platformValues) error {
	f, err := os.CreateTemp(filepath.Dir(s.path), ".settings-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(values)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	s.values = values
	return nil
}

var modelName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)
var relayAddress = regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}(:[0-9]{1,5})?$`)

func isSettingsAdmin(r *http.Request, cfg *Config) bool {
	a := actorFrom(r)
	return !a.Service && (a.Role == "owner" || a.Role == "admin")
}

func (s *platformSettings) handle(w http.ResponseWriter, r *http.Request, cfg *Config, store *DeviceStore) {
	w.Header().Set("Cache-Control", "no-store")
	if !isSettingsAdmin(r, cfg) {
		http.Error(w, "Administrator required", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPut {
		var change struct {
			Model        string  `json:"model"`
			RustDeskHost string  `json:"rustdesk_host"`
			RustDeskKey  string  `json:"rustdesk_key"`
			OpenAIKey    *string `json:"openai_key"`
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&change) != nil {
			http.Error(w, "Expected JSON settings", http.StatusBadRequest)
			return
		}
		key, err := base64.StdEncoding.DecodeString(change.RustDeskKey)
		if !modelName.MatchString(change.Model) || ((change.RustDeskHost != "" || change.RustDeskKey != "") && (!relayAddress.MatchString(change.RustDeskHost) || err != nil || len(key) != 32)) {
			http.Error(w, "Enter a model and either both RustDesk host/public key or neither", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		values := s.values
		values.Model, values.RustDeskHost, values.RustDeskKey = change.Model, change.RustDeskHost, change.RustDeskKey
		if change.OpenAIKey != nil {
			value := strings.TrimSpace(*change.OpenAIKey)
			if len(value) > 512 || strings.ContainsAny(value, " \t\r\n") {
				s.mu.Unlock()
				http.Error(w, "Invalid OpenAI key", http.StatusBadRequest)
				return
			}
			values.OpenAIKey = value
		}
		err = s.save(values)
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "Could not save platform settings", http.StatusInternalServerError)
			return
		}
		store.AddAudit(cfg.AdminUser, "", "settings.updated", "Platform settings updated")
	} else if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	values := s.current()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"model": values.Model, "rustdesk_host": values.RustDeskHost, "rustdesk_key": values.RustDeskKey,
		"openai_configured": values.OpenAIKey != "",
		"hermes_configured": cfg.HermesAPIToken != "", "secure_cookie": os.Getenv("COOKIE_SECURE") == "true",
	})
}

var modelsClient = &http.Client{
	Timeout:       12 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (s *platformSettings) listOpenAIModels(w http.ResponseWriter, r *http.Request, cfg *Config) {
	w.Header().Set("Cache-Control", "no-store")
	if !isSettingsAdmin(r, cfg) {
		http.Error(w, "Administrator required", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := s.current().OpenAIKey
	if key == "" {
		http.Error(w, "Save an OpenAI API key to load models.", http.StatusConflict)
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.openai.com/v1/models", nil)
	if err != nil {
		http.Error(w, "Could not prepare the OpenAI model request.", http.StatusInternalServerError)
		return
	}
	request.Header.Set("Authorization", "Bearer "+key)
	response, err := modelsClient.Do(request)
	if err != nil {
		http.Error(w, "Could not reach OpenAI. Try refreshing the model list.", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		http.Error(w, "OpenAI rejected model listing. Check the saved API key and its Models permissions.", http.StatusBadGateway)
		return
	case http.StatusTooManyRequests:
		http.Error(w, "OpenAI rate limited model listing. Try again shortly.", http.StatusTooManyRequests)
		return
	default:
		http.Error(w, "OpenAI could not list models. Try again shortly.", http.StatusBadGateway)
		return
	}
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&result); err != nil || result.Data == nil {
		http.Error(w, "OpenAI returned an invalid model list.", http.StatusBadGateway)
		return
	}
	models := make([]string, 0, len(result.Data))
	seen := make(map[string]bool, len(result.Data))
	for _, model := range result.Data {
		if modelName.MatchString(model.ID) && !seen[model.ID] {
			models = append(models, model.ID)
			seen[model.ID] = true
		}
	}
	sort.Strings(models)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string][]string{"models": models})
}
