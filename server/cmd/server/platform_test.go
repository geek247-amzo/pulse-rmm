package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPlatform(t *testing.T) *Platform {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	h, _ := bcrypt.GenerateFromPassword([]byte("a-unique-test-password-123"), bcrypt.MinCost)
	cfg := &Config{DataDir: dir, AdminUser: "owner", AdminHash: h, HermesAPIToken: "legacy-test-service-token-1234567890"}
	store := NewDeviceStore(filepath.Join(dir, "devices.json"))
	settings := &platformSettings{values: platformValues{Model: "gpt-4.1-mini"}}
	p, err := newPlatform(db, cfg, store, settings)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func doRequest(p *Platform, method, path, token string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", p.login)
	mux.HandleFunc("/api/logout", p.logout)
	p.register(mux)
	mux.ServeHTTP(w, r)
	return w
}
func testSession(p *Platform, role, customer string) (string, *Account) {
	id := randomToken(12)
	u := &Account{ID: id, Username: id, Role: role, CustomerID: customer, Active: true}
	p.state.Users[id] = u
	token := "rmm_sess_" + randomToken(16)
	p.state.Sessions[hashText(token)] = &BrowserSession{id, time.Now().Unix(), time.Now().Unix(), time.Now().Add(time.Hour).Unix()}
	return token, u
}
func TestTOTPStandardVectorAndReplay(t *testing.T) {
	if got := totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1); got != "287082" {
		t.Fatalf("RFC vector mismatch: %s", got)
	}
	p := testPlatform(t)
	u := &Account{TOTP: p.seal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")}
	code := totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Now().Unix()/30)
	if !p.checkOTP(u, code) || p.checkOTP(u, code) {
		t.Fatal("TOTP replay accepted")
	}
	u.Recovery = []string{hashText("one-use-recovery")}
	if !p.checkOTP(u, "one-use-recovery") || p.checkOTP(u, "one-use-recovery") {
		t.Fatal("recovery code replay accepted")
	}
	if strings.Contains(u.TOTP, "GEZDGNBVGY3TQOJQ") {
		t.Fatal("factor seed persisted in plaintext")
	}
}
func TestLoginMFAAndSessionRevocation(t *testing.T) {
	p := testPlatform(t)
	var owner *Account
	for _, u := range p.state.Users {
		owner = u
	}
	owner.TOTP = p.seal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	req := map[string]string{"username": "owner", "password": "a-unique-test-password-123"}
	w := doRequest(p, "POST", "/api/login", "", req)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "mfa_required") {
		t.Fatal("password bypassed MFA")
	}
	req["otp"] = totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Now().Unix()/30)
	w = doRequest(p, "POST", "/api/login", "", req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	token := result["token"].(string)
	if doRequest(p, "GET", "/api/account/me", token, nil).Code != 200 {
		t.Fatal("new session rejected")
	}
	p.revokeSessions(owner.ID)
	if doRequest(p, "GET", "/api/account/me", token, nil).Code != 401 {
		t.Fatal("revoked session accepted")
	}
}
func TestDisabledAccountAndExpiredSession(t *testing.T) {
	p := testPlatform(t)
	token, u := testSession(p, "end_user", "a")
	u.Active = false
	if doRequest(p, "GET", "/api/account/me", token, nil).Code != 401 {
		t.Fatal("disabled account accepted")
	}
	u.Active = true
	p.state.Sessions[hashText(token)].Expires = time.Now().Unix() - 1
	if doRequest(p, "GET", "/api/account/me", token, nil).Code != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestCustomerDeviceAndTicketIsolation(t *testing.T) {
	p := testPlatform(t)
	token, u := testSession(p, "end_user", "a")
	p.store.devices["mine"] = &DeviceMetrics{DeviceID: "mine"}
	p.store.devices["other"] = &DeviceMetrics{DeviceID: "other"}
	p.store.devices["same-customer-other-user"] = &DeviceMetrics{DeviceID: "same-customer-other-user"}
	p.state.Assignments["mine"] = &Assignment{DeviceID: "mine", CustomerID: "a", UserID: u.ID}
	p.state.Assignments["other"] = &Assignment{DeviceID: "other", CustomerID: "b"}
	p.state.Assignments["same-customer-other-user"] = &Assignment{DeviceID: "same-customer-other-user", CustomerID: "a", UserID: "elsewhere"}
	w := doRequest(p, "GET", "/api/v1/devices", token, nil)
	var rows []map[string]any
	json.Unmarshal(w.Body.Bytes(), &rows)
	if w.Code != 200 || len(rows) != 1 {
		t.Fatal("device isolation failed", w.Code, len(rows))
	}
	if doRequest(p, "GET", "/api/v1/devices/other", token, nil).Code != 404 {
		t.Fatal("foreign device exposed")
	}
	p.state.Tickets["foreign"] = &SupportTicket{ID: "foreign", CustomerID: "b", Requester: "another"}
	w = doRequest(p, "POST", "/api/v1/tickets/foreign/messages", token, map[string]any{"body": "should fail"})
	if w.Code != 404 {
		t.Fatal("foreign ticket mutation accepted")
	}
}
func TestScopedKeyCannotUseLegacyRoutesOrEscalate(t *testing.T) {
	p := testPlatform(t)
	token := "scope-test"
	p.state.Keys["key"] = &ScopedKey{ID: "key", Hash: hashText(token), Scopes: []string{"devices.read"}, Customers: []string{"a"}, Expires: time.Now().Add(time.Hour).Unix()}
	mux := http.NewServeMux()
	p.register(mux)
	mux.HandleFunc("/api/command", p.middleware(func(w http.ResponseWriter, r *http.Request) { t.Error("legacy handler reached") }))
	r := httptest.NewRequest("POST", "/api/command", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("scoped key reached legacy API")
	}
	if doRequest(p, "GET", "/api/v1/users", token, nil).Code != 403 {
		t.Fatal("service identity managed users")
	}
	if doRequest(p, "GET", "/api/v1/keys", token, nil).Code != 403 {
		t.Fatal("service identity managed keys")
	}
	if doRequest(p, "GET", "/api/v1/customers", token, nil).Code != 403 {
		t.Fatal("missing scope accepted")
	}
	p.state.Keys["key"].Revoked = true
	if doRequest(p, "GET", "/api/v1/status", token, nil).Code != 401 {
		t.Fatal("revoked API key accepted")
	}
}
func TestLegacyServiceDeniedNewCustomerAPI(t *testing.T) {
	p := testPlatform(t)
	if doRequest(p, "GET", "/api/v1/customers", p.cfg.HermesAPIToken, nil).Code != 403 {
		t.Fatal("legacy credential silently gained new privileges")
	}
}
func TestCookieMutationRequiresCSRFHeader(t *testing.T) {
	p := testPlatform(t)
	token, _ := testSession(p, "owner", "")
	req := httptest.NewRequest("POST", "/api/v1/customers", strings.NewReader(`{"name":"test","active":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "rmm_session", Value: token})
	w := httptest.NewRecorder()
	p.middleware(p.handle)(w, req)
	if w.Code != 401 {
		t.Fatal("cookie mutation bypassed CSRF header")
	}
}
func TestDirectoryCrossCustomerRelationsRejected(t *testing.T) {
	p := testPlatform(t)
	token, _ := testSession(p, "owner", "")
	p.state.Customers["a"] = &DirectoryRecord{ID: "a", Active: true}
	p.state.Customers["b"] = &DirectoryRecord{ID: "b", Active: true}
	p.state.Locations["b-loc"] = &DirectoryRecord{ID: "b-loc", CustomerID: "b", Active: true}
	w := doRequest(p, "POST", "/api/v1/contacts", token, map[string]any{"name": "Contact", "customer_id": "a", "location_id": "b-loc", "active": true})
	if w.Code != 400 {
		t.Fatal("cross-customer contact assignment accepted")
	}
}
func TestAccountCannotDisableOrDemoteItself(t *testing.T) {
	p := testPlatform(t)
	token, u := testSession(p, "owner", "")
	w := doRequest(p, "PUT", "/api/v1/users/"+u.ID, token, map[string]any{"username": u.Username, "role": "viewer", "active": false, "customer_id": ""})
	if w.Code == 200 {
		t.Fatal("owner disabled own account")
	}
}
func TestDiagnosticNeedsConsentAndKnownTask(t *testing.T) {
	p := testPlatform(t)
	token, _ := testSession(p, "owner", "")
	for _, body := range []map[string]any{{"device_id": "device", "kind": "system-info", "consent": false}, {"device_id": "device", "kind": "sh -c arbitrary", "consent": true}} {
		if doRequest(p, "POST", "/api/v1/actions", token, body).Code != 400 {
			t.Fatal("unsafe diagnostic request accepted")
		}
	}
}
func TestAIWithoutConsentOrProviderDoesNotSend(t *testing.T) {
	p := testPlatform(t)
	token, u := testSession(p, "owner", "")
	p.state.Tickets["t"] = &SupportTicket{ID: "t", Requester: u.ID}
	if doRequest(p, "POST", "/api/v1/tickets/t/assist", token, map[string]bool{"consent": false}).Code != 400 {
		t.Fatal("AI consent bypass")
	}
	if doRequest(p, "POST", "/api/v1/tickets/t/assist", token, map[string]bool{"consent": true}).Code != 503 {
		t.Fatal("unconfigured AI should preserve human support")
	}
}
func TestEmptyScopesFailAndUserViewsHideSecrets(t *testing.T) {
	p := testPlatform(t)
	token, _ := testSession(p, "owner", "")
	w := doRequest(p, "POST", "/api/v1/keys", token, map[string]any{"name": "empty", "days": 30, "scopes": []string{}})
	if w.Code != 400 {
		t.Fatal("scope-free key issued")
	}
	w = doRequest(p, "GET", "/api/v1/users", token, nil)
	for _, name := range []string{"password_hash", "totp_ciphertext", "recovery_hashes"} {
		if strings.Contains(w.Body.String(), name) {
			t.Fatal("secret in user view")
		}
	}
}
func TestScopedStatePersists(t *testing.T) {
	p := testPlatform(t)
	p.state.Customers["persisted"] = &DirectoryRecord{ID: "persisted", Name: "Example", Active: true}
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	next, err := newPlatform(p.db, p.cfg, p.store, p.settings)
	if err != nil || next.state.Customers["persisted"] == nil {
		t.Fatal("state did not persist")
	}
}
func TestAuthFailuresAreThrottled(t *testing.T) {
	p := testPlatform(t)
	for i := 0; i < 12; i++ {
		doRequest(p, "POST", "/api/login", "", map[string]string{"username": "owner", "password": "wrong"})
	}
	if doRequest(p, "POST", "/api/login", "", map[string]string{"username": "owner", "password": "wrong"}).Code != 429 {
		t.Fatal("login brute-force limit missing")
	}
}
func TestPersistenceFailureClosesAuthentication(t *testing.T) {
	p := testPlatform(t)
	token, _ := testSession(p, "owner", "")
	p.db.Close()
	if p.save() == nil {
		t.Fatal("expected closed database failure")
	}
	if _, ok := p.authenticate(func() *http.Request {
		r := httptest.NewRequest("GET", "/api/account/me", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}()); ok {
		t.Fatal("authentication remained active after persistence failure")
	}
}
func TestInternalNotesHiddenFromCustomer(t *testing.T) {
	p := testPlatform(t)
	a := Principal{Role: "end_user", UserID: "user", CustomerID: "customer"}
	ticket := &SupportTicket{Messages: []SupportMessage{{Body: "visible"}, {Body: "private", Internal: true}}}
	v := p.ticketView(a, ticket)
	if len(v.Messages) != 1 || v.Messages[0].Body != "visible" {
		t.Fatal("internal note leaked")
	}
}

func TestDiagnosticDispatchHasSeparateApprovalAndNoReplay(t *testing.T) {
	p := testPlatform(t)
	requester, u := testSession(p, "owner", "")
	approver, _ := testSession(p, "technician", "")
	received := make(chan map[string]any, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		var message map[string]any
		if c.ReadJSON(&message) == nil {
			received <- message
		}
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	p.store.devices["fixture"] = &DeviceMetrics{DeviceID: "fixture", OS: "linux"}
	p.store.conns["fixture"] = conn
	p.state.Actions["action"] = &SupportAction{ID: "action", DeviceID: "fixture", RequestedBy: u.ID, Kind: "system-info", Status: "pending", Created: time.Now().Unix()}
	if doRequest(p, "POST", "/api/v1/actions/action/approve", requester, map[string]any{}).Code != 403 {
		t.Fatal("self approval accepted")
	}
	w := doRequest(p, "POST", "/api/v1/actions/action/approve", approver, map[string]any{})
	if w.Code != 200 {
		t.Fatal("approval failed", w.Code, w.Body.String())
	}
	select {
	case message := <-received:
		if message["command"] != "uname -sr; uptime" {
			t.Fatal("unexpected command")
		}
	case <-time.After(time.Second):
		t.Fatal("no dispatched diagnostic")
	}
	if doRequest(p, "POST", "/api/v1/actions/action/approve", approver, map[string]any{}).Code != 409 {
		t.Fatal("diagnostic dispatched twice")
	}
}

func TestMissingEncryptionKeyDoesNotSilentlyReplaceEnrolledFactors(t *testing.T) {
	p := testPlatform(t)
	for _, u := range p.state.Users {
		u.TOTP = p.seal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	}
	if p.save() != nil {
		t.Fatal("save")
	}
	if os.Remove(filepath.Join(p.cfg.DataDir, "account-encryption.key")) != nil {
		t.Fatal("remove")
	}
	if _, err := newPlatform(p.db, p.cfg, p.store, p.settings); err == nil {
		t.Fatal("missing factor key was silently replaced")
	}
}
func TestProtectedSubrouteCannotBeAliased(t *testing.T) {
	p := testPlatform(t)
	token, _ := testSession(p, "owner", "")
	if doRequest(p, "POST", "/api/v1/tickets/anything/messages/ignored", token, map[string]any{"body": "x"}).Code != 404 {
		t.Fatal("undeclared subroute accepted")
	}
}

func TestEnrollmentCannotReplaceOrReplayDeviceIdentity(t *testing.T) {
	p := testPlatform(t)
	one := p.store.GenerateOneTimeToken()
	two := p.store.GenerateOneTimeToken()
	if !p.store.BindTokenToDevice(one, "fixture") {
		t.Fatal("first enrollment failed")
	}
	if p.store.BindTokenToDevice(one, "different") || p.store.BindTokenToDevice(two, "fixture") {
		t.Fatal("enrollment replaced an established identity")
	}
}

func TestSupportRejectsMissingDeviceAndCustomerReferences(t *testing.T) {
	p := testPlatform(t)
	token, _ := testSession(p, "owner", "")
	for _, v := range []map[string]any{{"subject": "Example request", "body": "Example description", "device_id": "missing"}, {"subject": "Example request", "body": "Example description", "customer_id": "missing"}} {
		if doRequest(p, "POST", "/api/v1/tickets", token, v).Code == 201 {
			t.Fatal("unknown reference persisted")
		}
	}
}

func TestPlatformSettingsOptionalRustDesk(t *testing.T) {
	p := testPlatform(t)
	p.settings.path = filepath.Join(t.TempDir(), "settings.json")
	token, _ := testSession(p, "owner", "")
	r := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"model":"gpt-4.1-mini","rustdesk_host":"","rustdesk_key":"","openai_key":"fixture-provider-secret"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.middleware(func(w http.ResponseWriter, r *http.Request) { p.settings.handle(w, r, p.cfg, p.store) })(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "fixture-provider-secret") {
		t.Fatal("optional remote desktop/provider secret handling failed")
	}
}
