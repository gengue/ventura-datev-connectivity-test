package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testApp(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = newHandler(server.Listener.Addr().String(), "test-session-token")
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestEmbeddedUIAndSecurityHeaders(t *testing.T) {
	server := testApp(t)
	for _, path := range []string{"/", "/app.js", "/style.css", "/logo.png"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 || len(body) == 0 {
			t.Fatalf("asset unavailable %s", path)
		}
		if response.Header.Get("Cache-Control") != "no-store" || !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("missing security headers")
		}
		if path == "/" && (!strings.Contains(string(body), "test-session-token") || strings.Contains(string(body), "{{TOKEN}}")) {
			t.Fatal("session token not rendered")
		}
	}
}

func TestRejectUnauthorizedAndMalformedAPIRequests(t *testing.T) {
	server := testApp(t)
	for _, test := range []struct {
		name, method, body, token, origin, host, content string
		status                                           int
	}{
		{"missing token", "POST", `{"check":"datev"}`, "", "", "", "application/json", 403},
		{"foreign origin", "POST", `{}`, "test-session-token", "https://evil.example", "", "application/json", 403},
		{"DNS rebinding host", "POST", `{}`, "test-session-token", "", "evil.example", "application/json", 403},
		{"wrong method", "GET", "", "test-session-token", "", "", "application/json", 405},
		{"wrong content type", "POST", `{}`, "test-session-token", "", "", "text/plain", 415},
		{"unknown check", "POST", `{"check":"scan"}`, "test-session-token", "", "", "application/json", 400},
		{"extra JSON", "POST", `{"check":"datev"} {}`, "test-session-token", "", "", "application/json", 400},
		{"unknown field", "POST", `{"check":"datev","password":"no"}`, "test-session-token", "", "", "application/json", 400},
		{"oversized", "POST", strings.Repeat(" ", 17000), "test-session-token", "", "", "application/json", 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest(test.method, server.URL+"/api/check", strings.NewReader(test.body))
			req.Header.Set("Content-Type", test.content)
			req.Header.Set("X-Probe-Token", test.token)
			req.Header.Set("Origin", test.origin)
			if test.host != "" {
				req.Host = test.host
			}
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
		})
	}
	request := httptest.NewRequest("GET", "http://127.0.0.1:8080/", nil)
	request.RemoteAddr = "203.0.113.1:9000"
	recorder := httptest.NewRecorder()
	newHandler(address, "token").ServeHTTP(recorder, request)
	if recorder.Code != 403 {
		t.Fatal("non-loopback client accepted")
	}
}

func TestDATEVReportThroughLocalAPI(t *testing.T) {
	datev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer datev.Close()
	host, port, _ := net.SplitHostPort(datev.Listener.Addr().String())
	server := testApp(t)
	body := `{"check":"datev","datev":{"host":"` + host + `","port":` + port + `,"scheme":"http"}}`
	req, _ := http.NewRequest("POST", server.URL+"/api/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Probe-Token", "test-session-token")
	req.Header.Set("Origin", server.URL)
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var output report
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&output) != nil {
		t.Fatal("invalid report")
	}
	if output.Version != version || output.OS == "" || len(output.Results) != 3 || output.Results[2].Code != "authentication_required" {
		t.Fatalf("incorrect report: %+v", output)
	}
}
