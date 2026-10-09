package checks

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyQueries(t *testing.T) {
	for _, query := range []string{DefaultQuery, "{ trip { id } }", "# mutation is forbidden\nquery Q { thing(text: \"mutation\") }", `query { thing(text: """subscription""") }`, `query { thing(text: "a\"mutation") }`} {
		if err := ValidateQuery(query); err != nil {
			t.Errorf("valid query rejected %q: %v", query, err)
		}
	}
	for _, query := range []string{"", "mutation { delete_trip { id } }", "query Q { trip { id } } mutation M { remove }", "subscription { trip { id } }", "# comment\nmutation { remove }", `query { trip(text: "unterminated) }`, strings.Repeat("x", 8193)} {
		if ValidateQuery(query) == nil {
			t.Errorf("unsafe/invalid query accepted: %q", query)
		}
	}
}

func TestGraphQLResponsesAndAnonymousRequest(t *testing.T) {
	tests := []struct {
		name, body, code string
		status           int
		pass             bool
		count            int
	}{
		{"valid", `{"data":{"trip":[{"id":1},{"id":2}]}}`, "", 200, true, 2},
		{"graphql errors with HTTP 200", `{"data":null,"errors":[{"message":"denied"}]}`, "graphql_errors", 200, false, 0},
		{"partial errors", `{"data":{"trip":[]},"errors":[{}]}`, "graphql_errors", 200, false, 0},
		{"not JSON", `<html>proxy login</html>`, "invalid_response", 200, false, 0},
		{"null data", `{"data":null}`, "empty_data", 200, false, 0},
		{"HTTP denied", "", "http_status", 403, false, 0},
		{"too large", strings.Repeat("x", maxResponse+1), "invalid_response", 200, false, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s", r.Method)
				}
				for _, header := range []string{"Authorization", "X-Hasura-Admin-Secret", "X-Hasura-Role", "Cookie"} {
					if r.Header.Get(header) != "" {
						t.Errorf("unexpected credential header: %s", header)
					}
				}
				var body map[string]string
				if json.NewDecoder(r.Body).Decode(&body) != nil || body["query"] != DefaultQuery {
					t.Error("query not sent")
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			// Only the fake GraphQL server is trusted in this test; production uses system roots.
			old := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			defer func() { http.DefaultTransport = old }()
			r := GraphQL(context.Background(), server.URL, DefaultQuery)[0]
			if (r.Status == "pass") != test.pass || r.Code != test.code || r.RecordCount != test.count {
				t.Fatalf("unexpected result: %+v", r)
			}
			if len(r.Trips) != 0 {
				t.Fatal("custom endpoint data must not be displayed")
			}
		})
	}
}

func TestGraphQLRejectsUnsafeInputsBeforeRequest(t *testing.T) {
	for _, input := range [][2]string{
		{"http://example.com/graphql", DefaultQuery},
		{"https://user:password@example.com/graphql", DefaultQuery},
		{"https://example.com/graphql?secret=private", DefaultQuery},
		{"https://example.com/graphql#secret", DefaultQuery},
		{HasuraEndpoint, "mutation { delete_trip { id } }"},
	} {
		r := GraphQL(context.Background(), input[0], input[1])[0]
		if r.Code != "invalid_configuration" || r.Target != "" {
			t.Fatalf("unexpected result: %+v", r)
		}
	}
}

func TestGraphQLDoesNotFollowRedirects(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/second", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	old := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = old }()
	r := GraphQL(context.Background(), server.URL, DefaultQuery)[0]
	if calls != 1 || r.HTTPStatus != 307 || r.Status != "fail" {
		t.Fatalf("redirect followed: calls=%d result=%+v", calls, r)
	}
}

func TestDATEVAddressPolicy(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "fd00::1", "::ffff:127.0.0.1"} {
		if !permittedIP(netip.MustParseAddr(value)) {
			t.Errorf("blocked private address %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "0.0.0.0", "::", "169.254.169.254", "fe80::1", "100.64.0.1", "224.0.0.1", "::ffff:169.254.169.254"} {
		if permittedIP(netip.MustParseAddr(value)) {
			t.Errorf("accepted prohibited address %s", value)
		}
	}
	for _, host := range []string{"http://localhost", "localhost:58454", "user@localhost", "localhost/path", "[::1]", "fe80::1%eth0", "169.254.169.254", "8.8.8.8"} {
		if _, err := internalAddresses(context.Background(), host); err == nil {
			t.Errorf("accepted prohibited host %s", host)
		}
	}
}

func configFor(t *testing.T, value string) DATEVConfig {
	t.Helper()
	u, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return DATEVConfig{Host: u.Hostname(), Port: port, Scheme: u.Scheme}
}

func TestDATEVHeadersOnlyAndStatusInterpretation(t *testing.T) {
	for _, status := range []int{200, 401, 403, 404, 405, 307} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodHead || r.URL.Path != "/datev/api" {
					t.Errorf("unsafe request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("credentials sent")
				}
				w.Header().Set("Location", "http://example.com/accounting")
				w.WriteHeader(status)
			}))
			defer server.Close()
			results := DATEV(context.Background(), configFor(t, server.URL))
			last := results[len(results)-1]
			if len(results) != 3 || results[1].Status != "pass" || last.Status != "warn" || last.HTTPStatus != status || calls != 1 {
				t.Fatalf("unexpected results: %+v calls=%d", results, calls)
			}
			if (status == 401 || status == 403) && last.Code != "authentication_required" {
				t.Fatalf("auth required not reported: %+v", last)
			}
		})
	}
}

func TestDATEVRefusedAndUntrustedTLS(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := configFor(t, "http://"+listener.Addr().String())
	listener.Close()
	results := DATEV(context.Background(), config)
	if len(results) != 2 || results[1].Code != "connection_refused" {
		t.Fatalf("refused connection not classified: %+v", results)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS must not reach HTTP handler") }))
	defer server.Close()
	results = DATEV(context.Background(), configFor(t, server.URL))
	if results[len(results)-1].Code != "tls_certificate_error" {
		t.Fatalf("untrusted certificate not rejected: %+v", results)
	}
}

func TestErrorClassification(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{
		{context.DeadlineExceeded, "timeout"},
		{&net.DNSError{Err: "no such host", Name: "example.invalid"}, "dns_error"},
		{errors.New("transport error"), "connection_error"},
	} {
		if r := failure("test", "test", "test", time.Now(), test.err); r.Code != test.code {
			t.Errorf("wrong classification: %+v", r)
		}
	}
}

func TestProxySecretsAreRedacted(t *testing.T) {
	value := "http://user:private-password@proxy.example:8080"
	t.Setenv("HTTPS_PROXY", value)
	r := failure("test", "test", "test", time.Now(), errors.New("proxy configuration: "+value))
	if strings.Contains(r.Message, "private-password") || strings.Contains(r.Message, value) {
		t.Fatal("proxy setting leaked")
	}
	r = failure("test", "test", "test", time.Now(), errors.New("https://other:secret@proxy.example failed"))
	if strings.Contains(r.Message, "other:secret") {
		t.Fatal("URL credentials leaked")
	}
}
