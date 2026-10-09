package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Timeout = 12 * time.Second

type Result struct {
	Check       string `json:"check"`
	Stage       string `json:"stage"`
	Status      string `json:"status"`
	Target      string `json:"target"`
	Message     string `json:"message"`
	Code        string `json:"code,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	LatencyMS   int64  `json:"latency_ms"`
	TLSVersion  string `json:"tls_version,omitempty"`
	RecordCount int    `json:"record_count,omitempty"`
	Trips       []Trip `json:"trips,omitempty"`
}

func result(check, stage, target, status, message string, start time.Time) Result {
	return Result{Check: check, Stage: stage, Target: target, Status: status, Message: message, LatencyMS: time.Since(start).Milliseconds()}
}

var urlCredentials = regexp.MustCompile(`https?://[^\s"/]*@`)

func failure(check, stage, target string, start time.Time, err error) Result {
	message := err.Error()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		if value := os.Getenv(key); value != "" {
			message = strings.ReplaceAll(message, strconv.Quote(value), "[proxy setting]")
			message = strings.ReplaceAll(message, value, "[proxy setting]")
		}
	}
	message = urlCredentials.ReplaceAllString(message, "[credentials removed]@")
	r := result(check, stage, target, "fail", message, start)
	var dns *net.DNSError
	var certificate *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var timeout net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		r.Code = "timeout"
	case errors.As(err, &dns):
		r.Code = "dns_error"
	// Windows sockets use Winsock WSAECONNREFUSED (10061), not the POSIX errno.
	case errors.Is(err, syscall.ECONNREFUSED) || runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10061)):
		r.Code = "connection_refused"
	case errors.As(err, &certificate), errors.As(err, &authority), errors.As(err, &hostname):
		r.Code = "tls_certificate_error"
	case errors.As(err, &timeout) && timeout.Timeout():
		r.Code = "timeout"
	default:
		r.Code = "connection_error"
	}
	return r
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func publicClient() *http.Client {
	return &http.Client{Timeout: Timeout, CheckRedirect: noRedirect}
}

func tlsVersion(response *http.Response) string {
	if response.TLS == nil {
		return ""
	}
	return tls.VersionName(response.TLS.Version)
}

func publicURL(value string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL")
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("use an HTTPS URL without credentials, query parameters or fragments")
	}
	return u, nil
}
