package checks

import (
	"context"
	"net"
	"net/http"
	"time"
)

const InternetEndpoint = "https://example.com/"

func Internet(ctx context.Context) []Result {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	start := time.Now()
	addresses, err := net.DefaultResolver.LookupHost(ctx, "example.com")
	var results []Result
	if err != nil {
		results = append(results, failure("Internet", "DNS", "example.com", start, err))
	} else {
		results = append(results, result("Internet", "DNS", "example.com", "pass", "DNS resolved successfully.", start))
		if len(addresses) == 0 {
			results[0].Status, results[0].Message = "fail", "DNS returned no addresses."
		}
	}
	// HTTPS can work through an explicit proxy even when local DNS is blocked.
	start = time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, InternetEndpoint, nil)
	response, err := publicClient().Do(req)
	if err != nil {
		return append(results, failure("Internet", "HTTPS / TLS", InternetEndpoint, start, err))
	}
	defer response.Body.Close()
	r := result("Internet", "HTTPS / TLS", InternetEndpoint, "pass", "HTTPS connected with a verified TLS certificate.", start)
	r.HTTPStatus, r.TLSVersion = response.StatusCode, tlsVersion(response)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		r.Status, r.Code, r.Message = "warn", "http_status", "HTTPS responded, but the expected successful status was not returned. Check proxy or access restrictions."
	}
	return append(results, r)
}
