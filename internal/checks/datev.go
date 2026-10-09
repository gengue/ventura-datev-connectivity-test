package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type DATEVConfig struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
}

func permittedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate()
}

func internalAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\@?#:%[] \t\r\n") {
		// Colons are allowed only for a bare IPv6 address without a zone.
		if ip, err := netip.ParseAddr(host); err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("enter a hostname or bare IP address, without a URL, port or credentials")
		}
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("host returned no addresses")
	}
	for _, ip := range addresses {
		if !permittedIP(ip) {
			return nil, fmt.Errorf("DATEV targets must resolve only to loopback, RFC1918 private IPv4 or private IPv6 addresses; public and link-local targets are blocked")
		}
	}
	return addresses, nil
}

func DATEV(ctx context.Context, config DATEVConfig) []Result {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	start := time.Now()
	config.Host = strings.TrimSpace(config.Host)
	if config.Port < 1 || config.Port > 65535 || (config.Scheme != "http" && config.Scheme != "https") {
		r := result("DATEVconnect", "Configuration", "", "fail", "Use a port between 1 and 65535 and HTTP or HTTPS.", start)
		r.Code = "invalid_configuration"
		return []Result{r}
	}
	addresses, err := internalAddresses(ctx, config.Host)
	if err != nil {
		return []Result{failure("DATEVconnect", "DNS / target", config.Host, start, err)}
	}
	target := (&url.URL{Scheme: config.Scheme, Host: net.JoinHostPort(config.Host, strconv.Itoa(config.Port)), Path: "/datev/api"}).String()
	results := []Result{result("DATEVconnect", "DNS / target", config.Host, "pass", "Host resolves only to permitted local/internal addresses.", start)}
	// Pin the resolved addresses so DNS cannot change between validation and dial.
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var last error
		for _, ip := range addresses {
			conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(config.Port)))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
	start = time.Now()
	connection, err := dial(ctx, "tcp", "")
	if err != nil {
		return append(results, failure("DATEVconnect", "TCP", target, start, err))
	}
	connection.Close()
	results = append(results, result("DATEVconnect", "TCP", target, "pass", "TCP port is reachable. This does not identify the service or prove DATEV access.", start))
	transport := &http.Transport{DialContext: dial, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: Timeout, CheckRedirect: noRedirect}
	start = time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	response, err := client.Do(req)
	if err != nil {
		return append(results, failure("DATEVconnect", "HTTP HEAD", target, start, err))
	}
	defer response.Body.Close()
	r := result("DATEVconnect", "HTTP HEAD", target, "warn", "HTTP service responded. DATEV identity, licensing and data access are not verified. No credentials or financial data were requested.", start)
	r.HTTPStatus, r.TLSVersion = response.StatusCode, tlsVersion(response)
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		r.Code, r.Message = "authentication_required", "Service is reachable but requires authentication or permission. No credentials were sent; DATEV data access remains unverified."
	case http.StatusNotFound:
		r.Code, r.Message = "path_not_found", "HTTP service is reachable but /datev/api was not found. Confirm the DATEVconnect URL with your administrator."
	case http.StatusMethodNotAllowed, http.StatusNotImplemented:
		r.Code, r.Message = "head_not_supported", "HTTP service is reachable but does not support HEAD. No GET fallback is attempted, to avoid retrieving data."
	default:
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			r.Code = "redirect_not_followed"
		}
	}
	return append(results, r)
}
