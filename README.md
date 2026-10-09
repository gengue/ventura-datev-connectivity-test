# Ventura DATEV Connectivity Test

A portable connection check for a remote Windows desktop. Finance can run it without installing Go or other development tools. The app checks Internet access, an anonymous Ventura GraphQL query and a possible DATEVconnect address.

It does not sign in to DATEV, retrieve accounting records, synchronize data, install a service or send telemetry. Results stay in the browser's memory until the page is closed or reloaded. Copying the report is a manual action.

## Download and run

1. Open the **remote Windows desktop** where you normally use DATEV.
2. Download [datev-test-agent-windows-amd64.exe](https://github.com/gengue/ventura-datev-connectivity-test/releases/latest/download/datev-test-agent-windows-amd64.exe) inside that desktop. You can also download the [ZIP with instructions](https://github.com/gengue/ventura-datev-connectivity-test/releases/latest/download/ventura-datev-connectivity-test-windows-amd64.zip) and extract it first.
3. Double-click the executable. Leave its console window open.
4. A browser should open automatically. Otherwise, open **http://127.0.0.1:8080/** in the browser inside the same remote Windows desktop.
5. Click **Run all checks**, or test each connection separately.
6. Review the results. Click **Copy report** and share it through your approved internal channel if needed. Internal addresses and error messages may appear in the report; do not post it in public GitHub issues.
7. Close the application window or press **Ctrl+C** in it when finished.

The download is an unsigned Windows AMD64 executable. Windows 10/11 and Windows Server 2016 or newer are required by the Go toolchain; the initial release is smoke-tested on GitHub's Windows runner. Company policies may block downloaded executables even though the application itself needs no administrator rights. If execution is blocked, contact IT or your hosting administrator. Do not disable security controls.

The release includes `checksums.txt`. IT can compare its SHA-256 values with downloaded files using PowerShell's `Get-FileHash`.

## What each check proves

| Check | What it does | What success means |
| --- | --- | --- |
| Internet DNS | Resolves `example.com` | This process can use the configured system DNS resolver. |
| Internet HTTPS / TLS | Sends `HEAD https://example.com/` | HTTPS responds with a verified certificate. An unexpected HTTP status is a warning. |
| Hasura GraphQL | Sends one anonymous read-only query | HTTP and GraphQL both succeed. HTTP 200 with GraphQL errors is a failure. |
| DATEV DNS / target | Resolves the configured host and validates every returned address | Only permitted local or private addresses were found. |
| DATEV TCP | Opens and immediately closes a connection to one configured port | A service accepts TCP connections. This does not identify it as DATEV. |
| DATEV HTTP HEAD | Requests headers at `/datev/api`, without credentials | An HTTP service responds. Its identity, licensing and accounting permissions remain unverified. |

HTTP **401/403** from the DATEV target is a warning: a service is reachable but authentication or permission is required. **404** means the path was not found. **405/501** means HEAD is unsupported. No GET fallback is attempted. Redirects are reported and never followed.

## Hasura settings

The default public endpoint is `https://hasura.venturatravel.org/v1/graphql`. The default query was verified anonymously on 9 Oct 2026:

```graphql
query ConnectivityProbe {
  trip(limit: 10, order_by: {created_at: desc}) {
    id
    created_at
  }
}
```

Only trip IDs and creation dates from this exact default query are displayed. API settings allow another HTTPS endpoint and read-only query; custom responses are summarized with record counts and are not displayed or included in the report. Anonymous permissions can change, so a future failure may be a permissions change rather than a network problem.

The app has no fields for credentials and sends no Authorization, cookies, Hasura admin secret or role override. Endpoint URLs cannot contain credentials, query parameters or fragments. Mutation and subscription keywords outside strings/comments are rejected, including when appended after a query. This conservative check also rejects query fields with those names. The GraphQL server remains responsible for syntax validation and anonymous access permissions. Use only an approved anonymous endpoint and query.

## DATEV settings

`http://localhost:58454/datev/api` is the initial test address, **not a confirmed DATEV installation or a discovery mechanism**. Ask your administrator for the actual service host, port and protocol. The remote desktop may connect to DATEV running on another server.

Configure a bare hostname or IP address, a port from 1 to 65535 and HTTP or HTTPS. Only loopback, RFC1918 private IPv4 and private IPv6 addresses are permitted. Public, unspecified, multicast, link-local and carrier-grade NAT addresses are blocked, including addresses returned by DNS. The app pins validated addresses when connecting, performs no subnet or port scanning, uses no proxy for DATEV and follows no redirects.

Use HTTPS when connecting to another computer, as required by DATEV's documentation. Certificates are always verified against system trust. A certificate error does not prove the TCP port is unreachable. No credentials or accounting payload are requested, even when HTTP is selected for the initial loopback check.

[DATEV's official configuration guide](https://developer.datev.de/de/product-detail/accounting/1.7.4/documentation/configuration) explains installation, licensing and Windows/Basic authentication. A successful connection test does not establish that DATEVconnect is licensed or that a permitted accounting endpoint exists. See the [Accounting overview](https://developer.datev.de/de/product-detail/accounting/1.7.4/overview) for its capabilities.

## Troubleshooting

- **Browser cannot connect:** keep the executable running and open the URL in the remote desktop, not on your own computer. If port 8080 is occupied, close another copy of the app or contact IT. The listener address is fixed and loopback-only.
- **Connection refused:** the target port has no accepting listener, or a firewall actively rejected it. Confirm the service host and port.
- **Timeout:** check routing, firewall or proxy restrictions. Each check is bounded to about 12 seconds.
- **DNS error:** confirm the hostname and that the remote Windows host can resolve it.
- **TLS certificate error:** ask IT to verify the certificate and system trust configuration. This app has no certificate-bypass option.
- **Browser works but Go fails:** public HTTPS requests use Go's standard `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment settings. Browser/system PAC and integrated proxy authentication are not automatically inherited. Ask IT to configure the approved process environment if required. Proxy settings and URL credentials are redacted from errors; network errors can still include a proxy hostname or address.
- **HTTP 407 or a proxy login page:** connectivity to the expected API is not established. Hasura rejects responses that are not GraphQL JSON.
- **Another test is running:** checks are sequential. Wait for completion before trying again.

No files or persistent logs are written by the app. The visible session log and optional copied report include the application version, OS, architecture, target, stage, latency and error category. The report notes whether an explicit proxy environment is present without exposing its value. It does not collect the Windows username or machine name.

## Build and test

The runtime uses the Go standard library only. With Go 1.26 or newer:

```sh
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" -o dist/datev-test-agent-windows-amd64.exe .
```

For local development on your own OS, use `go run . -no-browser`, then open `http://127.0.0.1:8080/`. `-version` prints the version without starting the server.

Use a current Edge, Chrome or Firefox browser for the interface. Internet Explorer is not supported.

Tests cover local API protections, anonymous GraphQL requests, rejection of mutations, GraphQL errors with HTTP 200, response limits, DATEV private-address restrictions, HEAD-only requests, redirects, connection refusal and untrusted TLS. Windows CI builds and runs the executable, serves its embedded UI and requests a diagnostic report. CI uses local test servers; actual connectivity and DATEV configuration must be tested on the target desktop.

## Releases

The GitHub Actions workflow tests on Linux and Windows for main-branch pushes and pull requests. A tag such as `v0.1.0` runs the same checks, builds a Windows AMD64 executable and publishes a GitHub Release with the executable, an instructions ZIP and SHA-256 checksums. Actions are pinned to commit IDs. Release write permission is limited to the publishing job.

## Scope and license

This is a diagnostic tool, not a production integration or an official DATEV product. Unattended synchronization, credentials and BigQuery ingestion are outside its scope.

The code is licensed under MIT. The included official Ventura Travel logo is sourced from Ventura Travel's brand assets; the logo and trademarks are excluded from the MIT grant and remain the property of their respective owners. [Official logo source](https://media.venturatravel.org/unsafe/0x0/center/middle/smart/4e33dba7-fd9d-46ad-987d-8a866066851c-ventura-travel-logo-1200px-full-color-copy.png).
