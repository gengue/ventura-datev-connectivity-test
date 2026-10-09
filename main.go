package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/gengue/ventura-datev-connectivity-test/internal/checks"
)

//go:embed web/*
var web embed.FS
var version = "dev"

const address = "127.0.0.1:8080"

type probeRequest struct {
	Check    string             `json:"check"`
	Endpoint string             `json:"endpoint"`
	Query    string             `json:"query"`
	DATEV    checks.DATEVConfig `json:"datev"`
}

type report struct {
	Version       string          `json:"version"`
	OS            string          `json:"os"`
	Arch          string          `json:"arch"`
	FinishedAt    string          `json:"finished_at"`
	ExplicitProxy bool            `json:"explicit_proxy_configured"`
	Results       []checks.Result `json:"results"`
}

func newHandler(host, token string) http.Handler {
	busy := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(remote).IsLoopback() || r.Host != host {
			http.Error(w, "Only the local application address is permitted.", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+host {
			http.Error(w, "Cross-origin requests are blocked.", http.StatusForbidden)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Cross-site requests are blocked.", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/check" {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				http.Error(w, "Use POST.", http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("X-Probe-Token") != token || token == "" {
				http.Error(w, "Reload the application page to use this session.", http.StatusForbidden)
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "Use application/json.", http.StatusUnsupportedMediaType)
				return
			}
			var input probeRequest
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
				http.Error(w, "Invalid or oversized request.", http.StatusBadRequest)
				return
			}
			if input.Check != "internet" && input.Check != "hasura" && input.Check != "datev" {
				http.Error(w, "Choose internet, hasura or datev.", http.StatusBadRequest)
				return
			}
			select {
			case busy <- struct{}{}:
				defer func() { <-busy }()
			default:
				http.Error(w, "Another test is running. Please wait.", http.StatusTooManyRequests)
				return
			}
			if input.Endpoint == "" {
				input.Endpoint = checks.HasuraEndpoint
			}
			if input.Query == "" {
				input.Query = checks.DefaultQuery
			}
			if input.DATEV.Host == "" {
				input.DATEV.Host = "localhost"
			}
			if input.DATEV.Port == 0 {
				input.DATEV.Port = 58454
			}
			if input.DATEV.Scheme == "" {
				input.DATEV.Scheme = "http"
			}
			var results []checks.Result
			switch input.Check {
			case "internet":
				results = checks.Internet(r.Context())
			case "hasura":
				results = checks.GraphQL(r.Context(), input.Endpoint, input.Query)
			case "datev":
				results = checks.DATEV(r.Context(), input.DATEV)
			}
			proxy := os.Getenv("HTTPS_PROXY") != "" || os.Getenv("https_proxy") != "" || os.Getenv("HTTP_PROXY") != "" || os.Getenv("http_proxy") != ""
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(report{version, runtime.GOOS, runtime.GOARCH, time.Now().UTC().Format(time.RFC3339), proxy, results})
			for _, item := range results {
				log.Printf("%s | %s | %s | %d ms", item.Check, item.Stage, item.Status, item.LatencyMS)
			}
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Use GET.", http.StatusMethodNotAllowed)
			return
		}
		name := ""
		switch r.URL.Path {
		case "/":
			name = "index.html"
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "/app.js":
			name = "app.js"
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case "/style.css":
			name = "style.css"
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case "/logo.png":
			name = "logo.png"
			w.Header().Set("Content-Type", "image/png")
		default:
			http.NotFound(w, r)
			return
		}
		content, err := web.ReadFile("web/" + name)
		if err != nil {
			http.Error(w, "Asset unavailable.", http.StatusInternalServerError)
			return
		}
		if name == "index.html" {
			content = []byte(strings.ReplaceAll(string(content), "{{TOKEN}}", token))
		}
		if r.Method != http.MethodHead {
			_, _ = w.Write(content)
		}
	})
}

func run(noBrowser bool) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w. Close another copy of this app or ask IT about port 8080", address, err)
	}
	defer listener.Close()
	server := &http.Server{Handler: newHandler(address, rand.Text()), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	fmt.Printf("Ventura DATEV Connectivity Test %s\nOpen http://%s in this Windows desktop's browser.\nKeep this window open. Press Ctrl+C or close it to stop.\n", version, address)
	if !noBrowser {
		go func() {
			var command *exec.Cmd
			switch runtime.GOOS {
			case "windows":
				command = exec.Command("rundll32", "url.dll,FileProtocolHandler", "http://"+address)
			case "darwin":
				command = exec.Command("open", "http://"+address)
			default:
				command = exec.Command("xdg-open", "http://"+address)
			}
			if err := command.Run(); err != nil {
				log.Print("Open the URL printed above manually in your browser.")
			}
		}()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	noBrowser := flag.Bool("no-browser", false, "Do not open a browser automatically")
	showVersion := flag.Bool("version", false, "Print the application version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if err := run(*noBrowser); err != nil {
		log.Print(err)
		if runtime.GOOS == "windows" {
			fmt.Print("Press Enter to close... ")
			_, _ = fmt.Scanln()
		}
		os.Exit(1)
	}
}
