package main

import (
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

func TestSetForwardedHeaders(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		host            string
		remoteAddr      string
		tlsState        *tls.ConnectionState
		inboundHeader   http.Header
		expectedHeaders map[string]string
		unsetHeaders    []string
	}{
		{
			name:       "ipv4",
			host:       "example.com",
			remoteAddr: "192.0.2.10:54321",
			expectedHeaders: map[string]string{
				"Forwarded":         "for=192.0.2.10;proto=http;host=example.com",
				"X-Forwarded-For":   "192.0.2.10",
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  "example.com",
			},
		},
		{
			// Per RFC 7239 an IPv6 address must be bracketed and quoted in
			// Forwarded, while X-Forwarded-For carries it bare.
			name:       "ipv6 is bracketed and quoted in forwarded only",
			host:       "example.com",
			remoteAddr: "[2001:db8::1]:54321",
			expectedHeaders: map[string]string{
				"Forwarded":       `for="[2001:db8::1]";proto=http;host=example.com`,
				"X-Forwarded-For": "2001:db8::1",
			},
		},
		{
			name:       "tls makes the protocol https",
			host:       "example.com",
			remoteAddr: "192.0.2.10:54321",
			tlsState:   &tls.ConnectionState{},
			expectedHeaders: map[string]string{
				"Forwarded":         "for=192.0.2.10;proto=https;host=example.com",
				"X-Forwarded-Proto": "https",
			},
		},
		{
			// SplitHostPort fails, so the address is used verbatim.
			name:       "remote address without a port",
			host:       "example.com",
			remoteAddr: "192.0.2.10",
			expectedHeaders: map[string]string{
				"Forwarded":       "for=192.0.2.10;proto=http;host=example.com",
				"X-Forwarded-For": "192.0.2.10",
			},
		},
		{
			name:       "no host leaves the host parts out",
			remoteAddr: "192.0.2.10:54321",
			expectedHeaders: map[string]string{
				"Forwarded": "for=192.0.2.10;proto=http",
			},
			unsetHeaders: []string{"X-Forwarded-Host"},
		},
		{
			// A colon is not a token character, so unquoted the port would
			// not parse as part of the value.
			name:       "a host with a port is quoted in forwarded only",
			host:       "example.com:8443",
			remoteAddr: "192.0.2.10:54321",
			expectedHeaders: map[string]string{
				"Forwarded":        `for=192.0.2.10;proto=http;host="example.com:8443"`,
				"X-Forwarded-Host": "example.com:8443",
			},
		},
		{
			name:       "an ipv6 host is quoted",
			host:       "[2001:db8::2]:8443",
			remoteAddr: "[2001:db8::1]:54321",
			expectedHeaders: map[string]string{
				"Forwarded": `for="[2001:db8::1]";proto=http;host="[2001:db8::2]:8443"`,
			},
		},
		{
			// net.ParseIP refuses a zone, which left this unbracketed.
			name:       "an ipv6 address with a zone is bracketed",
			host:       "example.com",
			remoteAddr: "[fe80::1%eth0]:54321",
			expectedHeaders: map[string]string{
				"Forwarded":       `for="[fe80::1%eth0]";proto=http;host=example.com`,
				"X-Forwarded-For": "fe80::1%eth0",
			},
		},
		{
			// Whatever the client claimed must be replaced, never appended to.
			name:       "client supplied values are replaced",
			host:       "example.com",
			remoteAddr: "192.0.2.10:54321",
			inboundHeader: http.Header{
				"Forwarded":         []string{"for=10.0.0.1"},
				"X-Forwarded-For":   []string{"10.0.0.1"},
				"X-Forwarded-Proto": []string{"https"},
				"X-Forwarded-Host":  []string{"evil.example"},
			},
			expectedHeaders: map[string]string{
				"Forwarded":         "for=192.0.2.10;proto=http;host=example.com",
				"X-Forwarded-For":   "192.0.2.10",
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  "example.com",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			inboundHeader := testCase.inboundHeader
			if inboundHeader == nil {
				inboundHeader = http.Header{}
			}

			inbound := &http.Request{
				Header:     inboundHeader,
				Host:       testCase.host,
				RemoteAddr: testCase.remoteAddr,
				TLS:        testCase.tlsState,
			}
			outbound := &http.Request{Header: inboundHeader.Clone()}

			setForwardedHeaders(outbound, inbound)

			for header, expected := range testCase.expectedHeaders {
				if got := outbound.Header.Get(header); got != expected {
					t.Errorf("%s = %q, want %q", header, got, expected)
				}

				// A replaced header must hold exactly one value.
				if values := outbound.Header.Values(header); len(values) != 1 {
					t.Errorf("%s has %d values, want 1: %v", header, len(values), values)
				}
			}

			for _, header := range testCase.unsetHeaders {
				if got := outbound.Header.Get(header); got != "" {
					t.Errorf("%s should be unset, got %q", header, got)
				}
			}
		})
	}
}

func TestRejectMalformedHost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		host         string
		expectServed bool
	}{
		{name: "a name", host: "upload-logs.home.arpa", expectServed: true},
		{name: "a name and a port", host: "upload-logs.home.arpa:443", expectServed: true},
		// RFC 3986 allows an empty port, and it carries nothing.
		{name: "an empty port", host: "upload-logs.home.arpa:", expectServed: true},
		{name: "an ipv6 address", host: "[2001:db8::1]", expectServed: true},
		{name: "an ipv6 address and a port", host: "[2001:db8::1]:443", expectServed: true},
		// The mux refuses this one, having no vhost for it.
		{name: "no host", host: "", expectServed: true},
		{name: "a parameter in the port", host: "restic.home.arpa:1;for=10.0.0.1"},
		{name: "an element in the port", host: "restic.home.arpa:1,for=10.0.0.1"},
		{name: "a name in the port", host: "restic.home.arpa:https"},
		{name: "two ports", host: "restic.home.arpa:1:2"},
		{name: "an unbracketed ipv6 address", host: "2001:db8::1"},
		{name: "a non-numeric port after an ipv6 address", host: "[2001:db8::1]:x"},
		{name: "text after an ipv6 address", host: "[2001:db8::1]x"},
		{name: "an unterminated bracket", host: "[2001:db8::1"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var served bool
			handler := rejectMalformedHost(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				served = true
			}))

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			request.Host = testCase.host

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if served != testCase.expectServed {
				t.Errorf("%s: served = %v, want %v", testCase.name, served, testCase.expectServed)
			}

			if !testCase.expectServed && recorder.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want %d", testCase.name, recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

// newTestProxy builds the proxy exactly as main does, so the test exercises the
// real Rewrite hook rather than a copy of it.
func newTestProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			inbound := proxyRequest.In
			outbound := proxyRequest.Out

			proxyRequest.SetURL(target)
			outbound.Host = inbound.Host

			setForwardedHeaders(outbound, inbound)
		},
	}
}

func TestProxyForwardedHeaders(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		inboundHost       string
		inboundForwarded  string
		expectedForwarded string
		// expectRefused is a request the upstream must never see.
		expectRefused bool
	}{
		{
			name:              "the client address appears once",
			inboundHost:       "vhost.example",
			expectedForwarded: "for=127.0.0.1;proto=http;host=vhost.example",
		},
		{
			// Regression: with a Director, ReverseProxy appended the client
			// address to the one already set, sending it upstream twice.
			name:              "a client supplied value is dropped, not appended",
			inboundHost:       "vhost.example",
			inboundForwarded:  "203.0.113.9",
			expectedForwarded: "for=127.0.0.1;proto=http;host=vhost.example",
		},
		{
			name:              "a host with a port reaches the upstream quoted",
			inboundHost:       "vhost.example:8443",
			expectedForwarded: `for=127.0.0.1;proto=http;host="vhost.example:8443"`,
		},
		{
			// This arrived as for=127.0.0.1;proto=http;host=vhost.example:1;for=10.0.0.1.
			name:          "a host smuggling a client address is refused",
			inboundHost:   "vhost.example:1;for=10.0.0.1",
			expectRefused: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var reached bool
			var seenForwardedFor string
			var seenForwarded string
			var seenHost string

			upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				reached = true
				seenForwardedFor = request.Header.Get("X-Forwarded-For")
				seenForwarded = request.Header.Get("Forwarded")
				seenHost = request.Host
			}))
			defer upstream.Close()

			target, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("parse upstream url: %v", err)
			}

			front := httptest.NewServer(rejectMalformedHost(newTestProxy(target)))
			defer front.Close()

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Host = testCase.inboundHost
			if testCase.inboundForwarded != "" {
				request.Header.Set("X-Forwarded-For", testCase.inboundForwarded)
			}

			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			defer func() {
				_ = response.Body.Close()
			}()

			if testCase.expectRefused {
				if reached || response.StatusCode != http.StatusBadRequest {
					t.Errorf("%s: status = %d and upstream reached = %v, want a 400 it never saw", testCase.name, response.StatusCode, reached)
				}
				return
			}

			if seenForwardedFor != "127.0.0.1" {
				t.Errorf("%s: upstream saw X-Forwarded-For %q, want a single \"127.0.0.1\"", testCase.name, seenForwardedFor)
			}

			// The RFC 7239 header travels alongside the X-Forwarded-* ones.
			if seenForwarded != testCase.expectedForwarded {
				t.Errorf("%s: upstream saw Forwarded %q, want %q", testCase.name, seenForwarded, testCase.expectedForwarded)
			}

			// SetURL points Host at the upstream; the host the client asked for
			// has to survive for the upstream to route on it.
			if seenHost != testCase.inboundHost {
				t.Errorf("%s: upstream saw Host %q, want %q", testCase.name, seenHost, testCase.inboundHost)
			}
		})
	}
}

func TestUpstreamConfigurationUnmarshal(t *testing.T) {
	t.Parallel()

	const data = `{
		"a.example": {"url": "http://backend-a:8080"},
		"b.example": {"url": "https://backend-b", "use_client_authentication": true},
		"c.example": {"url": "https://elsewhere.example", "redirect": true},
		"d.example": {"url": "http://backend-d:9090", "stream_request_body": true}
	}`

	var configurations map[string]*UpstreamConfiguration
	if err := json.Unmarshal([]byte(data), &configurations); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	testCases := []struct {
		name                         string
		host                         string
		expectedUrl                  string
		expectedClientAuthentication bool
		expectedRedirect             bool
		expectedStreamRequestBody    bool
	}{
		{name: "plain upstream", host: "a.example", expectedUrl: "http://backend-a:8080"},
		{name: "client authentication", host: "b.example", expectedUrl: "https://backend-b", expectedClientAuthentication: true},
		{name: "redirect", host: "c.example", expectedUrl: "https://elsewhere.example", expectedRedirect: true},
		// The tag name is what config.json has to spell; a typo here would
		// silently leave the upstream on the default timeout and pooling.
		{name: "stream request body", host: "d.example", expectedUrl: "http://backend-d:9090", expectedStreamRequestBody: true},
	}

	if len(configurations) != len(testCases) {
		t.Fatalf("got %d configurations, want %d", len(configurations), len(testCases))
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			configuration := configurations[testCase.host]
			if configuration == nil {
				t.Fatalf("no configuration for %s", testCase.host)
			}

			if configuration.Url != testCase.expectedUrl {
				t.Errorf("url = %q, want %q", configuration.Url, testCase.expectedUrl)
			}

			if configuration.UseClientAuthentication != testCase.expectedClientAuthentication {
				t.Errorf("use_client_authentication = %v, want %v", configuration.UseClientAuthentication, testCase.expectedClientAuthentication)
			}

			if configuration.Redirect != testCase.expectedRedirect {
				t.Errorf("redirect = %v, want %v", configuration.Redirect, testCase.expectedRedirect)
			}

			if configuration.StreamRequestBody != testCase.expectedStreamRequestBody {
				t.Errorf("stream_request_body = %v, want %v", configuration.StreamRequestBody, testCase.expectedStreamRequestBody)
			}
		})
	}
}

// TestStreamRequestBody drives a real server whose ReadTimeout is shorter than
// the body takes to arrive, which is the shape that cut every journal-upload at
// 60s. The unconfigured case is what every vhost still gets, so together they
// pin both halves: the deadline is lifted where it is asked for and nowhere
// else.
func TestStreamRequestBody(t *testing.T) {
	t.Parallel()

	const (
		serverReadTimeout = 250 * time.Millisecond
		chunkCount        = 4
		chunkDelay        = 200 * time.Millisecond
		chunk             = "0123456789"
	)

	testCases := []struct {
		name string
		// configured makes the request's own host one of streamHosts, as
		// upload-logs.home.arpa is; otherwise the set names a different host and
		// the request must keep the deadline the server gave it.
		configured      bool
		expectReadError bool
	}{
		{
			name:       "configured host outlives the read timeout",
			configured: true,
		},
		{
			name:            "unconfigured host keeps the read timeout",
			expectReadError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			type readResult struct {
				byteCount int
				err       error
			}
			readResults := make(chan readResult, 1)

			var handler http.Handler = http.HandlerFunc(
				func(_ http.ResponseWriter, request *http.Request) {
					body, err := io.ReadAll(request.Body)
					readResults <- readResult{byteCount: len(body), err: err}
				},
			)

			// httptest serves on a loopback address, so that is the host the
			// request carries and the one the wrapper has to match on.
			streamHost := "127.0.0.1"
			if !testCase.configured {
				streamHost = "some-other-host.invalid"
			}

			loggedErrors := make(chan error, 8)
			handler = streamRequestBody(
				handler,
				map[string]struct{}{streamHost: {}},
				false,
				func(_ string, err error, _ ...any) { loggedErrors <- err },
			)

			server := httptest.NewUnstartedServer(handler)
			server.Config.ReadTimeout = serverReadTimeout
			server.Start()
			defer server.Close()

			pipeReader, pipeWriter := io.Pipe()
			go func() {
				for range chunkCount {
					time.Sleep(chunkDelay)
					if _, err := io.WriteString(pipeWriter, chunk); err != nil {
						_ = pipeWriter.CloseWithError(err)
						return
					}
				}
				_ = pipeWriter.Close()
			}()

			request, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				server.URL,
				pipeReader,
			)
			if err != nil {
				t.Fatalf("%s: new request: %v", testCase.name, err)
			}

			if response, err := server.Client().Do(request); err == nil {
				_ = response.Body.Close()
			}

			select {
			case result := <-readResults:
				switch {
				case testCase.expectReadError && result.err == nil:
					t.Errorf(
						"%s: expected a body read error, read %d bytes without one",
						testCase.name,
						result.byteCount,
					)
				case !testCase.expectReadError && result.err != nil:
					t.Errorf("%s: unexpected body read error: %v", testCase.name, result.err)
				case !testCase.expectReadError && result.byteCount != chunkCount*len(chunk):
					t.Errorf(
						"%s: read %d bytes, want %d",
						testCase.name,
						result.byteCount,
						chunkCount*len(chunk),
					)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: the handler was never reached", testCase.name)
			}

			close(loggedErrors)
			for err := range loggedErrors {
				t.Errorf("%s: clearing the read deadline logged an error: %v", testCase.name, err)
			}
		})
	}
}

func TestParseArgumentsKeepResponseBody(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		arguments []string
		want      int
		wantError error
	}{
		// Zero holds every byte of a large download in memory until it ends.
		{name: "a 64 KiB cap by default", arguments: nil, want: 65536},
		{name: "a cap", arguments: []string{"--keep-response-body", "8192"}, want: 8192},
		{name: "zero keeps all of it", arguments: []string{"--keep-response-body=0"}, want: 0},
		{name: "a cap given with an equals sign", arguments: []string{"--keep-response-body=4096"}, want: 4096},
		{name: "a negative cap", arguments: []string{"--keep-response-body=-1"}, wantError: altshiftErrors.ErrValidationError},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config, err := parseArguments(testCase.arguments)
			if testCase.wantError != nil {
				if !errors.Is(err, testCase.wantError) {
					t.Fatalf("error = %v, want %v", err, testCase.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse arguments: %v", err)
			}
			if config.KeepResponseBody != testCase.want {
				t.Errorf("keep response body = %d, want %d", config.KeepResponseBody, testCase.want)
			}
		})
	}
}

func TestNewHttpServerCapsRequestHeaders(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(nil)
	server.Config = newHttpServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil)
	server.Start()
	// Not defer: the subtests below are parallel, so they run after this
	// function returns.
	t.Cleanup(server.Close)

	testCases := []struct {
		name         string
		headerSize   int
		expectStatus int
	}{
		{name: "headers under the cap are served", headerSize: 32 << 10, expectStatus: http.StatusOK},
		// net/http's default of 1 MiB admits this one.
		{name: "headers over the cap are refused", headerSize: 128 << 10, expectStatus: http.StatusRequestHeaderFieldsTooLarge},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("%s: new request: %v", testCase.name, err)
			}
			request.Header.Set("X-Padding", strings.Repeat("a", testCase.headerSize))

			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatalf("%s: do request: %v", testCase.name, err)
			}
			_ = response.Body.Close()

			if response.StatusCode != testCase.expectStatus {
				t.Errorf("%s: status = %d, want %d", testCase.name, response.StatusCode, testCase.expectStatus)
			}
		})
	}
}
