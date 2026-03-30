package nginx

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/HT4w5/flux/pkg/dto"
)

const (
	testLine = `{
    "time": "1774852695.272",
    "client": "114.51.4.19",
    "server": "19.19.8.10",
    "method": "GET",
    "url": "/foo/bar",
    "status": 200,
    "sent": 369,
    "duration": "0.000",
    "host": "19.19.8.10",
    "agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
}`
)

func TestParse(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}

	r, err := p.Parse([]byte(testLine))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	t.Log(r)
}

func TestParseRandom(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}

	// Use a fixed seed for reproducibility
	rng := rand.New(rand.NewSource(42))
	const numTests = 1000

	for i := 0; i < numTests; i++ {
		// Generate random values
		timeVal := generateRandomTime(rng)
		clientIP := generateRandomIP(rng)
		serverIP := generateRandomIP(rng)
		method := generateRandomMethod(rng)
		urlPath := generateRandomURL(rng)
		status := generateRandomStatus(rng)
		sent := generateRandomSent(rng)
		duration := generateRandomDuration(rng)
		host := generateRandomHost(rng)
		agent := generateRandomAgent(rng)

		// Create JSON line
		jsonLine := fmt.Sprintf(`{
    "time": "%s",
    "client": "%s",
    "server": "%s",
    "method": "%s",
    "url": "%s",
    "status": %d,
    "sent": %d,
    "duration": "%s",
    "host": "%s",
    "agent": "%s"
}`, timeVal, clientIP, serverIP, method, urlPath, status, sent, duration, host, agent)

		// Parse
		req, err := p.Parse([]byte(jsonLine))
		if err != nil {
			t.Errorf("parse failed for test %d: %v\nJSON: %s", i, err, jsonLine)
			continue
		}

		// Verify parsed values match expected
		// Note: We need to compare with tolerance for floating point time/duration
		verifyParsedRequest(t, i, jsonLine, req, timeVal, clientIP, serverIP, method, urlPath, status, sent, duration, host, agent)
	}
}

// Helper functions for generating random test data
func generateRandomTime(rng *rand.Rand) string {
	// Generate random Unix timestamp with milliseconds
	sec := rng.Int63n(2000000000) // Up to year ~2033
	millis := rng.Intn(1000)
	return fmt.Sprintf("%d.%03d", sec, millis)
}

func generateRandomIP(rng *rand.Rand) string {
	// Generate random IPv4 address
	return fmt.Sprintf("%d.%d.%d.%d",
		rng.Intn(256),
		rng.Intn(256),
		rng.Intn(256),
		rng.Intn(256),
	)
}

func generateRandomMethod(rng *rand.Rand) string {
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
	return methods[rng.Intn(len(methods))]
}

func generateRandomURL(rng *rand.Rand) string {
	paths := []string{
		"/",
		"/index.html",
		"/api/v1/users",
		"/static/css/style.css",
		"/images/photo.jpg",
		"/blog/post/123",
		"/search?q=test",
		"/admin/dashboard",
		"/products/electronics",
		"/user/profile/settings",
	}
	return paths[rng.Intn(len(paths))]
}

func generateRandomStatus(rng *rand.Rand) int {
	// Common HTTP status codes
	statusCodes := []int{
		200, 201, 204, 301, 302, 304, 400, 401, 403, 404,
		405, 409, 500, 502, 503, 504,
	}
	return statusCodes[rng.Intn(len(statusCodes))]
}

func generateRandomSent(rng *rand.Rand) int64 {
	// Random bytes sent (0 to 10MB)
	return rng.Int63n(10 * 1024 * 1024)
}

func generateRandomDuration(rng *rand.Rand) string {
	// Random duration in seconds with milliseconds
	sec := rng.Intn(60) // Up to 60 seconds
	millis := rng.Intn(1000)
	return fmt.Sprintf("%d.%03d", sec, millis)
}

func generateRandomHost(rng *rand.Rand) string {
	hosts := []string{
		"example.com",
		"api.example.com",
		"www.google.com",
		"localhost",
		"192.168.1.1",
		"10.0.0.1",
		"test.server.local",
		"cdn.example.net",
	}
	return hosts[rng.Intn(len(hosts))]
}

func generateRandomAgent(rng *rand.Rand) string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
		"curl/7.88.1",
		"PostmanRuntime/7.36.3",
		"Go-http-client/2.0",
		"python-requests/2.31.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
	}
	return agents[rng.Intn(len(agents))]
}

func verifyParsedRequest(t *testing.T, testNum int, jsonLine string, req dto.Request,
	timeVal, clientIP, serverIP, method, urlPath string, status int, sent int64, duration, host, agent string) {
	// Helper function to verify parsed request matches expected values

	// Parse expected time from string
	expectedTime, err := parseNginxTime([]byte(timeVal))
	if err != nil {
		t.Errorf("test %d: failed to parse expected time %q: %v", testNum, timeVal, err)
		return
	}

	// Parse expected duration from string
	expectedDuration, err := parseNginxDuration([]byte(duration))
	if err != nil {
		t.Errorf("test %d: failed to parse expected duration %q: %v", testNum, duration, err)
		return
	}

	// Parse expected IP addresses
	expectedClient, err := netip.ParseAddr(clientIP)
	if err != nil {
		t.Errorf("test %d: failed to parse expected client IP %q: %v", testNum, clientIP, err)
		return
	}

	expectedServer, err := netip.ParseAddr(serverIP)
	if err != nil {
		t.Errorf("test %d: failed to parse expected server IP %q: %v", testNum, serverIP, err)
		return
	}

	// Compare time (allow small tolerance for floating point)
	if !req.Time.Equal(expectedTime) {
		t.Errorf("test %d: time mismatch: got %v, expected %v", testNum, req.Time, expectedTime)
	}

	// Compare client IP
	if req.Client != expectedClient {
		t.Errorf("test %d: client IP mismatch: got %v, expected %v", testNum, req.Client, expectedClient)
	}

	// Compare server IP
	if req.Server != expectedServer {
		t.Errorf("test %d: server IP mismatch: got %v, expected %v", testNum, req.Server, expectedServer)
	}

	// Compare method
	if req.Method != method {
		t.Errorf("test %d: method mismatch: got %q, expected %q", testNum, req.Method, method)
	}

	// Compare URL
	if req.URL != urlPath {
		t.Errorf("test %d: URL mismatch: got %q, expected %q", testNum, req.URL, urlPath)
	}

	// Compare status
	if req.Status != status {
		t.Errorf("test %d: status mismatch: got %d, expected %d", testNum, req.Status, status)
	}

	// Compare sent bytes
	if req.Sent != sent {
		t.Errorf("test %d: sent bytes mismatch: got %d, expected %d", testNum, req.Sent, sent)
	}

	// Compare duration (allow small tolerance)
	if req.Duration != expectedDuration {
		// Allow 1 microsecond tolerance due to floating point precision
		diff := req.Duration - expectedDuration
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Microsecond {
			t.Errorf("test %d: duration mismatch: got %v, expected %v (diff: %v)", testNum, req.Duration, expectedDuration, diff)
		}
	}

	// Compare host
	if req.Host != host {
		t.Errorf("test %d: host mismatch: got %q, expected %q", testNum, req.Host, host)
	}

	// Compare agent
	if req.Agent != agent {
		t.Errorf("test %d: agent mismatch: got %q, expected %q", testNum, req.Agent, agent)
	}
}
