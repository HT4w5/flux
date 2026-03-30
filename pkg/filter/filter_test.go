package filter

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/HT4w5/flux/pkg/dto"
	"go4.org/netipx"
)

// Helper function to create a test request
func createTestRequest() *dto.Request {
	return &dto.Request{
		Time:     time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC),
		Client:   netip.MustParseAddr("192.168.1.100"),
		Server:   netip.MustParseAddr("10.0.0.1"),
		Method:   "GET",
		URL:      "/api/v1/users",
		Status:   200,
		Sent:     1024,
		Duration: 150 * time.Millisecond,
		Host:     "api.example.com",
		Agent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

// Helper function to create a test request with custom values
func createCustomRequest(timeVal time.Time, clientIP, serverIP string, method, url string, status int, sent int64, duration time.Duration, host, agent string) *dto.Request {
	return &dto.Request{
		Time:     timeVal,
		Client:   netip.MustParseAddr(clientIP),
		Server:   netip.MustParseAddr(serverIP),
		Method:   method,
		URL:      url,
		Status:   status,
		Sent:     sent,
		Duration: duration,
		Host:     host,
		Agent:    agent,
	}
}

// Test And rule
func TestAnd(t *testing.T) {
	req := createTestRequest()

	// Test pass: both rules match
	rule1 := Method("GET")
	rule2 := URL("/api/v1/users")
	andRule := And{rule1, rule2}

	if !andRule.Match(req) {
		t.Error("And rule should match when all sub-rules match")
	}

	// Test fail: one rule doesn't match
	rule3 := Method("POST")
	andRule2 := And{rule3, rule2}

	if andRule2.Match(req) {
		t.Error("And rule should not match when one sub-rule doesn't match")
	}
}

// Test Or rule
func TestOr(t *testing.T) {
	req := createTestRequest()

	// Test pass: at least one rule matches
	rule1 := Method("POST")       // Doesn't match
	rule2 := URL("/api/v1/users") // Matches
	orRule := Or{rule1, rule2}

	if !orRule.Match(req) {
		t.Error("Or rule should match when at least one sub-rule matches")
	}

	// Test fail: no rules match
	rule3 := Method("POST")
	rule4 := URL("/nonexistent")
	orRule2 := Or{rule3, rule4}

	if orRule2.Match(req) {
		t.Error("Or rule should not match when no sub-rules match")
	}
}

// Test Not rule
func TestNot(t *testing.T) {
	req := createTestRequest()

	// Test pass: inner rule doesn't match, so Not matches
	innerRule := Method("POST") // Doesn't match
	notRule := &Not{Rule: innerRule}

	if !notRule.Match(req) {
		t.Error("Not rule should match when inner rule doesn't match")
	}

	// Test fail: inner rule matches, so Not doesn't match
	innerRule2 := Method("GET") // Matches
	notRule2 := &Not{Rule: innerRule2}

	if notRule2.Match(req) {
		t.Error("Not rule should not match when inner rule matches")
	}
}

// Test Before rule
func TestBefore(t *testing.T) {
	req := createTestRequest()

	// Test pass: request time is before the rule time
	ruleTime := time.Date(2024, 1, 16, 0, 0, 0, 0, time.UTC)
	beforeRule := &Before{Time: ruleTime}

	if !beforeRule.Match(req) {
		t.Error("Before rule should match when request time is before rule time")
	}

	// Test fail: request time is after the rule time
	ruleTime2 := time.Date(2024, 1, 14, 0, 0, 0, 0, time.UTC)
	beforeRule2 := &Before{Time: ruleTime2}

	if beforeRule2.Match(req) {
		t.Error("Before rule should not match when request time is after rule time")
	}
}

func TestBeforeRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		// Create random request with random time
		reqTime := time.Unix(rng.Int63n(2000000000), 0)
		req := createCustomRequest(
			reqTime,
			"192.168.1.100",
			"10.0.0.1",
			"GET",
			"/test",
			200,
			1024,
			100*time.Millisecond,
			"example.com",
			"test-agent",
		)

		// Create random rule time
		ruleTime := time.Unix(rng.Int63n(2000000000), 0)
		beforeRule := &Before{Time: ruleTime}

		result := beforeRule.Match(req)
		expected := reqTime.Before(ruleTime)

		if result != expected {
			t.Errorf("Test %d: Before rule mismatch. Request time: %v, Rule time: %v, Expected %v, got %v",
				i, reqTime, ruleTime, expected, result)
		}
	}
}

// Test After rule
func TestAfter(t *testing.T) {
	req := createTestRequest()

	// Test pass: request time is after the rule time
	ruleTime := time.Date(2024, 1, 14, 0, 0, 0, 0, time.UTC)
	afterRule := &After{Time: ruleTime}

	if !afterRule.Match(req) {
		t.Error("After rule should match when request time is after rule time")
	}

	// Test fail: request time is before the rule time
	ruleTime2 := time.Date(2024, 1, 16, 0, 0, 0, 0, time.UTC)
	afterRule2 := &After{Time: ruleTime2}

	if afterRule2.Match(req) {
		t.Error("After rule should not match when request time is before rule time")
	}
}

func TestAfterRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		// Create random request with random time
		reqTime := time.Unix(rng.Int63n(2000000000), 0)
		req := createCustomRequest(
			reqTime,
			"192.168.1.100",
			"10.0.0.1",
			"GET",
			"/test",
			200,
			1024,
			100*time.Millisecond,
			"example.com",
			"test-agent",
		)

		// Create random rule time
		ruleTime := time.Unix(rng.Int63n(2000000000), 0)
		afterRule := &After{Time: ruleTime}

		result := afterRule.Match(req)
		expected := reqTime.After(ruleTime)

		if result != expected {
			t.Errorf("Test %d: After rule mismatch. Request time: %v, Rule time: %v, Expected %v, got %v",
				i, reqTime, ruleTime, expected, result)
		}
	}
}

// Test ClientIPSet rule
func TestClientIPSet(t *testing.T) {
	req := createTestRequest()

	// Test pass: client IP is in the set
	builder := &netipx.IPSetBuilder{}
	builder.AddPrefix(netip.MustParsePrefix("192.168.1.0/24"))
	ipSet, _ := builder.IPSet()
	clientIPSetRule := &ClientIPSet{Set: *ipSet}

	if !clientIPSetRule.Match(req) {
		t.Error("ClientIPSet rule should match when client IP is in the set")
	}

	// Test fail: client IP is not in the set
	builder2 := &netipx.IPSetBuilder{}
	builder2.AddPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	ipSet2, _ := builder2.IPSet()
	clientIPSetRule2 := &ClientIPSet{Set: *ipSet2}

	if clientIPSetRule2.Match(req) {
		t.Error("ClientIPSet rule should not match when client IP is not in the set")
	}
}

func TestClientIPSetRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		// Create random client IP
		clientIP := netip.AddrFrom4([4]byte{
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
		})

		req := createCustomRequest(
			time.Now(),
			clientIP.String(),
			"10.0.0.1",
			"GET",
			"/test",
			200,
			1024,
			100*time.Millisecond,
			"example.com",
			"test-agent",
		)

		// Create random IP set
		builder := &netipx.IPSetBuilder{}
		numPrefixes := rng.Intn(3) + 1
		inSet := false

		for j := 0; j < numPrefixes; j++ {
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{
				byte(rng.Intn(256)),
				byte(rng.Intn(256)),
				byte(rng.Intn(256)),
				0,
			}), 24)
			builder.AddPrefix(prefix)

			if prefix.Contains(clientIP) {
				inSet = true
			}
		}

		ipSet, err := builder.IPSet()
		if err != nil {
			t.Errorf("Test %d: Failed to create IP set: %v", i, err)
			continue
		}

		clientIPSetRule := &ClientIPSet{Set: *ipSet}
		result := clientIPSetRule.Match(req)

		if result != inSet {
			t.Errorf("Test %d: ClientIPSet rule mismatch. Client IP: %v, Expected %v, got %v",
				i, clientIP, inSet, result)
		}
	}
}

// Test ServerIPSet rule
func TestServerIPSet(t *testing.T) {
	req := createTestRequest()

	// Test pass: server IP is in the set
	builder := &netipx.IPSetBuilder{}
	builder.AddPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	ipSet, _ := builder.IPSet()
	serverIPSetRule := &ServerIPSet{Set: *ipSet}

	if !serverIPSetRule.Match(req) {
		t.Error("ServerIPSet rule should match when server IP is in the set")
	}

	// Test fail: server IP is not in the set
	builder2 := &netipx.IPSetBuilder{}
	builder2.AddPrefix(netip.MustParsePrefix("192.168.1.0/24"))
	ipSet2, _ := builder2.IPSet()
	serverIPSetRule2 := &ServerIPSet{Set: *ipSet2}

	if serverIPSetRule2.Match(req) {
		t.Error("ServerIPSet rule should not match when server IP is not in the set")
	}
}

func TestServerIPSetRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		// Create random server IP
		serverIP := netip.AddrFrom4([4]byte{
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
		})

		req := createCustomRequest(
			time.Now(),
			"192.168.1.100",
			serverIP.String(),
			"GET",
			"/test",
			200,
			1024,
			100*time.Millisecond,
			"example.com",
			"test-agent",
		)

		// Create random IP set
		builder := &netipx.IPSetBuilder{}
		numPrefixes := rng.Intn(3) + 1
		inSet := false

		for j := 0; j < numPrefixes; j++ {
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{
				byte(rng.Intn(256)),
				byte(rng.Intn(256)),
				byte(rng.Intn(256)),
				0,
			}), 24)
			builder.AddPrefix(prefix)

			if prefix.Contains(serverIP) {
				inSet = true
			}
		}

		ipSet, err := builder.IPSet()
		if err != nil {
			t.Errorf("Test %d: Failed to create IP set: %v", i, err)
			continue
		}

		serverIPSetRule := &ServerIPSet{Set: *ipSet}
		result := serverIPSetRule.Match(req)

		if result != inSet {
			t.Errorf("Test %d: ServerIPSet rule mismatch. Server IP: %v, Expected %v, got %v",
				i, serverIP, inSet, result)
		}
	}
}

// Test Method rule
func TestMethod(t *testing.T) {
	req := createTestRequest()

	// Test pass: method matches
	methodRule := Method("GET")

	if !methodRule.Match(req) {
		t.Error("Method rule should match when method matches")
	}

	// Test fail: method doesn't match
	methodRule2 := Method("POST")

	if methodRule2.Match(req) {
		t.Error("Method rule should not match when method doesn't match")
	}
}

// Helper functions for random testing
func createRandomRequest(rng *rand.Rand) *dto.Request {
	// Generate random values for all fields
	timeVal := time.Unix(rng.Int63n(2000000000), 0)

	clientIP := netip.AddrFrom4([4]byte{
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
	})

	serverIP := netip.AddrFrom4([4]byte{
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
	})

	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
	method := methods[rng.Intn(len(methods))]

	urls := []string{
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
	url := urls[rng.Intn(len(urls))]

	statusCodes := []int{200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 409, 500, 502, 503, 504}
	status := statusCodes[rng.Intn(len(statusCodes))]

	sent := rng.Int63n(10 * 1024 * 1024) // Up to 10MB

	duration := time.Duration(rng.Int63n(60*1000)) * time.Millisecond // Up to 60 seconds

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
	host := hosts[rng.Intn(len(hosts))]

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
	agent := agents[rng.Intn(len(agents))]

	return &dto.Request{
		Time:     timeVal,
		Client:   clientIP,
		Server:   serverIP,
		Method:   method,
		URL:      url,
		Status:   status,
		Sent:     sent,
		Duration: duration,
		Host:     host,
		Agent:    agent,
	}
}

func TestMethodRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random method
		expectedMethod := methods[rng.Intn(len(methods))]
		methodRule := Method(expectedMethod)

		result := methodRule.Match(req)
		expected := req.Method == expectedMethod

		if result != expected {
			t.Errorf("Test %d: Method rule mismatch. Request method: %q, Rule method: %q, Expected %v, got %v",
				i, req.Method, expectedMethod, expected, result)
		}
	}
}

// Test URL rule
func TestURL(t *testing.T) {
	req := createTestRequest()

	// Test pass: URL matches
	urlRule := URL("/api/v1/users")

	if !urlRule.Match(req) {
		t.Error("URL rule should match when URL matches")
	}

	// Test fail: URL doesn't match
	urlRule2 := URL("/nonexistent")

	if urlRule2.Match(req) {
		t.Error("URL rule should not match when URL doesn't match")
	}
}

func TestURLRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	urls := []string{"/", "/index.html", "/api/v1/users", "/static/css/style.css", "/images/photo.jpg", "/blog/post/123", "/search?q=test"}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random URL
		expectedURL := urls[rng.Intn(len(urls))]
		urlRule := URL(expectedURL)

		result := urlRule.Match(req)
		expected := req.URL == expectedURL

		if result != expected {
			t.Errorf("Test %d: URL rule mismatch. Request URL: %q, Rule URL: %q, Expected %v, got %v",
				i, req.URL, expectedURL, expected, result)
		}
	}
}

// Test URLPrefix rule
func TestURLPrefix(t *testing.T) {
	req := createTestRequest()

	// Test pass: URL has the prefix
	urlPrefixRule := URLPrefix("/api")

	if !urlPrefixRule.Match(req) {
		t.Error("URLPrefix rule should match when URL has the prefix")
	}

	// Test fail: URL doesn't have the prefix
	urlPrefixRule2 := URLPrefix("/static")

	if urlPrefixRule2.Match(req) {
		t.Error("URLPrefix rule should not match when URL doesn't have the prefix")
	}
}

func TestURLPrefixRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	prefixes := []string{"/api", "/static", "/images", "/admin", "/user", "/blog", "/search"}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random prefix
		expectedPrefix := prefixes[rng.Intn(len(prefixes))]
		urlPrefixRule := URLPrefix(expectedPrefix)

		result := urlPrefixRule.Match(req)
		expected := len(req.URL) >= len(expectedPrefix) && req.URL[:len(expectedPrefix)] == expectedPrefix

		if result != expected {
			t.Errorf("Test %d: URLPrefix rule mismatch. Request URL: %q, Rule prefix: %q, Expected %v, got %v",
				i, req.URL, expectedPrefix, expected, result)
		}
	}
}

// Test URLKeyword rule
func TestURLKeyword(t *testing.T) {
	req := createTestRequest()

	// Test pass: URL contains the keyword
	urlKeywordRule := URLKeyword("api")

	if !urlKeywordRule.Match(req) {
		t.Error("URLKeyword rule should match when URL contains the keyword")
	}

	// Test fail: URL doesn't contain the keyword
	urlKeywordRule2 := URLKeyword("static")

	if urlKeywordRule2.Match(req) {
		t.Error("URLKeyword rule should not match when URL doesn't contain the keyword")
	}
}

func TestURLKeywordRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	keywords := []string{"api", "user", "admin", "static", "image", "blog", "search", "test", "css", "jpg"}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random keyword
		expectedKeyword := keywords[rng.Intn(len(keywords))]
		urlKeywordRule := URLKeyword(expectedKeyword)

		result := urlKeywordRule.Match(req)
		expected := false
		for j := 0; j <= len(req.URL)-len(expectedKeyword); j++ {
			if req.URL[j:j+len(expectedKeyword)] == expectedKeyword {
				expected = true
				break
			}
		}

		if result != expected {
			t.Errorf("Test %d: URLKeyword rule mismatch. Request URL: %q, Rule keyword: %q, Expected %v, got %v",
				i, req.URL, expectedKeyword, expected, result)
		}
	}
}

// Test Status rule
func TestStatus(t *testing.T) {
	req := createTestRequest()

	// Test pass: status matches
	statusRule := Status(200)

	if !statusRule.Match(req) {
		t.Error("Status rule should match when status matches")
	}

	// Test fail: status doesn't match
	statusRule2 := Status(404)

	if statusRule2.Match(req) {
		t.Error("Status rule should not match when status doesn't match")
	}
}

func TestStatusRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	statusCodes := []int{200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 409, 500, 502, 503, 504}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random status code
		expectedStatus := statusCodes[rng.Intn(len(statusCodes))]
		statusRule := Status(expectedStatus)

		result := statusRule.Match(req)
		expected := req.Status == expectedStatus

		if result != expected {
			t.Errorf("Test %d: Status rule mismatch. Request status: %d, Rule status: %d, Expected %v, got %v",
				i, req.Status, expectedStatus, expected, result)
		}
	}
}

// Test StatusClass rule
func TestStatusClass(t *testing.T) {
	req := createTestRequest()

	// Test pass: status class matches (200 is in 2xx class)
	statusClassRule := StatusClass(Successful)

	if !statusClassRule.Match(req) {
		t.Error("StatusClass rule should match when status class matches")
	}

	// Test fail: status class doesn't match
	statusClassRule2 := StatusClass(ClientError)

	if statusClassRule2.Match(req) {
		t.Error("StatusClass rule should not match when status class doesn't match")
	}

	// Test with a 404 status
	req2 := createCustomRequest(
		req.Time,
		req.Client.String(),
		req.Server.String(),
		req.Method,
		req.URL,
		404,
		req.Sent,
		req.Duration,
		req.Host,
		req.Agent,
	)

	if !StatusClass(ClientError).Match(req2) {
		t.Error("StatusClass rule should match 404 as ClientError")
	}
}

func TestStatusClassRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	statusClasses := []StatusClass{Informational, Successful, Redirection, ClientError, ServerError}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random status class
		expectedClass := statusClasses[rng.Intn(len(statusClasses))]
		statusClassRule := expectedClass

		result := statusClassRule.Match(req)
		expected := req.Status/100 == int(expectedClass)

		if result != expected {
			t.Errorf("Test %d: StatusClass rule mismatch. Request status: %d, Rule class: %d, Expected %v, got %v",
				i, req.Status, expectedClass, expected, result)
		}
	}
}

// Test SentMoreThan rule
func TestSentMoreThan(t *testing.T) {
	req := createTestRequest()

	// Test pass: sent bytes is more than threshold
	sentMoreThanRule := SentMoreThan(500)

	if !sentMoreThanRule.Match(req) {
		t.Error("SentMoreThan rule should match when sent bytes is more than threshold")
	}

	// Test fail: sent bytes is not more than threshold
	sentMoreThanRule2 := SentMoreThan(2000)

	if sentMoreThanRule2.Match(req) {
		t.Error("SentMoreThan rule should not match when sent bytes is not more than threshold")
	}
}

func TestSentMoreThanRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random threshold
		threshold := rng.Int63n(10 * 1024 * 1024) // Up to 10MB
		sentMoreThanRule := SentMoreThan(threshold)

		result := sentMoreThanRule.Match(req)
		expected := req.Sent > threshold

		if result != expected {
			t.Errorf("Test %d: SentMoreThan rule mismatch. Request sent: %d, Rule threshold: %d, Expected %v, got %v",
				i, req.Sent, threshold, expected, result)
		}
	}
}

// Test SentLessThan rule
func TestSentLessThan(t *testing.T) {
	req := createTestRequest()

	// Test pass: sent bytes is less than threshold
	sentLessThanRule := SentLessThan(2000)

	if !sentLessThanRule.Match(req) {
		t.Error("SentLessThan rule should match when sent bytes is less than threshold")
	}

	// Test fail: sent bytes is not less than threshold
	sentLessThanRule2 := SentLessThan(500)

	if sentLessThanRule2.Match(req) {
		t.Error("SentLessThan rule should not match when sent bytes is not less than threshold")
	}
}

func TestSentLessThanRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random threshold
		threshold := rng.Int63n(10 * 1024 * 1024) // Up to 10MB
		sentLessThanRule := SentLessThan(threshold)

		result := sentLessThanRule.Match(req)
		expected := req.Sent < threshold

		if result != expected {
			t.Errorf("Test %d: SentLessThan rule mismatch. Request sent: %d, Rule threshold: %d, Expected %v, got %v",
				i, req.Sent, threshold, expected, result)
		}
	}
}

// Test TookLongerThan rule
func TestTookLongerThan(t *testing.T) {
	req := createTestRequest()

	// Test pass: duration is longer than threshold
	tookLongerThanRule := TookLongerThan(100 * time.Millisecond)

	if !tookLongerThanRule.Match(req) {
		t.Error("TookLongerThan rule should match when duration is longer than threshold")
	}

	// Test fail: duration is not longer than threshold
	tookLongerThanRule2 := TookLongerThan(200 * time.Millisecond)

	if tookLongerThanRule2.Match(req) {
		t.Error("TookLongerThan rule should not match when duration is not longer than threshold")
	}
}

func TestTookLongerThanRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random threshold
		threshold := time.Duration(rng.Int63n(60*1000)) * time.Millisecond // Up to 60 seconds
		tookLongerThanRule := TookLongerThan(threshold)

		result := tookLongerThanRule.Match(req)
		expected := req.Duration > threshold

		if result != expected {
			t.Errorf("Test %d: TookLongerThan rule mismatch. Request duration: %v, Rule threshold: %v, Expected %v, got %v",
				i, req.Duration, threshold, expected, result)
		}
	}
}

// Test TookShorterThan rule
func TestTookShorterThan(t *testing.T) {
	req := createTestRequest()

	// Test pass: duration is shorter than threshold
	tookShorterThanRule := TookShorterThan(200 * time.Millisecond)

	if !tookShorterThanRule.Match(req) {
		t.Error("TookShorterThan rule should match when duration is shorter than threshold")
	}

	// Test fail: duration is not shorter than threshold
	tookShorterThanRule2 := TookShorterThan(100 * time.Millisecond)

	if tookShorterThanRule2.Match(req) {
		t.Error("TookShorterThan rule should not match when duration is not shorter than threshold")
	}
}

func TestTookShorterThanRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random threshold
		threshold := time.Duration(rng.Int63n(60*1000)) * time.Millisecond // Up to 60 seconds
		tookShorterThanRule := TookShorterThan(threshold)

		result := tookShorterThanRule.Match(req)
		expected := req.Duration < threshold

		if result != expected {
			t.Errorf("Test %d: TookShorterThan rule mismatch. Request duration: %v, Rule threshold: %v, Expected %v, got %v",
				i, req.Duration, threshold, expected, result)
		}
	}
}

// Test Host rule
func TestHost(t *testing.T) {
	req := createTestRequest()

	// Test pass: host matches
	hostRule := Host("api.example.com")

	if !hostRule.Match(req) {
		t.Error("Host rule should match when host matches")
	}

	// Test fail: host doesn't match
	hostRule2 := Host("example.com")

	if hostRule2.Match(req) {
		t.Error("Host rule should not match when host doesn't match")
	}
}

func TestHostRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	hosts := []string{"example.com", "api.example.com", "www.google.com", "localhost", "192.168.1.1", "test.server.local"}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random host
		expectedHost := hosts[rng.Intn(len(hosts))]
		hostRule := Host(expectedHost)

		result := hostRule.Match(req)
		expected := req.Host == expectedHost

		if result != expected {
			t.Errorf("Test %d: Host rule mismatch. Request host: %q, Rule host: %q, Expected %v, got %v",
				i, req.Host, expectedHost, expected, result)
		}
	}
}

// Test HostSuffix rule
func TestHostSuffix(t *testing.T) {
	req := createTestRequest()

	// Test pass: host has the suffix
	hostSuffixRule := HostSuffix(".example.com")

	if !hostSuffixRule.Match(req) {
		t.Error("HostSuffix rule should match when host has the suffix")
	}

	// Test fail: host doesn't have the suffix
	hostSuffixRule2 := HostSuffix(".google.com")

	if hostSuffixRule2.Match(req) {
		t.Error("HostSuffix rule should not match when host doesn't have the suffix")
	}
}

func TestHostSuffixRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	suffixes := []string{".com", ".net", ".local", ".example.com", ".google.com", ".org"}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random suffix
		expectedSuffix := suffixes[rng.Intn(len(suffixes))]
		hostSuffixRule := HostSuffix(expectedSuffix)

		result := hostSuffixRule.Match(req)
		expected := len(req.Host) >= len(expectedSuffix) && req.Host[len(req.Host)-len(expectedSuffix):] == expectedSuffix

		if result != expected {
			t.Errorf("Test %d: HostSuffix rule mismatch. Request host: %q, Rule suffix: %q, Expected %v, got %v",
				i, req.Host, expectedSuffix, expected, result)
		}
	}
}

// Test HostKeyword rule
func TestHostKeyword(t *testing.T) {
	req := createTestRequest()

	// Test pass: host contains the keyword
	hostKeywordRule := HostKeyword("example")

	if !hostKeywordRule.Match(req) {
		t.Error("HostKeyword rule should match when host contains the keyword")
	}

	// Test fail: host doesn't contain the keyword
	hostKeywordRule2 := HostKeyword("google")

	if hostKeywordRule2.Match(req) {
		t.Error("HostKeyword rule should not match when host doesn't contain the keyword")
	}
}

func TestHostKeywordRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	keywords := []string{"example", "api", "google", "local", "test", "server", "cdn", "www"}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random keyword
		expectedKeyword := keywords[rng.Intn(len(keywords))]
		hostKeywordRule := HostKeyword(expectedKeyword)

		result := hostKeywordRule.Match(req)
		expected := false
		for j := 0; j <= len(req.Host)-len(expectedKeyword); j++ {
			if req.Host[j:j+len(expectedKeyword)] == expectedKeyword {
				expected = true
				break
			}
		}

		if result != expected {
			t.Errorf("Test %d: HostKeyword rule mismatch. Request host: %q, Rule keyword: %q, Expected %v, got %v",
				i, req.Host, expectedKeyword, expected, result)
		}
	}
}

// Test Agent rule
func TestAgent(t *testing.T) {
	req := createTestRequest()

	// Test pass: agent matches
	agentRule := Agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	if !agentRule.Match(req) {
		t.Error("Agent rule should match when agent matches")
	}

	// Test fail: agent doesn't match
	agentRule2 := Agent("curl/7.88.1")

	if agentRule2.Match(req) {
		t.Error("Agent rule should not match when agent doesn't match")
	}
}

func TestAgentRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

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

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random agent
		expectedAgent := agents[rng.Intn(len(agents))]
		agentRule := Agent(expectedAgent)

		result := agentRule.Match(req)
		expected := req.Agent == expectedAgent

		if result != expected {
			t.Errorf("Test %d: Agent rule mismatch. Request agent: %q, Rule agent: %q, Expected %v, got %v",
				i, req.Agent, expectedAgent, expected, result)
		}
	}
}

// Test AgentKeyword rule
func TestAgentKeyword(t *testing.T) {
	req := createTestRequest()

	// Test pass: agent contains the keyword
	agentKeywordRule := AgentKeyword("Windows")

	if !agentKeywordRule.Match(req) {
		t.Error("AgentKeyword rule should match when agent contains the keyword")
	}

	// Test fail: agent doesn't contain the keyword
	agentKeywordRule2 := AgentKeyword("Linux")

	if agentKeywordRule2.Match(req) {
		t.Error("AgentKeyword rule should not match when agent doesn't contain the keyword")
	}
}

func TestAgentKeywordRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const numTests = 100

	keywords := []string{"Mozilla", "Chrome", "Firefox", "Safari", "curl", "Windows", "Mac", "Linux", "iPhone", "Android", "AppleWebKit", "Gecko"}

	for i := 0; i < numTests; i++ {
		// Create random request
		req := createRandomRequest(rng)

		// Choose a random keyword
		expectedKeyword := keywords[rng.Intn(len(keywords))]
		agentKeywordRule := AgentKeyword(expectedKeyword)

		result := agentKeywordRule.Match(req)
		expected := false
		for j := 0; j <= len(req.Agent)-len(expectedKeyword); j++ {
			if req.Agent[j:j+len(expectedKeyword)] == expectedKeyword {
				expected = true
				break
			}
		}

		if result != expected {
			t.Errorf("Test %d: AgentKeyword rule mismatch. Request agent: %q, Rule keyword: %q, Expected %v, got %v",
				i, req.Agent, expectedKeyword, expected, result)
		}
	}
}
