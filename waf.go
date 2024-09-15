package gowaf

import (
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var logFile, _ = os.OpenFile("waf.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
var logger = log.New(logFile, "WAF_LOG: ", log.Ldate|log.Ltime|log.Lshortfile)

func logBlockReq(r *http.Request, reason string) {
	logger.Printf("Blocked request from %s: %s, URL: %s\n", r.RemoteAddr, reason, r.URL.String())
}

// Middleware to wrap around an http handler to use the WAF functionality so to check for sql injections, xss scripting, header attakcs, malicious code or files, etc...
func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inspecting the request for attacks and malicious code
		// if isMalRequest(r) {
		// 	http.Error(w, "Request Blocked", http.StatusForbidden)
		// 	return
		// }

		// SQL Injection and XSS detection
		if containsSQLInject(r.URL.RawQuery) || containsXSS(r.URL.RawQuery) || containsSQLInject(r.Form.Encode()) {
			logBlockReq(r, "SQLi/XSS attack detected")
			http.Error(w, "Blocked: SQLi/XSS detected", http.StatusForbidden)
			return
		}

		// Path Traversal detection
		if containsPathTraversal(r.URL.Path) {
			logBlockReq(r, "Path Traversal attack detected")
			http.Error(w, "Blocked: Path Traversal detected", http.StatusForbidden)
			return
		}

		// // CSRF protection for POST requests
		// if r.Method == "POST" && !validateCSRFToken(r) {
		// 	logBlockedRequest(r, "Invalid CSRF token")
		// 	http.Error(w, "Blocked: Invalid CSRF token", http.StatusForbidden)
		// 	return
		// }

		// Rate limiting: block excessive requests
		if rateLimitExceeded(r) {
			logBlockReq(r, "Rate limit exceeded")
			http.Error(w, "Blocked: Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Check whether a request has malicious code / patterns in it
// func isMalRequest(r *http.Request) bool {
// 	err := r.ParseForm()
// 	if err != nil {
// 		log.Println("Problem parsing the forms in the first place to check for malicious code: ", err)
// 		return true
// 	}
// 	return containsSQLInject(r.URL.RawQuery) || containsXSS(r.URL.RawQuery) || containsSQLInject(r.Form.Encode())
// }

// Trying to detect possible SQL injection in the query
func containsSQLInject(query string) bool {
	sqlPatterns := []string{
		`(?i)(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b)`, // SQL keywords
		`'|"|;|--`,                           // SQL characters
		`(\bOR\b|\bAND\b).*(\b=\b|\bLIKE\b)`, // Logical operators
	}

	for _, pattern := range sqlPatterns {
		matched, _ := regexp.MatchString(pattern, query)
		if matched {
			log.Println("SQL Injection detected in query:", query)
			return true
		}
	}
	return false
}

// Trying to detect possible XSS
func containsXSS(query string) bool {
	xssPatterns := []string{"<script>", "onerror=", "onload=", "<iframe>", "javascript:"}
	for _, p := range xssPatterns {
		if strings.Contains(query, p) {
			log.Println("XSS problem detected in query: ", query)
			return true
		}
	}
	return false
}

func containsPathTraversal(query string) bool {
	traversalPatterns := `(\.\./|\.\.\\)` // Common path traversal sequences

	matched, _ := regexp.MatchString(traversalPatterns, query)
	if matched {
		log.Println("Path traversal attempt detected:", query)
		return true
	}
	return false
}

// Should also have some CSRF token validation but I dont know if it is what I want to implement for now

var reqCount = make(map[string]int)
var mu sync.Mutex

func rateLimitExceeded(r *http.Request) bool {
	ip := r.RemoteAddr
	mu.Lock()
	reqCount[ip]++
	mu.Unlock()

	go func() {
		time.Sleep(time.Minute * 1)
		mu.Lock()
		reqCount[ip] = 0
		mu.Unlock()
	}()

	if reqCount[ip] > 100 {
		log.Println("Rate limit is set to 100 requests per minute, you exceeded that")
		return true
	}
	return false
}
