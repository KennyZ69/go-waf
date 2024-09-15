package gowaf

import (
	"log"
	"net/http"
	"strings"
)

// Middleware to wrap around an http handler to use the WAF functionality
func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inspecting the request for attacks and malicious code
		if isMalRequest(r) {
			http.Error(w, "Request Blocked", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Check whether a request has malicious code / patterns in it
func isMalRequest(r *http.Request) bool {
	err := r.ParseForm()
	if err != nil {
		log.Println("Problem parsing the forms in the first place to check for malicious code: ", err)
		return true
	}
	return containsSQLInject(r.URL.RawQuery) || containsXSS(r.URL.RawQuery) || containsSQLInject(r.Form.Encode())
}

// Trying to detect possible SQL injection in the input
func containsSQLInject(query string) bool {
	sqlPatterns := []string{"\"", ";--", " OR ", " AND "}
	for _, p := range sqlPatterns {
		if strings.Contains(query, p) {
			log.Println("SQL INJECTION detected in input: ", query)
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
