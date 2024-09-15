package gowaf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestWAFMiddleware(t *testing.T) {

	// Test handler that return "OK"
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// wrap it in the waf middleware
	handler := WAFMiddleware(testHandler)

	// Test with a good request
	req := httptest.NewRequest("GET", "http://example.com/?q=hello", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", rr.Code)
	}

	// Test with a malicious request
	// Properly escape the SQL injection payload
	query := url.QueryEscape("' OR 1=1--")
	req = httptest.NewRequest("GET", "/?q="+query, nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status Forbidden, got %v", rr.Code)
	}
}

func TestWAFMiddleware_XSS(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := WAFMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/?q=<script>alert('XSS')</script>", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status Forbidden, got %v", rr.Code)
	}
}

func TestWAFMiddleware_SQLInjection(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := WAFMiddleware(testHandler)

	// Properly escape the SQL injection payload
	query := url.QueryEscape("' OR 1=1--")
	req := httptest.NewRequest("GET", "/?q="+query, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status Forbidden, got %v because of them escaping the query injection", rr.Code)
	}

	// Clean request
	req = httptest.NewRequest("GET", "/?q=hello", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", rr.Code)
	}
}
