package session

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"github.com/owaspattacksimulator/pkg/httpx"
)

// SessionManager manages browser sessions
type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
}

// Session represents a browser session
type Session struct {
	ID        string
	Target    string
	Client    *httpx.Client
	Jar       *cookiejar.Jar
	Headers   map[string]string
	Storage   map[string]interface{}
	CreatedAt time.Time
	mu        sync.RWMutex
}

// NewSession creates a new session
func (sm *SessionManager) NewSession(target string, timeout time.Duration) (*Session, error) {
	// Create cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %v", err)
	}

	// Create HTTP client with cookie jar
	client := httpx.NewClient(timeout)

	// Create session
	session := &Session{
		ID:        generateSessionID(),
		Target:    target,
		Client:    client,
		Jar:       jar,
		Headers:   make(map[string]string),
		Storage:   make(map[string]interface{}),
		CreatedAt: time.Now(),
	}

	// Add default headers
	session.Headers["User-Agent"] = "OWASPAttackSimulator/1.0"
	session.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	session.Headers["Accept-Language"] = "en-US,en;q=0.5"
	session.Headers["Accept-Encoding"] = "gzip, deflate"
	session.Headers["Connection"] = "keep-alive"

	// Store session
	sm.mutex.Lock()
	sm.sessions[session.ID] = session
	sm.mutex.Unlock()

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	session, exists := sm.sessions[id]
	return session, exists
}

// CloseSession closes and removes a session
func (sm *SessionManager) CloseSession(id string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if _, exists := sm.sessions[id]; !exists {
		return fmt.Errorf("session not found: %s", id)
	}

	delete(sm.sessions, id)
	return nil
}

// ListSessions returns all active sessions
func (sm *SessionManager) ListSessions() []*Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// Navigate navigates to a URL
func (s *Session) Navigate(ctx context.Context, urlStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("🌐 Navigating to: %s\n", urlStr)

	// Create request
	req := &httpx.Request{
		Method:  "GET",
		URL:     urlStr,
		Headers: s.Headers,
	}

	// Perform request
	resp, err := s.Client.DoRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("navigation failed: %v", err)
	}

	fmt.Printf("✅ Navigation successful (Status: %d)\n", resp.StatusCode)
	return nil
}

// FillForm fills a form with data
func (s *Session) FillForm(ctx context.Context, urlStr string, formData map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("📝 Filling form at: %s\n", urlStr)

	// Create request with form data
	req := &httpx.Request{
		Method:  "POST",
		URL:     urlStr,
		Headers: s.Headers,
		Params:  formData,
	}

	// Add form content type
	req.Headers["Content-Type"] = "application/x-www-form-urlencoded"

	// Perform request
	resp, err := s.Client.DoRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("form submission failed: %v", err)
	}

	fmt.Printf("✅ Form submitted successfully (Status: %d)\n", resp.StatusCode)
	return nil
}

// ClickElement simulates clicking an element
func (s *Session) ClickElement(ctx context.Context, urlStr string, selector string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("🖱️  Clicking element: %s at %s\n", selector, urlStr)

	// For now, just navigate to the URL
	// In a real implementation, this would use Playwright to click elements
	req := &httpx.Request{
		Method:  "GET",
		URL:     urlStr,
		Headers: s.Headers,
	}

	resp, err := s.Client.DoRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("click failed: %v", err)
	}

	fmt.Printf("✅ Click successful (Status: %d)\n", resp.StatusCode)
	return nil
}

// SetCookie sets a cookie
func (s *Session) SetCookie(name, value, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	parsedURL, err := url.Parse(s.Target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %v", err)
	}

	cookie := &http.Cookie{
		Name:   name,
		Value:  value,
		Domain: domain,
		Path:   "/",
	}

	s.Jar.SetCookies(parsedURL, []*http.Cookie{cookie})
	fmt.Printf("🍪 Cookie set: %s=%s\n", name, value)
	return nil
}

// GetCookies returns all cookies for the session
func (s *Session) GetCookies() []*http.Cookie {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parsedURL, err := url.Parse(s.Target)
	if err != nil {
		return nil
	}

	return s.Jar.Cookies(parsedURL)
}

// SetHeader sets a header
func (s *Session) SetHeader(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Headers[name] = value
	fmt.Printf("📋 Header set: %s: %s\n", name, value)
}

// GetHeader gets a header value
func (s *Session) GetHeader(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.Headers[name]
}

// SetStorage sets a value in session storage
func (s *Session) SetStorage(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Storage[key] = value
	fmt.Printf("💾 Storage set: %s = %v\n", key, value)
}

// GetStorage gets a value from session storage
func (s *Session) GetStorage(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, exists := s.Storage[key]
	return value, exists
}

// GetInfo returns session information
func (s *Session) GetInfo() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"id":         s.ID,
		"target":     s.Target,
		"created_at": s.CreatedAt,
		"headers":    s.Headers,
		"cookies":    len(s.GetCookies()),
		"storage":    len(s.Storage),
	}
}

// generateSessionID generates a unique session ID
func generateSessionID() string {
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}
