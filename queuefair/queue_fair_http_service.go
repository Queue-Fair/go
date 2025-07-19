package queuefair

import (
	"net/http"
	"time"
)

// QueueFairHTTPService is the net/http implementation of QueueFairService.
type QueueFairHTTPService struct {
	Request    *http.Request
	Writer     http.ResponseWriter
	secure     bool
	respStatus int
	headers    http.Header
}

func NewQueueFairHTTPService(w http.ResponseWriter, r *http.Request, isSecure bool) *QueueFairHTTPService {
	return &QueueFairHTTPService{
		Request: r,
		Writer:  w,
		secure:  isSecure,
		headers: make(http.Header),
	}
}

func (s *QueueFairHTTPService) SetCookie(name, value string, lifetimeSeconds int, domain string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		MaxAge:   lifetimeSeconds,
		Secure:   s.secure,
		HttpOnly: false,
	}
	if s.secure {
		c.SameSite = http.SameSiteNoneMode
	}
	c.Expires = time.Now().Add(time.Duration(lifetimeSeconds) * time.Second)
	http.SetCookie(s.Writer, c)
}

func (s *QueueFairHTTPService) Redirect(location string) {
	s.AddHeader("Location", location)
	s.Writer.WriteHeader(http.StatusFound)
}

func (s *QueueFairHTTPService) GetCookie(name string) string {
	c, err := s.Request.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *QueueFairHTTPService) AddHeader(name, value string) {
	s.Writer.Header().Set(name, value)
}

func (s *QueueFairHTTPService) IsSecure() bool {
	return s.secure
}