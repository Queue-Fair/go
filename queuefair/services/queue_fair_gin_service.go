package queuefair

import (
	"net/http"
	"github.com/gin-gonic/gin"
)

// QueueFairGinService wraps a gin.Context for use by the QueueFairAdapter.
type QueueFairGinService struct {
	Ctx      *gin.Context
	secure bool
}

// NewQueueFairGinService creates a new QueueFairGinService from a Gin context.
func NewQueueFairGinService(c *gin.Context, isSecure bool) *QueueFairGinService {
	return &QueueFairGinService{
		Ctx:      c,
		secure: isSecure,
	}
}

// SetCookie sets a cookie on the Gin context's response.
func (s *QueueFairGinService) SetCookie(name string, value string, lifetimeSeconds int, domain string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		MaxAge:   lifetimeSeconds,
		Secure:   s.secure,
		HttpOnly: false,
		SameSite: http.SameSiteNoneMode, // Required for cross-origin in many cases
	}
	http.SetCookie(s.Ctx.Writer, cookie)
}

// Redirect issues a 302 redirect.
func (s *QueueFairGinService) Redirect(location string) {
	s.Ctx.Header("Location", location)
	s.Ctx.Status(http.StatusFound)
	s.Ctx.Abort()
}

// GetCookie retrieves a cookie value.
func (s *QueueFairGinService) GetCookie(name string) string {
	cookie, err := s.Ctx.Request.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// AddHeader adds a header to the Gin context.
func (s *QueueFairGinService) AddHeader(name string, value string) {
	s.Ctx.Writer.Header().Add(name, value)
}

func (s *QueueFairGinService) IsSecure() bool {
	return s.secure
}