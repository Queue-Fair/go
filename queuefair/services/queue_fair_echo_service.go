// queue_fair_echo_service.go
package queuefair

import (
	"net/http"
	"github.com/labstack/echo/v4"
)

type QueueFairEchoService struct {
	Ctx      echo.Context
	secure bool
}

func NewQueueFairEchoService(c echo.Context, isSecure bool) *QueueFairEchoService {
	return &QueueFairEchoService{
		Ctx:      c,
		secure: isSecure,
	}
}

func (s *QueueFairEchoService) SetCookie(name, value string, lifetimeSeconds int, domain string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		MaxAge:   lifetimeSeconds,
		Secure:   s.secure,
		HttpOnly: false,
		SameSite: http.SameSiteNoneMode,
	}
	s.Ctx.SetCookie(cookie)
}

func (s *QueueFairEchoService) Redirect(location string) {
	s.Ctx.Response().Header().Set("Location", location)
	s.Ctx.Response().WriteHeader(http.StatusFound)
}

func (s *QueueFairEchoService) GetCookie(name string) string {
	cookie, err := s.Ctx.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (s *QueueFairEchoService) AddHeader(name, value string) {
	s.Ctx.Response().Header().Add(name, value)
}

func (s *QueueFairEchoService) IsSecure() bool {
	return s.secure
}
