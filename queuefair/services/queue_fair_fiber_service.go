// queue_fair_fiber_service.go
package queuefair

import (
	"time"
	"github.com/gofiber/fiber/v2"
)

type QueueFairFiberService struct {
	Ctx      *fiber.Ctx
	secure bool
}

func NewQueueFairFiberService(c *fiber.Ctx, isSecure bool) *QueueFairFiberService {
	return &QueueFairFiberService{
		Ctx:      c,
		secure: isSecure,
	}
}

func (s *QueueFairFiberService) SetCookie(name, value string, lifetimeSeconds int, domain string) {
	s.Ctx.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		MaxAge:   lifetimeSeconds,
		Secure:   s.secure,
		HTTPOnly: false,
		SameSite: "None",
	})
}

func (s *QueueFairFiberService) Redirect(location string) {
	s.Ctx.Status(fiber.StatusFound).Location(location).Send(nil)
}

func (s *QueueFairFiberService) GetCookie(name string) string {
	val := s.Ctx.Cookies(name,"")
	return val
}

func (s *QueueFairFiberService) AddHeader(name, value string) {
	s.Ctx.Set(name, value)
}

func (s *QueueFairFiberService) IsSecure() bool {
	return s.secure
}
