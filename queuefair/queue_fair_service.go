package queuefair

// QueueFairService defines behavior expected by the adapter.
type QueueFairService interface {
	SetCookie(name, value string, lifetimeSeconds int, domain string)
	Redirect(location string)
	GetCookie(name string) string
	AddHeader(name, value string)
	IsSecure() bool
}