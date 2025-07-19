package queuefair

import (
	"time"
	"sync"
	"fmt"
)

type SettingsCache struct {
	settings   map[string]interface{}
	lastLoaded time.Time
	mu         sync.RWMutex
	url        string
	lifetime   time.Duration // How long before refresh
}

// NewSettingsCache initializes the cache.
func NewSettingsCache(settingsURL string, lifetimeMinutes int) *SettingsCache {
	return &SettingsCache{
		url:      settingsURL,
		lifetime: time.Duration(lifetimeMinutes) * time.Minute,
	}
}

// Get returns cached settings, refreshing if needed.
func (sc *SettingsCache) Get(a *QueueFairAdapter) (map[string]interface{}, error) {
	sc.mu.RLock()
	if time.Since(sc.lastLoaded) < sc.lifetime && sc.settings != nil {
		if a.D { a.log("Using cached settings") }
		defer sc.mu.RUnlock()
		return sc.settings, nil
	}
	sc.mu.RUnlock()

	// Needs refresh
	return sc.refresh(a)
}

// refresh fetches fresh settings from the server.
func (sc *SettingsCache) refresh(a *QueueFairAdapter) (map[string]interface{}, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if a.D { a.log("Getting settings from server") }

	// If another goroutine already refreshed, skip
	if time.Since(sc.lastLoaded) < sc.lifetime && sc.settings != nil {
		return sc.settings, nil
	}

	resp := a.UrlToJSON(sc.url)

	if(resp == nil) {
		return nil, fmt.Errorf("Settings not downloaded")
	}

	sc.settings = resp
	sc.lastLoaded = time.Now()
	return sc.settings, nil
}
