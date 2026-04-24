// Package server implements the DNS tunnel server.
package server

import (
	"sync"
	"time"
)

// Session represents a connected client.
type Session struct {
	ID        byte
	CreatedAt time.Time
	LastSeen  time.Time
	TuneSize  int // negotiated TXT response size (255, 512, or 1000)

	mu sync.Mutex

	// Transfer management for reliable delivery
	Transfers *TransferManager

	// Upload state
	UploadFile  string // current upload filename (empty = no active upload)
	UploadBytes int    // bytes received so far

	// Reverse shell bridge
	RShell *rshellBridge

	// SOCKS5 proxy bridge
	Socks5 *socks5Bridge

	// Deduplication: cache responses by request counter.
	// DNS resolvers may retry requests or send to multiple upstreams.
	// If we see the same counter again, return the cached response.
	responseCache map[uint32][]byte // counter → wire-format response
	seenCounters  map[uint32]bool
}

// isDuplicate returns true if this request counter was already processed.
// Used for state-mutating commands (data, upload) to prevent side effects.
func (s *Session) isDuplicate(counter uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seenCounters == nil {
		s.seenCounters = make(map[uint32]bool)
	}
	if s.seenCounters[counter] {
		return true
	}
	s.seenCounters[counter] = true
	if len(s.seenCounters) > 2000 {
		threshold := counter - 1000
		for k := range s.seenCounters {
			if k < threshold {
				delete(s.seenCounters, k)
			}
		}
	}
	return false
}

// CacheResponse stores the wire-format response for a request counter.
func (s *Session) CacheResponse(counter uint32, wireData []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.responseCache == nil {
		s.responseCache = make(map[uint32][]byte)
	}
	s.responseCache[counter] = wireData
	// Prune old entries
	if len(s.responseCache) > 200 {
		threshold := counter - 100
		for k := range s.responseCache {
			if k < threshold {
				delete(s.responseCache, k)
			}
		}
	}
}

// GetCachedResponse returns a previously cached response, or nil if not found.
func (s *Session) GetCachedResponse(counter uint32) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.responseCache == nil {
		return nil
	}
	return s.responseCache[counter]
}

// SessionManager manages client sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[byte]*Session
	nextID   byte
}

// NewSessionManager creates a new session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[byte]*Session),
		nextID:   1, // 0 is reserved for unassigned
	}
}

// NewSession creates and registers a new client session.
func (sm *SessionManager) NewSession() (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	startID := sm.nextID
	for {
		if _, exists := sm.sessions[sm.nextID]; !exists {
			break
		}
		sm.nextID++
		if sm.nextID > 63 {
			sm.nextID = 1
		}
		if sm.nextID == startID {
			return nil, ErrMaxClients
		}
	}

	s := &Session{
		ID:        sm.nextID,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		TuneSize:  255,
		Transfers: NewTransferManager(),
	}
	sm.sessions[s.ID] = s
	sm.nextID++
	if sm.nextID > 63 {
		sm.nextID = 1
	}
	return s, nil
}

// Get returns a session by ID.
func (sm *SessionManager) Get(id byte) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[id]
}

// Remove removes a session.
func (sm *SessionManager) Remove(id byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, id)
}

var ErrMaxClients = &maxClientsError{}

type maxClientsError struct{}

func (e *maxClientsError) Error() string { return "maximum number of clients reached" }
