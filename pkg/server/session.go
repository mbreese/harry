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
	UploadFile     string // current upload filename (empty = no active upload)
	UploadBytes    int    // bytes received so far
	UploadExpSize  uint32 // expected file size
	UploadExpHash  [20]byte // expected SHA1 hash

	// Deduplication: track seen request counters to detect DNS retries.
	// DNS resolvers may retry any request, and retries can arrive
	// out of order (after newer requests have been processed).
	seenCounters map[uint32]bool
}

// isDuplicate returns true if this request counter was already processed.
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
	// Keep the map from growing unbounded — prune old entries
	// when it gets large. Counters are monotonically increasing,
	// so anything more than 1000 behind the current is safe to drop.
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
