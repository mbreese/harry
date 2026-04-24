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

	mu       sync.Mutex
	outQueue []byte // data queued for sending to the client

	// Upload state
	UploadFile  string // current upload filename (empty = no active upload)
	UploadBytes int    // bytes received so far
}

// QueueData appends data to the client's outbound queue.
func (s *Session) QueueData(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outQueue = append(s.outQueue, data...)
}

// Dequeue removes up to maxBytes from the outbound queue.
// Returns the data and whether more remains.
func (s *Session) Dequeue(maxBytes int) (data []byte, more bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.outQueue) == 0 {
		return nil, false
	}

	if maxBytes >= len(s.outQueue) {
		data = s.outQueue
		s.outQueue = nil
		return data, false
	}

	data = make([]byte, maxBytes)
	copy(data, s.outQueue[:maxBytes])
	s.outQueue = s.outQueue[maxBytes:]
	return data, true
}

// QueueLen returns the current outbound queue length.
func (s *Session) QueueLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.outQueue)
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

	// Find next available ID (1-63)
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
		TuneSize:  255, // start conservative
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
