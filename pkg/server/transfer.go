package server

import (
	"sync"
)

// Transfer represents a chunked data transfer (download or response).
// Chunks are indexed and retained until the transfer completes,
// allowing retransmission of any chunk.
type Transfer struct {
	ID         uint16
	Chunks     [][]byte // indexed chunks of plaintext data
	TotalChunks uint16
}

// TransferManager manages active transfers per session.
type TransferManager struct {
	mu        sync.Mutex
	nextID    uint16
	transfers map[uint16]*Transfer
}

// NewTransferManager creates a new transfer manager.
func NewTransferManager() *TransferManager {
	return &TransferManager{
		transfers: make(map[uint16]*Transfer),
	}
}

// NewTransfer creates a new transfer, splitting data into chunks of maxSize.
// Returns the transfer and sends the first chunk via the returned values.
func (tm *TransferManager) NewTransfer(data []byte, maxChunkSize int) *Transfer {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.nextID++
	id := tm.nextID

	var chunks [][]byte
	for len(data) > 0 {
		end := maxChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, end)
		copy(chunk, data[:end])
		chunks = append(chunks, chunk)
		data = data[end:]
	}

	// Handle empty data — still create a transfer with one empty chunk
	if len(chunks) == 0 {
		chunks = [][]byte{{}}
	}

	t := &Transfer{
		ID:          id,
		Chunks:      chunks,
		TotalChunks: uint16(len(chunks)),
	}
	tm.transfers[id] = t
	return t
}

// Get returns a transfer by ID.
func (tm *TransferManager) Get(id uint16) *Transfer {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.transfers[id]
}

// Remove removes a completed transfer.
func (tm *TransferManager) Remove(id uint16) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.transfers, id)
}

// GetChunk returns a specific chunk from a transfer.
func (t *Transfer) GetChunk(index uint16) []byte {
	if int(index) >= len(t.Chunks) {
		return nil
	}
	return t.Chunks[index]
}
