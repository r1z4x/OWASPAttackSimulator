package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owaspchecker/internal/common"
)

// SQLiteStore implements storage using SQLite
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLite store
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &SQLiteStore{db: db}
	if err := store.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	return store, nil
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// initTables creates the necessary tables
func (s *SQLiteStore) initTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS requests (
			id TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			method TEXT NOT NULL,
			headers TEXT,
			body TEXT,
			content_type TEXT,
			variant TEXT,
			timestamp DATETIME NOT NULL,
			source TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS responses (
			id TEXT PRIMARY KEY,
			request_id TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			headers TEXT,
			body TEXT,
			content_type TEXT,
			size INTEGER,
			duration INTEGER,
			timestamp DATETIME NOT NULL,
			hash TEXT,
			FOREIGN KEY (request_id) REFERENCES requests (id)
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			request_id TEXT NOT NULL,
			response_id TEXT NOT NULL,
			type TEXT NOT NULL,
			category TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			evidence TEXT,
			payload TEXT,
			url TEXT NOT NULL,
			method TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			FOREIGN KEY (request_id) REFERENCES requests (id),
			FOREIGN KEY (response_id) REFERENCES responses (id)
		)`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// StoreRequest stores a recorded request
func (s *SQLiteStore) StoreRequest(req *common.RecordedRequest) error {
	headersJSON, err := json.Marshal(req.Headers)
	if err != nil {
		return fmt.Errorf("failed to marshal headers: %w", err)
	}

	query := `INSERT INTO requests (id, url, method, headers, body, content_type, variant, timestamp, source)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.Exec(query, req.ID, req.URL, req.Method, string(headersJSON), req.Body, req.ContentType, req.Variant, req.Timestamp, req.Source)
	if err != nil {
		return fmt.Errorf("failed to store request: %w", err)
	}

	return nil
}

// StoreResponse stores a recorded response
func (s *SQLiteStore) StoreResponse(resp *common.RecordedResponse) error {
	headersJSON, err := json.Marshal(resp.Headers)
	if err != nil {
		return fmt.Errorf("failed to marshal headers: %w", err)
	}

	query := `INSERT INTO responses (id, request_id, status_code, headers, body, content_type, size, duration, timestamp, hash)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.Exec(query, resp.ID, resp.RequestID, resp.StatusCode, string(headersJSON), resp.Body, resp.ContentType, resp.Size, resp.Duration.Milliseconds(), resp.Timestamp, resp.Hash)
	if err != nil {
		return fmt.Errorf("failed to store response: %w", err)
	}

	return nil
}

// StoreFinding stores a finding
func (s *SQLiteStore) StoreFinding(finding *common.Finding) error {
	query := `INSERT INTO findings (id, request_id, response_id, type, category, severity, title, description, evidence, payload, url, method, timestamp)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query, finding.ID, finding.RequestID, finding.ResponseID, finding.Type, finding.Category, finding.Severity, finding.Title, finding.Description, finding.Evidence, finding.Payload, finding.URL, finding.Method, finding.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to store finding: %w", err)
	}

	return nil
}

// GetRequests retrieves all requests
func (s *SQLiteStore) GetRequests() ([]common.RecordedRequest, error) {
	query := `SELECT id, url, method, headers, body, content_type, variant, timestamp, source FROM requests ORDER BY timestamp`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query requests: %w", err)
	}
	defer rows.Close()

	var requests []common.RecordedRequest
	for rows.Next() {
		var req common.RecordedRequest
		var headersJSON string
		err := rows.Scan(&req.ID, &req.URL, &req.Method, &headersJSON, &req.Body, &req.ContentType, &req.Variant, &req.Timestamp, &req.Source)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}

		if err := json.Unmarshal([]byte(headersJSON), &req.Headers); err != nil {
			return nil, fmt.Errorf("failed to unmarshal headers: %w", err)
		}

		requests = append(requests, req)
	}

	return requests, nil
}

// GetResponses retrieves all responses
func (s *SQLiteStore) GetResponses() ([]common.RecordedResponse, error) {
	query := `SELECT id, request_id, status_code, headers, body, content_type, size, duration, timestamp, hash FROM responses ORDER BY timestamp`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query responses: %w", err)
	}
	defer rows.Close()

	var responses []common.RecordedResponse
	for rows.Next() {
		var resp common.RecordedResponse
		var headersJSON string
		var durationMs int64
		err := rows.Scan(&resp.ID, &resp.RequestID, &resp.StatusCode, &headersJSON, &resp.Body, &resp.ContentType, &resp.Size, &durationMs, &resp.Timestamp, &resp.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to scan response: %w", err)
		}

		resp.Duration = time.Duration(durationMs) * time.Millisecond
		if err := json.Unmarshal([]byte(headersJSON), &resp.Headers); err != nil {
			return nil, fmt.Errorf("failed to unmarshal headers: %w", err)
		}

		responses = append(responses, resp)
	}

	return responses, nil
}

// GetFindings retrieves all findings
func (s *SQLiteStore) GetFindings() ([]common.Finding, error) {
	query := `SELECT id, request_id, response_id, type, category, severity, title, description, evidence, payload, url, method, timestamp FROM findings ORDER BY timestamp`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []common.Finding
	for rows.Next() {
		var finding common.Finding
		err := rows.Scan(&finding.ID, &finding.RequestID, &finding.ResponseID, &finding.Type, &finding.Category, &finding.Severity, &finding.Title, &finding.Description, &finding.Evidence, &finding.Payload, &finding.URL, &finding.Method, &finding.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}

		findings = append(findings, finding)
	}

	return findings, nil
}
