package common

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Request represents an HTTP request
type Request struct {
	ID          string            `json:"id"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        []byte            `json:"body"`
	ContentType string            `json:"content_type"`
	Variant     string            `json:"variant"`
	Timestamp   time.Time         `json:"timestamp"`
	Raw         string            `json:"raw"` // Raw HTTP request like Burp Suite
}

// Response represents an HTTP response
type Response struct {
	ID          string            `json:"id"`
	RequestID   string            `json:"request_id"`
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	BodySnippet string            `json:"body_snippet"`
	BodyHash    string            `json:"body_hash"`
	Duration    time.Duration     `json:"duration"`
	Timestamp   time.Time         `json:"timestamp"`
	RedirectURL string            `json:"redirect_url,omitempty"`
	Raw         string            `json:"raw"` // Raw HTTP response like Burp Suite
}

// Finding represents a security finding
type Finding struct {
	ID         string            `json:"id"`
	RequestID  string            `json:"request_id"`
	Category   string            `json:"category"`
	Title      string            `json:"title"`
	Evidence   string            `json:"evidence"`
	Tags       map[string]string `json:"tags"`
	Timestamp  time.Time         `json:"timestamp"`
	Confidence float64           `json:"confidence"`
}

// Session represents a browser session
type Session struct {
	ID        string            `json:"id"`
	TargetURL string            `json:"target_url"`
	Cookies   map[string]string `json:"cookies"`
	Headers   map[string]string `json:"headers"`
	CSRFToken string            `json:"csrf_token"`
	Storage   map[string]string `json:"storage"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Event represents a system event
type Event struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"session_id"`
	StepID    string                 `json:"step_id"`
	Kind      string                 `json:"kind"`
	Payload   map[string]interface{} `json:"payload"`
	Timestamp time.Time              `json:"timestamp"`
}

// Artifact represents a file or data artifact
type Artifact struct {
	ID        string            `json:"id"`
	SessionID string            `json:"session_id"`
	StepID    string            `json:"step_id"`
	Kind      string            `json:"kind"`
	Path      string            `json:"path"`
	Data      []byte            `json:"data"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
}

// Step represents a scenario step
type Step struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Inputs      map[string]string `json:"inputs"`
	Guards      map[string]string `json:"guards"`
	Effects     map[string]string `json:"effects"`
	Timeout     time.Duration     `json:"timeout"`
	RetryCount  int               `json:"retry_count"`
	OnSuccess   []string          `json:"on_success"`
	OnFailure   []string          `json:"on_failure"`
	Children    []*Step           `json:"children,omitempty"`
	Metadata    map[string]string `json:"metadata"`
}

// StepStatus represents the status of a step execution
type StepStatus struct {
	StepID       string                 `json:"step_id"`
	Status       string                 `json:"status"`
	ErrorMessage string                 `json:"error_message"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  time.Time              `json:"completed_at"`
	Results      map[string]interface{} `json:"results"`
}

// Scenario represents a complete scenario
type Scenario struct {
	Version     string            `json:"version"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Variables   map[string]string `json:"variables"`
	Steps       []*Step           `json:"steps"`
	Metadata    map[string]string `json:"metadata"`
}

// ExecutionConfig represents scenario execution configuration
type ExecutionConfig struct {
	Workers       int           `json:"workers"`
	Timeout       time.Duration `json:"timeout"`
	DryRun        bool          `json:"dry_run"`
	EnabledSteps  []string      `json:"enabled_steps"`
	DisabledSteps []string      `json:"disabled_steps"`
}

// MutationConfig represents request mutation configuration
type MutationConfig struct {
	Methods           []string          `json:"methods"`
	Bodies            []string          `json:"bodies"`
	PayloadSets       []string          `json:"payload_sets"`
	MaxVariantsPerReq int               `json:"max_variants_per_req"`
	Options           map[string]string `json:"options"`
}

// CheckConfig represents security check configuration
type CheckConfig struct {
	Enabled    []string          `json:"enabled"`
	Thresholds map[string]string `json:"thresholds"`
	Options    map[string]string `json:"options"`
}

// Store interface for data persistence
type Store interface {
	// Request/Response operations
	SaveRequest(ctx context.Context, req *Request) error
	SaveResponse(ctx context.Context, resp *Response) error
	GetRequest(ctx context.Context, id string) (*Request, error)
	GetResponse(ctx context.Context, id string) (*Response, error)
	ListRequests(ctx context.Context, filter map[string]string) ([]*Request, error)
	ListResponses(ctx context.Context, filter map[string]string) ([]*Response, error)

	// Finding operations
	SaveFinding(ctx context.Context, finding *Finding) error
	GetFinding(ctx context.Context, id string) (*Finding, error)
	ListFindings(ctx context.Context, filter map[string]string) ([]*Finding, error)
	GetFindingsByCategory(ctx context.Context, category string) ([]*Finding, error)

	// Session operations
	SaveSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	DeleteSession(ctx context.Context, id string) error

	// Event operations
	SaveEvent(ctx context.Context, event *Event) error
	GetEvents(ctx context.Context, filter map[string]string) ([]*Event, error)
	StreamEvents(ctx context.Context, filter map[string]string) (<-chan *Event, error)

	// Artifact operations
	SaveArtifact(ctx context.Context, artifact *Artifact) error
	GetArtifact(ctx context.Context, id string) (*Artifact, error)
	ListArtifacts(ctx context.Context, filter map[string]string) ([]*Artifact, error)

	// Utility operations
	Vacuum(ctx context.Context) error
	GetStats(ctx context.Context) (map[string]interface{}, error)
	Close() error
}

// Engine interface for attack execution
type Engine interface {
	// Queue management
	PushJob(ctx context.Context, job *AttackJob) error
	CancelJob(ctx context.Context, jobID string) error
	GetJobStatus(ctx context.Context, jobID string) (*JobStatus, error)

	// Execution control
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Pause(ctx context.Context) error
	Resume(ctx context.Context) error

	// Metrics
	GetMetrics(ctx context.Context) (*EngineMetrics, error)
}

// AttackJob represents a job to be executed by the engine
type AttackJob struct {
	ID          string            `json:"id"`
	SessionID   string            `json:"session_id"`
	Target      *Request          `json:"target"`
	Mutation    *MutationConfig   `json:"mutation"`
	Checks      *CheckConfig      `json:"checks"`
	Workers     int               `json:"workers"`
	RateLimit   string            `json:"rate_limit"`
	Timeout     time.Duration     `json:"timeout"`
	RetryPolicy *RetryPolicy      `json:"retry_policy"`
	Metadata    map[string]string `json:"metadata"`
}

// JobStatus represents the status of an attack job
type JobStatus struct {
	JobID         string    `json:"job_id"`
	Status        string    `json:"status"`
	Progress      float64   `json:"progress"`
	TotalJobs     int       `json:"total_jobs"`
	CompletedJobs int       `json:"completed_jobs"`
	FailedJobs    int       `json:"failed_jobs"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	Error         string    `json:"error"`
}

// RetryPolicy represents retry configuration
type RetryPolicy struct {
	MaxRetries   int           `json:"max_retries"`
	BackoffDelay time.Duration `json:"backoff_delay"`
	MaxDelay     time.Duration `json:"max_delay"`
	Jitter       bool          `json:"jitter"`
}

// EngineMetrics represents engine performance metrics
type EngineMetrics struct {
	ActiveJobs     int     `json:"active_jobs"`
	QueuedJobs     int     `json:"queued_jobs"`
	CompletedJobs  int     `json:"completed_jobs"`
	FailedJobs     int     `json:"failed_jobs"`
	RequestsPerSec float64 `json:"requests_per_sec"`
	AvgLatency     float64 `json:"avg_latency"`
	P50Latency     float64 `json:"p50_latency"`
	P95Latency     float64 `json:"p95_latency"`
	ErrorRate      float64 `json:"error_rate"`
}

// Mutator interface for request mutation
type Mutator interface {
	Mutate(ctx context.Context, req *Request, config *MutationConfig) ([]*Request, error)
	GetPayloadSets() map[string][]string
	GetMethods() []string
	GetBodyTypes() []string
}

// Checker interface for security checks
type Checker interface {
	Check(ctx context.Context, req *Request, resp *Response, config *CheckConfig) ([]*Finding, error)
	GetSupportedChecks() []string
	GetThresholds() map[string]string
}

// ScenarioRunner interface for scenario execution
type ScenarioRunner interface {
	Run(ctx context.Context, scenario *Scenario, config *ExecutionConfig) (<-chan *Event, error)
	Pause(ctx context.Context) error
	Resume(ctx context.Context) error
	Stop(ctx context.Context) error
	GetStatus(ctx context.Context) (*RunnerStatus, error)
}

// RunnerStatus represents scenario runner status
type RunnerStatus struct {
	Running     bool      `json:"running"`
	Paused      bool      `json:"paused"`
	CurrentStep string    `json:"current_step"`
	Progress    float64   `json:"progress"`
	StartedAt   time.Time `json:"started_at"`
	Error       string    `json:"error"`
}

// Utility functions for context management
// Note: These functions are not currently used but may be needed for future features

// GenerateRawRequest generates raw HTTP request format like Burp Suite
func (r *Request) GenerateRawRequest() string {
	var raw strings.Builder

	// Parse URL to get path and query
	parsedURL, err := url.Parse(r.URL)
	if err != nil {
		return ""
	}

	// Build request line
	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	raw.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", r.Method, path))

	// Add headers
	if host := parsedURL.Host; host != "" {
		raw.WriteString(fmt.Sprintf("Host: %s\n", host))
	}

	for key, value := range r.Headers {
		raw.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	// Add empty line to separate headers from body
	raw.WriteString("\n")

	// Add body if exists
	if len(r.Body) > 0 {
		raw.WriteString(string(r.Body))
	}

	return raw.String()
}

// GenerateRawResponse generates raw HTTP response format like Burp Suite
func (r *Response) GenerateRawResponse() string {
	var raw strings.Builder

	// Build status line
	statusText := getStatusText(r.Status)
	raw.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", r.Status, statusText))

	// Add headers
	for key, value := range r.Headers {
		raw.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	// Add empty line to separate headers from body
	raw.WriteString("\n")

	// Add body if exists
	if r.BodySnippet != "" {
		raw.WriteString(r.BodySnippet)
	}

	return raw.String()
}

// getStatusText returns HTTP status text for status code
func getStatusText(statusCode int) string {
	switch statusCode {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Unknown"
	}
}
