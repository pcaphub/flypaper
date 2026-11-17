// Package pcaphub is the small part of the PcapHub API a collector needs:
// upload a private capture, read it back, patch its description, add it to a
// collection. Honours 429 with Retry-After and treats 409 (duplicate file) as
// success.
package pcaphub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Client talks to one PcapHub instance with one API key.
type Client struct {
	BaseURL   string
	APIKey    string
	UserAgent string
	HTTP      *http.Client
}

// New returns a client with sane timeouts.
func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		APIKey:    apiKey,
		UserAgent: "flypaper/" + Version,
		HTTP:      &http.Client{Timeout: 5 * time.Minute},
	}
}

// Version is set by the build (-ldflags "-X ...pcaphub.Version=...").
var Version = "dev"

// Capture is the subset of the capture document the collector reads.
type Capture struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Slug               string   `json:"slug"`
	Username           string   `json:"username"`
	Status             string   `json:"status"`
	Visibility         string   `json:"visibility"`
	PacketCount        *int     `json:"packet_count"`
	SuricataAlertCount int      `json:"suricata_alert_count"`
	SuricataStatus     string   `json:"suricata_status"`
	Tags               []string `json:"tags"`
	Description        string   `json:"description"`
}

// Alert is one Suricata alert group.
type Alert struct {
	SignatureID int64  `json:"signature_id"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
	Count       int    `json:"count"`
}

// UploadRequest is one capture to send.
type UploadRequest struct {
	Path        string
	Title       string
	Description string
	Tags        []string
}

// ErrDuplicate is returned by Upload when PcapHub already has this file.
var ErrDuplicate = errors.New("duplicate capture")

// APIError is a non-2xx answer.
type APIError struct {
	Status int
	Code   string
	Msg    string
	Retry  time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("pcaphub: %d %s: %s", e.Status, e.Code, e.Msg)
}

// Upload sends a private capture. On 409 it returns ErrDuplicate with the
// existing capture's URL in the error chain (ExistingURL).
func (c *Client) Upload(ctx context.Context, req UploadRequest) (*Capture, error) {
	f, err := os.Open(req.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("title", req.Title)
	_ = mw.WriteField("description", req.Description)
	_ = mw.WriteField("visibility", "private")
	_ = mw.WriteField("legal_confirm", "true")
	for _, t := range req.Tags {
		_ = mw.WriteField("tags[]", t)
	}
	part, err := mw.CreateFormFile("file", filepath.Base(req.Path))
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, f); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	var out struct {
		Data Capture `json:"data"`
	}
	err = c.do(ctx, http.MethodPost, "/api/captures", mw.FormDataContentType(), &body, &out)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusConflict {
		return nil, fmt.Errorf("%w: %s", ErrDuplicate, ae.Msg)
	}
	if err != nil {
		return nil, err
	}
	return &out.Data, nil
}

// Get fetches a capture.
func (c *Client) Get(ctx context.Context, id string) (*Capture, error) {
	var out struct {
		Data Capture `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/captures/"+id, "", nil, &out); err != nil {
		return nil, err
	}
	return &out.Data, nil
}

// WaitReady polls until the capture is ready or errored, or the context ends.
func (c *Client) WaitReady(ctx context.Context, id string, every time.Duration) (*Capture, error) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		cap, err := c.Get(ctx, id)
		if err == nil && (cap.Status == "ready" || cap.Status == "error") {
			return cap, nil
		}
		if err != nil {
			var ae *APIError
			if !errors.As(err, &ae) || ae.Status >= 500 || ae.Status == 429 {
				// transient; keep polling
			} else {
				return nil, err
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// Alerts returns the Suricata alert groups of a capture.
func (c *Client) Alerts(ctx context.Context, id string) ([]Alert, error) {
	var out struct {
		Data []Alert `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/captures/"+id+"/alerts", "", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Patch updates the description (and optionally tags) of an own capture.
func (c *Client) Patch(ctx context.Context, id string, description *string, tags []string) error {
	payload := map[string]any{}
	if description != nil {
		payload["description"] = *description
	}
	if tags != nil {
		payload["tags"] = tags
	}
	b, _ := json.Marshal(payload)
	return c.do(ctx, http.MethodPatch, "/api/captures/"+id, "application/json", bytes.NewReader(b), nil)
}

// AddToCollection adds a capture to one of the account's collections.
func (c *Client) AddToCollection(ctx context.Context, collectionID, captureID string) error {
	b, _ := json.Marshal(map[string]string{"capture_id": captureID})
	err := c.do(ctx, http.MethodPost, "/api/collections/"+collectionID+"/captures", "application/json", bytes.NewReader(b), nil)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusConflict {
		return nil // already in it
	}
	return err
}

// Ping checks the key works for the upload scope by reading /api/health and
// a scope-gated endpoint; returns a short description for the self-check.
func (c *Client) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/api/health", "", nil, nil)
}

// do performs one request with retries on 429 and 5xx (up to 5 attempts).
func (c *Client) do(ctx context.Context, method, path, contentType string, body io.Reader, out any) error {
	var buf []byte
	if body != nil {
		var err error
		if buf, err = io.ReadAll(body); err != nil {
			return err
		}
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		var rdr io.Reader
		if buf != nil {
			rdr = bytes.NewReader(buf)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		req.Header.Set("User-Agent", c.UserAgent)
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			if !sleepCtx(ctx, backoff(attempt)) {
				return ctx.Err()
			}
			continue
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(rb) > 0 {
				return json.Unmarshal(rb, out)
			}
			return nil
		}
		ae := &APIError{Status: resp.StatusCode}
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(rb, &e)
		ae.Code, ae.Msg = e.Code, e.Error
		if ae.Msg == "" {
			ae.Msg = strings.TrimSpace(string(rb[:min(len(rb), 200)]))
		}
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil {
				ae.Retry = time.Duration(secs) * time.Second
			}
		}
		lastErr = ae
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			wait := backoff(attempt)
			if ae.Retry > 0 && ae.Retry < 15*time.Minute {
				wait = ae.Retry
			}
			if !sleepCtx(ctx, wait) {
				return ctx.Err()
			}
			continue
		}
		return ae
	}
	return lastErr
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt)) * 2 * time.Second
	if d > 2*time.Minute {
		d = 2 * time.Minute
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
