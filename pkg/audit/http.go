package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPConfig configures an HTTP audit sink. By default it POSTs the event as JSON. In Splunk
// mode it wraps the event for a Splunk HTTP Event Collector and sends the token.
type HTTPConfig struct {
	// URL is the endpoint events are POSTed to. For Splunk HEC this ends in
	// /services/collector/event.
	URL string `yaml:"url"`
	// Method defaults to POST.
	Method string `yaml:"method"`
	// Headers are added to every request.
	Headers map[string]string `yaml:"headers"`
	// Splunk wraps the event as {"event": ...} and sends the Splunk HEC token.
	Splunk bool `yaml:"splunk"`
	// Token is the Splunk HEC token (sent as "Authorization: Splunk <token>"), or read from
	// TokenFile.
	Token     string `yaml:"token"`
	TokenFile string `yaml:"tokenFile"`
	// Sourcetype is the Splunk sourcetype. Default "vouch:audit".
	Sourcetype string `yaml:"sourcetype"`
	// Index is the optional Splunk index.
	Index string `yaml:"index"`
	// Timeout bounds each request. Default 10s.
	Timeout time.Duration `yaml:"timeout"`
	// Retries is how many times a failed request is retried. Default 3.
	Retries int `yaml:"retries"`
	// InsecureSkipVerify disables TLS verification. For testing only.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
}

// httpSink POSTs events to an HTTP endpoint.
type httpSink struct {
	cfg    HTTPConfig
	token  string
	client *http.Client
}

// splunkEnvelope is the Splunk HEC event wrapper.
type splunkEnvelope struct {
	Time       float64 `json:"time"`
	Sourcetype string  `json:"sourcetype"`
	Index      string  `json:"index,omitempty"`
	Event      Event   `json:"event"`
}

// Log implements Sink. It retries on error and returns an error only if every attempt fails,
// so the unlock gate blocks a lost audit record.
func (s *httpSink) Log(ctx context.Context, e Event) error {
	var payload any = e
	if s.cfg.Splunk {
		payload = splunkEnvelope{
			Time:       float64(e.Time.UnixNano()) / 1e9,
			Sourcetype: s.cfg.Sourcetype,
			Index:      s.cfg.Index,
			Event:      e,
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("audit: encoding event: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= s.cfg.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("audit: %w (last error: %v)", ctx.Err(), lastErr)
			case <-time.After(backoff(attempt)):
			}
		}
		if lastErr = s.send(ctx, body); lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("audit: delivering event failed after %d attempts: %w", s.cfg.Retries+1, lastErr)
}

// send makes one request.
func (s *httpSink) send(ctx context.Context, body []byte) error {
	method := s.cfg.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.Splunk && s.token != "" {
		req.Header.Set("Authorization", "Splunk "+s.token)
	}
	for key, value := range s.cfg.Headers {
		req.Header.Set(key, value)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned %s", resp.Status)
	}
	return nil
}

// Close implements Sink.
func (s *httpSink) Close() error { return nil }

// backoff returns the delay before the given retry attempt (1-based).
func backoff(attempt int) time.Duration {
	delay := 200 * time.Millisecond * time.Duration(1<<(attempt-1))
	if max := 5 * time.Second; delay > max {
		delay = max
	}
	return delay
}

// newHTTPSink builds an HTTP sink.
func newHTTPSink(cfg HTTPConfig, token string) (Sink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("audit: http sink needs a url")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.Sourcetype == "" {
		cfg.Sourcetype = "vouch:audit"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for testing
	}
	return &httpSink{
		cfg:    cfg,
		token:  token,
		client: &http.Client{Timeout: cfg.Timeout, Transport: transport},
	}, nil
}
