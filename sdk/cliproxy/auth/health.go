package auth

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// healthTracker holds lightweight per-auth rolling-window failure tracking
// used by the smart-health-aware routing strategy.
type healthTracker struct {
	mu sync.RWMutex

	// windowFailures tracks failures in the last N request buckets.
	windowFailures int64
	windowTotal    int64

	// consecutiveFailures counts consecutive failures (reset on success).
	consecutiveFailures int

	// lastQuotaFailure records the most recent quota-related failure time.
	lastQuotaFailure time.Time

	// quotaFailureCount in the current window.
	quotaFailureCount int64
}

// RecordSuccess marks a successful request.
func (h *healthTracker) RecordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.windowTotal++
	h.consecutiveFailures = 0
}

// RecordFailure marks a failed request. isQuota indicates whether the failure
// was quota-related (usage_limit_reached, insufficient_quota, rate_limit_exceeded).
func (h *healthTracker) RecordFailure(isQuota bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.windowTotal++
	h.windowFailures++
	h.consecutiveFailures++
	if isQuota {
		h.lastQuotaFailure = time.Now()
		h.quotaFailureCount++
	}
}

// Score returns a 0.0–1.0 health score where 1.0 is perfectly healthy.
// Factors:
//   - Recent failure rate in the rolling window (0–0.5 weight)
//   - Consecutive failure streak (0–0.3 weight)
//   - Quota failure recency (0–0.2 weight)
func (h *healthTracker) Score(now time.Time) float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.windowTotal == 0 {
		return 1.0 // No data yet; treat as healthy.
	}

	// 1. Failure rate penalty (max 0.5)
	failureRate := float64(h.windowFailures) / float64(h.windowTotal)
	failurePenalty := failureRate * 0.5

	// 2. Consecutive failure penalty (max 0.3)
	// Penalty escalates quickly: 1 fail = 0.05, 2 = 0.15, 3+ = 0.3
	var consecutivePenalty float64
	switch {
	case h.consecutiveFailures >= 3:
		consecutivePenalty = 0.3
	case h.consecutiveFailures == 2:
		consecutivePenalty = 0.15
	case h.consecutiveFailures == 1:
		consecutivePenalty = 0.05
	}

	// 3. Quota failure recency penalty (max 0.2)
	// If a quota failure happened in the last 10 minutes, apply a penalty.
	var quotaPenalty float64
	if !h.lastQuotaFailure.IsZero() {
		since := now.Sub(h.lastQuotaFailure)
		if since < 10*time.Minute {
			quotaPenalty = 0.2 * (1.0 - float64(since)/float64(10*time.Minute))
		}
	}

	score := 1.0 - failurePenalty - consecutivePenalty - quotaPenalty
	if score < 0.05 {
		score = 0.05 // Floor so auths can still be selected in emergencies.
	}
	return score
}

// Reset clears the tracker (e.g. when auth is refreshed or manually reset).
func (h *healthTracker) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.windowFailures = 0
	h.windowTotal = 0
	h.consecutiveFailures = 0
	h.lastQuotaFailure = time.Time{}
	h.quotaFailureCount = 0
}

// isQuotaError checks whether an error code indicates a quota or rate-limit issue.
func isQuotaError(code string) bool {
	code = strings.ToLower(strings.TrimSpace(code))
	switch code {
	case "usage_limit_reached",
		"insufficient_quota",
		"rate_limit_exceeded",
		"quota_exceeded",
		"payment_required",
		"billing_hard_limit_reached",
		"too_many_requests":
		return true
	}
	return false
}

// authHealth holds the per-Auth health tracker instance.
// Access is via the Auth.Runtime field (non-serialised, in-memory only).
type authHealth struct {
	tracker healthTracker
}

// ensureAuthHealth returns the authHealth for an Auth, creating it if absent.
func ensureAuthHealth(a *Auth) *authHealth {
	if a == nil {
		return nil
	}
	if h, ok := a.Runtime.(*authHealth); ok && h != nil {
		return h
	}
	h := &authHealth{}
	a.Runtime = h
	return h
}

// AuthHealthScore computes the health score for an auth (0.0–1.0).
// Returns 1.0 if no health tracker is present (backwards compatible).
func AuthHealthScore(a *Auth, now time.Time) float64 {
	if a == nil {
		return 1.0
	}
	h := ensureAuthHealth(a)
	if h == nil {
		return 1.0
	}
	return h.tracker.Score(now)
}

// AuthRecordSuccess records a successful request on the auth's health tracker.
func AuthRecordSuccess(a *Auth) {
	h := ensureAuthHealth(a)
	if h == nil {
		return
	}
	h.tracker.RecordSuccess()
}

// AuthRecordFailure records a failed request on the auth's health tracker.
func AuthRecordFailure(a *Auth, errCode string) {
	h := ensureAuthHealth(a)
	if h == nil {
		return
	}
	isQuota := isQuotaError(errCode)
	h.tracker.RecordFailure(isQuota)
}

// AuthResetHealth resets the health tracker for an auth (e.g. after token refresh).
func AuthResetHealth(a *Auth) {
	h := ensureAuthHealth(a)
	if h == nil {
		return
	}
	h.tracker.Reset()
}

// healthPenalty returns a sorting penalty for an auth based on its health score.
// Lower penalty = prefer this auth. Used by sort.SliceStable.
func healthPenalty(a *Auth, now time.Time) float64 {
	score := AuthHealthScore(a, now)
	// Invert score so higher health = lower penalty.
	return 1.0 - score
}

// sortAuthsByHealth re-orders the available auth slice by descending health score
// (healthiest first). Uses stable sort so deterministic ties are preserved.
func sortAuthsByHealth(auths []*Auth, now time.Time) {
	if len(auths) <= 1 {
		return
	}
	sort.SliceStable(auths, func(i, j int) bool {
		penaltyI := healthPenalty(auths[i], now)
		penaltyJ := healthPenalty(auths[j], now)
		return penaltyI < penaltyJ
	})
}
