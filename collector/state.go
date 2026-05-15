// Package collector provides global IP-level traffic statistics and
// active probing coordination for VLESS/REALITY detection.
//
// Architecture:
//
//	analyzer (vless.go) ──Report()──▶ State (per-IP stats)
//	                                       │
//	                               ShouldProbe(ip) ?
//	                                       │
//	Prober ──active probe──▶ Server ◀──┘
//	    │
//	    └──▶ State.MarkProbed(ip, sni, result)
//
// Rules use state via expr functions: ipVlessRatio(), ipHasProbe()
package collector

import (
	"net"
	"sync"
	"time"
)

// IPState tracks connection-level statistics for a single source IP.
type IPState struct {
	SrcIP       string
	TotalConns  int64
	VlessConns  int64
	TotalBytes  int64
	FirstSeen   time.Time
	LastSeen    time.Time
	SNIs        map[string]int64 // SNI → count
	ProbeSent   bool
	ProbeResult map[string]bool // SNI → confirmed VLESS?
}

// State is the global, thread-safe tracker of per-IP stats.
type State struct {
	mu    sync.RWMutex
	ips   map[string]*IPState
	probe ProbeFunc
}

// ProbeFunc is called when an IP exceeds the VLESS ratio threshold.
// It receives the IP and top SNIs to probe.
type ProbeFunc func(srcIP string, topSNIs []string)

// Report records a classified connection.
func (s *State) Report(srcIP, sni string, isVless bool, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.ips[srcIP]
	if !ok {
		st = &IPState{
			SrcIP:       srcIP,
			FirstSeen:   time.Now(),
			SNIs:        make(map[string]int64),
			ProbeResult: make(map[string]bool),
		}
		s.ips[srcIP] = st
	}

	st.LastSeen = time.Now()
	st.TotalConns++
	st.TotalBytes += bytes
	if isVless {
		st.VlessConns++
	}
	if sni != "" {
		st.SNIs[sni]++
	}

	// Trigger active probe if conditions met
	if s.shouldProbeLocked(st) {
		st.ProbeSent = true
		top := topSNIsLocked(st, 3)
		if s.probe != nil {
			go s.probe(srcIP, top)
		}
	}
}

// shouldProbeLocked checks probe conditions (caller holds mu).
func (s *State) shouldProbeLocked(st *IPState) bool {
	if st.ProbeSent {
		return false
	}
	if st.TotalConns < 10 {
		return false // need enough samples
	}
	ratio := float64(st.VlessConns) / float64(st.TotalConns)
	return ratio > 0.2
}

// VlessRatio returns the VLESS connection ratio for an IP.
func (s *State) VlessRatio(srcIP string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok || st.TotalConns == 0 {
		return 0
	}
	return float64(st.VlessConns) / float64(st.TotalConns)
}

// IsLongConn checks if connections from this IP tend to be long-lived
// (high bytes per connection, indicating proxy/tunnel usage).
func (s *State) IsLongConn(srcIP string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok || st.TotalConns == 0 {
		return false
	}
	avgBytes := st.TotalBytes / st.TotalConns
	// Long connections typically transfer 100KB+ per connection
	return avgBytes > 102400
}

// IsHighTraffic checks if an IP has high traffic volume.
func (s *State) IsHighTraffic(srcIP string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return false
	}
	// High traffic: >10MB total
	return st.TotalBytes > 10*1024*1024
}

// GetSNIs returns the most common SNIs for an IP.
func (s *State) GetSNIs(srcIP string, topN int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return nil
	}
	return topSNIsLocked(st, topN)
}

// IsProbed checks if an IP has been probed for a specific SNI.
func (s *State) IsProbed(srcIP, sni string, confirmed bool) *bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return nil
	}
	v, ok := st.ProbeResult[sni]
	if !ok {
		return nil
	}
	// Return nil if confirmed doesn't match
	if v != confirmed {
		return nil
	}
	return &v
}

// MarkProbed records the result of an active probe.
func (s *State) MarkProbed(srcIP, sni string, isVLESS bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return
	}
	st.ProbeResult[sni] = isVLESS
}

// GetState returns a copy of the IP state for inspection.
func (s *State) GetState(srcIP string) *IPState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return nil
	}
	cp := *st
	cp.SNIs = make(map[string]int64, len(st.SNIs))
	for k, v := range st.SNIs {
		cp.SNIs[k] = v
	}
	cp.ProbeResult = make(map[string]bool, len(st.ProbeResult))
	for k, v := range st.ProbeResult {
		cp.ProbeResult[k] = v
	}
	return &cp
}

func topSNIsLocked(st *IPState, n int) []string {
	type kv struct {
		k string
		v int64
	}
	var kvs []kv
	for k, v := range st.SNIs {
		kvs = append(kvs, kv{k, v})
	}
	for i := 0; i < len(kvs)-1; i++ {
		for j := i + 1; j < len(kvs); j++ {
			if kvs[j].v > kvs[i].v {
				kvs[i], kvs[j] = kvs[j], kvs[i]
			}
		}
	}
	if n > len(kvs) {
		n = len(kvs)
	}
	var result []string
	for i := 0; i < n; i++ {
		result = append(result, kvs[i].k)
	}
	return result
}

// NewState creates a new State tracker.
func NewState(probeFn ProbeFunc) *State {
	return &State{
		ips:   make(map[string]*IPState),
		probe: probeFn,
	}
}

// Stub functions for rule expression integration.
// These are called by expr rules to check global state.

// IPVlessRatio returns VLESS ratio for an IP (for use in expr rules).
func (s *State) IPVlessRatio(ipStr string) float64 {
	return s.VlessRatio(ipStr)
}

// IPHighTraffic returns true if the IP has high traffic volume.
func (s *State) IPHighTraffic(ipStr string) bool {
	return s.IsHighTraffic(ipStr)
}

// IPLongConn returns true if the IP tends to have long connections.
func (s *State) IPLongConn(ipStr string) bool {
	return s.IsLongConn(ipStr)
}

// IPSNIs returns comma-separated SNIs for an IP.
func (s *State) IPSNIs(ipStr string) []string {
	return s.GetSNIs(ipStr, 10)
}

// Ensure net import is used
var _ net.IP
