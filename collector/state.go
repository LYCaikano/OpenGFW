package collector

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// IPState tracks connection-level statistics for a single source IP.
type IPState struct {
	SrcIP      string
	TotalConns int64
	VlessConns int64
	TotalBytes int64
	FirstSeen  time.Time
	LastSeen   time.Time
	SNIs       map[string]*SNIInfo
	ProbeSent  bool
}

// SNIInfo holds per-SNI data including captured ClientHello for replay.
type SNIInfo struct {
	Count        int64
	ClientHellos [][]byte // captured ClientHello TLS records
	Probed       bool
	Confirmed    bool
}

// State is the global, thread-safe tracker of per-IP stats.
type State struct {
	mu    sync.RWMutex
	ips   map[string]*IPState
	probe ProbeFunc
}

// ProbeFunc is called when an IP exceeds the VLESS ratio threshold.
type ProbeFunc func(srcIP string, topSNIs []SNIProbeTarget)

// SNIProbeTarget bundles SNI with ClientHello for probing.
type SNIProbeTarget struct {
	SNI         string
	ClientHello []byte
}

// Report records a classified connection with the captured ClientHello.
func (s *State) Report(srcIP, sni string, isVless bool, bytes int64, clientHello []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.ips[srcIP]
	if !ok {
		st = &IPState{
			SrcIP:     srcIP,
			FirstSeen: time.Now(),
			SNIs:      make(map[string]*SNIInfo),
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
		si, ok := st.SNIs[sni]
		if !ok {
			si = &SNIInfo{}
			st.SNIs[sni] = si
		}
		si.Count++
		if len(clientHello) > 0 && len(si.ClientHellos) < 5 {
			si.ClientHellos = append(si.ClientHellos, clientHello)
		}
	}

	if s.shouldProbeLocked(st) {
		st.ProbeSent = true
		targets := topSNIProbeTargetsLocked(st, 3)
		if s.probe != nil && len(targets) > 0 {
			go s.probe(srcIP, targets)
		}
	}
}

func (s *State) shouldProbeLocked(st *IPState) bool {
	if st.ProbeSent {
		return false
	}
	if st.TotalConns < 10 {
		return false
	}
	ratio := float64(st.VlessConns) / float64(st.TotalConns)
	return ratio > 0.2
}

func topSNIProbeTargetsLocked(st *IPState, n int) []SNIProbeTarget {
	type kv struct {
		sni string
		cnt int64
	}
	var kvs []kv
	for sni, info := range st.SNIs {
		kvs = append(kvs, kv{sni, info.Count})
	}
	for i := 0; i < len(kvs)-1; i++ {
		for j := i + 1; j < len(kvs); j++ {
			if kvs[j].cnt > kvs[i].cnt {
				kvs[i], kvs[j] = kvs[j], kvs[i]
			}
		}
	}
	if n > len(kvs) {
		n = len(kvs)
	}
	var targets []SNIProbeTarget
	for i := 0; i < n; i++ {
		si := st.SNIs[kvs[i].sni]
		var ch []byte
		if len(si.ClientHellos) > 0 {
			ch = si.ClientHellos[0]
		}
		targets = append(targets, SNIProbeTarget{
			SNI:         kvs[i].sni,
			ClientHello: ch,
		})
	}
	return targets
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

// IsLongConn checks if connections from this IP tend to be long-lived.
func (s *State) IsLongConn(srcIP string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok || st.TotalConns == 0 {
		return false
	}
	return st.TotalBytes/st.TotalConns > 102400
}

// IsHighTraffic checks if an IP has high traffic volume.
func (s *State) IsHighTraffic(srcIP string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return false
	}
	return st.TotalBytes > 10*1024*1024
}

// MarkProbed records the result of an active probe.
func (s *State) MarkProbed(srcIP, sni string, confirmed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return
	}
	si, ok := st.SNIs[sni]
	if !ok {
		return
	}
	si.Probed = true
	si.Confirmed = confirmed
}

// IsConfirmed checks if an SNI has been confirmed as VLESS for an IP.
func (s *State) IsConfirmed(srcIP, sni string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return false
	}
	si, ok := st.SNIs[sni]
	if !ok {
		return false
	}
	return si.Confirmed
}

// GetSNIs returns SNI names for an IP.
func (s *State) GetSNIs(srcIP string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.ips[srcIP]
	if !ok {
		return nil
	}
	var snis []string
	for sni := range st.SNIs {
		snis = append(snis, sni)
	}
	return snis
}

// NewState creates a new State tracker.
func NewState(probeFn ProbeFunc) *State {
	return &State{
		ips:   make(map[string]*IPState),
		probe: probeFn,
	}
}

// Ensure imports used
var _ = fmt.Sprintf
var _ net.IP
