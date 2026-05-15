package collector

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	replayTimeoutMs       = 3000
	probeObserveTimeoutMs = 4000
	requiredConfirmations = 3
	maxProbeBytes         = 4096
)

// probeStatus represents the server's response to a single probe.
type probeStatus int

const (
	probeNone    probeStatus = iota // no response
	probeAlert                      // TLS Alert (0x15 record)
	probeFin                        // TCP FIN
	probeRst                        // TCP RST
	probeTimeout                    // connection timeout
	probeConnFail                   // connection failed
)

func (s probeStatus) String() string {
	switch s {
	case probeNone:
		return "NONE"
	case probeAlert:
		return "ALERT"
	case probeFin:
		return "FIN"
	case probeRst:
		return "RST"
	case probeTimeout:
		return "TO"
	case probeConnFail:
		return "CONN_FAIL"
	}
	return "?"
}

// Prober actively probes suspected VLESS/REALITY servers.
// Implements the complete cracker logic (dual-stack fingerprint comparison).
type Prober struct {
	state   *State
	dialer  *net.Dialer
	mu      sync.Mutex
	results map[string]map[string]*ProbeResult
}

// ProbeResult holds the outcome of an active probe.
type ProbeResult struct {
	SrcIP     string
	SNI       string
	IsVLESS   bool
	Confirmed int    // confirmation rounds matched
	RoundA    []string
	RoundB    []string
	Error     string
	Duration  time.Duration
}

// NewProber creates a new active prober.
func NewProber(state *State) *Prober {
	return &Prober{
		state: state,
		dialer: &net.Dialer{
			Timeout:   time.Duration(replayTimeoutMs) * time.Millisecond,
			KeepAlive: -1,
		},
		results: make(map[string]map[string]*ProbeResult),
	}
}

// SetState sets the state reference.
func (p *Prober) SetState(s *State) {
	p.state = s
}

// StartProbeCallback returns a ProbeFunc for State.
func (p *Prober) StartProbeCallback() ProbeFunc {
	return func(srcIP string, targets []SNIProbeTarget) {
		for _, t := range targets {
			// Probe on common REALITY ports — the actual port from the connection should be used ideally
			result := p.ProbeWithClientHello(srcIP, t.SNI, t.ClientHello, t.SNI+":443")
			if result.Error != "" {
				fmt.Printf("[VLESS-probe] %s %s: %s\n", srcIP, t.SNI, result.Error)
			} else {
				fmt.Printf("[VLESS-probe] %s %s: confirmed=%v conf=%d/3 A=%v B=%v (%v)\n",
					srcIP, t.SNI, result.IsVLESS, result.Confirmed,
					result.RoundA, result.RoundB, result.Duration)
			}
		}
	}
}

// ProbeWithClientHello runs the full active probe using a captured ClientHello.
// This is the core detection logic matching the C cracker's behavior.
func (p *Prober) ProbeWithClientHello(srcIP, sni string, clientHello []byte, serverAddr string) *ProbeResult {
	result := &ProbeResult{SrcIP: srcIP, SNI: sni}
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	if len(clientHello) == 0 {
		result.Error = "no captured ClientHello available"
		return result
	}

	// 3 confirmation rounds (matching C cracker's REQUIRED_CONFIRMATION_ROUNDS)
	for round := 0; round < requiredConfirmations; round++ {
		// Round A: replay original ClientHello → VLESS stack
		roundA, aErr := p.probeRound(serverAddr, clientHello)
		if aErr != nil {
			result.Error = fmt.Sprintf("round A/%d: %v", round+1, aErr)
			return result
		}

		// Round B: randomize session ID → fallback stack
		modifiedCH := randomizeSessionID(clientHello)
		roundB, bErr := p.probeRound(serverAddr, modifiedCH)
		if bErr != nil {
			// B-connectivity asymmetry: A works, B consistently fails
			if round >= 1 {
				result.Confirmed = round + 1
				result.RoundA = statusStrings(roundA)
				result.IsVLESS = true
				return result
			}
			result.Error = fmt.Sprintf("round B/%d: %v", round+1, bErr)
			return result
		}

		result.RoundA = statusStrings(roundA)
		result.RoundB = statusStrings(roundB)

		// Alarm condition: A != B AND A matches expected fingerprint
		if !probeRoundsMatch(roundA, roundB) && matchesExpectedFingerprint(roundA) {
			result.Confirmed++
			if result.Confirmed >= requiredConfirmations {
				result.IsVLESS = true
				break
			}
		} else {
			// Fingerprints match — not VLESS, stop probing
			result.IsVLESS = false
			break
		}

		if round < requiredConfirmations-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Record result
	p.mu.Lock()
	if _, ok := p.results[srcIP]; !ok {
		p.results[srcIP] = make(map[string]*ProbeResult)
	}
	p.results[srcIP][sni] = result
	p.mu.Unlock()

	if p.state != nil && result.IsVLESS {
		p.state.MarkProbed(srcIP, sni, true)
	}

	return result
}

// probeRound sends all probes concurrently against the server and returns statuses.
// Each probe opens a fresh TCP connection (matching C cracker behavior).
func (p *Prober) probeRound(serverAddr string, clientHello []byte) ([]probeStatus, error) {
	probes := allProbes()
	if len(probes) == 0 {
		return nil, fmt.Errorf("no probes configured")
	}

	results := make([]probeStatus, len(probes))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for i, probe := range probes {
		wg.Add(1)
		go func(idx int, probeBytes []byte) {
			defer wg.Done()

			conn, err := p.dialer.Dial("tcp", serverAddr)
			if err != nil {
				mu.Lock()
				results[idx] = probeConnFail
				if firstErr == nil {
					firstErr = fmt.Errorf("dial probe %d: %w", idx+1, err)
				}
				mu.Unlock()
				return
			}
			defer conn.Close()

			// Send ClientHello
			conn.SetWriteDeadline(time.Now().Add(time.Duration(replayTimeoutMs) * time.Millisecond))
			if _, err := conn.Write(clientHello); err != nil {
				mu.Lock()
				results[idx] = probeConnFail
				mu.Unlock()
				return
			}

			// Read response (ServerHello, up to 64KB)
			conn.SetReadDeadline(time.Now().Add(time.Duration(replayTimeoutMs) * time.Millisecond))
			respBuf := make([]byte, 65536)
			respN, respErr := conn.Read(respBuf)
			if respErr != nil || respN == 0 {
				mu.Lock()
				results[idx] = probeConnFail
				mu.Unlock()
				return
			}
			respData := respBuf[:respN]

			// Send probe
			conn.SetWriteDeadline(time.Now().Add(time.Duration(replayTimeoutMs) * time.Millisecond))
			if _, err := conn.Write(probeBytes); err != nil {
				mu.Lock()
				results[idx] = probeConnFail
				mu.Unlock()
				return
			}

			// Observe response to probe
			conn.SetReadDeadline(time.Now().Add(time.Duration(probeObserveTimeoutMs) * time.Millisecond))
			obsBuf := make([]byte, maxProbeBytes)
			obsN, obsErr := conn.Read(obsBuf)

			status := classifyProbeResponse(obsBuf[:obsN], obsErr, respData)
			mu.Lock()
			results[idx] = status
			mu.Unlock()
		}(i, probe)
	}

	wg.Wait()

	if firstErr != nil && allFailed(results) {
		return nil, firstErr
	}

	return results, nil
}

func allFailed(statuses []probeStatus) bool {
	for _, s := range statuses {
		if s != probeConnFail {
			return false
		}
	}
	return true
}

// classifyProbeResponse classifies the server's response to a probe.
// Matches the C cracker's logic: check for ALERT record (0x15), FIN/RST via errno.
func classifyProbeResponse(obsData []byte, obsErr error, serverHelloResp []byte) probeStatus {
	if obsErr != nil {
		if netErr, ok := obsErr.(net.Error); ok && netErr.Timeout() {
			return probeTimeout
		}
		// Check for connection reset (RST)
		if opErr, ok := obsErr.(*net.OpError); ok {
			if opErr.Err.Error() == "connection reset by peer" {
				return probeRst
			}
			if sysErr, ok := opErr.Err.(*net.OpError); ok {
				_ = sysErr
			}
		}
		return probeFin // treat other errors as FIN
	}

	if len(obsData) == 0 {
		return probeNone
	}

	// Check for TLS Alert record (0x15) — primary detection signal
	if containsRecord(obsData, 0x15) {
		return probeAlert
	}

	// Check for TLS 1.3 encrypted alert pattern (0x15 0x03 0x03 0x00 0x13)
	if len(obsData) >= 5 && obsData[0] == 0x15 && obsData[1] == 0x03 && obsData[2] == 0x03 {
		return probeAlert
	}

	// Any response data received → treat as alert-like
	return probeAlert
}

// containsRecord checks if a TLS record of given type exists in the data.
func containsRecord(data []byte, recordType byte) bool {
	for i := 0; i+5 <= len(data); i++ {
		if data[i] == recordType && data[i+1] == 0x03 && data[i+2] == 0x03 {
			return true
		}
	}
	return false
}

// matchesExpectedFingerprint checks if Round A results match the expected VLESS pattern.
// Expected: probe 0 = TIMEOUT, probes 1..N = ALERT
func matchesExpectedFingerprint(statuses []probeStatus) bool {
	if len(statuses) < 2 {
		return false
	}
	if statuses[0] != probeTimeout {
		return false
	}
	for i := 1; i < len(statuses); i++ {
		if statuses[i] != probeAlert {
			return false
		}
	}
	return true
}

// probeRoundsMatch checks if two probe result sets are identical.
func probeRoundsMatch(a, b []probeStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func statusStrings(s []probeStatus) []string {
	r := make([]string, len(s))
	for i, v := range s {
		r[i] = v.String()
	}
	return r
}

// allProbes returns the 14-probe combined set (CCS + Alert).
func allProbes() [][]byte {
	ccs := [][]byte{
		{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
		{0x17, 0x99, 0x99, 0x00, 0x10},
		{0x17, 0x03, 0x03, 0x42, 0x00},
		{0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01},
		{0x14, 0x03, 0x03, 0x00, 0x01, 0x02},
		{0x14, 0x03, 0x01, 0x00, 0x01, 0x01},
		{0x14, 0x03, 0x03, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01},
	}
	alert := [][]byte{
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x0a},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0xff},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x03, 0x00},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00, 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0xff},
	}
	return append(ccs, alert...)
}

// randomizeSessionID randomizes the legacy_session_id in a ClientHello.
// This causes the REALITY server to fail authentication → request falls to fallback stack.
func randomizeSessionID(ch []byte) []byte {
	cp := make([]byte, len(ch))
	copy(cp, ch)

	// TLS Record(5) + Handshake header(4) + legacy_version(2) + random(32) = 43
	// Then: session_id_length(1) + session_id
	offset := 5 + 4 + 2 + 32
	if offset+1 >= len(cp) {
		return cp
	}
	sessLen := int(cp[offset])
	offset++
	if sessLen == 0 || offset+sessLen > len(cp) {
		return cp
	}
	newSess := make([]byte, sessLen)
	rand.Read(newSess)
	copy(cp[offset:offset+sessLen], newSess)
	return cp
}
