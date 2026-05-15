package collector

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

// Prober actively probes suspected VLESS/REALITY servers to confirm detection.
//
// When a source IP exceeds the VLESS ratio threshold (>20% of connections
// classified as VLESS-like by the passive analyzer), the prober:
//  1. Takes the top 3 most common SNIs from that IP
//  2. Opens TLS connections to each suspected server (the REALITY server)
//  3. Sends CCS + Alert probe payloads
//  4. Compares Round A (valid session) vs Round B (randomized session) responses
//  5. If fingerprints differ, confirms VLESS detection
//
// This is the active confirmation layer that complements the passive analyzer.
type Prober struct {
	state     *State
	dialer    *net.Dialer
	probeMu   sync.Mutex
	probeSet  [][]byte
	results   map[string]map[string]bool // srcIP → sni → confirmed
}

// ProbeResult holds the outcome of an active probe.
type ProbeResult struct {
	SrcIP     string
	SNI       string
	IsVLESS   bool
	RoundA    []string // probe statuses per probe
	RoundB    []string
	Error     string
	Duration  time.Duration
}

// NewProber creates a new active prober.
func NewProber(state *State) *Prober {
	return &Prober{
		state:  state,
		dialer: &net.Dialer{Timeout: 5 * time.Second},
		results: make(map[string]map[string]bool),
	}
}

// SetProbes configures which probe payloads to use for active detection.
// Default: combined CCS + Alert probe set (14 probes).
func (p *Prober) SetProbes(probes [][]byte) {
	p.probeSet = probes
}

// Probe initiates an active probe against a suspected VLESS server.
// serverAddr should be "ip:port" of the REALITY server.
func (p *Prober) Probe(srcIP, sni, serverAddr string) *ProbeResult {
	result := &ProbeResult{
		SrcIP: srcIP,
		SNI:   sni,
	}

	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
	}()

	probes := p.probeSet
	if len(probes) == 0 {
		probes = defaultProbes()
	}

	// Phase 1: Capture a valid TLS ClientHello-like fingerprint by
	// opening a connection to the server with standard TLS
	// (This simulates what the cracker does — it replays a captured ClientHello)

	// Actually, we need a REAL ClientHello to replay. In practice,
	// the OpenGFW analyzer would have captured the original ClientHello bytes.
	// For standalone probing, we generate a Chrome-like ClientHello.

	clientHello := generateChromeClientHello(sni)

	// Round A: Send original ClientHello → should hit VLESS stack
	roundA, err := p.probeRound(serverAddr, sni, clientHello, probes)
	if err != nil {
		result.Error = fmt.Sprintf("round A: %v", err)
		return result
	}
	result.RoundA = roundA

	// Round B: Randomize session ID and resend → should hit fallback stack
	modifiedCH := randomizeSessionID(clientHello)
	roundB, err := p.probeRound(serverAddr, sni, modifiedCH, probes)
	if err != nil {
		result.Error = fmt.Sprintf("round B: %v", err)
		// If B fails but A succeeded, treat as potential Cloudflare blocking pattern
		if len(roundA) > 0 {
			result.IsVLESS = true // B-connectivity asymmetry
		}
		return result
	}
	result.RoundB = roundB

	// Compare fingerprints
	result.IsVLESS = !probeRoundsMatch(roundA, roundB)

	// Record result in state
	p.probeMu.Lock()
	if _, ok := p.results[srcIP]; !ok {
		p.results[srcIP] = make(map[string]bool)
	}
	p.results[srcIP][sni] = result.IsVLESS
	p.probeMu.Unlock()

	if p.state != nil {
		p.state.MarkProbed(srcIP, sni, result.IsVLESS)
	}

	return result
}

// SetState sets the state reference (called after construction).
func (p *Prober) SetState(s *State) {
	p.state = s
}
func (p *Prober) StartProbeCallback() ProbeFunc {
	return func(srcIP string, topSNIs []string) {
		for _, sni := range topSNIs {
			// Use default port 443 for probing
			// In production, the actual server port should be known
			result := p.Probe(srcIP, sni, sni+":443")
			if result.Error != "" {
				fmt.Printf("[VLESS-probe] %s %s: %s\n", srcIP, sni, result.Error)
			} else {
				fmt.Printf("[VLESS-probe] %s %s: confirmed=%v A=%v B=%v (%v)\n",
					srcIP, sni, result.IsVLESS, result.RoundA, result.RoundB, result.Duration)
			}
		}
	}
}

// probeRound opens a TLS connection, sends ClientHello, waits for ServerHello,
// then sends probe payloads and observes responses.
func (p *Prober) probeRound(serverAddr, sni string, clientHello []byte, probes [][]byte) ([]string, error) {
	conn, err := p.dialer.Dial("tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send ClientHello
	_, err = conn.Write(clientHello)
	if err != nil {
		return nil, fmt.Errorf("write ClientHello: %w", err)
	}

	// Read until we get ServerHello response (or timeout)
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read ServerHello: %w", err)
	}
	_ = n // response data

	// Now send each probe and observe the response
	var statuses []string
	for i, probe := range probes {
		_ = i
		// Each probe opens a new connection (like the C cracker does)
		pConn, err := p.dialer.Dial("tcp", serverAddr)
		if err != nil {
			statuses = append(statuses, "CONN_FAIL")
			continue
		}

		pConn.SetDeadline(time.Now().Add(5 * time.Second))
		pConn.Write(clientHello)

		// Read ServerHello
		respBuf := make([]byte, 65536)
		pConn.Read(respBuf) // read and discard ServerHello

		// Send probe
		pConn.Write(probe)

		// Observe response
		obsBuf := make([]byte, 4096)
		pConn.SetReadDeadline(time.Now().Add(4 * time.Second))
		obsN, obsErr := pConn.Read(obsBuf)
		pConn.Close()

		status := classifyProbeResponse(obsBuf[:obsN], obsErr)
		statuses = append(statuses, status)
	}

	return statuses, nil
}

// classifyProbeResponse determines the probe response type.
func classifyProbeResponse(data []byte, err error) string {
	if err != nil {
		// Check for timeout vs reset
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "TO"
		}
		return "ERR"
	}
	if len(data) == 0 {
		return "NONE"
	}
	// Check for TLS Alert (0x15 record)
	if len(data) >= 3 && data[0] == 0x15 && data[1] == 0x03 && data[2] == 0x03 {
		return "ALERT"
	}
	// Check for TLS Handshake (0x16 record)
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] == 0x03 {
		return "ALERT" // handshake response to probe = alert-like
	}
	// Any response data
	return "ALERT"
}

// probeRoundsMatch checks if two probe result sets match.
// Matching means the server has only ONE TLS stack (normal HTTPS).
// Non-matching means TWO different stacks (VLESS/REALITY).
func probeRoundsMatch(a, b []string) bool {
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

// defaultProbes returns the combined CCS + Alert probe set.
func defaultProbes() [][]byte {
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
		{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x0a},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0xff},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x03, 0x00},
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00, 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
	}
	return append(ccs, alert[1:]...) // Skip duplicate probe 0 from alert set
}

// generateChromeClientHello creates a Chrome-like TLS 1.3 ClientHello for the given SNI.
// This is a simplified version; production would capture real ClientHello bytes.
func generateChromeClientHello(sni string) []byte {
	// Build a minimal but valid TLS 1.3 ClientHello
	var ch []byte

	// TLS Record: Handshake (0x16), TLS 1.2 record version (0x0303)
	// We'll fill in the length later

	// Handshake: ClientHello (0x01)
	// We use a simplified snake-oil ClientHello — in production,
	// the actual captured ClientHello from the original connection
	// should be used for accurate probing.

	// For now, return a pre-built template that's sufficient for probing
	// Real implementation should capture and replay actual ClientHello

	// Simplified Chrome-like ClientHello
	clientVer := []byte{0x03, 0x03} // TLS 1.2 in legacy field
	random := make([]byte, 32)
	rand.Read(random)
	sessID := make([]byte, 32)
	rand.Read(sessID)

	// Cipher suites: Chrome's TLS 1.3 ciphers
	ciphers := []byte{
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
		0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
		0x13, 0x04, // TLS_AES_128_CCM_SHA256
		0x13, 0x05, // TLS_AES_128_CCM_8_SHA256
		// GREASE
		0x0A, 0x0A,
	}
	cipherLen := []byte{byte(len(ciphers) >> 8), byte(len(ciphers))}

	comp := []byte{0x01, 0x00} // 1 compression method: null

	// Extensions: SNI + supported_versions + supported_groups + ALPN + ...
	extensions := buildExtensions(sni)

	// Handshake body
	hsBody := append(clientVer, random...)
	hsBody = append(hsBody, byte(len(sessID)))
	hsBody = append(hsBody, sessID...)
	hsBody = append(hsBody, cipherLen...)
	hsBody = append(hsBody, ciphers...)
	hsBody = append(hsBody, comp...)
	hsBody = append(hsBody, extensions...)

	// Handshake header: type(1) + length(3)
	hsHeader := []byte{0x01}
	hsLen := len(hsBody)
	hsHeader = append(hsHeader, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))

	fullHS := append(hsHeader, hsBody...)

	// TLS Record header: type(1) + version(2) + length(2)
	recHeader := []byte{0x16, 0x03, 0x03}
	recLen := len(fullHS)
	recHeader = append(recHeader, byte(recLen>>8), byte(recLen))

	ch = append(recHeader, fullHS...)
	return ch
}

// buildExtensions creates a minimal but valid set of TLS extensions.
func buildExtensions(sni string) []byte {
	var exts []byte

	// SNI extension (type 0x0000)
	sniData := []byte{0x00} // host_name type
	sniData = append(sniData, byte(len(sni)>>8), byte(len(sni)))
	sniData = append(sniData, []byte(sni)...)
	sniListLen := []byte{byte(len(sniData) >> 8), byte(len(sniData))}
	sniExt := append([]byte{0x00, 0x00}, sniListLen...)
	sniExt = append(sniExt, sniData...)
	exts = append(exts, addExt(0x0000, sniExt[4:])...)

	// Supported versions (type 0x002b)
	vers := []byte{0x06, 0xFA, 0xFA, 0x03, 0x04, 0x03, 0x03} // GREASE + TLS 1.3 + TLS 1.2
	exts = append(exts, addExt(0x002b, vers)...)

	// Supported groups (type 0x000a)
	groups := []byte{
		0x00, 0x08, // length
		0xEA, 0xEA, // GREASE
		0x00, 0x1d, // x25519
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
	}
	exts = append(exts, addExt(0x000a, groups)...)

	// ALPN (type 0x0010)
	alpn := []byte{
		0x00, 0x0c, // list length
		0x02, 'h', '2',
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
	}
	exts = append(exts, addExt(0x0010, alpn)...)

	// Total extensions length
	extLen := []byte{byte(len(exts) >> 8), byte(len(exts))}
	return append(extLen, exts...)
}

func addExt(extType uint16, data []byte) []byte {
	ext := []byte{byte(extType >> 8), byte(extType)}
	ext = append(ext, byte(len(data)>>8), byte(len(data)))
	ext = append(ext, data...)
	return ext
}

// randomizeSessionID creates a copy of the ClientHello with a new random session ID.
// This simulates Round B of the active probe: changing the session ID causes the
// REALITY server to fail authentication and route the request to the fallback stack.
func randomizeSessionID(ch []byte) []byte {
	cp := make([]byte, len(ch))
	copy(cp, ch)

	// Find the session ID field in the ClientHello
	// Record header (5 bytes) + Handshake header (4 bytes) + client version (2) + random (32) = 43
	// At offset 43: session_id_length (1 byte) + session_id
	offset := 5 + 4 + 2 + 32 // = 43
	if offset+1 >= len(cp) {
		return cp
	}
	sessLen := int(cp[offset])
	offset++
	if offset+sessLen > len(cp) {
		return cp
	}
	newSess := make([]byte, sessLen)
	rand.Read(newSess)
	copy(cp[offset:offset+sessLen], newSess)
	return cp
}

// Ensure crypto/rand is used
var _ = hex.EncodeToString
