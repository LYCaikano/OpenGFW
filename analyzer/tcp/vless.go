package tcp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var _ analyzer.TCPAnalyzer = (*VLESSAnalyzer)(nil)

// VLESSAnalyzer detects VLESS/REALITY traffic using passive heuristics.
//
// Detection approach:
//
//	Phase 1: Extract TLS ClientHello features (SNI, ALPN, GREASE versions, cipher suites)
//	         Score the ClientHello on how "Chrome-like" it is. VLESS/REALITY always
//	         uses a Chrome fingerprint.
//	Phase 2: Count alternating data segment sizes after the TLS handshake.
//	         VLESS traffic has characteristic post-handshake size patterns:
//	         small auth record (~100-500B) → server response (~200-8000B) →
//	         small follow-up → server follow-up.
//
// The analyzer produces: vless.yes (bool), vless.score (int 0-100), vless.sni (string)
type VLESSAnalyzer struct{}

func (a *VLESSAnalyzer) Name() string {
	return "vless"
}

func (a *VLESSAnalyzer) Limit() int {
	return 16384
}

func (a *VLESSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newVLESSStream(logger)
}

type vlessStream struct {
	logger analyzer.Logger

	reqBuf   *utils.ByteBuffer
	reqLSM   *utils.LinearStateMachine
	reqDone  bool
	reqScore int

	respBuf  *utils.ByteBuffer
	respLSM  *utils.LinearStateMachine
	respDone bool

	// Post-handshake data segment counting (like TrojanAnalyzer)
	counting bool
	rev      bool
	seq      [4]int
	seqIndex int

	sni string
}

func newVLESSStream(logger analyzer.Logger) *vlessStream {
	s := &vlessStream{
		logger:  logger,
		reqBuf:  &utils.ByteBuffer{},
		respBuf: &utils.ByteBuffer{},
	}
	s.reqLSM = utils.NewLinearStateMachine(
		s.preprocessClientHello,
		s.parseClientHello,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.preprocessServerHello,
	)
	return s
}

func (s *vlessStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}

	if !rev && !s.reqDone {
		s.reqBuf.Append(data)
		cancelled, _ := s.reqLSM.Run()
		if cancelled {
			s.reqDone = true
		}
		return nil, false
	}

	if rev && !s.respDone {
		s.respBuf.Append(data)
		cancelled, _ := s.respLSM.Run()
		if cancelled {
			s.respDone = true
		}
		return nil, false
	}

	// Phase 2: after both ClientHello and ServerHello seen,
	// count alternating data segment sizes
	if s.reqDone && s.respDone {
		if !s.counting {
			// Start counting when we see the first post-handshake data from client
			// In TLS 1.3 flow: after ServerHello, client sends CCS(6 bytes) + Finished(encrypted)
			// The CCS is: 14 03 03 00 01 01
			if !rev && len(data) >= 6 &&
				data[0] == 0x14 && data[1] == 0x03 && data[2] == 0x03 &&
				data[3] == 0x00 && data[4] == 0x01 && data[5] == 0x01 {
				s.counting = true
			}
			return nil, false
		}

		if rev == s.rev {
			s.seq[s.seqIndex] += len(data)
		} else {
			s.seqIndex++
			if s.seqIndex == 4 {
				// 4 alternating segments collected → final classification
				score := s.computeScore()
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateMerge,
					M: analyzer.PropMap{
						"yes":   score >= 50,
						"score": score,
						"sni":   s.sni,
					},
				}, true
			}
			s.seq[s.seqIndex] += len(data)
			s.rev = rev
		}
	}

	return nil, false
}

func (s *vlessStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

// computeScore combines ClientHello fingerprint score with data segment patterns.
func (s *vlessStream) computeScore() int {
	score := s.reqScore

	c2s1 := s.seq[0]
	s2c1 := s.seq[1]
	c2s2 := s.seq[2]
	s2c2 := s.seq[3]

	// VLESS post-handshake pattern:
	// small C→S auth record, then larger S→C response
	if c2s1 > 50 && c2s1 < 800 && s2c1 > 200 && s2c1 < 16000 {
		score += 10
	}
	if c2s2 > 50 && c2s2 < 800 {
		score += 5
	}
	if s2c2 > 200 && s2c2 < 16000 {
		score += 5
	}

	return score
}

func (s *vlessStream) preprocessClientHello() utils.LSMAction {
	const headersSize = 9
	const minDataSize = 41

	header, ok := s.reqBuf.Get(headersSize, true)
	if !ok {
		return utils.LSMActionPause
	}

	if header[0] != 0x16 || header[5] != 0x01 {
		return utils.LSMActionCancel
	}

	hsLen := int(header[6])<<16 | int(header[7])<<8 | int(header[8])
	if hsLen < minDataSize {
		return utils.LSMActionCancel
	}

	// Store hsLen for next step
	s.reqBuf.Buf = append([]byte{byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}, s.reqBuf.Buf...)
	return utils.LSMActionNext
}

func (s *vlessStream) parseClientHello() utils.LSMAction {
	// Read the hsLen we prepended
	hsLen := int(s.reqBuf.Buf[0])<<16 | int(s.reqBuf.Buf[1])<<8 | int(s.reqBuf.Buf[2])
	s.reqBuf.Skip(3)

	// Get the full ClientHello body as a sub-buffer
	chBuf, ok := s.reqBuf.GetSubBuffer(hsLen, true)
	if !ok {
		return utils.LSMActionPause
	}

	// Parse ClientHello fields
	score := 0
	_ = score

	// Legacy version (2 bytes)
	chBuf.GetUint16(false, true)

	// Random (32 bytes)
	random, ok := chBuf.Get(32, true)
	if !ok {
		return utils.LSMActionCancel
	}

	// Session ID
	sessLen, ok := chBuf.GetByte(true)
	if !ok {
		return utils.LSMActionCancel
	}
	chBuf.Skip(int(sessLen))

	// Cipher suites
	cipherLen, ok := chBuf.GetUint16(false, true)
	if !ok || cipherLen%2 != 0 {
		return utils.LSMActionCancel
	}
	ciphers := make([]uint16, cipherLen/2)
	for i := range ciphers {
		ciphers[i], ok = chBuf.GetUint16(false, true)
		if !ok {
			return utils.LSMActionCancel
		}
	}

	// Compression methods
	compLen, ok := chBuf.GetByte(true)
	if !ok {
		return utils.LSMActionCancel
	}
	chBuf.Skip(int(compLen))

	// Extensions
	extsLen, ok := chBuf.GetUint16(false, true)
	if !ok {
		// No extensions, score as-is
		s.reqScore = score
		s.reqDone = true
		return utils.LSMActionNext
	}

	extBuf, ok := chBuf.GetSubBuffer(int(extsLen), true)
	if !ok {
		return utils.LSMActionCancel
	}

	// Parse extensions for scoring
	hasH2, hasHTTP1 := false, false
	hasGREASE := false
	hasECH := false

	for extBuf.Len() > 0 {
		extType, ok := extBuf.GetUint16(false, true)
		if !ok {
			break
		}
		extLen, ok := extBuf.GetUint16(false, true)
		if !ok {
			break
		}
		extData, ok := extBuf.GetSubBuffer(int(extLen), true)
		if !ok {
			break
		}

		switch extType {
		case 0x0000: // SNI
			extData.Skip(2)
			sniType, _ := extData.GetByte(true)
			if sniType == 0 {
				sniLen, _ := extData.GetUint16(false, true)
				sni, ok := extData.GetString(int(sniLen), true)
				if ok {
					s.sni = sni
					// Known VLESS target SNIs
					switch sni {
					case "aws.amazon.com", "www.amazon.com", "www.apple.com",
						"www.icloud.com", "www.microsoft.com", "docs.github.com":
						score += 25
					}
				}
			}
		case 0x0010: // ALPN
			extData.Skip(2)
			for extData.Len() > 0 {
				alpnLen, ok := extData.GetByte(true)
				if !ok {
					break
				}
				alpn, ok := extData.GetString(int(alpnLen), true)
				if !ok {
					break
				}
				if alpn == "h2" {
					hasH2 = true
				}
				if alpn == "http/1.1" {
					hasHTTP1 = true
				}
			}
		case 0x002b: // supported_versions
			verListLen, _ := extData.GetByte(true)
			for i := 0; i < int(verListLen)/2 && extData.Len() >= 2; i++ {
				ver, _ := extData.GetUint16(false, true)
				if (ver & 0x0F0F) == 0x0A0A {
					hasGREASE = true
				}
			}
		case 0xfe0d: // ECH
			hasECH = true
		}
	}

	// Scoring based on extracted features
	if hasH2 && hasHTTP1 {
		score += 20 // VLESS ALPN matches Chrome
	}
	if hasGREASE {
		score += 10 // Chrome GREASE
	}
	if int(sessLen) == 32 {
		score += 10 // TLS 1.3 middlebox compat session ID
	}
	if len(ciphers) >= 12 && len(ciphers) <= 20 {
		score += 10 // Chrome-like cipher count
	}
	// Chrome cipher suites: always includes 0x1301, 0x1302, 0x1303
	has1301, has1302, has1303 := false, false, false
	for _, c := range ciphers {
		if c == 0x1301 {
			has1301 = true
		}
		if c == 0x1302 {
			has1302 = true
		}
		if c == 0x1303 {
			has1303 = true
		}
	}
	if has1301 && has1302 {
		score += 10
	}
	if has1303 {
		score += 5
	}

	// Entropy check on random bytes (REALITY embeds auth there)
	if len(random) > 0 {
		seen := make(map[byte]bool)
		for _, b := range random {
			seen[b] = true
		}
		entropy := float64(len(seen)) / float64(len(random))
		if entropy > 0.7 {
			score += 5 // high entropy = looks like random → could be REALITY auth
		}
	}

	_ = hasECH

	s.reqScore = score
	s.reqDone = true
	return utils.LSMActionNext
}

func (s *vlessStream) preprocessServerHello() utils.LSMAction {
	const headersSize = 9
	const minDataSize = 38

	header, ok := s.respBuf.Get(headersSize, true)
	if !ok {
		return utils.LSMActionPause
	}

	if header[0] != 0x16 || header[5] != 0x02 {
		return utils.LSMActionCancel
	}

	shLen := int(header[6])<<16 | int(header[7])<<8 | int(header[8])
	if shLen < minDataSize {
		return utils.LSMActionCancel
	}

	s.respDone = true
	return utils.LSMActionNext
}
