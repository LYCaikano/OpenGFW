package tcp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
	"github.com/apernet/OpenGFW/collector"
)

// Collector is set by cmd/root.go to enable global state tracking and active probing.
var Collector *collector.State

var _ analyzer.TCPAnalyzer = (*VLESSAnalyzer)(nil)

// VLESSAnalyzer detects VLESS/REALITY traffic using passive heuristics.
//
// Detection is based on two phases:
//
//	Phase 1: TLS ClientHello fingerprinting — VLESS/REALITY always uses
//	         a Chrome-like ClientHello (ALPN=h2+http/1.1, GREASE versions,
//	         specific cipher suites, 32-byte session ID).
//	Phase 2: Post-handshake data segment size pattern — after TLS handshake,
//	         VLESS traffic has characteristic alternating record sizes
//	         (small C→S auth, larger S→C response).
//
// Exposed properties for rule expressions:
//
//	vless.yes    (bool)   — heuristic score >= threshold (default 50)
//	vless.score  (int)    — confidence 0-100
//	vless.sni    (string) — SNI from ClientHello
//	vless.alpn   ([]string) — ALPN protocols
//	vless.grease (bool)   — has GREASE versions
//	vless.probes (int)    — matching probe count (reserved for active probing integration)
type VLESSAnalyzer struct{}

func (a *VLESSAnalyzer) Name() string {
	return "vless"
}

func (a *VLESSAnalyzer) Limit() int {
	return 16384
}

func (a *VLESSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newVLESSStream(logger, info.SrcIP.String())
}

type vlessStream struct {
	logger analyzer.Logger

	srcIP string

	reqBuf       *utils.ByteBuffer
	reqLSM       *utils.LinearStateMachine
	reqDone      bool
	reqScore     int
	clientHello  []byte // captured ClientHello TLS record for active probing

	respBuf  *utils.ByteBuffer
	respLSM  *utils.LinearStateMachine
	respDone bool

	sni  string
	alpn []string

	counting   bool
	rev        bool
	seq        [4]int
	seqIndex   int
	totalBytes int64
}

func newVLESSStream(logger analyzer.Logger, srcIP string) *vlessStream {
	s := &vlessStream{
		srcIP:   srcIP,
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
	s.totalBytes += int64(len(data))

	if !rev && !s.reqDone {
		// Capture ClientHello bytes before LSM consumes them
		if len(s.clientHello) == 0 && len(data) > 0 && data[0] == 0x16 {
			s.clientHello = make([]byte, len(data))
			copy(s.clientHello, data)
		}
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

	if s.reqDone && s.respDone {
		if !s.counting {
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
				score := s.computeScore()
				isVless := score >= 50

				// Report to global collector for IP-level tracking
				if Collector != nil && s.srcIP != "" {
					Collector.Report(s.srcIP, s.sni, isVless, s.totalBytes, s.clientHello)
				}

				props := analyzer.PropMap{
					"yes":    isVless,
					"score":  score,
					"bytes":  s.totalBytes,
					"probes": 0,
				}
				if s.sni != "" {
					props["sni"] = s.sni
				}
				if len(s.alpn) > 0 {
					props["alpn"] = s.alpn
				}
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateMerge,
					M:    props,
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

func (s *vlessStream) computeScore() int {
	score := s.reqScore

	c2s1 := s.seq[0]
	s2c1 := s.seq[1]
	c2s2 := s.seq[2]
	s2c2 := s.seq[3]

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

	s.reqBuf.Buf = append([]byte{byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}, s.reqBuf.Buf...)
	return utils.LSMActionNext
}

func (s *vlessStream) parseClientHello() utils.LSMAction {
	hsLen := int(s.reqBuf.Buf[0])<<16 | int(s.reqBuf.Buf[1])<<8 | int(s.reqBuf.Buf[2])
	s.reqBuf.Skip(3)

	chBuf, ok := s.reqBuf.GetSubBuffer(hsLen, true)
	if !ok {
		return utils.LSMActionPause
	}

	score := 0

	chBuf.GetUint16(false, true) // legacy version

	random, ok := chBuf.Get(32, true)
	if !ok {
		return utils.LSMActionCancel
	}

	sessLen, ok := chBuf.GetByte(true)
	if !ok {
		return utils.LSMActionCancel
	}
	chBuf.Skip(int(sessLen))

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

	compLen, ok := chBuf.GetByte(true)
	if !ok {
		return utils.LSMActionCancel
	}
	chBuf.Skip(int(compLen))

	extsLen, ok := chBuf.GetUint16(false, true)
	if !ok {
		s.reqScore = score
		s.reqDone = true
		return utils.LSMActionNext
	}

	extBuf, ok := chBuf.GetSubBuffer(int(extsLen), true)
	if !ok {
		return utils.LSMActionCancel
	}

	hasH2, hasHTTP1 := false, false
	hasGREASE := false

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
		case 0x0000: // SNI — extracted for rule matching, NOT hardcoded scoring
			extData.Skip(2)
			sniType, _ := extData.GetByte(true)
			if sniType == 0 {
				sniLen, _ := extData.GetUint16(false, true)
				sniStr, ok := extData.GetString(int(sniLen), true)
				if ok {
					s.sni = sniStr
				}
			}
		case 0x0010: // ALPN
			extData.Skip(2)
			var alpns []string
			for extData.Len() > 0 {
				alpnLen, ok := extData.GetByte(true)
				if !ok {
					break
				}
				alpnStr, ok := extData.GetString(int(alpnLen), true)
				if !ok {
					break
				}
				alpns = append(alpns, alpnStr)
				if alpnStr == "h2" {
					hasH2 = true
				}
				if alpnStr == "http/1.1" {
					hasHTTP1 = true
				}
			}
			s.alpn = alpns
		case 0x002b: // supported_versions
			verListLen, _ := extData.GetByte(true)
			for i := 0; i < int(verListLen)/2 && extData.Len() >= 2; i++ {
				ver, _ := extData.GetUint16(false, true)
				if (ver & 0x0F0F) == 0x0A0A {
					hasGREASE = true
				}
			}
		}
	}

	// Scoring based on TLS fingerprint features (SNI-independent)
	if hasH2 && hasHTTP1 {
		score += 20
	}
	if hasGREASE {
		score += 15
	}
	if int(sessLen) == 32 {
		score += 10
	}
	if len(ciphers) >= 12 && len(ciphers) <= 20 {
		score += 10
	}

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

	if len(random) > 0 {
		seen := make(map[byte]bool)
		for _, b := range random {
			seen[b] = true
		}
		if float64(len(seen))/float64(len(random)) > 0.7 {
			score += 5
		}
	}

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
