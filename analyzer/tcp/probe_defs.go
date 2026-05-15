package tcp

// VLESSProbeSet defines a set of TLS probes for VLESS/REALITY detection.
//
// Each probe is a byte sequence sent to the server AFTER receiving ServerHello
// in a replayed TLS connection. By comparing the server's response to these
// probes across two connections (Round A: valid session → VLESS stack,
// Round B: randomized session → fallback stack), the TLS stack fingerprint
// differs, revealing the presence of two independent TLS stacks.
//
// This file defines the probe payloads from the proven characteristic sets.
// In OpenGFW's passive architecture, these are used as reference patterns
// rather than actively sent (active probing requires a separate tool or
// future modifier-layer integration).

// CCSProbeSet is the original ChangeCipherSpec + malformed AppData probe set.
// Effective against: s2n-tls targets (aws.amazon.com, docs.github.com).
//
// Round A expected fingerprint: [TIMEOUT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT]
// Round B for s2n-tls fallback: [TIMEOUT, ALERT, ALERT, ALERT, TIMEOUT, ALERT, TIMEOUT]
var CCSProbeSet = [][]byte{
	// Probe 0: Triple CCS — causes Go TLS to TIMEOUT (TO trigger)
	{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
	// Probe 1: AppData with invalid TLS version 0x9999
	{0x17, 0x99, 0x99, 0x00, 0x10},
	// Probe 2: AppData with valid version, specific length
	{0x17, 0x03, 0x03, 0x42, 0x00},
	// Probe 3: CCS with extra byte
	{0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01},
	// Probe 4: CCS with invalid content type 0x02
	{0x14, 0x03, 0x03, 0x00, 0x01, 0x02},
	// Probe 5: CCS at TLS 1.0 record version
	{0x14, 0x03, 0x01, 0x00, 0x01, 0x01},
	// Probe 6: CCS with padding
	{0x14, 0x03, 0x03, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01},
}

// AlertProbeSet is the 0x15 Alert-based probe set.
// Effective against: OpenSSL/nginx targets (Akamai/Apple, Azure/Microsoft,
// Tencent Cloud, Alibaba Cloud).
//
// Round A expected fingerprint: [TIMEOUT, ALERT, ALERT, ALERT, ALERT, ALERT, ALERT]
// Round B for OpenSSL fallback:  [TIMEOUT, FIN,    FIN,    FIN,    FIN,    FIN,    FIN]
//
// Key behavior: Go TLS sends ALERT on malformed alerts, while OpenSSL sends TCP FIN.
var AlertProbeSet = [][]byte{
	// Probe 0: Triple CCS (same TO trigger)
	{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
	// Probe 1: close_notify warning alert
	{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
	// Probe 2: fatal unexpected_message
	{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x0a},
	// Probe 3: fatal handshake_failure
	{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
	// Probe 4: warning with invalid description 0xFF
	{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0xff},
	// Probe 5: alert with invalid level 0x03 (key differentiator)
	{0x15, 0x03, 0x03, 0x00, 0x02, 0x03, 0x00},
	// Probe 6: double close_notify
	{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00, 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
}

// KnownVLESSProbeTargets is a reference list of SNIs commonly used as
// REALITY fallback targets. This is NOT hardcoded into the detection logic;
// rules should use `vless.sni contains "..."` expressions for flexible matching.
//
// These SNIs were validated in laboratory testing:
//
//	aws.amazon.com      — s2n-tls, CCS probes 99.8% effective
//	docs.github.com     — Fastly, CCS probes 99.6% effective
//	www.amazon.com      — CloudFront, Alert probes 98.0% effective
//	www.apple.com       — Akamai, Alert probes 100% effective
//	www.microsoft.com   — Azure, Alert probes 100% effective
//	cloud.tencent.com   — OpenSSL, Alert probes 100% effective
//	www.aliyun.com      — OpenSSL, Alert probes 100% effective
var KnownVLESSProbeTargets = []string{
	"aws.amazon.com",
	"www.amazon.com",
	"www.apple.com",
	"www.icloud.com",
	"www.microsoft.com",
	"docs.github.com",
	"cloud.tencent.com",
	"www.aliyun.com",
}
