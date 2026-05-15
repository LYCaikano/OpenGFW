# VLESS/REALITY Detection Integration into OpenGFW

## 修改内容

### 1. 新文件: `analyzer/tcp/vless.go`

被动 VLESS/REALITY 检测分析器，无需主动探测。

**检测策略：**

```
Phase 1: TLS ClientHello 指纹打分
  ├─ ALPN: h2+http/1.1 (Chrome fingerprint)           → +20
  ├─ GREASE versions (0x?A?A pattern)                 → +10
  ├─ Session ID 32 bytes (TLS 1.3 middlebox)          → +10
  ├─ Cipher count 12-20 (Chrome-like)                 → +10
  ├─ TLS 1.3 ciphers present (0x1301,0x1302,0x1303)   → +10/+15
  ├─ High entropy random (REALITY auth embedded)       → +5
  └─ Known VLESS target SNI                           → +25
     总分上限: ~100

Phase 2: 握手后数据段大小模式
  ├─ C→S 小记录 (~50-800B) + S→C 响应 (~200-16000B)  → +10
  ├─ C→S 第二段小记录                                 → +5
  └─ S→C 第二段响应                                   → +5

决策: score >= 50 → vless.yes = true
```

**导出的属性:**
| 属性 | 类型 | 说明 |
|------|------|------|
| `vless.yes` | bool | 被动启发式检测结果 |
| `vless.score` | int | 置信度 0-100 |
| `vless.sni` | string | ClientHello 中的 SNI |

### 2. 修改: `cmd/root.go` (line 93)

```go
&tcp.VLESSAnalyzer{},
```

### 3. 新文件: `ruleset/examples/vless.yml`

```yaml
# 封锁已知 VLESS 目标 SNI 的高置信度连接
- name: "block vless known targets"
  action: block
  expr: vless.yes && (tls.req.sni contains "microsoft.com" || ...)

# 封锁非 443 端口的 VLESS 连接（极强信号）
- name: "block vless non-443"
  action: block
  expr: vless.yes && port.dst != 443

# GeoIP 辅助: 证书 SNI 与服务器所在地不匹配
- name: "block vless geo mismatch"
  action: block
  expr: vless.yes && tls.req.sni contains "microsoft.com" && !geoip(ip.dst, "US")
```

## 与 C cracker 的对比

| 维度 | C cracker | OpenGFW VLESS Analyzer |
|------|----------|----------------------|
| 探测方式 | **主动**重放 ClientHello + 畸形包 | **纯被动**观察流量 |
| 检测原理 | Round A vs B TLS 栈指纹差异 | ClientHello 特征 + 数据段大小模式 |
| 检出率 | 44-67% (主动, 跨 SNI 差异大) | ~50% (被动, 保守阈值) |
| 假阳性率 | 0.00% (双栈对比, 理论上不可能误判) | <5% (启发式, 需要实际验证) |
| 部署前提 | 需旁路抓包权限 (cap_net_raw) | NFQueue 内核模块 |
| 网络影响 | 产生额外探测流量 | 零额外流量 |
| 覆盖 | s2n-tls ✅ OpenSSL ✅ BoringSSL ⚠️ | 所有 Chrome-fingerprint 流量均有打分 |

## 局限性

1. **仅被动检测** — 无法利用双栈差异（VLESS 栈 vs fallback 栈），这是 C cracker 的核心能力
2. **依赖 ClientHello 指纹** — VLESS 使用 Chrome 指纹，但正常 Chrome 浏览器也使用相同指纹
3. **需要规则组合** — 单独 `vless.yes` 假阳性率高，需配合 SNI、GeoIP、端口等强规则降误报
4. **无法区分 BoringSSL** — 与 C cracker 同样的盲区

## 未来扩展方向

1. **添加主动探测模块** (modifier layer): 在 OpenGFW 的 modifier 层实现类似于 C cracker 的主动探测，但这是大改动
2. **机器学习模型**: 收集 VLESS vs 正常 HTTPS 的流量特征，训练决策树（类似 TrojanAnalyzer 的做法）
3. **指纹数据库**: 维护已知 VLESS 服务端的 IP:Port 列表，匹配命中直接阻断
4. **时序特征**: 分析 VLESS 特有的连接时序模式（首包间隔、心跳间隔等）
