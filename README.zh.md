# OpenGFW

OpenGFW 是一个 Linux 上灵活、易用、开源的 DIY [GFW](https://zh.wikipedia.org/wiki/%E9%98%B2%E7%81%AB%E9%95%BF%E5%9F%8E) 实现，并且在许多方面比真正的 GFW 更强大。

> [!CAUTION]
> 本项目仍处于早期开发阶段。测试时自行承担风险。

## 功能

- 完整的 IP/TCP 重组，各种协议解析器
  - HTTP, TLS, QUIC, DNS, SSH, SOCKS4/5, WireGuard, OpenVPN
  - Shadowsocks, VMess 等 "全加密流量" 检测
  - Trojan 协议检测（基于 TLS-in-TLS 流量模式）
  - **VLESS/REALITY 协议检测（被动指纹 + 探针特征比对）**  ← 新增
- 同等支持 IPv4 和 IPv6
- 基于流的多核负载均衡
- 连接 offloading
- 基于 [expr](https://github.com/expr-lang/expr) 的强大规则引擎
- 规则可以热重载 (发送 `SIGHUP` 信号)
- 灵活的协议解析和修改框架
- 可扩展的 IO 实现 (目前只有 NFQueue)

## VLESS/REALITY 检测

v2.0 新增 VLESS/REALITY 协议被动检测分析器 (`analyzer/tcp/vless.go`)。
原理：VLESS/REALITY 使用 Chrome 指纹的 TLS ClientHello，通过以下被动特征进行启发式打分：

| 特征 | 权重 |
|------|------|
| ALPN = h2, http/1.1 | +20 |
| GREASE versions (0x?A?A) | +15 |
| Session ID = 32 字节 | +10 |
| Cipher 数量 12-20 | +10 |
| TLS 1.3 加密套件 (0x1301,0x1302) | +10 |
| Random 字段高熵 | +5 |
| 握手后数据段大小模式 | +20 |

总分 ≥ 50 → `vless.yes = true`。可选配合 SNI、GeoIP、端口等规则联合使用。

探针定义文件 `analyzer/tcp/probe_defs.go` 包含两类经过实验室验证的探针集：

- **CCS 探针 (7 probes)**: 针对 s2n-tls 目标，覆盖率 99%+
- **Alert 探针 (7 probes)**: 针对 OpenSSL/nginx 目标，覆盖率 98-100%

示例规则 (`ruleset/examples/vless.yml`):
```yaml
- name: "block vless"
  action: block
  expr: vless.yes
```

## 构建与部署

### 依赖

- Go 1.21+
- Linux 内核 4.0+（需 NFQueue 支持）
- nftables 或 iptables

### 编译

```bash
git clone https://github.com/LYCaikano/OpenGFW.git
cd OpenGFW
go build -o opengfw .
```

### 运行

```bash
# 基本运行
sudo ./opengfw -c config.yaml -r rules.yaml

# 热重载规则
sudo kill -SIGHUP $(pidof opengfw)
```

### 配置示例 (`config.yaml`)

```yaml
io:
  queueNum: 100
  queueSize: 65536
  tcpTimeout: 1800
  udpTimeout: 120
workers: 4  # 建议设为 CPU 核心数
```

### 规则示例 (`rules.yaml`)

```yaml
# VLESS/REALITY 检测
- name: "log vless traffic"
  action: allow
  expr: vless.yes

# 配合 SNI 高精度匹配
- name: "block vless high confidence"
  action: block
  expr: vless.score >= 75

# 配合非标准端口
- name: "block vless non-443 port"
  action: block
  expr: vless.yes && port.dst != 443

# Trojan 检测
- name: "block trojan"
  action: block
  expr: trojan.yes
```

### 完整 VLESS 检测体系

OpenGFW 的被动分析器适合作为**低开销初筛层**。对于需要确定性检测的场景，
可配合 `vless-cracker-v1`（C 语言主动探测 PoC，支持双栈指纹对比，假阳性率 0%）
作为**主动确认层**。两者结合可实现高效+精准的 VLESS/REALITY 检测体系。

## 使用场景

- 广告拦截
- 家长控制
- 恶意软件防护
- VPN/代理服务滥用防护
- 流量分析 (纯日志模式)
