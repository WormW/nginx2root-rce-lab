# 免责声明 / Disclaimer

本仓库只用于授权安全研究、CTF 和隔离实验环境。内容是公开漏洞
CVE-2026-123007（nginx2root）的复现记录，使用 Rapid7 公开 PoC 和我们自己
的标定工具。

- 不要对未授权系统运行本项目的任何内容。
- 一次利用尝试会产生约 119 GiB 入站 TLS 流量，并可能让 nginx worker 崩溃；
  对生产或共享系统有破坏性，可能违反法律或政策。
- 本仓库不提供超出公开 PoC 的武器化代码；Rapid7 PoC 只以链接引用，不重新
  分发。
- 作者不对误用或损害负责。

---

This repository is for authorized security research, CTFs and isolated lab
environments only. It documents a reproduction of the publicly disclosed
CVE-2026-123007 (nginx2root) using Rapid7's public PoC and our own
calibration tooling.

- Do not run any of this against systems you don't own or have explicit
  written permission to test.
- One exploit attempt generates roughly 119 GiB of inbound TLS traffic and
  may crash nginx worker processes. On production or shared systems this is
  disruptive and may violate law or policy.
- No exploit weaponization beyond the public PoC is provided; the Rapid7 PoC
  is referenced, not redistributed.
- The authors are not responsible for misuse or damage.
