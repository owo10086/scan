# reality-scan

以 VPS 的 IP 为起点，扫描同机房的 HTTPS 站点，自动挑出适合做 VLESS + REALITY 伪装目标（`target` / `serverNames`）的域名。

扫描器是 XTLS 官方的 [RealiTLScanner](https://github.com/XTLS/RealiTLScanner)，验证时用官方 Xray 的 `xray tls ping`。

## 快速开始（Linux VPS）

用 root 登录要扫的那台 VPS（x86_64 / arm64），执行：

```bash
git clone https://github.com/owo10086/scan.git && cd scan
./scan.sh <VPS_IP>
```

没有 git 的话，用 curl 下载：

```bash
mkdir -p scan && curl -fsSL https://github.com/owo10086/scan/archive/refs/heads/main.tar.gz | tar xz -C scan --strip-components=1
cd scan && ./scan.sh <VPS_IP>
```

| 参数 | 说明 | 默认 |
|---|---|---|
| `-n` | 推荐几个域名 | 10 |
| `-t` | 扫描并发（最大 20） | 10 |
| `--max-prefix` | 最远扩到多大的网段（20～24） | 20（最多 4096 个地址） |

例如：`./scan.sh 1.2.3.4 -n 5 -t 20`

第一次运行时，脚本会自动做这些准备：
- 缺少 `python3`、`curl`、`openssl`、`unzip` 时，用 apt、dnf 或 yum 自动安装（需要 root）
- 按 CPU 架构下载官方 RealiTLScanner v0.2.3
- 下载官方 Xray v26.10.31 的 Linux 版，并校验 SHA256

扫描时间较长，建议在 `tmux` 或 `screen` 里运行，断线也不会中断。

## 在 Mac 上运行

Clash Verge TUN 开着即可，不用改设置。仓库里不带二进制，先准备两个工具（RealiTLScanner 官方没有 Mac 版，需要用 Go 编译）：

```bash
git clone https://github.com/XTLS/RealiTLScanner.git
(cd RealiTLScanner && go build -o realitlscanner .)

mkdir -p xray && curl -fsSLo /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-macos-arm64-v8a.zip
unzip -o /tmp/xray.zip xray -d xray
```

然后：

```bash
./scan.sh <VPS_IP>
```

**在 VPS 上跑和在 Mac 上跑的区别：**
- VPS 上测得的是 VPS 到目标的真实延迟，也不受 Clash 嗅探和 fake-ip 干扰，结果更准。
- VPS 上扫描流量直接从 VPS 发出，有被机房标记的风险（见下方注意事项）。
- 要扫哪台就在哪台上跑。在别的机器上扫，报告会提示"本机出口不是目标 VPS"。

## 从 Mac 打包上传到 VPS（可选）

VPS 上不方便访问 GitHub 时，可以在 Mac 上打包后上传：

```bash
./deploy.sh myvps              # myvps 是 ~/.ssh/config 里的别名，上传到 /root/reality-scan
./deploy.sh root@1.2.3.4 2333  # 也可以直接写 用户@IP 加端口
./deploy.sh                    # 只打包，生成 dist/reality-scan-vps.tar.gz，自己用任意工具上传
```

包里只有：脚本、文档，以及本地已有的 Linux 版扫描器。自己上传的包，先解压再运行：

```bash
mkdir -p /root/reality-scan && tar xzf reality-scan-vps.tar.gz -C /root/reality-scan
cd /root/reality-scan && ./scan.sh <VPS_IP>
```

**在 VPS 上跑和在 Mac 上跑的区别：**
- 延迟是 VPS 到目标的真实延迟，也不受 Clash 嗅探和 fake-ip 干扰，结果更准。
- 扫描流量直接从 VPS 发出，有被机房标记的风险（见下方注意事项）。
- 要扫哪台就在哪台上跑。在别的机器上扫，报告会提示"本机出口不是目标 VPS"。

## 脚本做了什么

1. **网络信息**：用 RIPEstat 和 ipinfo 查 VPS 的 ASN、前缀和城市，并显示扫描流量的出口 IP。
2. **扫描**：先扫 VPS 所在的 /24。不够数量，就按距离由近到远扫相邻的 /24，只扫和 VPS 同 ASN、同城市的，最远到 `--max-prefix`。
3. **初筛**：去掉默认证书和自签证书（1Panel、自签、CloudFlare Origin、Fastly），以及 `www.cloudflare.com` 这类大站证书（基本是别人的 REALITY 节点）。
4. **验证**：
   - DoH 解析必须回到扫描到的 IP
   - TLS 1.3 + h2 + X25519
   - 证书和主机名校验
   - 首页响应和跳转
   - `xray tls ping`
5. **剔除**：
   - 走 CDN 的
   - 403、404、502 等错误页
   - 默认页、探针、面板、代理和 AI 中转站
   - 机房默认主机名
   - Xray 风险名单里的域名（`.ru`/`.ir`/`.cn`，或含 apple、icloud、microsoft）
6. **稳定性与打分**：连续握手 5 次，然后打分排序。打分依据：
   - 网段距离、握手稳定性和波动
   - 首页是否像正常网站、证书剩余天数
   - 免费二级域名、数字域名、盗版/成人内容会扣分
7. **域名注册信息**：对最后推荐的域名查注册时间和最近更新时间（先用 RDAP，查不到再用 whois），只显示，不参与打分。刚注册不久的域名要慎选。

## 输出

结果在 `scan-<IP>/` 目录：

| 文件 | 内容 |
|---|---|
| `report.md` | 推荐列表、前三名的 Xray / 3x-ui 配置、说明 |
| `candidates.csv` | 全部候选，含每一项检测结果和剔除原因 |
| `results.json` | 同上，JSON 格式 |
| `scan_<网段>.csv` | 原始扫描结果；有对应的 `.done` 文件时，再次运行会直接复用，不会重扫 |

配置格式：

```
target: 域名:443
serverNames: ["域名"]
client SNI: 域名
```

## 目录结构

```
reality-scan/
├── scan.sh                    一键入口（Mac / Linux 自动识别）
├── deploy.sh                  打包 VPS 版并上传
├── REALITY目标扫描教程.md      手动操作的详细教程、VPS 上扫描的方法、给 AI 用的提示词
├── reality-verify/
│   ├── oneclick.py            一键流程：扫描、验证、打分、报告
│   ├── verify.py              单个主机的验证逻辑（oneclick.py 会调用它）
│   └── summary.py / final.py  手动流程用：打印验证结果 / 5 次稳定性测试
│
│   以下不在仓库里，运行时下载或自己准备：
├── RealiTLScanner/            扫描器：Mac 版 realitlscanner；Linux 版 realitlscanner-linux-<架构>
├── xray/                      Xray：Mac 版 xray；Linux 版 xray-linux-<架构>
├── dist/                      deploy.sh 生成的 VPS 包
└── scan-<IP>/                 每个 IP 的扫描结果
```

## 依赖

**Linux VPS**：只需要 root；python3（3.7 以上）、curl、openssl、unzip 和 Xray，`scan.sh` 都会自动准备。

**Mac**：

- macOS arm64
- `python3`（只用标准库）
- Homebrew 装的 OpenSSL 3（`/opt/homebrew/bin/openssl`），系统自带的 LibreSSL 不支持需要的参数
- `curl`
- 重新编译扫描器需要 Go：
  ```bash
  cd RealiTLScanner
  go build -o realitlscanner .
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o realitlscanner-linux-amd64 .
  ```

## 注意事项

- **在 VPS 上运行时，扫描流量直接从 VPS 发出。** 官方 README 提醒过，这样可能导致 VPS 被机房标记。默认并发 10，不建议调高。
- **在 Mac 上运行时，扫描流量从 Clash 当前节点发出。** 如果当前节点正好是要扫的那台 VPS，相当于在 VPS 上扫描。官方 README 提醒过，在云服务器上扫描可能导致 VPS 被标记。想避免的话，先在 Clash 里切到别的节点，或者给目标网段加一条 `IP-CIDR,<网段>,DIRECT,no-resolve` 规则，TUN 不用关。
- **延迟只能横向比较。** 报告里的延迟是本机经节点测得的，包含国内到节点那一段，不代表 VPS 到目标的延迟。要在 VPS 上测真实延迟，见 `report.md` 末尾的命令。
- **"同机房"是推断。** 依据是同 ASN、同城市、相邻网段；脚本也没有做实际的 REALITY 连接测试。上线前请用客户端实际连一次。
- **小站可能下线。** 被选中的多是个人或小公司网站，随时可能下线或换证书。建议定期重跑，已扫过的网段会直接复用。
- **扫描范围有限制。** 只做 TCP 443 的 TLS / HTTPS 探测，不做漏洞扫描；单次最多 4096 个地址。
