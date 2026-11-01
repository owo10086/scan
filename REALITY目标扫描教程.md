# REALITY 伪装目标扫描教程（按 VPS IP 扫描）

目标：以 VPS 的 IP 为起点，扫描同网段、同 ASN 的 HTTPS 站点，从中挑出适合做 REALITY `target` / `serverNames` 的域名。

## 目录结构

```
reality-scan/
├── RealiTLScanner/        官方源码编译
│   ├── realitlscanner                 Mac 版（本机用）
│   ├── realitlscanner-linux-amd64     Linux x86_64 版（传到 VPS 用）
│   └── realitlscanner-linux-arm64     Linux arm64 版
├── xray/xray              官方 Xray v26.10.31，用于 xray tls ping
├── reality-verify/        验证脚本
│   ├── verify.py          逐个验证扫描结果（DNS / TLS / HTTP / xray tls ping / ASN）
│   ├── summary.py         把 verify.py 的结果打印成一行一个
│   └── final.py           对入围域名连续握手 5 次，并读取证书信息
└── scan-<IP>/             每个 IP 的扫描结果放一个目录
```

下面所有命令都在项目根目录（`scan.sh` 所在的目录）里执行。

---

## 一键脚本（推荐）

Clash TUN 开着即可，不用改任何设置：

```bash
./scan.sh 1.2.3.4              # 换成你的 VPS IP，默认找 10 个
./scan.sh 1.2.3.4 -n 5         # 只要 5 个
./scan.sh 1.2.3.4 -t 20        # 并发调到 20（最大 20）
```

脚本自动完成下面全部步骤：

1. 用 RIPEstat 和 ipinfo 查 VPS 的 ASN、前缀和城市，并显示扫描流量从哪个 IP 出去。
2. 先扫 VPS 所在的 /24。不够 10 个，就按距离由近到远继续扫相邻的 /24。只扫和 VPS 同 ASN、同城市的，最远到 /20（最多 4096 个地址）。
3. 去掉默认证书、自签证书，以及 `www.cloudflare.com` 这类大站证书（基本是别人的 REALITY 节点）。
4. 逐个验证：DoH 解析回扫描 IP、TLS 1.3 + h2 + X25519、证书校验、首页响应和跳转、`xray tls ping`。
5. 自动剔除：
   - Xray 风险名单里的域名、走 CDN 的
   - 403、404、502 等错误页
   - 默认页、探针、面板、代理和中转站
   - 机房默认主机名
6. 连续握手 5 次测稳定性，然后打分排序。打分依据：
   - 网段距离、握手稳定性和波动
   - 首页是否像正常网站、证书剩余天数
   - 免费二级域名、数字域名、盗版/成人内容会扣分
7. 对最后推荐的域名查注册时间和最近更新时间（RDAP / whois），只显示，不参与打分。

结果在 `scan-<IP>/` 目录：

- `report.md`：推荐列表、前三名的配置、说明
- `candidates.csv`：全部候选及剔除原因
- `scan_*.csv`：原始扫描结果（已扫过的网段，再次运行时直接复用，不会重扫）

后面的第 0～6 步是手动做法，脚本就是按这些步骤实现的。

---

## 第 0 步：设置要扫的 IP（Clash TUN 保持开启）

```bash
IP=1.2.3.4   # 换成要扫的 VPS IP
```

整套流程都在 Clash Verge TUN 开启的状态下进行。TUN 开着时要注意三点：

1. **扫描流量会从当前代理节点发出去。** 如果当前节点正好就是要扫的这台 VPS，相当于在 VPS 上扫描。官方 README 提醒过，在云服务器上扫描可能被机房标记，所以范围控制在 /24 或公告前缀以内，并发不超过 10。
   如果想让扫描流量从本地宽带出去、同时 TUN 继续开着，可以在 Clash 规则最前面加一条直连规则（网段换成第 1 步查到的前缀）。这一条可选：
   ```
   IP-CIDR,1.2.0.0/22,DIRECT,no-resolve
   ```
2. **不要用 `dig` 查 DNS。** TUN 的 fake-ip 会返回 `198.18.x.x` 这种假地址，要用 DoH 查。`verify.py` 已经是用 DoH 查的，手动验证的命令见第 4 步。
3. **只认"DNS 解析回扫描 IP"的域名。** Clash 的 SNI 嗅探会把"连 IP + SNI"改写成按域名重新解析，所以用 `openssl`、`curl --resolve` 验证时，实际连上的是域名解析出来的那个 IP。只有 DNS 正好解析回扫描 IP 的域名（`same=True`），验证结果才对应扫描到的那台机器。其他域名本来就该剔除，不受影响。

## 第 1 步：查这个 IP 属于哪个 ASN、哪个前缀

```bash
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=$IP"
# 看 "asns" 和 "prefix"，例如 {"asns":["64500"],"prefix":"1.2.0.0/22"}

curl -s https://ipinfo.io/$IP      # 看所属机构和城市
```

## 第 2 步：扫描

```bash
mkdir -p scan-$IP && cd scan-$IP

# 先扫 VPS 所在的 /24（256 个地址，大约 1 分钟）
../RealiTLScanner/realitlscanner -addr ${IP%.*}.0/24 -thread 10 -timeout 5 -out scan_24.csv

# 合格的不够，再扩到第 1 步查到的前缀（/22 大约 4 分钟）
../RealiTLScanner/realitlscanner -addr 1.2.0.0/22 -thread 10 -timeout 5 -out scan_22.csv
```

注意：

- **`-addr` 一定要写网段（CIDR）。** 只写一个 IP 会进入无限扩散模式，一直扫下去。
- `-thread` 是并发数，不要超过 20；`-timeout` 是超时秒数，填 5。总共扫描的地址不要超过 4096 个。
- 结果里只会出现同时满足 TLS 1.3 和 h2 的 IP。CSV 的列依次是：`IP, ORIGIN, TLS, ALPN, CURVE, CERT_LENGTH, CERT_SIGNATURE, CERT_PUBLICKEY, CERT_DOMAIN, CERT_ISSUER, GEO_CODE`。
- 扫描时不带 SNI，拿到的是服务器默认证书。通配符证书（`*.xxx.com`）要从证书 SAN 里找具体域名，`verify.py` 会自动处理。

## 第 3 步：去掉没用的结果

```bash
grep -v -E 'localhost|Common Name|CloudFlare Origin|fastly|fnOS|Lucky|default.com' scan_24.csv | cut -d, -f1,5,9,10
# 输出四列：IP、密钥交换、证书域名、签发者
```

| 证书域名 / 签发者 | 是什么 | 处理 |
|---|---|---|
| `localhost` / FIT2CLOUD | 1Panel 面板的默认证书 | 丢掉 |
| `Common Name` / Organization（Ed25519） | 自签证书 | 丢掉 |
| `CloudFlare Origin Certificate` | 只在 Cloudflare 后面才有效的源站证书 | 丢掉 |
| `*.ssl.fastly.net` | Fastly CDN 的默认证书 | 丢掉 |
| `www.cloudflare.com` 之类的大站 | 基本是别人的 REALITY 节点 | 丢掉 |

## 第 4 步：验证候选

### 自动验证（推荐）

```bash
python3 -I ../reality-verify/verify.py scan_24.csv verify.json > /dev/null
python3 -I ../reality-verify/summary.py verify.json | grep "same=True"
```

只看 `same=True`（公网 DNS 正好解析回扫描到的 IP）的行，并且要求以下全部满足：

- `t13=True h2=True x=True vfy=True`：TLS 1.3、h2、X25519、证书和主机名校验都通过
- 状态码是 `200`
- `redir=` 为空（没有跳转）
- `cdn=False`

再对挑出来的几个做 5 次稳定性测试。先建 `shortlist.txt`，每行写"域名 空格 IP"：

```
example.com 1.2.3.10
example.org 1.2.3.20
```

```bash
python3 -I ../reality-verify/final.py shortlist.txt final.json
# 看 ok_of_5 是否为 5，以及 median_ms（握手延迟中位数）、证书签发者和到期时间
```

### 手动验证单个域名

`openssl` 要用 Homebrew 装的 OpenSSL 3（`/opt/homebrew/bin/openssl`），系统自带的 LibreSSL 不支持下面这些参数。

```bash
D=example.com; T=1.2.3.4   # 换成证书里的域名和扫描到的 IP

# 1. DNS（TUN 下用 DoH，不要用 dig）：必须解析到 $T；如果是 104.21.x / 172.67.x / 104.16.x 就是 Cloudflare，剔除
curl -s "https://dns.google/resolve?name=$D&type=A"

# 2. TLS：要同时看到 TLSv1.3、ALPN protocol: h2、X25519、Verify return code: 0 (ok)
echo | openssl s_client -connect $T:443 -servername $D -verify_hostname $D \
  -tls1_3 -alpn h2 -groups X25519 2>&1 | grep -E "TLSv1.3|ALPN|group|Verify return"

# 3. HTTP：要 200 且没有跳转地址；连跑 3 次，看握手时间是否稳定
curl -so /dev/null -w "%{http_code} %{redirect_url} %{time_appconnect}\n" --resolve $D:443:$T https://$D/

# 4. Xray：带 SNI 和不带 SNI 都要显示 Handshake succeeded
../xray/xray tls ping -ip $T $D

# 5. 解析出的 IP 属于哪个 ASN
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=$T"
```

## 第 5 步：挑选原则

1. **必须满足**：
   - DNS 解析和扫描 IP 一致
   - TLS 1.3、h2、X25519 和证书校验全部通过
   - 首页返回 200，没有跳转到其他域名
   - 不走 CDN
2. **网络接近程度**：同 /24 优先于同前缀，同前缀优先于同 ASN。
3. **站点质量**：正规的业务网站（公司官网、商业网站）优先于个人小站，后者可能随时下线。
4. **不要选**：
   - VPN 节点、转发面板（FLVX 等）、AI 接口中转站（Sub2API、UniAPI 等）、1Panel 等面板页
   - 盗版站
   - 返回 444、403、404、502 的
   - 域名以 `.ru`/`.ir`/`.cn` 结尾，或包含 `apple`、`icloud`、`microsoft` 的（Xray 会对这类域名发出风险警告）
5. **证书**：到期时间太近的，往后排。

## 第 6 步：填进 3x-ui / Xray

```
target: 域名:443
serverNames: ["域名"]
client SNI: 域名
```

最后在 VPS 上测一下 VPS 到目标的真实延迟（本机测到的包含国内到 VPS 那一段，不能代表这个延迟）：

```bash
for d in 域名1 域名2 域名3; do curl -so /dev/null -w "$d connect=%{time_connect} tls=%{time_appconnect}\n" https://$d/; done
```

---

## 附录 A：在 VPS 上扫描

官方 README 原文：*It is recommended to run this tool locally, as running the scanner in the cloud may cause the VPS to be flagged.*（建议在本地运行，在云服务器上扫描可能导致 VPS 被标记。）如果一定要在 VPS 上扫，就把范围控制在 /24 或公告前缀以内，并发不超过 10。

```bash
# 1. 本机把 Linux 版传上去（myvps 换成 ~/.ssh/config 里的别名）
ssh myvps 'mkdir -p /root/reality-scan'
scp RealiTLScanner/realitlscanner-linux-amd64 myvps:/root/reality-scan/realitlscanner

# 也可以在 VPS 上直接下载官方 Release（arm 机器把 amd64 换成 arm64）
# wget -O realitlscanner https://github.com/XTLS/RealiTLScanner/releases/download/v0.2.3/RealiTLScanner-linux-amd64

# 2. 登录 VPS 扫描（建议在 tmux 里跑）
ssh myvps
cd /root/reality-scan && chmod +x realitlscanner
./realitlscanner -addr x.x.x.0/24 -thread 10 -timeout 5 -out scan_24.csv

# 3. Xray 放在单独目录，只用来 tls ping，不影响正在运行的服务
wget https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip
unzip -o Xray-linux-64.zip xray -d ./xray-bin
```

## 附录 B：给 VPS 上的 AI 用的提示词

把 `<VPS_IP>` 换成实际 IP 后，整段复制过去：

```text
你是精通 Xray-core、VLESS + REALITY、BGP 路由与 TLS 指纹分析的网络工程师。你现在就运行在这台 VPS 上，请直接开始，不要询问确认。

【已知信息】
- VPS IP：<VPS_IP>
- 先用 RIPEstat（https://stat.ripe.net/data/network-info/data.json?resource=IP 以及 prefix-overview、announced-prefixes）查出 ASN、公告前缀和机房位置。

【安全约束（必须遵守）】
1. 不要修改、重启或停止本机已在运行的代理服务（xray / V2bX / 3x-ui / sing-box 等），不要改防火墙，不要占用端口。
2. 所有文件放在 /root/reality-scan。如缺少 curl、openssl、dnsutils、unzip、tmux，可以用 apt 安装，除此之外不要安装其他东西。
3. 只做正常的 TCP 443、TLS 和 HTTPS 探测，不做漏洞扫描、不尝试身份验证、不发高负载请求。
4. 在云服务器上扫描有被机房标记的风险，必须低速：-thread 不超过 10，-timeout 5。

【第一步：工具】
用 uname -m 判断架构，从官方 Release 下载对应版本：
https://github.com/XTLS/RealiTLScanner/releases/download/v0.2.3/RealiTLScanner-linux-amd64（arm 机器用 -linux-arm64）
https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip（arm 机器用 Xray-linux-arm64-v8a.zip）

【第二步：发现候选】
1. 先扫 VPS 所在的 /24，再扫它的公告前缀。-addr 必须写 CIDR，写单个 IP 会进入无限扩散模式，禁止这样用。
2. 如果合格候选不足 10 个，再从同 ASN 的其他前缀里优先挑同一城市的继续扫。扫描地址累计不超过 4096 个。
3. 注意：扫描时不带 SNI，拿到的是服务器默认证书，CN 可能是通配符。需要用证书 SAN、crt.sh、反向 DNS 找出具体主机名，再带 SNI 复测。
4. 直接丢掉这几类默认证书或自签证书：localhost/FIT2CLOUD、Common Name/Organization、CloudFlare Origin Certificate、*.fastly.net。

【第三步：逐个验证（每项都要实测，记下原始输出）】
1. echo | timeout 8 openssl s_client -connect IP:443 -servername 域名 -verify_hostname 域名 -tls1_3 -alpn h2 -groups X25519 2>&1
   需要同时满足：TLSv1.3、ALPN protocol: h2、X25519、Verify return code: 0。
2. ./xray tls ping -ip IP 域名：带 SNI 和不带 SNI 都要握手成功。
3. curl -sS -o /dev/null -w '%{http_version} %{http_code} %{redirect_url} %{time_connect} %{time_appconnect}\n' https://域名/
   重复至少 3 次，记录中位数；如果跳转到其他域名，要标注出来。
4. 分别用 dig @1.1.1.1 和 @8.8.8.8 解析，解析结果必须等于扫描到的 IP，或者至少在同一个 ASN 里。
5. CDN 判定：解析 IP 属于 Cloudflare(AS13335)、Akamai、Fastly，或响应头里有 cf-ray 的，都剔除。
6. Xray 风险警告：后缀为 .ru、.ir、.cn，或名字里含 apple、icloud、microsoft 的域名，剔除。
7. VPN 节点、转发面板、AI 接口中转站、1Panel 等面板页、盗版站，以及返回 444、403、404、502 的，剔除。

【第四步：排序】
按以下因素综合排序：网络接近性（同 /24 > 同前缀 > 同 ASN）、TLS 兼容性、5 次握手的稳定性、站点正规程度、延迟、证书质量与到期时间。

【第五步：交付】
1. 只给 10 个最推荐的域名，按推荐程度排序。每个写明：域名、解析 IP、ASN、TLS1.3/h2/X25519 结果、是否 CDN、是否跳转、延迟中位数（测量位置：本 VPS）、推荐理由与风险、验证时间。
2. 明确给出首选、第二、第三选择，每个附上可直接复制的配置：
   target: 域名:443
   serverNames: ["域名"]
   client SNI: 域名
3. 把全部候选（包括被剔除的及剔除原因）导出到 /root/reality-scan/candidates.csv。
4. 严格区分"实测通过"和"仅由公开资料推断"，不允许编造扫描结果、延迟或协议支持情况。
```
