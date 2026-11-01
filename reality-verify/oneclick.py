"""一键扫描：给 VPS IP，自动扫描 → 剔除 → 验证 → 稳定性测试 → 打分 → 出报告。

用法：python3 -I oneclick.py <VPS_IP> [-n 推荐数量] [-t 并发] [--max-prefix 20]
从 VPS 所在 /24 开始扫，合格域名不够就按距离由近到远扫相邻的 /24（逐级翻倍到 /23、/22…），
只扫和 VPS 同 ASN、同城市的 /24，最远到 --max-prefix（默认 /20，即最多 4096 个地址）。
"""
import argparse, csv, importlib.util, ipaddress, json, os, re, statistics, subprocess, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("verify", os.path.join(HERE, "verify.py"))
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)
SCANNER = V.SCANNER

BIG_BRAND = re.compile(r"(^|\.)(cloudflare|microsoft|apple|icloud|amazon|google|yahoo|bing|samsung|nvidia|"
                       r"intel|amd|tesla|speedtest|github|azure|aws|dl\.google|swdist)\.")
BAD_TITLE = re.compile(r"welcome to (openresty|nginx)|apache2?.*default|default page|test page|it works|"
                       r"403 forbidden|404 not found|502 bad gateway|503 service|access temporarily unavailable|"
                       r"index of /|komari|nezha|哪吒|探针|1panel|宝塔|x-ui|3x-ui|s-ui|sub2api|uniapi|new api|one api|"
                       r"flvx|flux-panel|v2board|xboard|sspanel|nginx proxy manager|portainer|openwrt|"
                       r"speedtest|测速|subconverter|机场|节点|访问成功|站点创建成功|恭喜.{0,8}成功|hello,? world|"
                       r"coming soon|under construction|domain (is )?for sale|parked", re.I)
BAD_DOMAIN = re.compile(r"(^|[.-])(xui|x-ui|3xui|panel|vpn|proxy|v2ray|vless|vmess|trojan|hy2|hysteria|nezha|"
                        r"komari|status|probe|tz|speed|airport|sub|clash|reality|warp|ss|ssr|jms|node\d*)([.-]|$)")
DEFAULT_HOST = re.compile(r"(^|\.)(vps\d*|server\d+|host\d+|ip-\d+|static|colocrossing|hostname|localhost)([.-]|\d|$)"
                          r"|^\d+-\d+-\d+-\d+\.|\.vps\.")
FREE_SUFFIX = re.compile(r"\.(eu\.org|us\.kg|ccwu\.cc|kdns\.fr|de5\.net|dpdns\.org|qzz\.io|ggff\.net|xx\.kg|"
                         r"duckdns\.org|ddns\.net|nip\.io|sslip\.io|ip-ddns\.com|hidns\.(co|vip)|pp\.ua|"
                         r"workers\.dev|pages\.dev)$")
CONTENT_RISK = re.compile(r"影视|电影|电视剧|动漫|番剧|acg|绅士|成人|色情|福利|博彩|赌|彩票|"
                          r"\b(porn|xxx|casino|bet|torrent|warez|iptv)\b", re.I)
GENERIC_TITLES = {"", "home", "index", "welcome", "document", "untitled", "loading", "loading...", "app", "react app",
                  "vite app"}


def log(*a):
    print(*a, flush=True)


def egress_note(info):
    """说明扫描流量从哪出去、延迟代表什么。Linux 视为在 VPS 上直接运行，Mac 视为经 Clash TUN。"""
    if V.ON_LINUX:
        if info["egress"] == info["ip"]:
            return "在目标 VPS 上直接扫描", "延迟是在本 VPS 上直连测得，就是 VPS 到目标的真实延迟。"
        return (f"注意：本机出口 {info['egress'] or '?'} 不是目标 VPS",
                "延迟是在本机（不是目标 VPS）上直连测得，只能横向比较。")
    if info["egress"] == info["ip"]:
        return ("当前 Clash 节点就是这台 VPS，扫描流量从它发出",
                "延迟是本机经 Clash 节点测得，包含国内到节点那一段，只能横向比较，不代表 VPS 到目标的延迟。")
    return ("经 Clash TUN 当前节点发出",
            "延迟是本机经 Clash 节点测得，包含国内到节点那一段，只能横向比较，不代表 VPS 到目标的延迟。")


def http_json(url):
    req = urllib.request.Request(url, headers={"user-agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def vps_info(ip):
    info = {"ip": ip, "asn": "?", "prefix": "", "holder": "", "city": "", "org": "", "egress": ""}
    try:
        d = http_json(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}")["data"]
        info["asn"], info["prefix"] = ",".join(d.get("asns", [])) or "?", d.get("prefix", "")
        if info["prefix"]:
            p = http_json(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={info['prefix']}")["data"]
            info["holder"] = ", ".join(a.get("holder", "") for a in p.get("asns", []))
    except Exception as e:
        log(f"  [!] RIPEstat 查询失败：{e}")
    try:
        d = http_json(f"https://ipinfo.io/{ip}/json")
        info["city"], info["org"] = f"{d.get('city', '')}, {d.get('country', '')}", d.get("org", "")
    except Exception:
        pass
    try:
        info["egress"] = http_json("https://ipinfo.io/json").get("ip", "")
    except Exception:
        pass
    return info


def subnets24(ip, max_plen):
    """按距离由近到远给出 /24：先 VPS 所在 /24，再逐级翻倍后新增的相邻 /24，直到 /max_plen。"""
    cur = ipaddress.ip_network(f"{ip}/24", strict=False)
    yield cur
    while cur.prefixlen > max_plen:
        parent = cur.supernet()
        yield from next(s for s in parent.subnets() if s != cur).subnets(new_prefix=24)
        cur = parent


def same_site(sub, info):
    """相邻 /24 必须和 VPS 同 ASN、同城市才扫（ColoCrossing 这类机房是一个个 /24 分开宣告的）。"""
    probe = str(sub.network_address + 1)
    try:
        asns = http_json(f"https://stat.ripe.net/data/network-info/data.json?resource={probe}")["data"].get("asns", [])
    except Exception as e:
        return f"RIPEstat 查询失败（{e}）"
    if info["asn"] not in asns:
        return f"不同 ASN（{'AS' + ','.join(asns) if asns else '未宣告'}）"
    try:
        d = http_json(f"https://ipinfo.io/{probe}/json")
        city = f"{d.get('city', '')}, {d.get('country', '')}"
        if info["city"] and city != info["city"]:
            return f"不同城市（{city}）"
    except Exception:
        pass
    return ""


def scan_block(block, outdir, threads):
    name = str(block).replace("/", "_")
    path, done = f"{outdir}/scan_{name}.csv", f"{outdir}/scan_{name}.done"
    if os.path.exists(done):
        log(f"  {block}：使用已有扫描结果")
    else:
        n = block.num_addresses
        log(f"  {block}：扫描 {n} 个地址（并发 {threads}，超时 5 秒，约 {max(1, n // 256)}-{max(2, n // 128)} 分钟）…")
        subprocess.run([SCANNER, "-addr", str(block), "-thread", str(threads), "-timeout", "5", "-out", path],
                       capture_output=True)
        open(done, "w").write(time.strftime("%F %T"))
    return list(csv.DictReader(open(path, encoding="utf-8", errors="replace", newline="")))


def prefilter(row):
    cn = row["CERT_DOMAIN"]
    if cn in V.JUNK_CN or cn.endswith(".fastly.net") or not cn:
        return "默认证书/自签证书"
    if BIG_BRAND.search(cn.lower()):
        return "大站证书，基本是别人的 REALITY 节点"
    return ""


def redirect_ok(domain, url):
    host = re.sub(r"^https?://([^/:]+).*$", r"\1", url).lower() if url else ""
    if not host or host == domain:
        return "same"
    if host == "www." + domain or domain == "www." + host:
        return "www"
    return ""


def judge(r):
    d, title = r["domain"].lower(), (r.get("title") or "").lower()
    if r["xray_warn"]:
        return "Xray 风险名单（.ru/.ir/.cn/apple/icloud/microsoft）"
    if not r["dns_ip"]:
        return "公网 DNS 无 A 记录"
    if not r["dns_has_scan_ip"]:
        return "公网 DNS 指向 Cloudflare" if r["dns_asn"] == "13335" else \
            f"公网 DNS 指向别处 {r['dns_ip']}（AS{r['dns_asn']}）"
    if not (r["tls13"] and r["h2"] and r["x25519"]):
        return "TLS1.3 / h2 / X25519 不全"
    if not r["verify_ok"]:
        return "证书校验失败"
    code = r.get("code", "")
    if not (code.startswith("2") or (code.startswith("3") and redirect_ok(d, r.get("redirect", "")))):
        return f"HTTP {code or '无响应'}" + (f" 跳转到 {r['redirect']}" if r.get("redirect") else "")
    if r.get("cdn_hdr"):
        return "响应头显示走 CDN"
    if BAD_TITLE.search(title):
        return f"默认页/面板/代理相关页面（{r.get('title')}）"
    if BAD_DOMAIN.search(d):
        return "域名疑似代理/面板/探针"
    if DEFAULT_HOST.search(d):
        return "机房默认主机名"
    return ""


def stability(d, ip):
    pem = V.run([V.OPENSSL, "s_client", "-connect", f"{ip}:443", "-servername", d], stdin="")
    x = V.run([V.OPENSSL, "x509", "-noout", "-issuer", "-enddate"], stdin=pem)
    ms = []
    for _ in range(5):
        o = V.run(["curl", "-sS", "-m", "12", "-o", "/dev/null", "--resolve", f"{d}:443:{ip}", "-A", "Mozilla/5.0",
                   "-w", "%{http_code} %{time_appconnect}", f"https://{d}/"]).split()
        if len(o) == 2 and o[0] != "000":
            ms.append(float(o[1]) * 1000)
        time.sleep(0.5)
    issuer = re.search(r"issuer=.*?O\s*=\s*([^,\n]+)", x)
    end = re.search(r"notAfter=(.*)", x)
    days = None
    if end:
        try:
            not_after = datetime.strptime(" ".join(end.group(1).split()), "%b %d %H:%M:%S %Y %Z")
            days = (not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        except ValueError:
            pass
    return {"issuer": issuer.group(1).strip() if issuer else "?", "cert_days_left": days, "ok_of_5": len(ms),
            "ms": [round(m) for m in ms], "median_ms": round(statistics.median(ms)) if ms else None,
            "jitter_ms": round(max(ms) - min(ms)) if ms else None}


def common_plen(a, b):
    return 32 - (int(ipaddress.ip_address(a)) ^ int(ipaddress.ip_address(b))).bit_length()


def score(r, vps_ip):
    plen = common_plen(vps_ip, r["scan_ip"])
    net = 30 if plen >= 24 else max(0, 30 - (24 - plen) * 5)
    stab = 20 if r["ok_of_5"] == 5 else 10
    jit = max(0.0, 10 - (r["jitter_ms"] or 0) / 50)
    title = (r.get("title") or "").strip().lower()
    site = 15 if title not in GENERIC_TITLES and title != r["domain"].lower() else 5
    days = r["cert_days_left"]
    cert = 10 if days is None or days >= 30 else 5 if days >= 14 else 0
    notes, dom = [], 15
    if FREE_SUFFIX.search(r["domain"].lower()):
        dom -= 10; notes.append("免费二级域名")
    if re.search(r"\d{5,}", r["domain"]):
        dom -= 5; notes.append("数字域名")
    if CONTENT_RISK.search(title):
        dom -= 15; notes.append("盗版/成人/博彩类内容，可能被下架")
    if r["domain"].count(".") >= 3:
        dom -= 3; notes.append("子域名层级深")
    if r.get("redirect") and redirect_ok(r["domain"].lower(), r["redirect"]) == "www":
        dom -= 3; notes.append("www 跳转")
    if days is not None and days < 14:
        notes.append(f"证书 {days} 天后到期")
    if site == 5:
        notes.append("首页无有效标题")
    r["same_net"] = f"/{plen}" if plen < 24 else "同 /24"
    r["score"] = round(net + stab + jit + site + cert + dom)
    r["notes"] = "；".join(notes)
    return r


def write_outputs(outdir, info, scanned, skipped, rows, top, n):
    fields = ["rank", "status", "reason", "score", "domain", "scan_ip", "same_net", "dns_ip", "dns_asn", "tls13", "h2",
              "x25519", "verify_ok", "code", "redirect", "title", "server", "issuer", "cert_days_left", "ok_of_5",
              "median_ms", "jitter_ms", "notes", "checked_at"]
    with open(f"{outdir}/candidates.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r.get("rank") or 999, -(r.get("score") or 0))))
    json.dump(rows, open(f"{outdir}/results.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    now = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    md = [f"# REALITY 伪装目标扫描报告：{info['ip']}", "",
          f"- 时间：{now}",
          f"- VPS：AS{info['asn']} {info['holder']}，公告前缀 {info['prefix'] or '?'}，{info['city']}",
          f"- 扫描范围：{', '.join(scanned)}（共 {sum(ipaddress.ip_network(b).num_addresses for b in scanned)} 个地址）",
          f"- 跳过的相邻网段：{'; '.join(skipped) or '无'}",
          f"- 扫描出口：{info['egress'] or '?'}（{egress_note(info)[0]}）",
          f"- 结果：验证 {len(rows)} 个域名，合格 {len(top)} 个" + ("" if len(top) >= n else f"（不足 {n} 个）"), "",
          "## 推荐列表", "",
          "下面这些都已实测：DNS 解析回扫描 IP（同 ASN）、TLS 1.3 + h2 + X25519、证书校验通过、首页正常且不跨域跳转、"
          "不走 CDN、不在 Xray 风险名单、连续握手 5 次。", "",
          "| # | 域名 | IP | 距离 | 分数 | 握手 | 中位数 | 证书 | 首页标题 | 备注 |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in top:
        md.append(f"| {r['rank']} | {r['domain']} | {r['scan_ip']} | {r['same_net']} | {r['score']} | {r['ok_of_5']}/5 | "
                  f"{r['median_ms']}ms | {r['issuer']}，剩 {r['cert_days_left']} 天 | {(r.get('title') or '')[:30]} | "
                  f"{r['notes'] or '-'} |")
    md += ["", "## 配置（前三名）", ""]
    for r, label in zip(top[:3], ["首选", "第二", "第三"]):
        md += [f"**{label}：{r['domain']}**", "```", f"target: {r['domain']}:443",
               f"serverNames: [\"{r['domain']}\"]", f"client SNI: {r['domain']}", "```", ""]
    md += ["## 说明", "",
           f"- {egress_note(info)[1]}",
           "- \"同机房\"是根据同 ASN、同前缀推断的；没有做实际 REALITY 连接测试。"]
    if not (V.ON_LINUX and info["egress"] == info["ip"]):
        md.append("- 在 VPS 上测真实延迟：`for d in 域名1 域名2; do curl -so /dev/null -w \"$d %{time_appconnect}\\n\" https://$d/; done`")
    md.append("- 全部候选及剔除原因见 candidates.csv。")
    open(f"{outdir}/report.md", "w", encoding="utf-8").write("\n".join(md) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip")
    ap.add_argument("-n", type=int, default=10, help="推荐数量，默认 10")
    ap.add_argument("-t", type=int, default=10, help="扫描并发，默认 10，最大 20")
    ap.add_argument("--max-prefix", type=int, default=20, help="最多扩到多大的网段，默认 20（4096 个地址）")
    a = ap.parse_args()
    ipaddress.ip_address(a.ip)
    threads, max_plen = min(a.t, 20), min(max(a.max_prefix, 20), 24)
    outdir = os.path.join(ROOT, f"scan-{a.ip}")
    os.makedirs(outdir, exist_ok=True)

    log(f"[1/4] 查询 {a.ip} 的网络信息…")
    info = vps_info(a.ip)
    log(f"  AS{info['asn']} {info['holder']}  前缀 {info['prefix'] or '?'}  {info['city']}")
    log(f"  扫描出口 IP：{info['egress'] or '?'}  ← {egress_note(info)[0]}")
    for tool in (SCANNER, V.XRAY):
        if not os.access(tool, os.X_OK):
            sys.exit(f"缺少 {tool}，请用 ./scan.sh 运行（它会自动准备工具）")
    rows, top, scanned, skipped, seen = [], [], [], [], set()
    own = ipaddress.ip_network(f"{a.ip}/24", strict=False)
    for block in subnets24(a.ip, max_plen):
        log(f"[2/4] 网段 {block}")
        if block != own:
            why = same_site(block, info)
            if why:
                log(f"  跳过：{why}")
                skipped.append(f"{block}（{why}）")
                continue
        scanned.append(str(block))
        todo = []
        for row in scan_block(block, outdir, threads):
            if row["IP"] in seen:
                continue
            seen.add(row["IP"])
            why = prefilter(row)
            if why:
                rows.append({"status": "剔除", "reason": why, "domain": row["CERT_DOMAIN"], "scan_ip": row["IP"]})
            else:
                todo.append(row)
        log(f"[3/4] 验证 {len(todo)} 个带真实域名的主机（DoH 解析 / TLS / HTTP / xray tls ping）…")
        with ThreadPoolExecutor(6) as ex:
            checked = [x for res in ex.map(V.check, todo) for x in res]
        good = []
        for r in checked:
            r["reason"] = judge(r)
            r["status"] = "剔除" if r["reason"] else "候选"
            if r["status"] == "候选":
                good.append(r)
        log(f"  通过初筛 {len(good)} 个，做 5 次握手稳定性测试…")
        with ThreadPoolExecutor(4) as ex:
            for r, s in zip(good, ex.map(lambda r: stability(r["domain"], r["scan_ip"]), good)):
                r.update(s)
                if r["ok_of_5"] < 4:
                    r["status"], r["reason"] = "剔除", f"握手不稳定（{r['ok_of_5']}/5）"
                else:
                    score(r, a.ip)
        rows += checked
        top = sorted((r for r in rows if r["status"] == "候选"), key=lambda r: (-r["score"], r["median_ms"] or 9e9))
        log(f"  目前合格 {len(top)} 个（目标 {a.n} 个）")
        if len(top) >= a.n:
            break
    if len(top) < a.n:
        log(f"  已扩到上限 /{max_plen}，只找到 {len(top)} 个合格的")

    for i, r in enumerate(top):
        if i < a.n:
            r["rank"], r["status"], r["reason"] = i + 1, "推荐", f"第 {i + 1} 名"
        else:
            r["status"], r["reason"] = "备选", "合格但排在推荐数量之外"
    top = top[:a.n]
    write_outputs(outdir, info, scanned, skipped, rows, top, a.n)

    log(f"\n[4/4] 结果（{len(top)} 个）")
    for r in top:
        log(f"  {r['rank']:>2}. {r['domain']:<36} {r['scan_ip']:<15} {r['same_net']:<6} 分数 {r['score']:<3} "
            f"握手 {r['ok_of_5']}/5 中位数 {r['median_ms']}ms  {(r.get('title') or '')[:24]}  {r['notes']}")
    for r, label in zip(top[:3], ["首选", "第二", "第三"]):
        log(f"\n  {label}：\n    target: {r['domain']}:443\n    serverNames: [\"{r['domain']}\"]\n    client SNI: {r['domain']}")
    log(f"\n报告：{outdir}/report.md\n全部候选：{outdir}/candidates.csv")


if __name__ == "__main__":
    main()
