import csv, json, os, platform, re, shutil, statistics, subprocess, sys, tempfile, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

# 同一套文件在 Mac 和 Linux VPS 上都能用：按系统和 CPU 架构选择工具
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ON_LINUX = platform.system() == "Linux"
ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower(),
                                                                                       platform.machine())
if ON_LINUX:
    SCANNER = os.path.join(ROOT, "RealiTLScanner", f"realitlscanner-linux-{ARCH}")
    XRAY = os.path.join(ROOT, "xray", f"xray-linux-{ARCH}")
else:
    SCANNER = os.path.join(ROOT, "RealiTLScanner", "realitlscanner")
    XRAY = os.path.join(ROOT, "xray", "xray")
# Mac 自带的 LibreSSL 不支持 -groups 等参数，优先用 Homebrew 的 OpenSSL 3
OPENSSL = "/opt/homebrew/bin/openssl" if os.path.exists("/opt/homebrew/bin/openssl") else shutil.which("openssl") or "openssl"
JUNK_CN = {"localhost", "Common Name", "fnOS", "Lucky", "default.com", "CloudFlare Origin Certificate"}
XRAY_WARN = re.compile(r"(\.ru|\.ir|\.cn)$|apple|icloud|microsoft")
_asn_cache = {}


def run(cmd, timeout=20, stdin=""):
    try:
        # 证书和网页里可能有非 UTF-8 字节，替换掉，不要让整个流程崩溃
        p = subprocess.run(cmd, input=stdin, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout)
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def read(path):
    try:
        return open(path, errors="ignore").read()
    except FileNotFoundError:
        return ""


def http_json(url):
    req = urllib.request.Request(url, headers={"accept": "application/dns-json", "user-agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def doh_a(name):
    out = {}
    for tag, url in (("google", f"https://dns.google/resolve?name={name}&type=A"),
                     ("cloudflare", f"https://cloudflare-dns.com/dns-query?name={name}&type=A")):
        try:
            d = http_json(url)
            out[tag] = [a["data"] for a in d.get("Answer", []) if a.get("type") == 1]
            out[tag + "_cname"] = [a["data"] for a in d.get("Answer", []) if a.get("type") == 5]
        except Exception as e:
            out[tag] = [f"ERR {e}"]
    return out


def asn_of(ip):
    if ip not in _asn_cache:
        try:
            d = http_json(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}")["data"]
            _asn_cache[ip] = (",".join(d.get("asns", [])), d.get("prefix", ""))
        except Exception as e:
            _asn_cache[ip] = (f"ERR {e}", "")
    return _asn_cache[ip]


def sans(ip):
    pem = run([OPENSSL, "s_client", "-connect", f"{ip}:443"], stdin="")
    txt = run([OPENSSL, "x509", "-noout", "-ext", "subjectAltName"], stdin=pem)
    return re.findall(r"DNS:([^,\s]+)", txt)


def tls_check(ip, d):
    o = run([OPENSSL, "s_client", "-connect", f"{ip}:443", "-servername", d, "-verify_hostname", d,
             "-tls1_3", "-alpn", "h2", "-groups", "X25519"], stdin="")
    return {
        "tls13": "TLSv1.3" in o,
        "h2": "ALPN protocol: h2" in o,
        "x25519": bool(re.search(r"(group|Temp Key): X25519\b", o)),
        "verify_ok": "Verify return code: 0 (ok)" in o,
        "verify_line": (re.search(r"Verify return code: .*", o) or [""])[0],
    }


def curl_check(ip, d):
    runs, last = [], {}
    tmp = tempfile.mkdtemp(prefix="rv_")
    bodyf, hdrf = f"{tmp}/body", f"{tmp}/hdr"
    for _ in range(3):
        o = run(["curl", "-sS", "-m", "12", "-o", bodyf, "-D", hdrf, "--resolve", f"{d}:443:{ip}",
                 "-A", "Mozilla/5.0", "-w", "%{http_version}|%{http_code}|%{redirect_url}|%{time_appconnect}|%{time_total}|%{size_download}",
                 f"https://{d}/"], timeout=20).strip().splitlines()
        line = o[-1] if o else ""
        parts = line.split("|")
        if len(parts) == 6:
            runs.append(float(parts[3]))
            hdr = read(hdrf).lower()
            body = read(bodyf)[:200000]
            title = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
            last = {"http_version": parts[0], "code": parts[1], "redirect": parts[2], "size": parts[5],
                    "server": (re.search(r"^server: (.*)$", hdr, re.M) or [None, ""])[1].strip(),
                    "cdn_hdr": any(h in hdr for h in ("cf-ray", "x-served-by", "x-amz-cf", "akamai")),
                    "title": re.sub(r"\s+", " ", title.group(1)).strip()[:60] if title else ""}
        else:
            last.setdefault("error", line[:120])
        time.sleep(0.3)
    last["tls_ms_runs"] = [round(x * 1000) for x in runs]
    last["tls_ms_median"] = round(statistics.median(runs) * 1000) if runs else None
    return last


def xray_ping(ip, d):
    o = run([XRAY, "tls", "ping", "-ip", ip, d], timeout=30)
    return {"xray_ok": o.count("Handshake succeeded"), "xray_domains": (re.findall(r"allowed domains:\s+\[(.*?)\]", o) or [""])[-1]}


def check(row):
    ip, cn = row["IP"], row["CERT_DOMAIN"]
    names = [cn] if not cn.startswith("*.") else []
    if not names:
        names = [s for s in sans(ip) if not s.startswith("*.")][:2] or ["www." + cn[2:]]
    results = []
    for d in names:
        r = {"domain": d, "scan_ip": ip, "scan_cn": cn, "issuer": row.get("CERT_ISSUER", ""), "scan_curve": row.get("CURVE", ""),
             "xray_warn": bool(XRAY_WARN.search(d.lower()))}
        dns = doh_a(d)
        r["dns_google"], r["dns_cf"] = dns.get("google"), dns.get("cloudflare")
        r["cname"] = dns.get("google_cname") or []
        ips = [x for x in (dns.get("google") or []) if not x.startswith("ERR")]
        r["dns_has_scan_ip"] = ip in ips
        r["dns_ip"] = ips[0] if ips else ""
        r["dns_asn"], r["dns_prefix"] = asn_of(ips[0]) if ips else ("", "")
        r.update(tls_check(ip, d))
        r.update(curl_check(ip, d))
        r.update(xray_ping(ip, d))
        r["checked_at"] = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        results.append(r)
    return results


def main(scan_csv, out_json):
    rows = [r for r in csv.DictReader(open(scan_csv, encoding="utf-8", errors="replace", newline=""))
            if r["CERT_DOMAIN"] not in JUNK_CN
            and not r["CERT_DOMAIN"].endswith(".fastly.net")]
    print(f"verifying {len(rows)} hosts", file=sys.stderr)
    with ThreadPoolExecutor(4) as ex:
        out = [x for res in ex.map(check, rows) for x in res]
    json.dump(out, open(out_json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    for r in out:
        print(json.dumps(r, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
