import json, re, statistics, subprocess, sys, time

OPENSSL = "/opt/homebrew/bin/openssl"


def run(cmd, stdin="", timeout=20):
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


out = []
for line in open(sys.argv[1]):
    d, ip = line.split()
    pem = run([OPENSSL, "s_client", "-connect", f"{ip}:443", "-servername", d], stdin="")
    x = run([OPENSSL, "x509", "-noout", "-issuer", "-enddate", "-ext", "subjectAltName"], stdin=pem)
    ms, ok = [], 0
    for _ in range(5):
        o = run(["curl", "-sS", "-m", "12", "-o", "/dev/null", "--resolve", f"{d}:443:{ip}", "-A", "Mozilla/5.0",
                 "-w", "%{http_code} %{time_appconnect}", f"https://{d}/"]).split()
        if len(o) == 2 and o[0] != "000":
            ok += 1
            ms.append(float(o[1]) * 1000)
        time.sleep(0.5)
    r = {"domain": d, "ip": ip,
         "issuer": (re.search(r"issuer=.*?O=([^,]+)", x) or [None, "?"])[1].strip(),
         "not_after": (re.search(r"notAfter=(.*)", x) or [None, "?"])[1].strip(),
         "san_count": len(re.findall(r"DNS:", x)),
         "ok_of_5": ok, "ms": [round(m) for m in ms],
         "median_ms": round(statistics.median(ms)) if ms else None,
         "checked_at": time.strftime("%Y-%m-%d %H:%M:%S %Z")}
    out.append(r)
    print(json.dumps(r, ensure_ascii=False), flush=True)
json.dump(out, open(sys.argv[2], "w"), ensure_ascii=False, indent=1)
