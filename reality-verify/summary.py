import json, sys

for r in json.load(open(sys.argv[1])):
    print(f"{r['domain'][:34]:34} {r['scan_ip']:15} dns={','.join(r['dns_google'] or [])[:32]:32} same={r['dns_has_scan_ip']!s:5} "
          f"asn={r['dns_asn']:7} t13={r['tls13']!s:5} h2={r['h2']!s:5} x={r['x25519']!s:5} vfy={r['verify_ok']!s:5} "
          f"{r.get('http_version', '')} {r.get('code', '')} redir={r.get('redirect', '')[:40]} ms={r.get('tls_ms_runs')} "
          f"xr={r['xray_ok']} srv={r.get('server', '')[:14]} cdn={r.get('cdn_hdr')} title={r.get('title', '')[:30]} "
          f"err={r.get('error', '')[:40]}")
