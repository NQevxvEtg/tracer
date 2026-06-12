#!/usr/bin/env python3
"""
Read tracer JSON, produce a clean, compact diagnostic report.
Usage: render_report.py <facts.json> <output.html>
"""

import json
import re
import sys
from pathlib import Path


def parse_mtr_hops(raw):
    hops = []
    for line in raw.replace("\t", "\n").splitlines():
        if not re.search(r"^\s*\d+\.\|--", line):
            continue
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            hop = int(parts[0].replace("|--", "").replace(".", "").strip())
            hops.append({
                "hop": hop, "host": parts[1],
                "loss_pct": float(parts[2].rstrip("%")),
                "avg_ms": float(parts[5]),
            })
        except (ValueError, IndexError):
            continue
    return hops


def find_spike(hops):
    if len(hops) < 2:
        return None
    jumps = []
    prev = 0
    for h in hops:
        if h["host"] == "???" or h["loss_pct"] == 100:
            continue
        j = max(0, h["avg_ms"] - prev)
        if j > 30:
            jumps.append({"hop": h, "jump_ms": round(j)})
        prev = h["avg_ms"]
    return jumps if jumps else None


def load_tracer_json(path, demo=False):
    wrapper = json.loads(Path(path).read_text())
    checks = wrapper.get("checks", [])
    data = {"_target": wrapper.get("target", ""), "_port": wrapper.get("port")}

    if demo:
        import re as _re
        raw = json.dumps(wrapper)
        raw = _re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'x.x.x.x', raw)
        raw = _re.sub(r'\b[\w.-]+\.(?:com|net|org|edu|net|gov|io|co|uk|jp)\b', 'example.com', raw)
        raw = _re.sub(r'\b[\w-]+\.localdomain\b', 'corp.example.com', raw)
        raw = raw.replace('rhel8-server', 'app-server-01')
        raw = raw.replace('wgivpn', 'ens192')
        raw = raw.replace('Arch Linux', 'Red Hat Enterprise Linux 9.4')
        raw = _re.sub(r'"uptime_seconds":\s*[\d.]+', '"uptime_seconds": 3600.0', raw)
        raw = _re.sub(r'"hostname":\s*"[\w-]+"', '"hostname": "app-server-01"', raw)
        raw = _re.sub(r'"os":\s*"[^"]+"', '"os": "Red Hat Enterprise Linux 9.4"', raw)
        wrapper = json.loads(raw)
        checks = wrapper.get("checks", [])
        data["_target"] = wrapper.get("target", "")
        data["_port"] = wrapper.get("port")

    for c in checks:
        name = c["name"]
        d = c.get("data", {})
        status = c.get("status")

        if name.startswith("Ping"):
            data["ping_avg_ms"] = d.get("rtt_avg_ms")
            data["ping_min_ms"] = d.get("rtt_min_ms")
            data["ping_max_ms"] = d.get("rtt_max_ms")
            data["ping_loss_pct"] = d.get("packet_loss_pct")
            data["ping_raw"] = c.get("raw", "")
            data["ping_status"] = status
        elif "System" in name:
            data["hostname"] = d.get("hostname", "")
            data["local_ip"] = d.get("local_ip", "")
            data["os"] = d.get("os", "")
            data["uptime"] = int(float(d.get("uptime_seconds", 0))) // 3600
        elif "resolv.conf" in name:
            data["nameservers"] = d.get("nameservers", [])
            data["search_domains"] = d.get("search_domains", [])
        elif name.startswith("DNS Resolution"):
            data["dns_ips"] = d.get("ips", [])
            data["dns_status"] = status
        elif "per-resolver" in name:
            data["resolver_results"] = d.get("results", [])
        elif "tcpdump" in name:
            data["tcpdump_status"] = status
        elif "Curl timing" in name:
            data["curl_total_ms"] = d.get("total_ms")
            data["curl_dns_ms"] = d.get("dns_ms")
            data["curl_tcp_ms"] = d.get("tcp_handshake_ms")
            data["curl_tls_ms"] = d.get("tls_handshake_ms")
            data["curl_server_ms"] = d.get("server_process_ms")
            data["curl_transfer_ms"] = d.get("transfer_ms")
            data["curl_http_code"] = d.get("http_code")
        elif "Traceroute" in name:
            data["traceroute_raw"] = c.get("raw", "")
        elif "PMTU" in name or "MTU" in name:
            data["pmtu"] = d.get("pmtu")
        elif "Port" in name:
            data["port_status"] = status
        elif "Listening sockets" in name or name == "ss":
            data["ss_total"] = d.get("total_listeners")
        elif "SELinux" in name:
            data["selinux_enforcing"] = d.get("enforcing", False)
            data["selinux_status"] = status
        elif "Firewall" in name:
            data["fw_status"] = status
        elif "HTTP/TLS" in name:
            data["http_version"] = d.get("http_version", "")
            data["tls_version"] = d.get("tls_version", "")
            data["tls_cipher"] = d.get("tls_cipher", "")
            data["server_header"] = d.get("server_header", "")
            data["tls_key_exchange"] = d.get("tls_key_exchange", "")
            data["content_encoding"] = d.get("content_encoding", "")
            data["content_length"] = d.get("content_length")
        elif "IP route" in name:
            data["ip_route"] = d.get("route", "")
            data["ip_gateway"] = d.get("gateway", "")
            data["ip_interface"] = d.get("interface", "")
            data["ip_source"] = d.get("source_ip", "")
        elif "Page asset" in name:
            data["html_size"] = d.get("html_size_bytes", 0)
            data["asset_count"] = d.get("asset_references", 0)
            data["script_count"] = d.get("script_tags", 0)
            data["css_count"] = d.get("stylesheet_tags", 0)
            data["img_count"] = d.get("image_tags", 0)

    # Build latency analysis
    data["_mtr_hops"] = parse_mtr_hops(data.get("traceroute_raw", ""))
    spikes = find_spike(data["_mtr_hops"])
    if spikes:
        spike_lines = "<br>".join(
            f"Hop {s['hop']['hop']} ({s['hop']['host']}) avg {s['hop']['avg_ms']}ms, jump +{s['jump_ms']}ms"
            for s in spikes
        )
        data["_mtr_spikes"] = spike_lines
    else:
        data["_mtr_spikes"] = ""

    data["_verdict"] = verdict(data)

    return data


def verdict(d):
    c_server = d.get("curl_server_ms") or 0
    c_tls = d.get("curl_tls_ms") or 0
    c_dns = d.get("curl_dns_ms") or 0
    c_transfer = d.get("curl_transfer_ms") or 0
    p_avg = d.get("ping_avg_ms") or 0

    if c_server > 2000:
        return f"SERVER: Server processing takes {c_server:.0f}ms — check app logic, DB queries, backend API calls"
    if c_tls > 500:
        return f"TLS: TLS handshake takes {c_tls:.0f}ms — check OCSP stapling, cipher negotiation, cert chain size"
    if c_dns > 200:
        return f"DNS: DNS resolution takes {c_dns:.0f}ms — check /etc/resolv.conf, resolver latency"
    slowest = 0
    slow_ns = ""
    for r in d.get("resolver_results", []):
        if r.get("elapsed_ms", 0) > slowest:
            slowest = r["elapsed_ms"]
            slow_ns = r.get("resolver", "?")
    if slowest > 200:
        return f"DNS_RESOLVER: Resolver {slow_ns} takes {slowest:.0f}ms — remove or reorder in /etc/resolv.conf"
    if p_avg > 100:
        return f"NETWORK: Baseline RTT {p_avg:.0f}ms — check ISP peering, F5, VPN, routing"
    if d.get("_mtr_spikes"):
        count = d["_mtr_spikes"].count("<br>") + 1
        return f"NETWORK_HOP: {count} latency spike{'s' if count > 1 else ''} detected<br>{d['_mtr_spikes']}"
    if c_transfer > 2000:
        return f"PAYLOAD: Content transfer takes {c_transfer:.0f}ms — enable compression, use CDN, reduce asset size"
    return "OK: No bottleneck detected — all metrics within normal ranges"


def _pf(v):
    try:
        return float(v) if v is not None else 0.0
    except (ValueError, TypeError):
        return 0.0


def _rating(val, good, ok):
    """Return CSS class for a value against good/ok thresholds."""
    v = _pf(val)
    if v <= good: return "good"
    if v <= ok: return "okr"
    return "badr"


def fmt_ms(v):
    if v is None:
        return "—"
    try:
        return f"{float(v):.0f}ms"
    except (ValueError, TypeError):
        return "—"


def fmt_pct(v, total):
    if not total:
        return "—"
    try:
        return f"{float(v) / float(total) * 100:.0f}%"
    except (ValueError, TypeError, ZeroDivisionError):
        return "—"


def render(data, demo=False):
    d = data
    target = d["_target"]
    port = d.get("_port", "")
    addr = f"{target}:{port}" if port else target
    scheme = "http" if str(port) == "80" else "https"
    curl_url = f"{scheme}://{addr}"

    rows = []

    # Header
    rows.append(f"<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Tracer — {addr}</title>")
    rows.append("<style>")
    rows.append("*{margin:0;padding:0;box-sizing:border-box}")
    rows.append("body{font-family:'SF Mono','Menlo','Monaco','Courier New',monospace;font-size:13px;line-height:1.5;max-width:900px;margin:0 auto;padding:20px 24px;color:#000;background:#c0c0c0}")
    rows.append("h1{font-size:15px;font-weight:700;padding:0 0 6px 0;margin:0 0 12px 0;border-bottom:2px solid #808080;color:#000}")
    rows.append("h2{font-size:13px;font-weight:700;padding:0;margin:20px 0 2px 0;color:#000}")
    rows.append(".cmd-sub{font-size:11px;color:#666;margin:0 0 8px 0;font-family:inherit}")
    rows.append("p{margin:4px 0}")
    rows.append("table{width:100%;border-collapse:collapse;margin:8px 0 14px 0}")
    rows.append("th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #808080;font-size:12px}")
    rows.append("th{font-weight:700;border-bottom:2px solid #000}")
    rows.append(".verdict{padding:8px 12px;margin:0 0 18px 0;border-left:4px solid #f0c000;font-weight:700;background:#ffffe0}")
    rows.append(".verdict.ok{border-left-color:#4a4;background:#e0ffe0}")
    rows.append(".verdict.bad{border-left-color:#c00;background:#ffe0e0}")
    rows.append(".num{font-weight:700}")
    rows.append(".warn{color:#800}")
    rows.append(".fail{color:#c00;font-weight:700}")
    rows.append(".good{color:#1a7f37;font-weight:700}")
    rows.append(".okr{color:#bf8700;font-weight:700}")
    rows.append(".badr{color:#cf222e;font-weight:700}")
    rows.append("code,.code{font-family:inherit;font-size:12px}")
    rows.append("pre{background:#fff;padding:10px 12px;overflow-x:auto;font-size:11px;line-height:1.5;max-height:400px;overflow-y:auto;border:2px inset #ddd;margin:8px 0}")
    rows.append("details{margin:8px 0}summary{cursor:pointer;font-weight:700;font-size:12px}")
    rows.append("details[open] summary{margin-bottom:8px}")
    rows.append("</style></head><body>")

    # Title
    rows.append(f"<h1>Tracer Report — {addr}</h1>")
    rows.append(f"<p>Source: {d.get('hostname','?')} ({d.get('local_ip','?')}) — {d.get('os','?')} — uptime {d.get('uptime','?')}h</p>")

    # --- VERDICT ---
    v = d["_verdict"]
    vc = "bad" if v.startswith("SERVER") else "warn" if not v.startswith("OK") else "ok"
    rows.append(f"<div class='verdict {vc}'>{v}</div>")

    # Anomaly: TCP handshake vs ping RTT
    ping = (d.get("ping_avg_ms") or 0)
    tcp = (d.get("curl_tcp_ms") or 0)
    if ping > 0 and tcp > 0 and tcp > ping * 1.5:
        rows.append(f"<p class='warn'><strong>Anomaly:</strong> TCP handshake ({fmt_ms(tcp)}) is {tcp/ping:.1f}x ping RTT ({fmt_ms(ping)}). "
                     "A TCP handshake takes exactly 1 RTT — this discrepancy suggests local gateway bufferbloat, VPN overhead, or aggressive QoS.</p>")

    # --- QUICK STATS ---
    rows.append("<h2>Key Metrics</h2>")
    rows.append("<table>")
    rows.append("<tr><th>Metric</th><th>Value</th><th>Command</th></tr>")
    rows.append(f"<tr><td>Ping RTT</td>"
                f"<td class='{_rating(d.get('ping_avg_ms'), 30, 100)}'>{fmt_ms(d.get('ping_avg_ms'))} (min {fmt_ms(d.get('ping_min_ms'))}, max {fmt_ms(d.get('ping_max_ms'))})</td>"
                f"<td><code>ping -c 4 -W 2 {target}</code></td></tr>")
    rows.append(f"<tr><td>Packet Loss</td>"
                f"<td class='{_rating(d.get('ping_loss_pct'), 0, 1)}'>{d.get('ping_loss_pct','—')}%</td>"
                f"<td></td></tr>")
    rows.append(f"<tr><td>Port</td>"
                f"<td class='{'good' if d.get('port_status') == 'PASS' else 'badr'}'>{'OPEN' if d.get('port_status') == 'PASS' else 'CLOSED' if d.get('port_status') else 'N/A'}</td>"
                f"<td><code>nc -zv -w 3 {target} {port or 443}</code></td></tr>")
    rows.append("</table>")

    # --- CURL WATERFALL ---
    total = d.get("curl_total_ms")
    if total:
        rows.append("<h2>Request Timing (curl)</h2>")
        rows.append(f"<div class='cmd-sub'>curl -sS -o /dev/null -w ... --connect-timeout 10 --max-time 30 {curl_url}</div>")

        rows.append("<table>")
        rows.append("<tr><th>Stage</th><th>Time</th><th>Share</th><th>What to check</th></tr>")
        segs = [
            ("DNS lookup", d.get("curl_dns_ms"), "Check /etc/resolv.conf order, resolver latency"),
            ("TCP handshake", d.get("curl_tcp_ms"), "Network RTT to target, SYN/ACK round trip"),
            ("TLS handshake", d.get("curl_tls_ms"), "OCSP stapling, cert chain, cipher suite"),
            ("Server processing", d.get("curl_server_ms"), "App logic, DB queries, upstream API calls"),
            ("Content transfer", d.get("curl_transfer_ms"), "Compression, CDN, asset sizes"),
        ]
        max_ms = max(s[1] or 0 for s in segs) or 1
        for label, ms, advice in segs:
            bar = "█" * int((ms or 0) / max_ms * 20)
            thresholds = {"DNS lookup": (20, 100), "TCP handshake": (ping*1.0, ping*1.5),
                         "TLS handshake": (ping*1.0, ping*2.0), "Server processing": (100, 500),
                         "Content transfer": (50, 500)}.get(label, (0, 999))
            c = _rating(ms or 0, thresholds[0], thresholds[1])
            rows.append(f"<tr><td>{label}</td><td class='{c}'>{fmt_ms(ms)}</td><td class='{c}'>{fmt_pct(ms, total)}</td><td>{advice}</td></tr>")
        rows.append(f"<tr><th>Total</th><th class='{_rating(total, 0, 3000)}'>{fmt_ms(total)}</th><th></th><th></th></tr>")
        rows.append("</table>")

    # --- HTTP/TLS ---
    http_ver = d.get("http_version", "")
    tls_ver = d.get("tls_version", "")
    tls_cipher = d.get("tls_cipher", "")
    server = d.get("server_header", "")
    encoding = d.get("content_encoding", "")
    if http_ver or tls_ver:
        rows.append("<h2>HTTP / TLS</h2>")
        rows.append(f"<div class='cmd-sub'>curl -sI {curl_url} ; openssl s_client -connect {target}:{port or 443}</div>")
        rows.append("<table>")
        if http_ver:
            rows.append(f"<tr><td>HTTP version</td><td>{http_ver}</td></tr>")
        if tls_ver:
            rows.append(f"<tr><td>TLS version</td><td>{tls_ver}</td></tr>")
        if tls_cipher:
            rows.append(f"<tr><td>TLS cipher</td><td>{tls_cipher}</td></tr>")
        if d.get("tls_key_exchange"):
            rows.append(f"<tr><td>Key exchange</td><td>{d['tls_key_exchange']}</td></tr>")
        if server:
            rows.append(f"<tr><td>Server</td><td>{server}</td></tr>")
        if encoding:
            rows.append(f"<tr><td>Content encoding</td><td>{encoding}</td></tr>")
        cl = d.get("content_length")
        if cl:
            rows.append(f"<tr><td>Content-Length</td><td>{cl} bytes</td></tr>")
        rows.append("</table>")
        if http_ver == "HTTP/1.1":
            rows.append("<p class='warn'>Server uses HTTP/1.1 — subject to head-of-line blocking. Check if HTTP/2 or HTTP/3 is available.</p>")
        if tls_ver and "1.3" not in tls_ver and "TLSv1.3" not in tls_ver:
            rows.append("<p class='warn'>TLS 1.2 takes 2 RTTs for handshake. TLS 1.3 takes 1 RTT. Consider upgrading.</p>")

    # --- Page Assets ---
    asset_count = d.get("asset_count", 0)
    html_size = d.get("html_size", 0)
    if asset_count > 0 or html_size > 0:
        rows.append("<h2>Page Content</h2>")
        rows.append(f"<div class='cmd-sub'>curl -sL {curl_url}</div>")
        rows.append("<table>")
        if html_size:
            rows.append(f"<tr><td>HTML size</td><td>{html_size} bytes ({html_size/1024:.0f} KB)</td></tr>")
        if asset_count:
            rows.append(f"<tr><td>Asset references</td><td>{asset_count} (scripts, stylesheets, images, embeds)</td></tr>")
        if d.get("script_count"):
            rows.append(f"<tr><td>Script tags</td><td>{d['script_count']}</td></tr>")
        if d.get("css_count"):
            rows.append(f"<tr><td>Stylesheet tags</td><td>{d['css_count']}</td></tr>")
        if d.get("img_count"):
            rows.append(f"<tr><td>Image tags</td><td>{d['img_count']}</td></tr>")
        rows.append("</table>")
        if asset_count > 50:
            rows.append(f"<p class='warn'>High asset count ({asset_count} references) — each asset requires a separate HTTP request. "
                         f"Consider bundling, HTTP/2 multiplexing, or a CDN. With {fmt_ms(ping)}ms baseline RTT, this compounds load time.</p>")
        if html_size > 100000:
            rows.append(f"<p class='warn'>Large HTML payload ({html_size/1024:.0f} KB) — check if server is embedding inline assets or uncompressed data.</p>")
    # --- IP ROUTE ---
    route = d.get("ip_route", "")
    if route:
        rows.append("<h2>Local Route</h2>")
        rows.append(f"<div class='cmd-sub'>ip route get {target}</div>")
        rows.append("<table>")
        if d.get("ip_gateway"):
            rows.append(f"<tr><td>Gateway</td><td>{d['ip_gateway']}</td></tr>")
        if d.get("ip_interface"):
            rows.append(f"<tr><td>Interface</td><td>{d['ip_interface']}</td></tr>")
        if d.get("ip_source"):
            rows.append(f"<tr><td>Source IP</td><td>{d['ip_source']}</td></tr>")
        rows.append(f"<tr><td>Full route</td><td><code>{route}</code></td></tr>")
        rows.append("</table>")

    results = d.get("resolver_results", [])
    ns_list = d.get("nameservers", [])
    search = d.get("search_domains", [])
    if ns_list:
        rows.append("<h2>DNS Configuration</h2>")
        rows.append("<div class='cmd-sub'>cat /etc/resolv.conf</div>")
        rows.append("<table>")
        rows.append(f"<tr><td>Nameservers</td><td>{' '.join(ns_list)}</td></tr>")
        rows.append(f"<tr><td>Search domains</td><td>{' '.join(search) if search else '(none)'}</td></tr>")
        rows.append("</table>")

    if results:
        rows.append("<h2>Per-Resolver Timing</h2>")
        rows.append(f"<div class='cmd-sub'>dig @NS +short +time=3 +tries=1 {target}</div>")
        rows.append("<table>")
        rows.append("<tr><th>Resolver</th><th>Response</th><th>Status</th></tr>")
        for r in results:
            ok = r.get("success", r.get("status") == "OK")
            st = "OK" if ok else "FAIL"
            rows.append(f"<tr><td>{r.get('resolver','?')}</td>"
                        f"<td>{r.get('elapsed_ms','?')}ms</td>"
                        f"<td class='{'fail' if st == 'FAIL' else ''}'>{st}</td></tr>")
        rows.append("</table>")

    # --- MTR ---
    hops = d.get("_mtr_hops", [])
    if hops:
        spike = d.get("_mtr_spikes", "")
        rows.append("<h2>Route (mtr)</h2>")
        rows.append(f"<div class='cmd-sub'>mtr --report --report-wide -c 10 {target}</div>")
        rows.append("<table>")
        rows.append("<tr><th>Hop</th><th>Host</th><th>Avg</th><th>Loss</th><th>Rating</th></tr>")
        prev_avg = 0
        for idx, h in enumerate(hops):
            jump = h["avg_ms"] - prev_avg
            is_silent = h["host"] == "???" or h["loss_pct"] == 100
            prev_silent = idx > 0 and (hops[idx-1]["host"] == "???" or hops[idx-1]["loss_pct"] == 100)
            is_spike = idx > 0 and jump > 40 and not prev_silent and not is_silent
            flag = " ← SPIKE" if is_spike else ""
            if is_silent:
                rating, label = "", "—"
            elif is_spike:
                rating, label = "badr", "spike"
            elif h["avg_ms"] < 30:
                rating, label = "good", "good"
            elif h["avg_ms"] < 100:
                rating, label = "okr", "ok"
            else:
                rating, label = "badr", "slow"
            host_display = h["host"]
            if idx == 0:
                host_display += " (your gateway)"
            elif idx == len(hops) - 1:
                host_display += " (target)"
            rows.append(f"<tr><td>{h['hop']}</td><td>{host_display}</td>"
                        f"<td>{h['avg_ms']:.0f}ms{flag}</td>"
                        f"<td>{h['loss_pct']:.0f}%</td>"
                        f"<td class='{rating}'>{label}</td></tr>")
            if not is_silent:
                prev_avg = h["avg_ms"]
        rows.append("</table>")
        tr_raw = d.get("traceroute_raw", "")
        if tr_raw.strip() and not demo:
            rows.append("<details>")
            rows.append("<summary>Raw mtr output</summary>")
            rows.append(f"<pre>{tr_raw}</pre>")
            rows.append("</details>")
        if spike:
            rows.append(f"<p class='warn'><strong>Latency spike:</strong> {spike}</p>")

    # --- PMTU ---
    pmtu = d.get("pmtu")
    if pmtu:
        rows.append(f"<h2>Path MTU</h2>")
        rows.append(f"<div class='cmd-sub'>tracepath -n {target}</div>")
        rows.append(f"<p>{pmtu} bytes</p>")

    # --- ISSUES ---
    issues = []
    if d.get("port_status") == "FAIL":
        issues.append(f"Port {port} unreachable — check firewall, service status, SELinux")
    if d.get("selinux_enforcing") and d.get("selinux_status") == "WARN":
        issues.append(f"SELinux enforcing but no port label for {port}")
    if d.get("fw_status") == "WARN":
        issues.append(f"No firewall rule found for port {port}")
    if d.get("tcpdump_status") == "WARN":
        issues.append("tcpdump captured no DNS packets — DNS may be cached, or no queries were needed")
    if issues:
        rows.append("<h2>Issues Found</h2>")
        for i in issues:
            rows.append(f"<p class='warn'>• {i}</p>")
    else:
        rows.append("<h2>Issues Found</h2>")
        rows.append("<p>• No issues detected — SELinux, firewall, and port checks all passed or not applicable.</p>")

    # --- ANALYSIS ---
    rows.append("<h2>Analysis &amp; Next Steps</h2>")
    rows.append("<table>")
    rows.append("<tr><th>Metric</th><th>Your Value</th><th>Rating</th><th>What This Means</th></tr>")

    ping = _pf(d.get("ping_avg_ms"))
    loss = _pf(d.get("ping_loss_pct"))
    dns_per = d.get("resolver_results", [])

    def metric_row(label, value, suffix, thresholds, note):
        v = _pf(value)
        if v < thresholds[0]: rating, css, word = "good", "good", "good"
        elif v < thresholds[1]: rating, css, word = "okr", "okr", "ok"
        else: rating, css, word = "badr", "badr", "slow"
        rows.append(f"<tr><td>{label}</td><td class='{css}'>{value}{suffix}</td><td class='{css}'>{word}</td><td>{note}</td></tr>")

    metric_row("Ping RTT", fmt_ms(ping).replace("ms",""), "ms", (30, 100),
               "Baseline round-trip time. Affects every stage: DNS, TCP, TLS, server.")
    if loss >= 0:
        word2 = "good" if loss == 0 else "badr"
        css2 = "good" if loss == 0 else "badr"
        rows.append(f"<tr><td>Packet loss</td><td class='{css2}'>{loss:.0f}%</td><td class='{css2}'>{word2}</td>"
                     "<td>Any loss causes TCP retransmissions — throughput drops sharply.</td></tr>")

    tcp = _pf(d.get("curl_tcp_ms"))
    if tcp:
        ratio = tcp / ping if ping > 0 else 0
        if ratio < 1.0: tcp_rating, tcp_word = "good", "good"
        elif ratio < 1.5: tcp_rating, tcp_word = "okr", "ok"
        else: tcp_rating, tcp_word = "badr", "slow"
        rows.append(f"<tr><td>TCP handshake</td><td class='{tcp_rating}'>{tcp:.0f}ms ({ratio:.1f}x RTT)</td>"
                    f"<td class='{tcp_rating}'>{tcp_word}</td>"
                     "<td>TCP handshake = 1 RTT. Higher means bufferbloat, QoS throttling, or SYN delays.</td></tr>")

    tls = _pf(d.get("curl_tls_ms"))
    if tls:
        tls_rtt = tls / ping if ping > 0 else 0
        if tls_rtt <= 1.2: tls_rating, tls_word = "good", "good"
        elif tls_rtt <= 2.2: tls_rating, tls_word = "okr", "ok"
        else: tls_rating, tls_word = "badr", "slow"
        rows.append(f"<tr><td>TLS handshake</td><td class='{tls_rating}'>{tls:.0f}ms (~{tls_rtt:.0f} RTT)</td>"
                    f"<td class='{tls_rating}'>{tls_word}</td>"
                     "<td>TLS 1.3 = 1 RTT. TLS 1.2 = 2 RTTs. More = OCSP fetch or large cert chain.</td></tr>")

    server = _pf(d.get("curl_server_ms"))
    if server:
        metric_row("Server processing", f"{server:.0f}", "ms", (100, 500),
                   "Time from TLS complete to first byte. App logic, DB queries, backend API calls.")

    # DNS resolver analysis
    if dns_per:
        for r in dns_per[:3]:
            ns = r.get("resolver", "?")
            ms = r.get("elapsed_ms", 0)
            metric_row(f"DNS resolver {ns}", f"{ms:.0f}", "ms", (20, 100),
                      "DNS response time from this resolver. Should be <20ms cached.")
    if d.get("search_domains") and len(d.get("search_domains", [])) > 2:
        rows.append(f"<tr><td>Search domains</td><td class='badr'>{len(d['search_domains'])}</td>"
                     "<td class='badr'>slow</td>"
                     "<td>Each domain adds a retry on short-name lookups. Reduce to 1-2.</td></tr>")

    # MTR hop count and spike
    hops = d.get("_mtr_hops", [])
    if hops:
        spike = d.get("_mtr_spikes", "")
        rows.append(f"<tr><td>Route hops</td><td>{len(hops)}</td>"
                     f"<td class='{'good' if len(hops) < 15 else 'okr'}'>{'good' if len(hops) < 15 else 'ok'}</td>"
                     "<td>Number of routers between you and target. <15 normal, >20 may indicate circuitous path.</td></tr>")
        if spike:
            rows.append(f"<tr><td>Latency spike</td><td class='badr'>{spike}</td>"
                         "<td class='badr'>slow</td>"
                         "<td>This hop introduces significant latency — likely a congested link, routing change, or distant gateway.</td></tr>")

    rows.append("</table>")

    # Actionable summary
    rows.append("<p style='margin-top:12px'><strong>Summary:</strong> ")
    if ping < 30:
        rows.append("Network latency is good. ")
    elif ping < 100:
        rows.append(f"Network latency is acceptable at {ping:.0f}ms. ")
    else:
        rows.append(f"Network latency is high at {ping:.0f}ms — this is the primary bottleneck. ")
        gw = d.get("ip_gateway", "")
        iface = d.get("ip_interface", "")
        if "vpn" in iface.lower() or "tun" in iface.lower():
            rows.append(f"Traffic is routed through <code>{iface}</code> — VPN overhead is likely contributing. Try disconnecting the VPN and re-running.")
        elif gw:
            rows.append(f"Check your connection to gateway <code>{gw}</code>. Run <code>mtr {target}</code> for live hop-by-hop.")

    if loss > 0:
        rows.append(f" Packet loss at {loss:.0f}% — investigate link quality.")
    if dns_per:
        slow_dns = [r for r in dns_per if r.get("elapsed_ms", 0) > 100]
        if slow_dns:
            rows.append(f" DNS resolver{'' if len(slow_dns)==1 else 's'} {', '.join(r['resolver'] for r in slow_dns)} {'is' if len(slow_dns)==1 else 'are'} slow ({', '.join(str(r['elapsed_ms'])+'ms' for r in slow_dns)}).")

    if not ping and not dns_per:
        rows.append("Insufficient data — re-run with <code>-p PORT</code> if targeting a web server.")

    rows.append("</p>")

    # --- RAW ---
    rows.append("<h2>Commands Executed</h2>")
    rows.append("<table>")
    rows.append("<tr><th>Check</th><th>Command</th><th>What it tells you</th></tr>")
    rows.append(f"<tr><td>System info</td><td><code>hostname; cat /etc/os-release; cat /proc/uptime</code></td><td>Host identity, OS version, uptime</td></tr>")
    rows.append(f"<tr><td>Resolv.conf</td><td><code>cat /etc/resolv.conf</code></td><td>DNS nameservers and search domains</td></tr>")
    rows.append(f"<tr><td>DNS resolution</td><td><code>dig +short +time=3 {target}</code></td><td>Resolved IPs and DNS latency</td></tr>")
    rows.append(f"<tr><td>DNS per-resolver</td><td><code>dig @NS +short +time=3 +tries=1 {target}</code></td><td>Each resolver's response time — finds slow ones</td></tr>")
    rows.append(f"<tr><td>Ping</td><td><code>ping -c 4 -W 2 {target}</code></td><td>Baseline RTT, jitter, packet loss</td></tr>")
    rows.append(f"<tr><td>Traceroute</td><td><code>mtr --report --report-wide -c 10 {target}</code></td><td>Per-hop latency — where latency enters the path</td></tr>")
    rows.append(f"<tr><td>PMTU</td><td><code>tracepath -n {target}</code></td><td>Path MTU — detects fragmentation issues</td></tr>")
    rows.append(f"<tr><td>Port check</td><td><code>nc -zv -w 3 {target} {port or 443}</code></td><td>TCP connectivity — is the port reachable</td></tr>")
    rows.append(f"<tr><td>Curl timing</td><td><code>curl -sS -o /dev/null -w '...' {curl_url}</code></td><td>Segmented request timing: DNS, TCP, TLS, server, transfer</td></tr>")
    rows.append(f"<tr><td>SS listeners</td><td><code>ss -tlnp</code></td><td>Local listening sockets — is the service running</td></tr>")
    rows.append(f"<tr><td>Firewall</td><td><code>iptables -L -n -v; nft list ruleset; firewall-cmd --list-all</code></td><td>Active firewall rules — is the port blocked</td></tr>")
    rows.append(f"<tr><td>SELinux</td><td><code>cat /sys/fs/selinux/enforce; semanage port -l</code></td><td>SELinux enforcement and port labels</td></tr>")
    rows.append(f"<tr><td>tcpdump DNS</td><td><code>tcpdump -i any -n port 53 -c 20</code></td><td>Wire-level DNS query/response timing per resolver</td></tr>")
    rows.append("</table>")

    # --- LATENCY REFERENCE ---
    rows.append("<h2>Latency Reference</h2>")
    rows.append("<table>")
    rows.append("<tr><th>Metric</th><th>Good</th><th>OK</th><th>Slow</th><th>Notes</th></tr>")
    rows.append("<tr><td>Ping RTT</td><td class='good'>&lt; 30ms</td><td class='okr'>30–100ms</td><td class='badr'>&gt; 100ms</td><td>Local network 1–5ms; cross-country 50–80ms; transatlantic 80–120ms</td></tr>")
    rows.append("<tr><td>DNS lookup</td><td class='good'>&lt; 20ms</td><td class='okr'>20–100ms</td><td class='badr'>&gt; 100ms</td><td>Cached should be &lt;5ms; first lookup depends on resolver distance</td></tr>")
    rows.append("<tr><td>TCP handshake</td><td class='good'>= ping RTT</td><td class='okr'>ping × 1.0–1.5</td><td class='badr'>&gt; ping × 1.5</td><td>TCP handshake is 1 RTT. Higher = bufferbloat or QoS throttling SYN</td></tr>")
    rows.append("<tr><td>TLS handshake</td><td class='good'>1 RTT</td><td class='okr'>2 RTT</td><td class='badr'>&gt; 2 RTT</td><td>TLS 1.3 = 1 RTT; TLS 1.2 = 2 RTTs; more = OCSP fetch or oversized cert chain</td></tr>")
    rows.append("<tr><td>Server processing</td><td class='good'>&lt; 100ms</td><td class='okr'>100–500ms</td><td class='badr'>&gt; 500ms</td><td>Time from TLS done to first byte. App logic, DB queries, backend calls</td></tr>")
    rows.append("<tr><td>Content transfer</td><td class='good'>&lt; 50ms</td><td class='okr'>50–500ms</td><td class='badr'>&gt; 500ms</td><td>Depends on payload size. 1MB over 100ms RTT = ~100ms with TCP window</td></tr>")
    rows.append("<tr><td>MTR hop jump</td><td class='good'>&lt; 10ms</td><td class='okr'>10–30ms</td><td class='badr'>&gt; 30ms</td><td>Large jump between hops = congestion or routing change at that hop</td></tr>")
    rows.append("<tr><td>Packet loss</td><td class='good'>0%</td><td class='okr'>&lt; 1%</td><td class='badr'>&gt; 1%</td><td>Any loss causes TCP retransmission — exponentially slows throughput</td></tr>")
    rows.append("</table>")

    if not demo:
        rows.append("<details>")
        rows.append("<summary>Raw JSON</summary>")
        raw_json = Path(sys.argv[1]).read_text()
        rows.append(f"<pre>{raw_json[:8000]}</pre>")
        rows.append("</details>")

    rows.append("</body></html>")
    return "\n".join(rows)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: render_report.py <facts.json> [output.html] [--demo]")
        print("  --demo  Redact source hostname/IP/OS for screenshots")
        sys.exit(0)

    json_path = sys.argv[1]
    output = Path(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else Path("report.html")
    demo = "--demo" in sys.argv

    data = load_tracer_json(json_path, demo)
    html = render(data, demo)
    output.write_text(html)
    print(f"Report: {output}")


if __name__ == "__main__":
    main()
