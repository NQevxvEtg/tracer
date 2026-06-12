#!/usr/bin/env python3
"""
Tracer — comprehensive network diagnostics for sysadmins.
Runs DNS, ping, traceroute, tracepath (PMTU), port check, ss, SELinux,
and firewall checks against a target host:port. Produces a clean report.
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Tuple


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------

class CheckResult:
    def __init__(self, name, status="PENDING", raw="", data=None, error="", duration_ms=0.0, order=0):
        self.name = name
        self.status = status
        self.raw = raw
        self.data = data if data is not None else {}
        self.error = error
        self.duration_ms = duration_ms
        self.order = order


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _run(cmd, timeout=30):
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            env={**os.environ, "LANG": "C"},
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return -127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -124, "", f"timed out after {timeout}s"


def _which(binary: str) -> bool:
    return shutil.which(binary) is not None


def _maybe_int(s):
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

def check_dns(target: str) -> CheckResult:
    """Resolve target hostname via dig and getaddrinfo."""
    r = CheckResult(name="DNS Resolution")
    t0 = time.monotonic()

    # If it's already an IP, skip dig
    try:
        socket.inet_pton(socket.AF_INET, target)
        is_ip = True
    except OSError:
        is_ip = False
    try:
        socket.inet_pton(socket.AF_INET6, target)
        is_ip_v6 = True
    except OSError:
        is_ip_v6 = False

    if is_ip or is_ip_v6:
        r.status = "SKIP"
        r.raw = f"Target is an IP address ({target}), no DNS needed"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    # dig +short
    if _which("dig"):
        rc, out, err = _run(["dig", "+short", "+time=3", target])
        r.raw = out or err
        if rc == 0 and out:
            ips = [l.strip() for l in out.splitlines() if l.strip()]
            r.data["ips"] = ips
            r.status = "PASS"
        else:
            r.status = "FAIL"
            r.error = f"dig returned rc={rc}"
    else:
        # fallback to getaddrinfo
        try:
            info = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = sorted({a[4][0] for a in info})
            r.data["ips"] = ips
            r.raw = "\n".join(ips)
            r.status = "PASS"
        except socket.gaierror as e:
            r.status = "FAIL"
            r.error = str(e)
            r.raw = str(e)

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_ping(target: str) -> CheckResult:
    """Ping target — 4 packets, capture latency and loss."""
    r = CheckResult(name="Ping (latency / loss)")
    t0 = time.monotonic()

    if not _which("ping"):
        r.status = "SKIP"
        r.error = "ping not available"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    rc, out, err = _run(["ping", "-c", "4", "-W", "2", target], timeout=15)
    r.raw = out or err

    if rc == 0:
        # parse summary line: "4 packets transmitted, 4 received, 0% packet loss"
        loss_match = re.search(r"(\d+)% packet loss", out)
        r.data["packet_loss_pct"] = _maybe_int(loss_match.group(1)) if loss_match else None

        # parse rtt line: "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.789 ms"
        rtt_match = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
        if rtt_match:
            r.data["rtt_min_ms"] = float(rtt_match.group(1))
            r.data["rtt_avg_ms"] = float(rtt_match.group(2))
            r.data["rtt_max_ms"] = float(rtt_match.group(3))
            r.data["rtt_mdev_ms"] = float(rtt_match.group(4))

        r.status = "PASS"
    else:
        r.status = "FAIL"
        r.error = out or err or f"ping failed rc={rc}"

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_traceroute(target: str) -> CheckResult:
    """Traceroute / mtr report."""
    r = CheckResult(name="Traceroute")
    t0 = time.monotonic()

    # Prefer mtr --report for richer output
    if _which("mtr"):
        rc, out, err = _run(["mtr", "--report", "--report-wide", "-c", "10", target], timeout=60)
        r.raw = out or err
        r.status = "PASS" if rc == 0 else "WARN"
        if rc != 0:
            r.error = f"mtr rc={rc}"
    elif _which("traceroute"):
        rc, out, err = _run(["traceroute", "-n", "-w", "2", target], timeout=30)
        r.raw = out or err
        r.status = "PASS" if rc == 0 else "WARN"
        if rc != 0:
            r.error = f"traceroute rc={rc}"
    else:
        r.status = "SKIP"
        r.error = "neither mtr nor traceroute available"

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_pMTU(target: str) -> CheckResult:
    """Discover path MTU via tracepath."""
    r = CheckResult(name="Path MTU (PMTU)")
    t0 = time.monotonic()

    if not _which("tracepath"):
        r.status = "SKIP"
        r.error = "tracepath not available"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    rc, out, err = _run(["tracepath", "-n", target], timeout=30)
    r.raw = out or err

    # parse "pmtu XXXX" lines
    pmtu_match = re.search(r"pmtu (\d+)", out or "")
    if pmtu_match:
        r.data["pmtu"] = int(pmtu_match.group(1))

    r.status = "PASS" if rc == 0 else "WARN"
    if rc != 0:
        r.error = err or f"tracepath rc={rc}"

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_port(target: str, port: int) -> CheckResult:
    """TCP connect check to target:port via nc and raw socket."""
    r = CheckResult(name=f"Port reachability (:{port})")
    t0 = time.monotonic()

    # raw socket first (fast, reliable)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, port))
        r.data["socket_connect"] = "open"
        sock.close()
        r.status = "PASS"
        r.raw = f"TCP connect to {target}:{port} succeeded"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        r.data["socket_connect"] = f"closed/blocked ({e})"
        r.status = "FAIL"
        r.error = str(e)
        r.raw = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # also try nc for cross-check
    if _which("nc"):
        rc, out, err = _run(["nc", "-zv", "-w", "3", target, str(port)], timeout=10)
        r.data["nc_check"] = "open" if rc == 0 else f"closed/filtered (rc={rc})"

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_ss(port: int) -> CheckResult:
    """ss -tlnp to check listening services on localhost."""
    r = CheckResult(name="Listening sockets (ss)")
    t0 = time.monotonic()

    if not _which("ss"):
        r.status = "SKIP"
        r.error = "ss not available"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    rc, out, err = _run(["ss", "-tlnp"], timeout=10)
    r.raw = out or err

    # Find lines mentioning the port
    port_str = str(port)
    matching = [l for l in (out or "").splitlines() if port_str in l.replace(":", " ").split()]
    r.data["matching_listeners"] = matching
    r.data["total_listeners"] = len((out or "").splitlines()) - 1 if out else 0

    r.status = "PASS" if matching else "WARN"
    if not matching:
        r.error = f"No listener on port {port} found locally"

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_selinux_port(port: int) -> CheckResult:
    """Check if SELinux labels a specific port (semanage port -l)."""
    r = CheckResult(name=f"SELinux port labels (:{port})")
    t0 = time.monotonic()

    # Check if SELinux is enforcing
    selinux_path = "/sys/fs/selinux/enforce"
    try:
        with open(selinux_path, "r") as f:
            enforcing = f.read().strip() == "1"
    except OSError:
        enforcing = False

    if not enforcing:
        r.status = "SKIP"
        r.raw = "SELinux not in enforcing mode (or unavailable)"
        r.data["enforcing"] = False
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    r.data["enforcing"] = True

    if not _which("semanage"):
        r.status = "SKIP"
        r.error = "semanage not available"
        r.raw = "Install policycoreutils-python-utils for semanage"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    # semanage port -l | grep 'tcp\|TYPE\|<port>'
    rc, out, err = _run(["semanage", "port", "-l"], timeout=15)
    if rc != 0:
        r.status = "SKIP"
        r.error = err or f"semanage rc={rc}"
        r.raw = err
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    r.raw = out
    port_str = str(port)
    matching = [l for l in out.splitlines() if port_str in l.split()]
    r.data["matching_labels"] = matching

    r.status = "PASS" if matching else "WARN"
    if not matching:
        r.error = f"No SELinux port label found for port {port}"

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_firewall(port: int) -> CheckResult:
    """Check iptables/nftables rules matching the port."""
    r = CheckResult(name=f"Firewall rules (port :{port})")
    t0 = time.monotonic()

    port_str = str(port)
    results = {}

    # iptables
    if _which("iptables"):
        rc, out, err = _run(["iptables", "-L", "-n", "-v"], timeout=10)
        if rc == 0:
            matching = [l for l in out.splitlines() if f"dpt:{port_str}" in l or f"spt:{port_str}" in l]
            results["iptables"] = matching
        else:
            results["iptables"] = {"error": err or f"rc={rc}"}

    # nft
    if _which("nft"):
        rc, out, err = _run(["nft", "list", "ruleset"], timeout=10)
        if rc == 0:
            matching = [l for l in out.splitlines() if port_str in l.split()]
            results["nftables"] = matching
        else:
            results["nftables"] = {"error": err or f"rc={rc}"}

    # firewalld
    if _which("firewall-cmd"):
        rc, out, err = _run(["firewall-cmd", "--list-all"], timeout=10)
        if rc == 0:
            results["firewalld"] = out
        else:
            results["firewalld"] = {"error": err or f"rc={rc}"}

    if not results:
        r.status = "SKIP"
        r.error = "no firewall tooling available (iptables, nft, firewall-cmd)"
    else:
        has_match = any(
            (isinstance(v, list) and len(v) > 0) or (isinstance(v, str) and port_str in v)
            for v in results.values()
            if isinstance(v, (list, str))
        )
        r.status = "PASS" if has_match else "WARN"
        if not has_match:
            r.error = f"No firewall rule referencing port {port} found"

    r.data = results
    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_curl_timing(target: str, port: int, tls=None) -> CheckResult:
    """curl -w timing breakdown: DNS, TCP, TLS, TTFB, total."""
    if tls is None:
        tls = port != 80
    r = CheckResult(name="Curl timing breakdown")
    t0_time = time.monotonic()

    if not _which("curl"):
        r.status = "SKIP"
        r.error = "curl not available"
        r.duration_ms = (time.monotonic() - t0_time) * 1000
        return r

    scheme = "https" if tls else "http"
    url = f"{scheme}://{target}:{port}"
    fmt = "time_namelookup: %{time_namelookup}\\ntime_connect: %{time_connect}\\ntime_appconnect: %{time_appconnect}\\ntime_starttransfer: %{time_starttransfer}\\ntime_total: %{time_total}\\nhttp_code: %{http_code}\\nremote_ip: %{remote_ip}"

    rc, out, err = _run(
        ["curl", "-sS", "-o", "/dev/null", "-w", fmt, "--connect-timeout", "10", "--max-time", "30", url],
        timeout=40,
    )
    r.raw = (out or "") + "\n" + (err or "")

    if rc != 0:
        r.status = "FAIL"
        r.error = err or f"curl failed rc={rc}"
        r.duration_ms = (time.monotonic() - t0_time) * 1000
        return r

    parsed = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            parsed[k.strip()] = v.strip()

    r.data["remote_ip"] = parsed.get("remote_ip", "")
    r.data["http_code"] = _maybe_int(parsed.get("http_code", ""))

    def _ms(val, default=0.0):
        try:
            return round(float(val) * 1000, 1)
        except (ValueError, TypeError):
            return default

    dns_ms = _ms(parsed.get("time_namelookup", "0"))
    tcp_connect = _ms(parsed.get("time_connect", "0"))
    tcp_ms = round(tcp_connect - dns_ms, 1)
    tls_app = _ms(parsed.get("time_appconnect", "0"))
    tls_ms = round(tls_app - tcp_connect, 1)
    ttfb_ms = _ms(parsed.get("time_starttransfer", "0"))
    server_ms = round(ttfb_ms - tls_app, 1)
    total_ms = _ms(parsed.get("time_total", "0"))
    transfer_ms = round(total_ms - ttfb_ms, 1)

    r.data["dns_ms"] = dns_ms
    r.data["tcp_handshake_ms"] = tcp_ms
    r.data["tls_handshake_ms"] = tls_ms
    r.data["server_process_ms"] = server_ms
    r.data["ttfb_ms"] = ttfb_ms
    r.data["transfer_ms"] = transfer_ms
    r.data["total_ms"] = total_ms

    segments = [
        ("DNS lookup", dns_ms),
        ("TCP handshake", tcp_ms),
        ("TLS handshake", tls_ms),
        ("Server processing (TTFB - TLS)", server_ms),
        ("Content transfer", transfer_ms),
    ]
    slowest = max(segments, key=lambda x: x[1])
    r.data["bottleneck_segment"] = slowest[0]
    r.data["bottleneck_ms"] = slowest[1]

    r.status = "PASS" if total_ms > 0 else "WARN"
    r.duration_ms = (time.monotonic() - t0_time) * 1000
    return r


def check_http_protocol(target, port, tls=None):
    """Check HTTP protocol version and TLS details."""
    if tls is None:
        tls = port != 80
    r = CheckResult(name="HTTP/TLS protocol")
    t0_time = time.monotonic()

    if not _which("curl"):
        r.status = "SKIP"; r.error = "curl not available"
        r.duration_ms = (time.monotonic() - t0_time) * 1000; return r

    scheme = "https" if tls else "http"
    url = f"{scheme}://{target}:{port}"

    rc, out, err = _run(
        ["curl", "-sI", "--connect-timeout", "10", "--max-time", "15", url],
        timeout=20,
    )
    r.raw = (out or "") + "\n" + (err or "")

    http_ver = ""
    for line in (out or "").splitlines():
        if line.upper().startswith("HTTP/"):
            http_ver = line.split()[0]
        if line.lower().startswith("server:"):
            r.data["server_header"] = line.split(":", 1)[1].strip()
        if line.lower().startswith("content-length:"):
            r.data["content_length"] = _maybe_int(line.split(":", 1)[1].strip())
        if line.lower().startswith("content-type:"):
            r.data["content_type"] = line.split(":", 1)[1].strip()
        if line.lower().startswith("content-encoding:"):
            r.data["content_encoding"] = line.split(":", 1)[1].strip()

    r.data["http_version"] = http_ver

    # TLS check via openssl
    if tls and _which("openssl"):
        rc2, out2, err2 = _run(
            ["openssl", "s_client", "-connect", f"{target}:{port}", "-servername", target],
            timeout=15,
        )
        for line in (out2 or "").splitlines():
            if "Protocol" in line and ":" in line:
                r.data["tls_version"] = line.split(":", 1)[1].strip()
            if "Cipher" in line and ":" in line and "Cipher Suite" not in line:
                r.data["tls_cipher"] = line.split(":", 1)[1].strip()
            if "Server Temp Key" in line and ":" in line:
                r.data["tls_key_exchange"] = line.split(":", 1)[1].strip()

    r.status = "PASS" if http_ver else "WARN"
    if not http_ver:
        r.error = "No HTTP response"

    r.duration_ms = (time.monotonic() - t0_time) * 1000
    return r


def check_page_assets(target, port, tls=None):
    """Count page dependencies (src/href references)."""
    if tls is None:
        tls = port != 80
    r = CheckResult(name="Page asset count")
    t0_time = time.monotonic()

    if not _which("curl"):
        r.status = "SKIP"; r.error = "curl not available"
        r.duration_ms = (time.monotonic() - t0_time) * 1000; return r

    scheme = "https" if tls else "http"
    url = f"{scheme}://{target}:{port}"

    rc, out, err = _run(
        ["curl", "-sL", "--connect-timeout", "10", "--max-time", "20", url],
        timeout=25,
    )

    if rc != 0:
        r.status = "FAIL"
        r.error = err or f"curl failed rc={rc}"
        r.duration_ms = (time.monotonic() - t0_time) * 1000
        return r

    body_size = len(out.encode("utf-8")) if out else 0
    src_count = len(re.findall(r'\s(src|href)=["\']', out or ""))
    script_count = len(re.findall(r'<script\b', out or ""))
    style_count = len(re.findall(r'<link[^>]*stylesheet', out or ""))
    img_count = len(re.findall(r'<img\b', out or ""))

    r.data["html_size_bytes"] = body_size
    r.data["asset_references"] = src_count
    r.data["script_tags"] = script_count
    r.data["stylesheet_tags"] = style_count
    r.data["image_tags"] = img_count

    r.status = "PASS"
    if src_count > 50:
        r.status = "WARN"
        r.error = f"High asset count: {src_count} references — page may load many external resources"

    r.duration_ms = (time.monotonic() - t0_time) * 1000
    return r


def check_ip_route(target):
    """Check local routing table for the target IP."""
    r = CheckResult(name="IP route")
    t0_time = time.monotonic()

    if not _which("ip"):
        r.status = "SKIP"; r.error = "ip command not available"
        r.duration_ms = (time.monotonic() - t0_time) * 1000; return r

    # Resolve target to IP first
    ip_target = target
    try:
        info = socket.getaddrinfo(target, None)
        ip_target = info[0][4][0]
    except (socket.gaierror, IndexError):
        pass

    rc, out, err = _run(["ip", "route", "get", ip_target], timeout=10)
    r.raw = out or err

    if rc == 0 and out:
        r.data["route"] = out.strip()
        # Parse out the gateway and interface
        gw_match = re.search(r"via\s+(\S+)", out)
        dev_match = re.search(r"dev\s+(\S+)", out)
        src_match = re.search(r"src\s+(\S+)", out)
        r.data["gateway"] = gw_match.group(1) if gw_match else ""
        r.data["interface"] = dev_match.group(1) if dev_match else ""
        r.data["source_ip"] = src_match.group(1) if src_match else ""
        r.status = "PASS"
    else:
        r.status = "WARN"
        r.error = err or "ip route get failed"

    r.duration_ms = (time.monotonic() - t0_time) * 1000
    return r


def _parse_mtr_hops(raw):
    hops = []
    for line in (raw or "").splitlines():
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


def _find_latency_spike(hops):
    if len(hops) < 2:
        return None
    biggest = None
    prev = 0
    for h in hops:
        jump = max(0, h["avg_ms"] - prev)
        if biggest is None or jump > biggest["jump_ms"]:
            biggest = {"hop": h, "jump_ms": round(jump)}
        prev = h["avg_ms"]
    return biggest


def analyze_latency(results):
    analysis = {"verdict": "unknown", "evidence": [], "bottleneck": ""}

    curl = next((r for r in results if r.name == "Curl timing breakdown"), None)
    ping = next((r for r in results if r.name.startswith("Ping")), None)
    tr = next((r for r in results if r.name == "Traceroute"), None)
    dns = next((r for r in results if r.name == "DNS Resolution"), None)
    dns_per = next((r for r in results if r.name == "DNS per-resolver timing"), None)

    if curl and curl.status not in ("SKIP", "ERROR"):
        b_ms = curl.data.get("bottleneck_ms", 0)
        analysis["evidence"].append(f"Curl bottleneck: {curl.data.get('bottleneck_segment','?')} ({b_ms}ms)")
        if curl.data.get("total_ms", 0) > 3000:
            analysis["evidence"].append(f"Total page load > 3s ({curl.data['total_ms']}ms) -- SLOW")
        analysis["curl"] = {k: v for k, v in curl.data.items()}

    if ping and ping.status == "PASS":
        avg = ping.data.get("rtt_avg_ms")
        loss = ping.data.get("packet_loss_pct")
        if avg is not None:
            analysis["evidence"].append(f"Ping avg RTT: {avg}ms")
            if avg > 100:
                analysis["evidence"].append("Network latency >100ms -- potential issue")
        if loss is not None and loss > 0:
            analysis["evidence"].append(f"Packet loss: {loss}%")
        analysis["ping"] = {k: v for k, v in ping.data.items()}

    if tr and tr.status == "PASS" and tr.raw:
        hops = _parse_mtr_hops(tr.raw)
        spike = _find_latency_spike(hops)
        if spike:
            h = spike["hop"]
            analysis["evidence"].append(
                f"Biggest RTT jump: hop {h['hop']} ({h['host']}) +{spike['jump_ms']}ms (avg {h['avg_ms']}ms)"
            )
            analysis["mtr_spike"] = spike

    if dns and dns.status == "PASS":
        analysis["dns_ms"] = round(dns.duration_ms, 1)

    if dns_per and dns_per.status in ("PASS", "WARN", "FAIL"):
        slowest_ms = dns_per.data.get("slowest_ms", 0)
        slowest_ns = dns_per.data.get("slowest_resolver", "")
        if slowest_ms > 100:
            analysis["evidence"].append(f"Slow resolver: {slowest_ns} ({slowest_ms}ms)")

    if curl and curl.data.get("server_process_ms", 0) > 2000:
        analysis["verdict"] = "SERVER"
        analysis["bottleneck"] = "Server-side processing (app logic, DB queries, backend calls)"
    elif curl and curl.data.get("tls_handshake_ms", 0) > 500:
        analysis["verdict"] = "TLS"
        analysis["bottleneck"] = "TLS/SSL handshake -- check cert chain, OCSP, cipher negotiation"
    elif curl and curl.data.get("dns_ms", 0) > 200:
        analysis["verdict"] = "DNS"
        analysis["bottleneck"] = "DNS resolution is slow -- check AD DNS, FreeIPA, resolvers"
    elif dns_per and dns_per.data.get("slowest_ms", 0) > 200:
        analysis["verdict"] = "DNS_RESOLVER"
        analysis["bottleneck"] = f"Specific DNS resolver slow: {dns_per.data.get('slowest_resolver','?')} ({dns_per.data['slowest_ms']}ms)"
    elif ping and ping.data.get("rtt_avg_ms", 0) > 100:
        analysis["verdict"] = "NETWORK"
        analysis["bottleneck"] = "High baseline network latency -- F5, ISP peering, routing"
    elif "mtr_spike" in analysis:
        spike = analysis["mtr_spike"]
        analysis["verdict"] = "NETWORK_HOP"
        analysis["bottleneck"] = f"Latency spike at hop {spike['hop']['hop']} ({spike['hop']['host']})"
    elif curl and curl.data.get("transfer_ms", 0) > 2000:
        analysis["verdict"] = "PAYLOAD"
        analysis["bottleneck"] = "Large payload transfer -- check compression, CDN, asset sizes"
    elif not analysis["evidence"]:
        analysis["verdict"] = "OK"
        analysis["bottleneck"] = "No bottleneck detected"

    return analysis


def check_system_info() -> CheckResult:
    """Gather basic system info."""
    r = CheckResult(name="System info")
    t0 = time.monotonic()

    r.data["hostname"] = socket.gethostname()
    r.data["local_ip"] = socket.gethostbyname(socket.gethostname())

    # OS release
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    r.data["os"] = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass

    # uptime
    try:
        with open("/proc/uptime", "r") as f:
            r.data["uptime_seconds"] = float(f.read().split()[0])
    except OSError:
        pass

    r.status = "PASS"
    r.raw = "\n".join(f"{k}: {v}" for k, v in r.data.items())
    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_resolv_conf() -> CheckResult:
    """Parse /etc/resolv.conf for nameservers, search domains, options."""
    r = CheckResult(name="DNS resolv.conf")
    t0 = time.monotonic()

    nameservers = []
    search = []
    options = []

    try:
        with open("/etc/resolv.conf", "r") as f:
            raw = f.read()
        r.raw = raw

        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    nameservers.append(parts[1])
            elif line.startswith("search"):
                search = line.split()[1:] if len(line.split()) > 1 else []
            elif line.startswith("options"):
                options = line.split()[1:] if len(line.split()) > 1 else []

        r.data["nameservers"] = nameservers
        r.data["search_domains"] = search
        r.data["options"] = options
        r.status = "PASS" if nameservers else "WARN"
        if not nameservers:
            r.error = "No nameservers configured in /etc/resolv.conf"
    except OSError as e:
        r.status = "FAIL"
        r.error = str(e)

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_dns_per_resolver(target: str) -> CheckResult:
    """Test DNS resolution against each resolver in /etc/resolv.conf to find slow ones."""
    r = CheckResult(name="DNS per-resolver timing")
    t0 = time.monotonic()

    if not _which("dig"):
        r.status = "SKIP"
        r.error = "dig not available"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    # Skip if target is already an IP
    try:
        socket.inet_pton(socket.AF_INET, target)
        r.status = "SKIP"
        r.raw = f"Target is an IP address ({target}), no DNS needed"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r
    except OSError:
        pass

    # Get nameservers from resolv.conf
    nameservers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        nameservers.append(parts[1])
    except OSError:
        pass

    if not nameservers:
        r.status = "SKIP"
        r.error = "No nameservers found in /etc/resolv.conf"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    results = []
    raw_parts = []
    slowest_ns = None
    slowest_ms = 0

    for ns in nameservers:
        t_ns = time.monotonic()
        rc, out, err = _run(["dig", f"@{ns}", "+short", "+time=3", "+tries=1", target], timeout=10)
        elapsed = (time.monotonic() - t_ns) * 1000

        ips = [l.strip() for l in (out or "").splitlines() if l.strip()]
        entry = {
            "resolver": ns,
            "elapsed_ms": round(elapsed, 1),
            "ips": ips,
            "success": rc == 0 and len(ips) > 0,
        }
        results.append(entry)
        raw_parts.append(f"@{ns}: {elapsed:.0f}ms — {', '.join(ips) if ips else 'FAIL'}")

        if elapsed > slowest_ms:
            slowest_ms = round(elapsed, 1)
            slowest_ns = ns

    r.data["results"] = results
    r.data["slowest_resolver"] = slowest_ns
    r.data["slowest_ms"] = slowest_ms
    r.raw = "\n".join(raw_parts)

    all_ok = all(e["success"] for e in results)
    if all_ok and slowest_ms < 100:
        r.status = "PASS"
    elif all_ok:
        r.status = "WARN"
        r.error = f"Slowest resolver {slowest_ns}: {slowest_ms}ms"
    else:
        r.status = "FAIL"
        failed = [e["resolver"] for e in results if not e["success"]]
        r.error = f"Resolution failed via: {', '.join(failed)}"

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


def check_tcpdump_dns(target: str, duration: int = 8) -> CheckResult:
    """Capture DNS traffic with tcpdump while resolving the target."""
    r = CheckResult(name="tcpdump DNS capture")
    t0 = time.monotonic()

    if not _which("tcpdump"):
        r.status = "SKIP"
        r.error = "tcpdump not available"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    # Skip if target is an IP
    try:
        socket.inet_pton(socket.AF_INET, target)
        r.status = "SKIP"
        r.raw = f"Target is an IP address ({target}), no DNS needed"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r
    except OSError:
        pass

    import tempfile

    pcap_path = os.path.join(tempfile.gettempdir(), f"tracer_dns_{os.getpid()}.pcap")

    # Start tcpdump in background
    tcpdump_cmd = [
        "tcpdump", "-i", "any", "-n", "port", "53",
        "-c", "20", "-w", pcap_path,
    ]
    try:
        tcpdump_proc = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as e:
        r.status = "SKIP"
        r.error = f"Failed to start tcpdump: {e}"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    # Give tcpdump a moment to start, then fire DNS queries
    time.sleep(0.5)

    # Do a few DNS lookups to generate traffic
    queries_done = 0
    for _ in range(4):
        if _which("dig"):
            _run(["dig", "+short", "+time=2", target], timeout=5)
        else:
            try:
                socket.getaddrinfo(target, None)
            except OSError:
                pass
        queries_done += 1
        time.sleep(0.5)

    # Wait for tcpdump to finish capturing, with timeout
    try:
        tcpdump_proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        tcpdump_proc.kill()
        tcpdump_proc.wait()

    # Parse captured packets with tcpdump -r
    rc, out, err = _run(["tcpdump", "-r", pcap_path, "-n", "-tttt"], timeout=15)
    r.raw = out or err

    # Parse packet lines for timing analysis
    # Format: 2026-06-11 23:10:00.123456 IP 10.0.2.15.54321 > 10.0.2.3.53: ...
    queries = []
    responses = []
    resolver_times = {}

    for line in (out or "").splitlines():
        # Timestamp
        ts_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)", line)
        if not ts_match:
            continue

        ts_str = ts_match.group(1)
        try:
            ts = time.mktime(time.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")) + float("0." + ts_str.split(".")[1].ljust(6, "0")[:6])
        except (ValueError, IndexError):
            ts = 0

        # Extract source/dest IPs
        ip_match = re.search(r"IP (\S+) > (\S+):", line)
        if not ip_match:
            continue
        src = ip_match.group(1).rsplit(".", 1)[0]
        dst = ip_match.group(1).rsplit(".", 1)[0]  # wait, this is wrong

    # More robust parsing: IP src.port > dst.port: flags...
    for line in (out or "").splitlines():
        ts_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)", line)
        if not ts_match:
            continue
        ts_str = ts_match.group(1)
        try:
            ts = time.mktime(time.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")) + float("0." + ts_str.split(".")[1].ljust(6, "0")[:6])
        except (ValueError, IndexError):
            ts = 0

        # Match src.port > dst.port
        flow_match = re.search(r"IP\s+(\S+)\.\d+\s+>\s+(\S+)\.\d+:", line)
        if not flow_match:
            flow_match = re.search(r"IP6?\s+(\S+)\.\d+\s+>\s+(\S+)\.\d+:", line)
        if not flow_match:
            continue

        src_ip = flow_match.group(1)
        dst_ip = flow_match.group(2)

        # DNS response has src_ip = resolver (server), dst_ip = client
        # DNS query has src_ip = client, dst_ip = resolver
        # tcpdump output shows: client.port > resolver.53 for query
        #                      resolver.53 > client.port for response

        is_response = ".53 >" in line or ": 53 > " in line  # server is source (port 53)
        is_query = "> " in line and ".53:" in line.split(">")[1] if ">" in line else False

        if is_query or (not is_response and ".53:" in line.split(">")[-1] if ">" in line else False):
            queries.append({"time": ts, "resolver": dst_ip, "line": line})
        elif is_response or ".53 >" in line:
            responses.append({"time": ts, "resolver": src_ip, "line": line})

        # Track resolver IPs
        if ".53" in line:
            for ip in (src_ip, dst_ip):
                if ip not in resolver_times:
                    resolver_times[ip] = {"queries": 0, "responses": 0, "total_rtt": 0.0, "rtt_samples": 0}

    r.data["packets_total"] = len((out or "").splitlines()) - 1 if out else 0
    r.data["resolvers_seen"] = list(resolver_times.keys())
    r.data["queries_sent"] = queries_done

    # Try to match query/response pairs for RTT
    for q in queries:
        q_resolver = q["resolver"]
        # Find first response from same resolver after query
        for resp in responses:
            if resp["resolver"] == q_resolver and resp["time"] > q["time"]:
                rtt = (resp["time"] - q["time"]) * 1000
                if rtt < 5000:  # ignore implausible RTTs
                    if q_resolver in resolver_times:
                        resolver_times[q_resolver]["total_rtt"] += rtt
                        resolver_times[q_resolver]["rtt_samples"] += 1
                break

    for ip, stats in resolver_times.items():
        if stats["rtt_samples"] > 0:
            stats["avg_rtt_ms"] = round(stats["total_rtt"] / stats["rtt_samples"], 1)

    r.data["resolver_stats"] = {k: {"avg_rtt_ms": v.get("avg_rtt_ms", 0)} for k, v in resolver_times.items()}

    # Clean up pcap
    try:
        os.unlink(pcap_path)
    except OSError:
        pass

    r.status = "PASS" if resolver_times else "WARN"
    if not resolver_times:
        r.error = "No DNS traffic captured (tcpdump may need root)"
    elif any(v.get("avg_rtt_ms", 0) > 100 for v in resolver_times.values()):
        slow = [f"{ip} ({v.get('avg_rtt_ms', 0)}ms)" for ip, v in resolver_times.items() if v.get("avg_rtt_ms", 0) > 100]
        r.status = "WARN"
        r.error = f"Slow resolver RTT: {', '.join(slow)}"

    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

STATUS_COLORS = {
    "PASS": "\033[32m",
    "FAIL": "\033[31m",
    "WARN": "\033[33m",
    "SKIP": "\033[90m",
    "ERROR": "\033[35m",
    "PENDING": "\033[37m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _format_latency_bar(label: str, ms: float, max_ms: float, width: int = 30) -> str:
    """ASCII bar for latency breakdown."""
    if max_ms <= 0:
        return f"  {label:30s} {ms:8.1f}ms"
    bar_len = int(ms / max_ms * width) if max_ms > 0 else 0
    bar = "█" * bar_len + "░" * (width - bar_len)
    return f"  {label:30s} {bar} {ms:8.1f}ms"


def _print_latency_analysis(results):
    """Print a dedicated latency breakdown section."""
    analysis = analyze_latency(results)
    curl = next((r for r in results if r.name == "Curl timing breakdown"), None)

    print()
    hdr = " LATENCY BREAKDOWN "
    hdr = hdr.center(56, "═")
    print(f"{BOLD}  ╔{hdr}╗{RESET}")

    if curl and curl.status == "PASS" and curl.data.get("total_ms"):
        max_ms = max(
            curl.data.get("dns_ms", 0),
            curl.data.get("tcp_handshake_ms", 0),
            curl.data.get("tls_handshake_ms", 0),
            curl.data.get("server_process_ms", 0),
            curl.data.get("transfer_ms", 0),
            1,
        )
        print(f"  ║  {BOLD}Segmented timing (curl){RESET}")
        print(f"  ║  {_format_latency_bar('DNS lookup', curl.data['dns_ms'], max_ms)}")
        print(f"  ║  {_format_latency_bar('TCP handshake', curl.data['tcp_handshake_ms'], max_ms)}")
        print(f"  ║  {_format_latency_bar('TLS handshake', curl.data['tls_handshake_ms'], max_ms)}")
        print(f"  ║  {_format_latency_bar('Server processing', curl.data['server_process_ms'], max_ms)}")
        print(f"  ║  {_format_latency_bar('Content transfer', curl.data['transfer_ms'], max_ms)}")
        print(f"  ║  {'─' * 56}")
        print(f"  ║  {'TOTAL (TTFB + transfer):':30s} {curl.data['total_ms']:8.1f}ms")
        print(f"  ║")

    # Per-hop latency jump
    tr = next((r for r in results if r.name == "Traceroute"), None)
    if tr and tr.status == "PASS" and tr.raw:
        hops = _parse_mtr_hops(tr.raw)
        spike = _find_latency_spike(hops)
        if spike:
            h = spike["hop"]
            print(f"  ║  {BOLD}MTR hop with largest avg jump:{RESET} hop {h['hop']} ({h['host']})")
            print(f"  ║    avg {h['avg_ms']}ms | best {h['best_ms']}ms | worst {h['worst_ms']}ms | loss {h['loss_pct']}%")
            print(f"  ║    jump from previous hop: +{spike['jump_ms']:.0f}ms")
            print(f"  ║")

    # Ping RTT
    ping = next((r for r in results if r.name.startswith("Ping")), None)
    if ping and ping.status == "PASS":
        avg = ping.data.get("rtt_avg_ms")
        loss = ping.data.get("packet_loss_pct")
        if avg is not None:
            print(f"  ║  {BOLD}Baseline network RTT:{RESET} avg {avg}ms, loss {loss}%")
            print(f"  ║")

    # Verdict
    verdict_color = {"SERVER": "\033[31m", "TLS": "\033[33m", "DNS": "\033[33m",
                     "NETWORK": "\033[31m", "NETWORK_HOP": "\033[31m", "PAYLOAD": "\033[33m",
                     "UNKNOWN": "\033[90m"}.get(analysis["verdict"], "")
    print(f"  ║  {BOLD}VERDICT:{RESET} {verdict_color}{analysis['bottleneck']}{RESET}")
    if analysis.get("evidence"):
        for e in analysis["evidence"]:
            print(f"  ║    • {e}")
    print(f"  ╚{'═' * 56}╝")
    print()


def print_report(results, target, port):
    """Print a clean formatted report to stdout."""
    sep = "─" * 70

    print()
    print(f"{BOLD}╔{'═' * 68}╗{RESET}")
    print(f"{BOLD}║{RESET}  {BOLD}Tracer Report{RESET} — {target}{f':{port}' if port else ''}")
    print(f"{BOLD}║{RESET}  {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"{BOLD}╚{'═' * 68}╝{RESET}")
    print()

    overall = all(r.status in ("PASS", "SKIP") for r in results)

    for r in results:
        color = STATUS_COLORS.get(r.status, "")
        dur = f" ({r.duration_ms:.0f}ms)" if r.duration_ms > 0 else ""

        print(f"{sep}")
        print(f"  {color}{BOLD}[{r.status:5s}]{RESET} {BOLD}{r.name}{RESET}{dur}")

        if r.error:
            print(f"         {color}Error:{RESET} {r.error}")

        # key data items
        for k, v in r.data.items():
            if isinstance(v, list):
                if v:
                    print(f"         {k}:")
                    for item in v[:20]:  # truncate long lists
                        print(f"           {item}")
                    if len(v) > 20:
                        print(f"           ... ({len(v)} total)")
            elif isinstance(v, dict):
                continue  # nested dicts shown via raw
            elif v is not None:
                print(f"         {k}: {v}")

        # raw output (truncated)
        if r.raw and r.raw.strip():
            lines = r.raw.strip().splitlines()
            if len(lines) > 25:
                print(f"         output:")
                for line in lines[:25]:
                    print(f"           {color}{line}{RESET}")
                print(f"         ... ({len(lines)} lines total, use --json for full)")
            else:
                for line in lines:
                    print(f"           {color}{line}{RESET}")

    print(f"{sep}")
    print()
    if overall:
        print(f"  {STATUS_COLORS['PASS']}{BOLD}[PASS]{RESET} All checks passed (or skipped).")
    else:
        fails = sum(1 for r in results if r.status == "FAIL")
        warns = sum(1 for r in results if r.status == "WARN")
        print(f"  {STATUS_COLORS['FAIL']}Issues found:{RESET} {fails} failure(s), {warns} warning(s)")
    print()

    # Latency analysis
    _print_latency_analysis(results)


def print_json_report(results, target, port):
    analysis = analyze_latency(results)
    report = {
        "target": target,
        "port": port,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "latency_analysis": analysis,
        "checks": [
            {
                "name": r.name,
                "status": r.status,
                "error": r.error,
                "data": {k: v for k, v in r.data.items()},
                "raw": r.raw,
                "duration_ms": round(r.duration_ms, 1),
            }
            for r in results
        ],
    }
    print(json.dumps(report, indent=2))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Tracer — comprehensive network diagnostics for sysadmins",
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p", "--port", type=int, help="Target port to check (default: auto-detect common ports)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output as machine-readable JSON"
    )
    parser.add_argument(
        "--no-ping", action="store_true", help="Skip ping"
    )
    parser.add_argument(
        "--no-traceroute", action="store_true", help="Skip traceroute"
    )
    parser.add_argument(
        "--no-firewall", action="store_true", help="Skip firewall check"
    )
    parser.add_argument(
        "--no-selinux", action="store_true", help="Skip SELinux check"
    )
    parser.add_argument(
        "--no-ss", action="store_true", help="Skip ss check"
    )
    parser.add_argument(
        "--no-pMTU", action="store_true", help="Skip PMTU check"
    )
    parser.add_argument(
        "--no-curl", action="store_true", help="Skip curl timing breakdown"
    )
    parser.add_argument(
        "--no-resolv", action="store_true", help="Skip resolv.conf check"
    )
    parser.add_argument(
        "--no-dns-resolvers", action="store_true", help="Skip per-resolver DNS timing"
    )
    parser.add_argument(
        "--no-tcpdump-dns", action="store_true", help="Skip tcpdump DNS capture"
    )
    parser.add_argument(
        "--quick", action="store_true", help="Quick mode: skip traceroute, firewall, selinux, pmtu, curl"
    )

    args = parser.parse_args()

    target = args.target
    port = args.port

    # Decide which checks to run
    checks_to_run = []

    checks_to_run.append(("system", lambda: check_system_info()))
    checks_to_run.append(("dns", lambda: check_dns(target)))

    if not args.no_resolv:
        checks_to_run.append(("resolv", lambda: check_resolv_conf()))
    if not args.no_dns_resolvers:
        checks_to_run.append(("dns-per-resolver", lambda: check_dns_per_resolver(target)))
    if not args.no_tcpdump_dns:
        checks_to_run.append(("tcpdump-dns", lambda: check_tcpdump_dns(target)))

    if not args.no_ping:
        checks_to_run.append(("ping", lambda: check_ping(target)))

    if not args.no_traceroute and not args.quick:
        checks_to_run.append(("traceroute", lambda: check_traceroute(target)))

    if not args.no_pMTU and not args.quick:
        checks_to_run.append(("pmtu", lambda: check_pMTU(target)))

    if port:
        checks_to_run.append(("port", lambda: check_port(target, port)))
        if not args.no_curl and not args.quick:
            checks_to_run.append(("curl", lambda: check_curl_timing(target, port)))
            checks_to_run.append(("http-protocol", lambda: check_http_protocol(target, port)))
            checks_to_run.append(("page-assets", lambda: check_page_assets(target, port)))
            checks_to_run.append(("ip-route", lambda: check_ip_route(target)))
        if not args.no_ss:
            checks_to_run.append(("ss", lambda: check_ss(port)))
        if not args.no_selinux and not args.quick:
            checks_to_run.append(("selinux", lambda: check_selinux_port(port)))
        if not args.no_firewall and not args.quick:
            checks_to_run.append(("firewall", lambda: check_firewall(port)))
    else:
        # If no port, check common ports on local machine (ss) and skip port-specific
        if not args.no_ss:
            checks_to_run.append(("ss-common", lambda: check_ss_common()))

    # Run checks in parallel
    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(fn): (name, idx) for idx, (name, fn) in enumerate(checks_to_run)}
        for future in as_completed(futures):
            name, idx = futures[future]
            try:
                result = future.result()
                result.order = idx
                results.append(result)
            except Exception as e:
                results.append(CheckResult(
                    name=name,
                    status="ERROR",
                    error=str(e),
                    order=idx,
                ))

    results.sort(key=lambda r: r.order)

    if args.json:
        print_json_report(results, target, port)
    else:
        print_report(results, target, port)


def check_ss_common() -> CheckResult:
    """ss -tlnp for common web ports when no port specified."""
    r = CheckResult(name="Listening sockets (common ports)")
    t0 = time.monotonic()

    if not _which("ss"):
        r.status = "SKIP"
        r.error = "ss not available"
        r.duration_ms = (time.monotonic() - t0) * 1000
        return r

    rc, out, err = _run(["ss", "-tlnp"], timeout=10)
    r.raw = out or err

    common = {"80", "443", "22", "8080", "8443", "3000", "5000", "8000", "9090"}
    matching = [
        l for l in (out or "").splitlines()
        if any(p in l.replace(":", " ").split() for p in common)
    ]
    r.data["common_listeners"] = matching
    r.data["total_listeners"] = max(0, len((out or "").splitlines()) - 1)

    r.status = "PASS"
    r.duration_ms = (time.monotonic() - t0) * 1000
    return r


if __name__ == "__main__":
    main()
