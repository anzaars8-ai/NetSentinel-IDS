#!/usr/bin/env bash
set -e

echo "[+] Backing up current project..."
mkdir -p backups/network_upgrade
cp -a detection/rules.py backups/network_upgrade/rules.py.$(date +%s) 2>/dev/null || true
cp -a config/config.yaml backups/network_upgrade/config.yaml.$(date +%s) 2>/dev/null || true

echo "[+] Creating network discovery module..."
mkdir -p discovery

cat > discovery/__init__.py <<'PY'
PY

cat > discovery/network_discovery.py <<'PY'
import ipaddress
import subprocess
import re

def get_local_network(interface="wlp2s0"):
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", "dev", interface],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if not m:
            return None
        return str(ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False))
    except Exception:
        return None

def discover_hosts(interface="wlp2s0"):
    network = get_local_network(interface)
    if not network:
        return []

    try:
        output = subprocess.check_output(
            ["ip", "neigh", "show", "dev", interface],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []

    hosts = []
    for line in output.splitlines():
        m = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})\s+(\S+)",
            line,
            re.I,
        )
        if m:
            hosts.append({
                "ip": m.group(1),
                "mac": m.group(2),
                "state": m.group(3),
            })

    return hosts
PY

echo "[+] Replacing detection engine with network-wide rules..."
cat > detection/rules.py <<'PY'
import ipaddress
import time


def _threshold(thresholds, name, default):
    try:
        return int(thresholds.get(name, default))
    except Exception:
        return default


def _external(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except Exception:
        return False


def _alert(rule, severity, confidence, message, src_ip=None, dst_ip=None, details=None):
    return {
        "rule": rule,
        "severity": severity,
        "confidence": confidence,
        "message": message,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "details": details or {},
        "timestamp": time.time(),
    }


def port_scan_rule(parsed, stats, thresholds):
    unique_ports = len(getattr(stats, "unique_ports", set()))
    syns = int(getattr(stats, "syns", 0))

    minimum_ports = _threshold(thresholds, "port_scan_unique_ports", 15)
    minimum_syns = _threshold(thresholds, "port_scan_min_syns", 10)

    if unique_ports >= minimum_ports and syns >= minimum_syns:
        return _alert(
            "PORT_SCAN",
            "HIGH",
            0.95,
            f"Network port scan detected: {unique_ports} ports / {syns} SYNs",
            getattr(parsed, "src_ip", None),
            getattr(parsed, "dst_ip", None),
            {"unique_ports": unique_ports, "syns": syns},
        )


def horizontal_scan_rule(parsed, stats, thresholds):
    hosts = len(getattr(stats, "unique_destinations", set()))
    syns = int(getattr(stats, "syns", 0))

    minimum_hosts = _threshold(thresholds, "horizontal_scan_hosts", 8)
    minimum_syns = _threshold(thresholds, "horizontal_scan_min_syns", 10)

    if hosts >= minimum_hosts and syns >= minimum_syns:
        return _alert(
            "HORIZONTAL_SCAN",
            "HIGH",
            0.96,
            f"Host sweep detected: {hosts} destinations / {syns} SYNs",
            getattr(parsed, "src_ip", None),
            None,
            {"unique_destinations": hosts, "syns": syns},
        )


def public_ip_scan_rule(parsed, stats, thresholds):
    src_ip = getattr(parsed, "src_ip", None)
    unique_ports = len(getattr(stats, "unique_ports", set()))
    syns = int(getattr(stats, "syns", 0))

    minimum_ports = _threshold(thresholds, "public_ip_scan_unique_ports", 5)
    minimum_syns = _threshold(thresholds, "public_ip_scan_min_syns", 5)

    if src_ip and _external(src_ip):
        if unique_ports >= minimum_ports and syns >= minimum_syns:
            return _alert(
                "PUBLIC_IP_SCAN",
                "CRITICAL",
                0.97,
                f"External reconnaissance detected: {unique_ports} ports / {syns} SYNs",
                src_ip,
                getattr(parsed, "dst_ip", None),
                {"unique_ports": unique_ports, "syns": syns},
            )


def syn_flood_rule(parsed, stats, thresholds):
    syns = int(getattr(stats, "syns", 0))
    minimum = _threshold(thresholds, "syn_flood_min_syns", 100)

    if syns >= minimum:
        return _alert(
            "SYN_FLOOD",
            "CRITICAL",
            0.98,
            f"Possible SYN flood: {syns} SYN packets",
            getattr(parsed, "src_ip", None),
            getattr(parsed, "dst_ip", None),
            {"syns": syns},
        )


def high_connection_rate_rule(parsed, stats, thresholds):
    connections = int(getattr(stats, "connection_count", 0))
    minimum = _threshold(thresholds, "high_conn_rate", 50)

    if connections >= minimum:
        return _alert(
            "HIGH_CONNECTION_RATE",
            "HIGH",
            0.91,
            f"Abnormally high connection rate: {connections}",
            getattr(parsed, "src_ip", None),
            getattr(parsed, "dst_ip", None),
            {"connections": connections},
        )


def high_traffic_rule(parsed, stats, thresholds):
    traffic = int(getattr(stats, "bytes", 0))
    minimum = _threshold(thresholds, "high_traffic_bytes", 5000000)

    if traffic >= minimum:
        return _alert(
            "HIGH_TRAFFIC",
            "MEDIUM",
            0.88,
            f"Abnormally high traffic volume: {traffic} bytes",
            getattr(parsed, "src_ip", None),
            getattr(parsed, "dst_ip", None),
            {"bytes": traffic},
        )


ALL_RULES = [
    port_scan_rule,
    horizontal_scan_rule,
    public_ip_scan_rule,
    syn_flood_rule,
    high_connection_rate_rule,
    high_traffic_rule,
]
PY

echo "[+] Updating configuration..."
cat > config/config.yaml <<'YAML'
capture:
  interface: wlp2s0
  store_unparsed: false
  promiscuous: true

window:
  seconds: 10

thresholds:
  port_scan_unique_ports: 15
  port_scan_min_syns: 10

  public_ip_scan_unique_ports: 5
  public_ip_scan_min_syns: 5

  horizontal_scan_hosts: 8
  horizontal_scan_min_syns: 10

  high_conn_rate: 50
  high_traffic_bytes: 5000000
  syn_flood_min_syns: 100

database:
  path: data/alerts.db

api:
  host: 127.0.0.1
  port: 5000
YAML

echo "[+] Creating network test..."
cat > tests/test_network_detection.py <<'PY'
from detection.rules import (
    port_scan_rule,
    horizontal_scan_rule,
    public_ip_scan_rule,
)


class Stats:
    def __init__(self, ports=None, syns=0, destinations=None):
        self.unique_ports = set(ports or [])
        self.syns = syns
        self.unique_destinations = set(destinations or [])


class Parsed:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip


def test_network_port_scan():
    parsed = Parsed("192.168.1.20", "192.168.1.50")
    stats = Stats(range(1, 21), 20)

    alert = port_scan_rule(parsed, stats, {
        "port_scan_unique_ports": 15,
        "port_scan_min_syns": 10,
    })

    assert alert
    assert alert["rule"] == "PORT_SCAN"


def test_horizontal_scan():
    parsed = Parsed("192.168.1.20", "192.168.1.50")
    stats = Stats([80], 10, [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.4",
        "192.168.1.5",
        "192.168.1.6",
        "192.168.1.7",
        "192.168.1.8",
    ])

    alert = horizontal_scan_rule(parsed, stats, {
        "horizontal_scan_hosts": 8,
        "horizontal_scan_min_syns": 10,
    })

    assert alert
    assert alert["rule"] == "HORIZONTAL_SCAN"


def test_external_scan():
    parsed = Parsed("8.8.8.8", "192.168.1.50")
    stats = Stats(range(1, 6), 5)

    alert = public_ip_scan_rule(parsed, stats, {
        "public_ip_scan_unique_ports": 5,
        "public_ip_scan_min_syns": 5,
    })

    assert alert
    assert alert["rule"] == "PUBLIC_IP_SCAN"
PY

echo
echo "=========================================="
echo " NETWORK IDS UPGRADE COMPLETE"
echo "=========================================="
echo

echo "[+] Running tests..."
pytest tests/ -v

echo
echo "[+] Active interfaces:"
ip -br link

echo
echo "[+] Your local IPv4:"
ip -4 addr show wlp2s0 | grep inet || true

echo
echo "[+] Your public IPv4:"
curl -4 -s https://api.ipify.org || true
echo

echo
echo "=========================================="
echo " IMPORTANT"
echo "=========================================="
echo "Your IDS can only detect network-wide traffic"
echo "that actually reaches the IDS interface."
echo
echo "Start IDS with:"
echo
echo "sudo ./venv/bin/python run_ids.py -i wlp2s0"
echo
echo "For TRUE full-LAN visibility, use one of:"
echo "  1. Router/gateway IDS placement"
echo "  2. Switch port mirroring"
echo "  3. Network TAP"
echo "  4. Router/AP traffic mirroring"
echo
echo "Testing packet visibility:"
echo "sudo tcpdump -ni wlp2s0 'tcp[tcpflags] & tcp-syn != 0'"
echo "=========================================="
