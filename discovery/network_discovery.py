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
