import ipaddress
from collections import Counter, defaultdict
from scapy.all import IP


def analyze_overall(packets, config, results):
    """Validate overall packet count and bandwidth."""
    total_packets = len(packets)
    total_bytes = sum(len(pkt) for pkt in packets)

    max_packets = config.get("overall", {}).get("max_packets", float("inf"))
    max_bandwidth = config.get("overall", {}).get("max_bandwidth_bytes", float("inf"))

    if total_packets > max_packets:
        results["pass"] = False
        results["violations"].append(
            f"Total packets ({total_packets}) exceed threshold of {max_packets}"
        )

    if total_bytes > max_bandwidth:
        results["pass"] = False
        results["violations"].append(
            f"Total bandwidth ({total_bytes} bytes) exceeds threshold of "
            f"{max_bandwidth} bytes"
        )

    results["stats"]["overall"] = {
        "total_packets": total_packets,
        "total_bandwidth_bytes": total_bytes,
    }


def analyze_ip_ranges(packets, config, results):
    """Group IP addresses into known vs unknown ranges."""
    src_ips = [pkt[IP].src for pkt in packets if IP in pkt]
    dst_ips = [pkt[IP].dst for pkt in packets if IP in pkt]
    all_ips = src_ips + dst_ips
    total_ips = len(all_ips)

    if total_ips == 0:
        results["stats"]["ip_analysis"] = "No IP packets found"
        return

    ip_counter = Counter(all_ips)
    allowed_ranges = [
        ipaddress.ip_network(net) for net in config["ip_thresholds"]["allowed_ranges"]
    ]
    known_ips = set()
    unknown_ips = set()
    for ip in ip_counter:
        ip_obj = ipaddress.ip_address(ip)
        if any(ip_obj in net for net in allowed_ranges):
            known_ips.add(ip)
        else:
            unknown_ips.add(ip)
    results["stats"]["ip_ranges"] = {
        "total_ips": total_ips,
        "known_ips": sorted(list(known_ips)),
        "unknown_ips": sorted(list(unknown_ips)),
    }


def analyze_unknown_sources(packets, config, results):
    """Check and always report unknown sources"""
    src_ips = [pkt[IP].src for pkt in packets if IP in pkt]
    total_src = len(src_ips)
    if total_src == 0:
        results["stats"]["unknown_sources"] = "No source IPs found"
        return
    known_networks = [
        ipaddress.ip_network(net) for net in config["ip_thresholds"]["allowed_ranges"]
    ]
    unknown_count = 0
    unknown_ips = set()
    for ip in src_ips:
        ip_obj = ipaddress.ip_address(ip)
        if not any(ip_obj in net for net in known_networks):
            unknown_count += 1
            unknown_ips.add(ip)
    unknown_percent = (unknown_count / total_src) * 100 if total_src else 0
    results["stats"]["unknown_sources"] = {
        "total_sources": total_src,
        "unknown_count": unknown_count,
        "unknown_percent": unknown_percent,
        "unknown_ips": list(unknown_ips),
    }
    max_unknown = config.get("unknown_sources", {}).get("max_percent", None)
    if max_unknown is not None and unknown_percent > max_unknown:
        results["warnings"].append(
            f"Unknown source traffic ({unknown_percent:.2f}%) exceeds threshold of "
            f"{max_unknown}%"
        )


def analyze_ip_and_ports(packets, config, results):
    """Validate traffic per IP address and port."""
    ip_traffic = defaultdict(lambda: defaultdict(lambda: {"packets": 0, "bytes": 0}))
    for pkt in packets:
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            pkt_len = len(pkt)
            if pkt.haslayer("TCP") or pkt.haslayer("UDP"):
                layer = pkt["TCP"] if pkt.haslayer("TCP") else pkt["UDP"]
                port_src = layer.sport
                port_dst = layer.dport
                ip_traffic[ip_src][port_src]["packets"] += 1
                ip_traffic[ip_src][port_src]["bytes"] += pkt_len
                ip_traffic[ip_dst][port_dst]["packets"] += 1
                ip_traffic[ip_dst][port_dst]["bytes"] += pkt_len
    per_ip_config = config["ip_thresholds"].get("per_ip", {})
    for ip, port_stats in ip_traffic.items():
        if ip in per_ip_config:
            ip_config = per_ip_config[ip]
            max_packets = ip_config.get("max_packets", float("inf"))
            max_bytes = ip_config.get("max_bytes", float("inf"))
            total_packets = sum(stats["packets"] for stats in port_stats.values())
            total_bytes = sum(stats["bytes"] for stats in port_stats.values())
            if total_packets > max_packets:
                results["pass"] = False
                results["violations"].append(
                    f"IP {ip} exceeds packet threshold ("
                    f"{total_packets} > {max_packets})"
                )
            if total_bytes > max_bytes:
                results["pass"] = False
                results["violations"].append(
                    f"IP {ip} exceeds byte threshold (" f"{total_bytes} > {max_bytes})"
                )
    results["stats"]["ip_traffic"] = ip_traffic
