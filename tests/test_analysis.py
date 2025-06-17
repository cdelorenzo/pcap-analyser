from scapy.all import IP, TCP, UDP, Ether
from pcap_analyser import analysis


def make_packet(src, dst, proto="TCP", sport=1234, dport=80, payload_len=100):
    ether = Ether()
    ip = IP(src=src, dst=dst)
    if proto == "TCP":
        l4 = TCP(sport=sport, dport=dport)
    else:
        l4 = UDP(sport=sport, dport=dport)
    pkt = ether / ip / l4 / (b"x" * payload_len)
    return pkt


def default_config():
    return {
        "overall": {"max_packets": 10, "max_bandwidth_bytes": 2000},
        "ip_thresholds": {
            "allowed_ranges": ["192.168.1.0/24"],
            "per_ip": {"192.168.1.1": {"max_packets": 5, "max_bytes": 1000}},
        },
        "unknown_sources": {"max_percent": 50},
    }


def test_analyze_overall_pass():
    packets = [make_packet("192.168.1.1", "192.168.1.2") for _ in range(5)]
    config = default_config()
    results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
    analysis.analyze_overall(packets, config, results)
    assert results["pass"] is True
    assert results["stats"]["overall"]["total_packets"] == 5
    assert "violations" in results


def test_analyze_overall_violation():
    packets = [make_packet("192.168.1.1", "192.168.1.2") for _ in range(15)]
    config = default_config()
    results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
    analysis.analyze_overall(packets, config, results)
    assert results["pass"] is False
    assert any("exceed threshold" in v for v in results["violations"])


def test_analyze_ip_ranges_known_unknown():
    packets = [make_packet("192.168.1.1", "10.0.0.1")]
    config = default_config()
    results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
    analysis.analyze_ip_ranges(packets, config, results)
    ip_ranges = results["stats"]["ip_ranges"]
    assert "192.168.1.1" in ip_ranges["known_ips"]
    assert "10.0.0.1" in ip_ranges["unknown_ips"]


def test_analyze_unknown_sources_warning():
    packets = [make_packet("10.0.0.1", "192.168.1.2") for _ in range(6)]
    config = default_config()
    config["unknown_sources"]["max_percent"] = 50
    results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
    analysis.analyze_unknown_sources(packets, config, results)
    assert results["stats"]["unknown_sources"]["unknown_count"] == 6
    assert results["warnings"]


def test_analyze_ip_and_ports_violation():
    packets = [make_packet("192.168.1.1", "192.168.1.2") for _ in range(6)]
    config = default_config()
    results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
    analysis.analyze_ip_and_ports(packets, config, results)
    assert results["pass"] is False
    assert any("exceeds packet threshold" in v for v in results["violations"])


def test_analyze_ip_ranges_empty():
    config = default_config()
    results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
    analysis.analyze_ip_ranges([], config, results)
    assert results["stats"]["ip_analysis"] == "No IP packets found"


def test_analyze_unknown_sources_empty():
    config = default_config()
    results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
    analysis.analyze_unknown_sources([], config, results)
    assert results["stats"]["unknown_sources"] == "No source IPs found"


def test_analyze_ip_and_ports_byte_violation():
    # Create packets to exceed max_bytes for 192.168.1.1
    packets = [
        make_packet("192.168.1.1", "192.168.1.2", payload_len=300) for _ in range(4)
    ]
    config = default_config()
    # Set max_bytes low to trigger violation
    config["ip_thresholds"]["per_ip"]["192.168.1.1"]["max_bytes"] = 100
    results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
    analysis.analyze_ip_and_ports(packets, config, results)
    assert results["pass"] is False
    assert any("exceeds byte threshold" in v for v in results["violations"])
