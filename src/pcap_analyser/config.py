import json
import os


def load_config(config_file):
    """Load configuration from a JSON file or use defaults."""
    default_config = {
        "overall": {"max_packets": 10000, "max_bandwidth_bytes": 10000000},
        "ip_thresholds": {
            "allowed_ranges": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
            "per_ip": {
                "192.168.1.1": {
                    "allowed_ports": [80, 443],
                    "max_packets": 1000,
                    "max_bytes": 500000,
                },
                "10.0.0.2": {
                    "allowed_ports": [22],
                    "max_packets": 500,
                    "max_bytes": 200000,
                },
            },
        },
    }

    if config_file and os.path.exists(config_file):
        with open(config_file, "r") as f:
            return json.load(f)
    return default_config
