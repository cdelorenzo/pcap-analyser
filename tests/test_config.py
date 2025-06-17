import json
from src.pcap_analyser.config import load_config


def test_load_config_returns_default_when_no_file():
    config = load_config(None)
    assert "overall" in config
    assert "ip_thresholds" in config
    assert config["overall"]["max_packets"] == 10000
    assert "allowed_ranges" in config["ip_thresholds"]
    assert isinstance(config["ip_thresholds"]["per_ip"], dict)


def test_load_config_returns_file_contents(tmp_path):
    # Create a temporary config file
    config_data = {
        "overall": {"max_packets": 123, "max_bandwidth_bytes": 456},
        "ip_thresholds": {
            "allowed_ranges": ["1.2.3.0/24"],
            "per_ip": {
                "1.2.3.4": {
                    "allowed_ports": [80],
                    "max_packets": 1,
                    "max_bytes": 2,
                }
            },
        },
    }
    config_file = tmp_path / "test_config.json"
    with open(config_file, "w") as f:
        json.dump(config_data, f)
    loaded = load_config(str(config_file))
    assert loaded == config_data


def test_load_config_returns_default_if_file_missing(tmp_path):
    missing_file = tmp_path / "does_not_exist.json"
    config = load_config(str(missing_file))
    assert "overall" in config
    assert config["overall"]["max_packets"] == 10000
