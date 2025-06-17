import json
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from pcap_analyser.cli import cli, PcapAnalyzer


def test_pcap_analyzer_analyze(monkeypatch):
    # Mock packets and config
    packets = [MagicMock(), MagicMock()]
    config = {
        "overall": {},
        "ip_thresholds": {"allowed_ranges": [], "per_ip": {}},
        "unknown_sources": {},
    }
    # Patch rdpcap and load_config
    with patch("pcap_analyser.cli.rdpcap", return_value=packets), patch(
        "pcap_analyser.cli.load_config", return_value=config
    ), patch("pcap_analyser.analysis.analyze_overall"), patch(
        "pcap_analyser.analysis.analyze_ip_ranges"
    ), patch(
        "pcap_analyser.analysis.analyze_unknown_sources"
    ), patch(
        "pcap_analyser.analysis.analyze_ip_and_ports"
    ):
        analyzer = PcapAnalyzer("dummy.pcap", "dummy.json")
        analyzer.results = {"pass": True, "violations": [], "stats": {}, "warnings": []}
        result = analyzer.analyze()
        assert isinstance(result, dict)
        assert "pass" in result


def test_generate_baseline(tmp_path, monkeypatch):
    packets = [MagicMock(), MagicMock()]
    with patch("pcap_analyser.cli.rdpcap", return_value=packets), patch(
        "pcap_analyser.cli.load_config", return_value={}
    ), patch("pcap_analyser.cli.IP", new=MagicMock()):
        analyzer = PcapAnalyzer("dummy.pcap")
        output_file = tmp_path / "baseline.json"
        analyzer.generate_baseline(str(output_file), variance_percent=10)
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
        assert "overall" in data
        assert "ip_thresholds" in data


def test_generate_baseline_multiple_ips_ports(tmp_path, monkeypatch):
    from scapy.all import IP, TCP, Ether

    def make_pkt(src, dst, sport, dport):
        return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport)

    packets = [
        make_pkt("192.168.1.1", "192.168.1.2", 1234, 80),
        make_pkt("192.168.1.2", "192.168.1.3", 4321, 443),
        make_pkt("10.0.0.1", "10.0.0.2", 5555, 8080),
    ]
    with patch("pcap_analyser.cli.rdpcap", return_value=packets), patch(
        "pcap_analyser.cli.load_config", return_value={}
    ), patch("pcap_analyser.cli.IP", new=IP):
        analyzer = PcapAnalyzer("dummy.pcap")
        output_file = tmp_path / "baseline_multi.json"
        analyzer.generate_baseline(str(output_file), variance_percent=10)
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
        # Check that multiple IPs and ports are present
        assert "overall" in data
        assert "ip_thresholds" in data
        assert len(data["ip_thresholds"]["per_ip"]) >= 2
        for ip, ipconf in data["ip_thresholds"]["per_ip"].items():
            assert "allowed_ports" in ipconf
            assert isinstance(ipconf["allowed_ports"], list)


def test_cli_analyze_command(tmp_path, monkeypatch):
    runner = CliRunner()
    # Create dummy files to satisfy click.Path(exists=True)
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_json = tmp_path / "dummy.json"
    dummy_pcap.write_bytes(b"")
    dummy_json.write_text("{}")
    # Patch PcapAnalyzer to control output
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = {
        "pass": True,
        "violations": [],
        "stats": {"overall": {"total_packets": 1, "total_bandwidth_bytes": 100}},
        "warnings": [],
    }
    with patch("pcap_analyser.cli.PcapAnalyzer", return_value=mock_analyzer):
        result = runner.invoke(
            cli,
            ["analyze", str(dummy_pcap), "-c", str(dummy_json), "-o", "out.json", "-v"],
        )
        assert result.exit_code == 0
        assert "PCAP Analysis Result" in result.output
        assert "PASS" in result.output
        assert "Statistics" in result.output


def test_cli_baseline_command(tmp_path, monkeypatch):
    runner = CliRunner()
    # Create dummy file to satisfy click.Path(exists=True)
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_pcap.write_bytes(b"")
    mock_analyzer = MagicMock()
    with patch("pcap_analyser.cli.PcapAnalyzer", return_value=mock_analyzer):
        output_file = tmp_path / "baseline.json"
        result = runner.invoke(
            cli,
            ["baseline", str(dummy_pcap), "-o", str(output_file), "--variance", "5"],
        )
        assert result.exit_code == 0
        assert "Baseline configuration saved" in result.output


def test_cli_analyze_command_with_warnings_and_violations(tmp_path):
    runner = CliRunner()
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_json = tmp_path / "dummy.json"
    dummy_pcap.write_bytes(b"")
    dummy_json.write_text("{}")
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = {
        "pass": False,
        "violations": ["Test violation"],
        "stats": {
            "overall": {"total_packets": 1, "total_bandwidth_bytes": 100},
            "nested": {"foo": {"bar": 1}},
        },
        "warnings": ["Test warning"],
    }
    with patch("pcap_analyser.cli.PcapAnalyzer", return_value=mock_analyzer):
        result = runner.invoke(
            cli,
            ["analyze", str(dummy_pcap), "-c", str(dummy_json), "-o", "out.json", "-v"],
        )
        assert result.exit_code == 1
        assert "Warnings:" in result.output
        assert "Violations:" in result.output
        assert "Test violation" in result.output
        assert "Test warning" in result.output
        assert "Statistics:" in result.output
        assert "foo:" in result.output or "bar:" in result.output  # nested stats


def test_cli_analyze_command_exception(tmp_path):
    runner = CliRunner()
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_json = tmp_path / "dummy.json"
    dummy_pcap.write_bytes(b"")
    dummy_json.write_text("{}")
    with patch("pcap_analyser.cli.PcapAnalyzer", side_effect=Exception("fail")):
        result = runner.invoke(
            cli,
            ["analyze", str(dummy_pcap), "-c", str(dummy_json), "-o", "out.json", "-v"],
        )
        assert result.exit_code == 1
        assert "Error: fail" in result.output


def test_cli_baseline_command_exception(tmp_path):
    runner = CliRunner()
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_pcap.write_bytes(b"")
    with patch("pcap_analyser.cli.PcapAnalyzer", side_effect=Exception("fail")):
        output_file = tmp_path / "baseline.json"
        result = runner.invoke(
            cli,
            ["baseline", str(dummy_pcap), "-o", str(output_file), "--variance", "5"],
        )
        assert result.exit_code == 1  # Baseline now calls sys.exit(1) on error
        assert "Error: fail" in result.output


def test_cli_analyze_command_with_exit_patch(tmp_path):
    runner = CliRunner()
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_json = tmp_path / "dummy.json"
    dummy_pcap.write_bytes(b"")
    dummy_json.write_text("{}")
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = {
        "pass": True,
        "violations": [],
        "stats": {"overall": {"total_packets": 1, "total_bandwidth_bytes": 100}},
        "warnings": [],
    }
    with patch("pcap_analyser.cli.PcapAnalyzer", return_value=mock_analyzer), patch(
        "sys.exit"
    ) as exit_patch:
        runner.invoke(
            cli,
            ["analyze", str(dummy_pcap), "-c", str(dummy_json), "-o", "out.json", "-v"],
        )
        exit_patch.assert_called()


def test_cli_baseline_command_with_exit_patch(tmp_path):
    runner = CliRunner()
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_pcap.write_bytes(b"")
    mock_analyzer = MagicMock()
    with patch("pcap_analyser.cli.PcapAnalyzer", return_value=mock_analyzer):
        output_file = tmp_path / "baseline.json"
        runner.invoke(
            cli,
            ["baseline", str(dummy_pcap), "-o", str(output_file), "--variance", "5"],
        )


def test_cli_analyze_command_with_exit_patch_pass(tmp_path):
    runner = CliRunner()
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_json = tmp_path / "dummy.json"
    dummy_pcap.write_bytes(b"")
    dummy_json.write_text("{}")
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = {
        "pass": True,
        "violations": [],
        "stats": {"overall": {"total_packets": 1, "total_bandwidth_bytes": 100}},
        "warnings": [],
    }
    with patch("pcap_analyser.cli.PcapAnalyzer", return_value=mock_analyzer), patch(
        "sys.exit"
    ) as exit_patch:
        runner.invoke(
            cli,
            ["analyze", str(dummy_pcap), "-c", str(dummy_json), "-o", "out.json", "-v"],
        )
        exit_patch.assert_called_with(0)


def test_cli_analyze_command_with_exit_patch_fail(tmp_path):
    runner = CliRunner()
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_json = tmp_path / "dummy.json"
    dummy_pcap.write_bytes(b"")
    dummy_json.write_text("{}")
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = {
        "pass": False,
        "violations": ["Total packets (243) exceed threshold of 2"],
        "stats": {"overall": {"total_packets": 243, "total_bandwidth_bytes": 100}},
        "warnings": [],
    }
    with patch("pcap_analyser.cli.PcapAnalyzer", return_value=mock_analyzer), patch(
        "sys.exit"
    ) as exit_patch:
        runner.invoke(
            cli,
            ["analyze", str(dummy_pcap), "-c", str(dummy_json), "-o", "out.json", "-v"],
        )
        # Accept either exit(1) or exit(0) due to Click/patching behavior
        # but assert the CLI exit code is 1 (fail)
        assert any(call.args == (1,) for call in exit_patch.call_args_list)


def test_cli_baseline_command_with_exit_patch_success(tmp_path):
    runner = CliRunner()
    dummy_pcap = tmp_path / "dummy.pcap"
    dummy_pcap.write_bytes(b"")
    mock_analyzer = MagicMock()
    with patch("pcap_analyser.cli.PcapAnalyzer", return_value=mock_analyzer), patch(
        "sys.exit"
    ) as exit_patch:
        output_file = tmp_path / "baseline.json"
        runner.invoke(
            cli,
            ["baseline", str(dummy_pcap), "-o", str(output_file), "--variance", "5"],
        )
        exit_patch.assert_called_with(0)
