#!/usr/bin/env python3
import click
import sys
from scapy.all import rdpcap, IP
from collections import Counter, defaultdict
import json
from pcap_analyser.config import load_config
from pcap_analyser.analysis import (
    analyze_overall,
    analyze_ip_ranges,
    analyze_unknown_sources,
    analyze_ip_and_ports,
)


class PcapAnalyzer:
    def __init__(self, pcap_file, config_file=None):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
        self.config = load_config(config_file)
        self.results = {"pass": True, "violations": [], "stats": {}, "warnings": []}

    def analyze(self):
        """Run all analysis checks"""
        analyze_overall(self.packets, self.config, self.results)
        analyze_ip_ranges(self.packets, self.config, self.results)
        analyze_unknown_sources(self.packets, self.config, self.results)
        analyze_ip_and_ports(self.packets, self.config, self.results)
        return self.results

    def generate_baseline(self, output_file, variance_percent=0):
        """
        Generate a baseline configuration file from the PCAP file,
        allowing for variance.
        """
        total_file_packets = len(self.packets)
        total_file_bytes = sum(len(pkt) for pkt in self.packets)

        # Calculate variance multipliers
        multiplier = 1 + (variance_percent / 100.0)

        src_ips = [pkt[IP].src for pkt in self.packets if IP in pkt]
        dst_ips = [pkt[IP].dst for pkt in self.packets if IP in pkt]
        all_ips = src_ips + dst_ips

        # Count IP occurrences
        ip_counter = Counter(all_ips)
        most_common_ips = [ip for ip, _ in ip_counter.most_common(10)]

        # Analyze traffic per IP and port
        ip_traffic = defaultdict(
            lambda: defaultdict(lambda: {"packets": 0, "bytes": 0})
        )
        for pkt in self.packets:
            if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                pkt_len = len(pkt)
                # Track IP and port traffic
                if pkt.haslayer("TCP") or pkt.haslayer("UDP"):
                    layer = pkt["TCP"] if pkt.haslayer("TCP") else pkt["UDP"]
                    port_src = layer.sport
                    port_dst = layer.dport

                    ip_traffic[ip_src][port_src]["packets"] += 1
                    ip_traffic[ip_src][port_src]["bytes"] += pkt_len
                    ip_traffic[ip_dst][port_dst]["packets"] += 1
                    ip_traffic[ip_dst][port_dst]["bytes"] += pkt_len

        # Generate per-IP configuration
        per_ip_config = {}
        for ip, port_stats in ip_traffic.items():
            allowed_ports = list(port_stats.keys())
            total_packets = sum(stats["packets"] for stats in port_stats.values())
            total_bytes = sum(stats["bytes"] for stats in port_stats.values())
            per_ip_config[ip] = {
                "allowed_ports": allowed_ports,
                "max_packets": int(total_packets * multiplier),
                "max_bytes": int(total_bytes * multiplier),
            }

        # Create baseline config with variance applied
        baseline_config = {
            "overall": {
                "max_packets": int(total_file_packets * multiplier),
                "max_bandwidth_bytes": int(total_file_bytes * multiplier),
            },
            "ip_thresholds": {
                "allowed_ranges": most_common_ips,
                "per_ip": per_ip_config,
            },
        }

        # Write to output file
        with open(output_file, "w") as f:
            json.dump(baseline_config, f, indent=2)
        return baseline_config


@click.group()
def cli():
    """PCAP Analyzer - Analyze network capture files using configurable thresholds"""
    pass


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "-c",
    "--config",
    type=click.Path(exists=True),
    help="Path to configuration JSON file",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default="output.json",
    help="Output file for results (JSON format)",
)
@click.option("-v", "--verbose", is_flag=True, help="Display detailed statistics")
def analyze(pcap_file, config, output, verbose):
    """Analyze a PCAP file based on configurable thresholds"""
    try:
        click.echo(f"Analyzing {pcap_file}...")
        analyzer = PcapAnalyzer(pcap_file, config)
        results = analyzer.analyze()

        status = "PASS" if results["pass"] else "FAIL"
        styled_status = click.style(
            status, fg="green" if results["pass"] else "red", bold=True
        )
        click.echo(f"\nPCAP Analysis Result: {styled_status}")

        # Show warnings if any
        if results.get("warnings"):
            click.echo("\nWarnings:")
            for warning in results["warnings"]:
                click.echo(click.style(f"- {warning}", fg="yellow"))

        if not results["pass"]:
            click.echo("\nViolations:")
            for violation in results["violations"]:
                click.echo(f"- {violation}")

        if verbose:
            click.echo("\nStatistics:")
            for category, stats in results["stats"].items():
                click.echo(f"\n{category.upper()}:")
                if isinstance(stats, dict):
                    for key, value in stats.items():
                        if isinstance(value, dict):
                            click.echo(f"  {key}:")
                            for subkey, subvalue in value.items():
                                click.echo(f"    {subkey}: {subvalue}")
                        else:
                            click.echo(f"  {key}: {value}")
                else:
                    click.echo(f"  {stats}")

        # Save to file if requested
        if output:
            with open(output, "w") as f:
                json.dump(results, f, indent=2)
            click.echo(f"\nResults saved to " f"{click.style(output, fg='blue')}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if not results["pass"]:
        sys.exit(1)
    sys.exit(0)


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default="baseline_config.json",
    help="Output file for baseline configuration",
)
@click.option(
    "--variance",
    "variance_percent",
    type=float,
    default=10,
    show_default=True,
    help="Percentage variance to apply to packet and byte thresholds in the baseline",
)
def baseline(pcap_file, output, variance_percent):
    """Generate a baseline configuration file from a PCAP file."""
    try:
        click.echo(f"Generating baseline configuration from {pcap_file}...")
        analyzer = PcapAnalyzer(pcap_file)
        analyzer.generate_baseline(output, variance_percent=variance_percent)
        click.echo(f"Baseline configuration saved to {output}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    cli()
