"""HomeShield CLI — main entry point for all commands.

Provides the 'homeshield' command with subcommands:
    measure     — Run discovery + reachability and write outputs
    diff        — Compare two run.json files (before/after)
    report      — Generate HTML report from diff or run data
    pcap-parse  — Extract mDNS/SSDP talkers from PCAP using tshark
"""

import argparse
import json
import sys
import traceback

from homeshield import __version__
from homeshield.utils.logging_config import setup_logging, get_logger


def parse_ports(ports_str: str):
    """Parse comma-separated port list string into list of integers.

    Args:
        ports_str: Comma-separated string of port numbers.

    Returns:
        List of integer port numbers.

    Raises:
        argparse.ArgumentTypeError: If parsing fails.
    """
    try:
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} out of range (1-65535)")
        return ports
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid port list: {exc}")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="homeshield",
        description="HomeShield — Home Network Exposure Measurement Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  homeshield measure --label baseline_iot --vantage iot --iface en0 --rounds 5\n"
            "  homeshield diff --before outputs/baseline/run.json --after outputs/hardened/run.json\n"
            "  homeshield report --diff outputs/diff.json --out reports/report.html\n"
            "  homeshield pcap-parse --pcap evidence/pcaps/capture.pcap\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"homeshield {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── measure ──
    measure_p = subparsers.add_parser(
        "measure",
        help="Run discovery + reachability and write outputs",
        description="Send multicast discovery probes and perform TCP reachability checks.",
    )
    measure_p.add_argument(
        "--label", required=True,
        help="Run label for output directory (e.g., baseline_iot_run1)",
    )
    measure_p.add_argument(
        "--vantage", default="default",
        help="Vantage point name (e.g., iot, guest, trusted). Default: default",
    )
    measure_p.add_argument(
        "--iface", default=None,
        help="Network interface (e.g., en0, eth0, wlan0) or on Windows: adapter name (e.g., 'Wi-Fi', 'Ethernet') or IP address",
    )
    measure_p.add_argument(
        "--rounds", type=int, default=3,
        help="Number of discovery rounds. Default: 3",
    )
    measure_p.add_argument(
        "--interval", type=float, default=10.0,
        help="Seconds between discovery rounds. Default: 10.0",
    )
    measure_p.add_argument(
        "--listen", type=float, default=4.0,
        help="Listen window in seconds per round. Default: 4.0",
    )
    measure_p.add_argument(
        "--ports", type=parse_ports, default=None,
        help="Comma-separated TCP ports to check (e.g., 80,443,554,445). Default: 80,443,554,445,1883,8080,8443,8883",
    )
    measure_p.add_argument(
        "--timeout", type=float, default=1.0,
        help="TCP connect timeout in seconds. Default: 1.0",
    )
    measure_p.add_argument(
        "--workers", type=int, default=10,
        help="Number of concurrent reachability workers. Default: 10",
    )
    measure_p.add_argument(
        "--output-dir", default="outputs",
        help="Base output directory. Default: outputs",
    )

    # ── diff ──
    diff_p = subparsers.add_parser(
        "diff",
        help="Compare two run.json files (before/after)",
        description="Compute exposure deltas and scores from baseline and hardened runs.",
    )
    diff_p.add_argument(
        "--before", required=True,
        help="Path to baseline run.json",
    )
    diff_p.add_argument(
        "--after", required=True,
        help="Path to hardened run.json",
    )
    diff_p.add_argument(
        "--out", default="outputs/diff.json",
        help="Output path for diff.json. Default: outputs/diff.json",
    )

    # ── report ──
    report_p = subparsers.add_parser(
        "report",
        help="Generate HTML report from diff or run data",
        description="Create a readable HTML report for non-technical audience.",
    )
    report_group = report_p.add_mutually_exclusive_group(required=True)
    report_group.add_argument(
        "--diff",
        help="Path to diff.json for comparison report",
    )
    report_group.add_argument(
        "--run",
        help="Path to run.json for single-run report",
    )
    report_p.add_argument(
        "--out", default="reports/report.html",
        help="Output path for HTML report. Default: reports/report.html",
    )

    # ── pcap-parse ──
    pcap_p = subparsers.add_parser(
        "pcap-parse",
        help="Extract mDNS/SSDP talkers from PCAP using tshark",
        description="Parse PCAP file to extract network discovery evidence.",
    )
    pcap_p.add_argument(
        "--pcap", required=True,
        help="Path to PCAP file",
    )

    return parser


def main():
    """Main entry point for the homeshield CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Initialize logging
    logger_root = setup_logging()
    logger = get_logger("cli")
    logger.info("HomeShield v%s — command: %s", __version__, args.command)

    try:
        if args.command == "measure":
            from homeshield.commands.measure import execute_measure
            execute_measure(
                label=args.label,
                vantage=args.vantage,
                iface=args.iface,
                rounds=args.rounds,
                interval=args.interval,
                listen=args.listen,
                ports=args.ports,
                timeout=args.timeout,
                workers=args.workers,
                output_dir=args.output_dir,
            )

        elif args.command == "diff":
            from homeshield.commands.diff_cmd import execute_diff
            execute_diff(
                before_path=args.before,
                after_path=args.after,
                output_path=args.out,
            )

        elif args.command == "report":
            from homeshield.commands.report_cmd import execute_report
            execute_report(
                diff_path=getattr(args, "diff", None),
                run_path=getattr(args, "run", None),
                output_path=args.out,
            )

        elif args.command == "pcap-parse":
            from homeshield.commands.pcap_cmd import execute_pcap_parse
            execute_pcap_parse(pcap_path=args.pcap)

        else:
            parser.print_help()
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(130)
    except FileNotFoundError as exc:
        logger.error("File not found: %s", exc)
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON: %s", exc)
        print(f"\nError: Invalid JSON — {exc}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as exc:
        logger.error("Runtime error: %s", exc)
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        logger.error("Value error: %s", exc)
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error: %s\n%s", exc, traceback.format_exc())
        print(f"\nUnexpected error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
