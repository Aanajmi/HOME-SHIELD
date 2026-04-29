# HOME-SHIELD

**Home IoT Exposure Validator**  
Defensive network exposure measurement for home, SOHO, student lab, and homelab environments.

HOME-SHIELD is a Python command-line tool that helps you measure what devices and services are visible or reachable from a specific network position, such as an IoT VLAN, guest Wi-Fi network, trusted LAN, or lab subnet.

The core workflow is:

```text
Measure baseline -> Harden network -> Re-measure -> Compare -> Report
```

The main question HOME-SHIELD helps answer is:

> Did my network hardening change actually reduce observable exposure?

---

## Table of contents

- [What HOME-SHIELD does](#what-home-shield-does)
- [What HOME-SHIELD does not do](#what-home-shield-does-not-do)
- [Example output](#example-output)
- [Sample report](#sample-report)
- [Supported platforms](#supported-platforms)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Understanding Bonjour, mDNS, and SSDP](#understanding-bonjour-mdns-and-ssdp)
- [Understanding the exposure score](#understanding-the-exposure-score)
- [Output files](#output-files)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Roadmap](#roadmap)

---

## What HOME-SHIELD does

HOME-SHIELD is a **defensive measurement tool** for validating home and small-office network hardening.

It helps test whether changes like these actually changed what is visible or reachable:

- moving IoT devices to a separate SSID
- adding or adjusting firewall rules
- enabling guest network or client isolation
- changing VLAN or inter-VLAN policy
- disabling unnecessary device services
- testing a reversible route or block rule

HOME-SHIELD collects two main types of evidence:

1. **Discovery evidence** — devices that respond to local discovery protocols such as mDNS/Bonjour and SSDP/UPnP.
2. **Reachability evidence** — TCP ports that are reachable on discovered devices.

Then it can compare a baseline run against a later run and generate a readable HTML report.

---

## What HOME-SHIELD does not do

HOME-SHIELD is **not** a vulnerability scanner, exploit tool, credential checker, firmware analyzer, or public internet scanner.

It does not:

- exploit devices
- brute-force passwords
- validate whether a device has a known CVE
- inspect device firmware
- scan the public internet
- prove that a network is fully secure

An open port means a service was reachable from the scanning machine. It does **not** automatically mean the service is vulnerable.

---

## Why this project matters

Modern home networks usually include laptops, phones, smart TVs, cameras, speakers, printers, hubs, thermostats, and other IoT devices.

Many users create separate SSIDs, guest networks, or VLANs, but still struggle to verify whether the isolation actually worked. HOME-SHIELD gives users a repeatable before-and-after workflow so they can observe whether hardening changes reduced visible devices, reachable services, or newly introduced exposure.

---

## Example output

After running a baseline scan, applying a hardening change, and running a second scan, HOME-SHIELD can produce a summary like this:

```text
HomeShield Exposure Report
Comparing: baseline_iot_run1 -> hardened_iot_run1

Verdict: IMPROVED
Before score: 75
After score: 91
Change: +16

Discovery changes:
- mDNS responders: 3 -> 1
- SSDP responders: 2 -> 1

Reachability changes:
- OPEN TCP services: 3 -> 1
- 192.168.10.1:443 changed from OPEN to CLOSED
- 192.168.10.20:80 changed from OPEN to CLOSED
```

This means the tested change reduced observable exposure from the machine and network position where the scan was run.

---

## Sample report

This repository includes sample artifacts so reviewers can see the expected output format without scanning their own network first:

- [Sample baseline run JSON](docs/sample_outputs/baseline_iot_run1/run.json)
- [Sample hardened run JSON](docs/sample_outputs/hardened_iot_run1/run.json)
- [Sample diff JSON](docs/sample_outputs/diff.json)
- [Sample HTML report](docs/sample_reports/before_after.html)

The HTML report is useful for demos, project documentation, and explaining results to technical or semi-technical reviewers.

---

## Supported platforms

| Item | Status |
|---|---|
| macOS | Supported / primary tested platform |
| Linux | Supported |
| Windows | Not fully validated for this release |
| Python | Python 3.8 or newer |
| Interface | Command line |
| License | MIT |

---

## Requirements

Required:

- Python 3.8+
- `jinja2>=3.0`
- A connected local network interface such as `en0`, `eth0`, or `wlan0`

Optional:

- `tshark` for optional PCAP parsing
- `pytest` for running the test suite as a developer or reviewer

---

## Quick start

These steps use a Python virtual environment. A virtual environment keeps HOME-SHIELD's Python packages separate from your system Python installation.

### 1. Clone the repository

```bash
git clone https://github.com/aanajmi/HOME-SHIELD.git
cd HOME-SHIELD
```

### 2. Create and activate a virtual environment

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

After activation, your terminal prompt may show `(.venv)`.

### 3. Upgrade pip

```bash
python -m pip install --upgrade pip
```

### 4. Install HOME-SHIELD

```bash
python -m pip install -e .
```

If report generation dependencies are not installed automatically, install Jinja2 manually:

```bash
python -m pip install jinja2
```

### 5. Verify the CLI starts

```bash
homeshield --help
```

You can also run the tool directly from the repository folder:

```bash
python homeshield_main.py --help
```

### 6. Find your active network interface

On macOS:

```bash
route -n get default | grep interface
```

On Linux:

```bash
ip link show
```

Common examples:

- macOS Wi-Fi: `en0`
- Linux Ethernet: `eth0`
- Linux Wi-Fi: `wlan0`

### 7. Run a baseline measurement

Run this before making a network change:

```bash
homeshield measure \
  --label baseline_iot_run1 \
  --vantage iot \
  --iface en0 \
  --rounds 5 \
  --interval 10 \
  --listen 4 \
  --ports 80,443,445,554,1883
```

What the values mean:

| Value | Meaning |
|---|---|
| `baseline_iot_run1` | Name of the output folder for this run |
| `iot` | Human-readable name for where you are scanning from |
| `en0` | Network interface to scan from; change this to match your system |
| `80,443,445,554,1883` | TCP ports to test for reachability |

This creates a folder like:

```text
outputs/baseline_iot_run1/
├── run.json
├── discovery.csv
└── reachability.csv
```

### 8. Apply one controlled hardening change

Make one network change at a time so the comparison stays meaningful.

Examples:

- move IoT devices to a separate SSID
- adjust a firewall rule
- enable guest network isolation
- block IoT-to-LAN access
- disable an unnecessary printer, camera, or hub service
- test a reversible route or blocking rule

Avoid changing many things at once. If the results improve or degrade, you want to know which change caused it.

### 9. Run the second measurement

Use the same interface, vantage point, timing, and port list. Change only the label:

```bash
homeshield measure \
  --label hardened_iot_run1 \
  --vantage iot \
  --iface en0 \
  --rounds 5 \
  --interval 10 \
  --listen 4 \
  --ports 80,443,445,554,1883
```

### 10. Compare the two runs

```bash
homeshield diff \
  --before outputs/baseline_iot_run1/run.json \
  --after outputs/hardened_iot_run1/run.json \
  --out outputs/diff.json
```

### 11. Generate an HTML report

```bash
homeshield report \
  --diff outputs/diff.json \
  --out reports/before_after.html
```

Open the report on macOS:

```bash
open reports/before_after.html
```

Open the report on Linux:

```bash
xdg-open reports/before_after.html
```

### 12. Deactivate the virtual environment when finished

```bash
deactivate
```

---

## Command reference

### `measure`

Runs mDNS discovery, SSDP discovery, and TCP reachability checks.

```bash
homeshield measure --label baseline_iot_run1 --vantage iot --iface en0
```

Useful options:

| Option | Meaning | Default |
|---|---|---|
| `--label` | Name for the run output folder | Required |
| `--vantage` | Name of the network position being tested, such as `iot`, `guest`, or `trusted` | `default` |
| `--iface` | Network interface to use, such as `en0`, `eth0`, or `wlan0` | Default route IP |
| `--rounds` | Number of discovery rounds | `3` |
| `--interval` | Seconds between discovery rounds | `10.0` |
| `--listen` | Seconds to listen during each discovery round | `4.0` |
| `--ports` | Comma-separated TCP ports to check | `80,443,554,445,1883,8080,8443,8883` |
| `--timeout` | TCP connection timeout in seconds | `1.0` |
| `--workers` | Concurrent reachability worker threads | `10` |
| `--output-dir` | Base output directory | `outputs` |

### `diff`

Compares two `run.json` files and writes a structured difference file.

```bash
homeshield diff \
  --before outputs/baseline_iot_run1/run.json \
  --after outputs/hardened_iot_run1/run.json \
  --out outputs/diff.json
```

### `report`

Generates a readable HTML report from either a comparison file or a single run.

Comparison report:

```bash
homeshield report --diff outputs/diff.json --out reports/before_after.html
```

Single-run report:

```bash
homeshield report --run outputs/baseline_iot_run1/run.json --out reports/baseline.html
```

### `pcap-parse`

Optionally parses a packet capture for mDNS and SSDP evidence. This requires `tshark`.

```bash
homeshield pcap-parse --pcap evidence/pcaps/capture.pcap
```

Use this when you want offline packet-capture evidence in addition to the normal measurement workflow.

---

## Understanding Bonjour, mDNS, and SSDP

One reviewer asked about Bonjour. This is directly relevant to HOME-SHIELD.

**Bonjour** is Apple's implementation of **mDNS**, or multicast DNS. mDNS helps devices discover local services without a traditional DNS server. For example, AirPrint printers, Apple TVs, smart speakers, and other local services may advertise themselves using Bonjour/mDNS.

This matters for home network security because discovery traffic can create two competing problems:

1. **Data leakage / visibility:** Devices may reveal that they exist, what services they offer, or which IP addresses are active.
2. **Usability friction:** If discovery is blocked too aggressively, useful features may break, such as printing from guest Wi-Fi or casting to a TV.

HOME-SHIELD currently treats mDNS/Bonjour responders as observable exposure indicators. It does not decide whether a Bonjour response is good or bad by itself. Instead, it helps you measure whether those responders are visible from a specific network vantage point before and after a change.

For example:

```text
Before: Guest Wi-Fi can see printer mDNS advertisements.
After: Guest Wi-Fi can no longer see printer mDNS advertisements.
Result: Reduced discovery visibility, but printing from guest Wi-Fi may also stop working.
```

That tradeoff is important. The right answer depends on the network owner's goal: stronger isolation, better usability, or a carefully allowed exception.

Future work could include richer Bonjour/mDNS reporting, such as showing advertised service names, service types, and suggested allowlist decisions.

---

## Understanding the exposure score

HOME-SHIELD starts each run with a score of `100`. Higher scores mean less observed exposure from the tested vantage point.

Current scoring model:

| Exposure item | Score impact | Meaning |
|---|---:|---|
| Base score | `100` | Starting point before exposure penalties |
| Unique mDNS responder | `-2` each | A device responded to multicast DNS / Bonjour discovery |
| Unique SSDP responder | `-2` each | A device responded to SSDP / UPnP-style discovery |
| OPEN TCP port | `-5` each | A TCP service was reachable |
| Newly OPEN TCP port after hardening | `-8` extra | A possible regression or newly introduced exposure |

Important interpretation:

- A higher score is better.
- A lower score means more observed exposure.
- A score improvement suggests reduced visibility or reachability.
- A score decrease suggests increased visibility or reachability.
- The score is a measurement aid, not a formal risk rating.

---

## Output files

### Measurement output

Each `measure` run creates a folder under `outputs/` using the label you provide.

| File | Purpose |
|---|---|
| `run.json` | Full structured record of the measurement run |
| `discovery.csv` | mDNS and SSDP responders observed during discovery |
| `reachability.csv` | TCP reachability results for tested hosts and ports |

### Diff output

| File | Purpose |
|---|---|
| `diff.json` | Before-and-after changes, exposure score changes, and summary verdict |

### Report output

| File | Purpose |
|---|---|
| `.html` report | Human-readable report suitable for review, demos, or project documentation |

---

## Running tests

Install test tooling if needed:

```bash
python -m pip install pytest
```

Run the test suite from the repository root:

```bash
python -m pytest -q
```

---

## Safety and authorization

Only run HOME-SHIELD on networks and devices that you own or have explicit permission to test.

The tool is intended for defensive validation in home, SOHO, student lab, and homelab environments. Even though the checks are non-exploitative, network scanning can still trigger alerts or violate policy on networks you do not control.

---

## Project structure

```text
HOME-SHIELD/
├── homeshield/          # source code
├── tests/               # test files
├── docs/                # project documentation and sample outputs
├── homeshield_main.py   # direct Python entry point
├── setup.py             # package metadata and CLI entry point
├── README.md
├── LICENSE
└── .gitignore
```

Main source modules:

| Module | Responsibility |
|---|---|
| `homeshield/cli.py` | Main CLI parser and command routing |
| `homeshield/commands/` | Command workflows for measure, diff, report, and pcap-parse |
| `homeshield/discovery/` | mDNS and SSDP discovery logic |
| `homeshield/reachability/` | TCP connect checks |
| `homeshield/diff/` | Comparison and scoring logic |
| `homeshield/report/` | HTML report generation |
| `homeshield/pcap/` | Optional PCAP parsing through `tshark` |
| `homeshield/utils/` | Logging, network, and output helpers |

---

## Troubleshooting

| Problem | Recommended fix |
|---|---|
| `homeshield: command not found` | Confirm the virtual environment is activated, then run `python -m pip install -e .` from the repository root |
| `python: command not found` | Use `python3` to create the virtual environment, then use `python` after activation |
| Wrong interface selected | Re-check your interface with `route -n get default \| grep interface` on macOS or `ip link show` on Linux |
| No discovered devices | Confirm you are on the expected network and that multicast discovery is allowed |
| Report generation fails | Install Jinja2 with `python -m pip install jinja2` |
| PCAP parsing fails | Install `tshark` and verify it with `tshark --version` |
| Results vary between runs | Re-run with the same interface, port list, rounds, interval, and listen settings |
| Printer or casting stops working after segmentation | Check whether Bonjour/mDNS or other discovery traffic was blocked by the new network policy |

---

## Limitations

HOME-SHIELD measures observable exposure from one vantage point. Results can change depending on where the scanning machine is connected.

Known limitations:

- mDNS and SSDP responses can vary between runs.
- Reachable does not automatically mean vulnerable.
- Not reachable does not prove a device is secure.
- Results from one home network may not generalize to another network.
- The tool currently focuses on discovery and TCP reachability, not full vulnerability assessment.
- Windows support is not fully validated in this release.
- Bonjour/mDNS usability decisions can be context-specific. Blocking discovery may improve isolation but break expected home-network features.

---

## Roadmap

Potential future improvements:

- add richer Bonjour/mDNS reporting, including service names and service types
- add more discovery and management protocol support
- improve report visualizations
- add trend reporting across multiple runs
- add topology-style views that show which segments can or cannot reach specific services
- improve packaging and release workflow
- validate additional operating systems and network environments
- expand sample datasets for repeatable demos

---

## Academic context

HOME-SHIELD was developed as a cybersecurity practicum / capstone project. The goal is to identify a real-world cybersecurity problem, implement a practical technical solution, and evaluate the solution through repeatable before-and-after testing.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
