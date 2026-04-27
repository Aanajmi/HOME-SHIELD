# HOME-SHIELD

## Overview

HOME-SHIELD is my cybersecurity practicum / capstone project focused on a real-world home network security problem.

The idea behind this project is pretty simple: a lot of people can set up a separate SSID, VLAN, or guest network for IoT devices, but it is still hard to actually **measure** what is visible and reachable after those changes are made.

HOME-SHIELD is a defensive Python CLI tool that helps measure that exposure through a **measure -> harden -> re-measure** workflow.

This project is **not** a full vulnerability scanner. It is meant to validate segmentation and show what devices and services are still visible across network boundaries.

---

## Why I built this

Modern home networks are not just laptops and phones anymore. They usually include smart TVs, speakers, cameras, hubs, printers, and other IoT devices.

That creates a real security problem:
- devices may still be visible even when they are supposed to be isolated
- services may still be reachable across segments
- users often configure networks, but do not have a simple way to verify whether those changes actually worked

HOME-SHIELD was built to help answer this question:

**Did my hardening change actually reduce exposure?**

---

## What the tool does

HOME-SHIELD supports four main commands:

- `measure` - collects discovery and TCP reachability results
- `diff` - compares two runs and shows what changed
- `report` - generates an HTML report
- `pcap-parse` - optionally parses packet captures for offline evidence

The main workflow is:

1. Run a baseline scan
2. Apply a hardening change
3. Run a second scan
4. Compare the two runs
5. Generate a report

---

## Project structure

```text
homeshield_submission/
├── homeshield/          # source code
├── tests/               # test files
├── homeshield_main.py   # main entry point
├── setup.py             # packaging / install metadata
├── README.md
├── LICENSE
└── .gitignore
```

---

## Main modules

Inside the `homeshield/` package, the project is split into modules by responsibility:

- `commands/` - command workflows
- `discovery/` - mDNS and SSDP discovery
- `reachability/` - TCP connect checks
- `diff/` - comparison and scoring logic
- `report/` - HTML report generation
- `pcap/` - optional PCAP parsing
- `utils/` - logging, output, and helper logic

I organized it this way to make the project easier to test, explain, and extend.

---

## Requirements

- Python 3.8+
- macOS or Linux
- `jinja2>=3.0`

Optional:
- `tshark` for PCAP parsing support

---

## Installation

Step 1: install from the repo
```bash
git clone https://github.com/aanajmi/HOME-SHIELD.git
cd HOME-SHIELD
pip install -e .
```

Step 1: Install the dependency manually
```bash
pip install jinja2
```

---

## Quick start

Show help:
```bash
python homeshield_main.py --help
```

Or, if installed with `pip install -e .`: (step 1)
```bash
homeshield --help
```

### Example measure command
```bash
homeshield measure --label (file name) --vantage iot --iface (interface) --rounds 5 --interval 10 --listen 4 --ports 80,443,445,554,1883
```

### Example diff command
```bash
homeshield diff --before outputs/(baseline file name)/run.json --after outputs/(new file name)/run.json --out outputs/blackhole_111_diff.json
```

### Example report command
```bash
homeshield report --diff outputs/(file name).json --out reports/blackhole_111_diff.html
```

---

## Output files

A measurement run can generate:

- `run.json` - full structured run data
- `discovery.csv` - discovery results
- `reachability.csv` - TCP reachability results

A comparison can generate:

- `diff.json` - before/after deltas and score changes

A report run can generate:

- HTML reports for a run or a diff

---

## Scoring

The scoring model starts at 100 and subtracts penalties based on observed exposure.

Current scoring:
- `-2` per unique mDNS responder
- `-2` per unique SSDP responder
- `-5` per OPEN port
- `-8` extra per newly OPEN port after hardening

Higher score = less exposure

---

## Example capstone evaluation idea

For my practicum testing, I used a baseline -> controlled change -> re-measurement workflow.

In one test:
- a target device initially had ports 80 and 443 open
- I introduced a temporary, reversible routing change on my Mac
- HOME-SHIELD detected both ports as closed in the second run
- the diff report marked the result as improved

That helped show the workflow worked the way I intended.

---

## Limitations

This project has a few important limits:

- multicast discovery can vary between runs
- visible does not always mean dangerous
- reachable does not automatically mean vulnerable
- results from one homelab do not automatically generalize to every home network
- this tool measures exposure indicators, not full security posture

---

## Future work

Some next steps I want to continue working on:
- support more discovery / management protocols
- improve reporting and visualization
- test across more devices and home environments
- improve packaging and public release workflow

---

## Notes

This repo is a student capstone project, so it is still evolving. The goal was to build something practical, testable, and useful for validating home / IoT network segmentation.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
