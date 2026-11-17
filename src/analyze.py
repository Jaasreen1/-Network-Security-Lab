#!/usr/bin/env python3
"""Analyze exported Nmap XML and Wireshark CSV locally; no scanning is performed."""
import argparse
import csv
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET

def read_nmap(path):
    root = ET.parse(path).getroot()
    if root.tag != "nmaprun":
        raise ValueError("Expected Nmap XML")
    hosts = []
    for host in root.findall("host"):
        address = host.find("address")
        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            ports.append({"protocol": port.get("protocol", ""),
                          "port": port.get("portid", ""),
                          "state": state.get("state", "unknown") if state is not None else "unknown",
                          "service": service.get("name", "unknown") if service is not None else "unknown"})
        hosts.append({"address": address.get("addr", "unknown") if address is not None else "unknown", "ports": ports})
    return hosts

def read_traffic(path):
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not {"Source", "Destination", "Protocol"}.issubset(reader.fieldnames or []):
            raise ValueError("CSV needs Source, Destination, Protocol columns")
        rows = list(reader)
    return {"packets": len(rows),
            "protocols": Counter(r["Protocol"] or "Unknown" for r in rows),
            "conversations": Counter((r["Source"], r["Destination"]) for r in rows)}

def report(hosts, traffic, synthetic=False):
    lines = ["# Network Analysis Report", "",
             "**Data:** " + ("SYNTHETIC EXAMPLES — not real captures" if synthetic else "User-supplied exports; authenticity not verified"),
             "", "## Nmap results", f"Hosts: {len(hosts)}", ""]
    for host in hosts:
        lines.append("### Host `" + host["address"] + "`")
        for port in host["ports"]:
            lines.append(f"- {port['protocol']}/{port['port']}: {port['state']} — reported service: {port['service']}")
        lines.append("")
    lines += ["## Traffic summary", f"Packets: {traffic['packets']}", "", "### Protocols"]
    lines += [f"- {name}: {count}" for name, count in traffic["protocols"].most_common()]
    lines += ["", "### Conversations"]
    lines += [f"- `{src}` → `{dst}`: {count}" for (src, dst), count in traffic["conversations"].most_common(10)]
    lines += ["", "## Limitations", "Metadata summaries do not prove vulnerabilities or intrusions. Validate findings manually."]
    return "\n".join(lines) + "\n"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nmap", required=True)
    parser.add_argument("--traffic", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    synthetic = Path(args.nmap).name == "nmap_demo.xml" and Path(args.traffic).name == "traffic_demo.csv"
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report(read_nmap(args.nmap), read_traffic(args.traffic), synthetic), encoding="utf-8")
    print(f"Report written to {output}")

if __name__ == "__main__":
    main()
