#!/usr/bin/env python3

import socket
import argparse
import datetime
import os
import csv
import xml.etree.ElementTree as ET

# Common ports for lite scan
LITE_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 3306, 8080]

# Function to detect OS from TTL
def detect_os(ttl):
    if ttl >= 128:
        return "Windows (TTL ~128)"
    elif ttl >= 64:
        return "Linux/Unix (TTL ~64)"
    else:
        return "Unknown"

# Function to write markdown report
def write_markdown_report(target, results):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/scan_{target}_{timestamp}.md"
    os.makedirs("reports", exist_ok=True)
    with open(filename, "w") as f:
        f.write(f"# Scan Report for {target}\n\n")
        for port, service in results:
            f.write(f"- **{port}/tcp** - Open - {service}\n")
        f.write("\n---\n**AI Summary**\n")
        f.write("→ Run: nikto -h <target>\n")
        f.write("→ Try: gobuster dir -u http://<target> -w common.txt\n")
    print(f"📁 Report saved: {filename}")

# Function to write CSV report
def write_csv_report(target, results):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/scan_{target}_{timestamp}.csv"
    with open(filename, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Protocol", "Status", "Service"])
        for port, service in results:
            writer.writerow([port, "tcp", "open", service])

# Function to write XML report
def write_xml_report(target, results):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/scan_{target}_{timestamp}.xml"
    root = ET.Element("scan")
    ET.SubElement(root, "target").text = target
    for port, service in results:
        port_el = ET.SubElement(root, "port")
        ET.SubElement(port_el, "number").text = str(port)
        ET.SubElement(port_el, "protocol").text = "tcp"
        ET.SubElement(port_el, "status").text = "open"
        ET.SubElement(port_el, "service").text = service
    tree = ET.ElementTree(root)
    tree.write(filename)

# Port scanner function
def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((target, port))
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            open_ports.append((port, service))
            s.close()
        except:
            pass
    return open_ports

def get_ttl(target):
    try:
        import subprocess
        result = subprocess.run(["ping", "-c", "1", target], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        for line in output.splitlines():
            if "ttl=" in line:
                ttl_value = int(line.split("ttl=")[1].split()[0])
                return ttl_value
    except:
        return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AI Port Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--smart", action="store_true", help="Smart scan mode (OS detection + port scan)")
    parser.add_argument("--lite", action="store_true", help="Lite scan mode (fast scan on common ports)")
    parser.add_argument("--deep", action="store_true", help="Deep scan mode (full scan 1-65535)")
    args = parser.parse_args()

    print("[!] Use this tool only on systems you own or are authorized to test.")

    if args.smart:
        print("[*] Smart scan mode activated.")
        ttl = get_ttl(args.target)
        os_name = detect_os(ttl)
        print(f"[*] Fingerprinting OS based on TTL: {os_name}")
        ports = LITE_PORTS
    elif args.lite:
        print("[*] Lite scan mode activated.")
        ports = LITE_PORTS
    elif args.deep:
        print("[*] Deep scan mode activated. This might take a while...")
        ports = list(range(1, 65536))
    else:
        ports = LITE_PORTS

    results = scan_ports(args.target, ports)
    for port, service in results:
        print(f"[+] {port}/tcp - Open - {service}")

    write_markdown_report(args.target, results)
    write_csv_report(args.target, results)
    write_xml_report(args.target, results)
