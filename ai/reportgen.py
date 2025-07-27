def generate_report(ip, open_ports, suggestions, filepath):
    with open(filepath, "w") as f:
        f.write(f"# Port Scan Report for {ip}\n\n")
        for port, service in open_ports:
            f.write(f"- Port {port}: Open ({service})\n")
        f.write("\n## AI Suggestions\n")
        f.write(suggestions + "\n")
