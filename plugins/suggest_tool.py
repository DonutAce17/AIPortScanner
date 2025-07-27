def suggest_tools(open_ports):
    suggestions = []
    if 80 in open_ports or 443 in open_ports:
        suggestions.append("→ Run: nikto -h <target>")
        suggestions.append("→ Try: gobuster dir -u http://<target> -w common.txt")
    if 22 in open_ports:
        suggestions.append("→ SSH detected, check brute-force protection")
    return "\n".join(suggestions)
