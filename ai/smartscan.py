import subprocess

def get_ttl(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            if "ttl=" in line.lower():
                ttl_value = int(line.lower().split("ttl=")[-1].split()[0])
                return ttl_value
    except Exception as e:
        print(f"[-] TTL detection failed: {e}")
    return None

def fingerprint_os(ttl):
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix (TTL ~64)"
    elif ttl <= 128:
        return "Windows (TTL ~128)"
    elif ttl <= 255:
        return "Cisco/Network Device (TTL ~255)"
    return "Unknown"

def get_priority_ports(ip):
    ttl = get_ttl(ip)
    os_guess = fingerprint_os(ttl)
    print(f"[*] Fingerprinting OS based on TTL: {os_guess}")
    
    if "Linux" in os_guess:
        return [22, 80, 443, 3306, 8080]
    elif "Windows" in os_guess:
        return [135, 139, 445, 3389]
    else:
        return list(range(1, 1025))
