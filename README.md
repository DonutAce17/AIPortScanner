# AIPortScanner 🔍🤖

**AI-Enhanced Network Port Scanner for Kali Linux**

AIPortScanner is a powerful and intelligent port scanning tool designed for ethical hacking, penetration testing, and network reconnaissance. It includes AI-powered smart scanning modes, automatic fingerprinting, and rich report generation in Markdown, XML, and CSV.

---

## 🚀 Features

- ✅ Smart Scan Mode (`--smart`) with OS fingerprinting
- ✅ Fast / Deep scan modes
- ✅ Markdown + XML + CSV report generation
- ✅ Plugin support (YAML-based)
- ✅ AI-based suggestions after scan
- ✅ Lightweight CLI and Binary tool (Linux `.deb` package ready)
- ✅ Burp-style structured output
- ✅ Compatible with Kali Linux & Debian systems

---

## 📦 Installation

### 📁 Option 1: Clone & Run
```bash
git clone https://github.com/DonutAce17/AIPortScanner.git
cd AIPortScanner
python3 portscanner.py <target-ip> --smart
