# Required and Optional Tools Setup

## Required (Python - no install needed)
The core scripts use only Python 3 standard library. No pip install required.

## Optional Go Tools (Recommended for Performance)

These tools dramatically speed up scanning. Install any/all:

### subfinder - Fast passive subdomain enumeration
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### httpx - Fast HTTP probing
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### puredns - Fast DNS brute-force with massdns
```bash
go install github.com/d3mondev/puredns/v2@latest
```

### naabu - Fast port scanner
```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### amass - Comprehensive subdomain enumeration
```bash
go install -v github.com/owasp-amass/amass/v4/...@master
```

## System Tools
- `dig` - DNS queries (pre-installed on macOS/Linux)
- `whois` - WHOIS lookups (pre-installed on macOS/Linux)
- `nmap` - Port scanning (install via package manager)

### Install nmap
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt install nmap

# Arch
sudo pacman -S nmap
```
