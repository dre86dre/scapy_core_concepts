# Scapy Concepts

This script shows beginner-friendly Scapy examples!

This repository contains a Python script that demonstrates a few core network conceptsand basic Scapy operations:
- `ping` - ICMP echo request/reply
- `show` - build and inspect a packet (IP/TCP/Raw)
- `scan` - very small TCP SYN probe for one port
- `sniff` - capture and summarise a few packets
- `trace` - a tiny traceroute using ICMP and increasing TTL

---

## Requirements

- Python 3.7+
- `scapy` library: install with:
```
python3 -m pip install scapy
```

## Safety

- Sending raw packets and sniffing usually requires elevated priviledges. On Linux/macOS, use `sudo` for commands that faildue to permissions. On Windows run the terminal as Administrator.
- Only test against systems you own or have explicit permission to test.
- Use `scanme.nmap.org` for learning scans if you need a public target that allows basic scanning.
- Do not run packet capture on networks where you may capture sensitive traffic without permission.

---

## Installation

Clone the repo:

```
git clone https://github.com/dre86dre/scapy_core_concepts.git
cd scapy_core_concepts
```

---

## Usage

Make sure `scapy` is installed, then run the script:

```
python scapy_core_concepts.py --help
```

Examples:
  - Ping a host:
    ```
    python scapy_core_concepts.py ping 8.8.8.8
    ```
    
  - Show a built packet (inspect structure):
    ```
    python scapy_core_concepts.py show --dest 1.1.1.1
    ```
    
  - Fast SYN probe of one port:
    ```
    sudo python scapy_core_concepts.py scan scanme.nmap.org --port 22
    ```
    
  - Capture 5 packets:
    ```
    sudo python scapy_core_concepts.py sniff --count 5
    ```
    
  - Traceroute:
    ```
    sudo python scapy_core_concepts.py trace 8.8.8.8 --max-hops 12
    ```

---

