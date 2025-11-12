#!/usr/bin/env python3

import sys          # for exiting on error or reading argv
import socket       # to resolve hostnames to IP addresses
import argparse     #tiny command-line parsing helper

# try importing minimal Scapy pieces; fail with a friendly message if not installed
try:
    from scapy.all import IP, ICMP, TCP, sr1, sniff, Raw
except Exception as e:
    # print a user-friendly message then exit if Scapy isn't available
    print("Scapy is required. Install with pip install scapy")
    print("Import error:", e)
    sys.exit(1)

# small helper: convert hostname to IPv4 string (raises on failure)
def resolve(host):
    # socket.hethostbyname does DNS lookup and returns an IPv4 address string
    return socket.gethostbyname(host)


# Ping Example

def ping_once(target, timeout=2.0):
    # Resolve the host to an IP address (will raise if the name is bad)
    ip = resolve(target)
    # Build an ICMP echo request packet: IP layer with destination + ICMP layer
    pkt = IP(dst=ip) / ICMP()
    # Send the packet and wait for one reply (sr1). verbose=0 hides scapy prints.
    reply = sr1(pkt, timeout=timeout, verbose=0)
    # If we got a reply, print a short friendly message, else say timeout
    if reply:
        print(f"Reply from {reply.src}: type={reply.getlayer(ICMP).type}")
    else:
        print("No reply (timeout)")


# Show Packet Example

def show_packet_example(dest="8.8.8.8"):
    # Resolve destination
    ip = resolve(dest)
    # Build a super simple packet: IP -> TCP -> Raw payload
    pkt = IP(dst=ip, ttl=64) / TCP(dport=80, sport=12345, flags="S") / Raw(load=b"hi")
    # Print detailed structure of the packet to learn fields
    pkt.show()


# Tiny SYN Scan (one port)

def syn_scan_one(target, port=80, timeout=1.0):
    # Resolve target
    ip = resolve(target)
    # Build a TCP SYN packet (IP + TCP with flags 'S')
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    # Send and wait for one reply
    resp = sr1(pkt, timeout=timeout, verbose=0)
    # Interpret response: SYN-ACK (flags 0x12) means likely open
    if resp is None:
        print(f"Port {port}: no response (closed/filtered)")
    elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
        print(f"Port {port}: open (SYN-ACK received)")
    else:
        print(f"Port {port}: closed or other response")


# Sniffing A Few Packets

def sniff_count(n=5, filter_expr=None):
    # sniff() captures packets; count tells how many; filter_expr accepts BPF-style filters
    pkts = sniff(count=n, filter=filter_expr)
    # print one-line summaries so results are easy to read
    for i, p in enumerate(pkts, 1):
        print(f"{i:02d}: {p.summary()}")


# Tiny Traceroute (ICMP based)

def tiny_trace(target, max_hops=10, timeout=1.0):
    # resolve target
    ip = resolve(target)
    # iterate TTL from 1..max hops
    for ttl in range(1, max_hops + 1):
        # build packet with increasing ttl
        pkt = IP(dst=ip, ttl=ttl) / ICMP()
        # send and wait for reply
        reply = sr1(pkt, timeout=timeout, verbose=0)
        # print hop result
        if reply is None:
            print(f"{ttl:02d}: *")
        else:
            print(f"{ttl:02d}: {reply.src}")
            # stop if we've reached the destination
            if reply.src == ip:
                break


# Small Command-Line Interface

def build_parser():
    # create an ArgumentParser to read simple commands and options
    p = argparse.ArgumentParser(description="Ultra-minimal Scapy examples (ping, show, scan, sniff, trace).")
    sub = p.add_subparsers(dest="cmd")  # subcommands: ping/show/scan/sniff/trace

    # ping subcommand
    a = sub.add_parser("ping", help="Send one ICMP echo request")
    a.add_argument("target", help="hostname or IP to ping")
    a.add_argument("--timeout", type=float, default=2.0)

    # show packet subcommand
    b = sub.add_parser("show", help="Build and display a small custom packet")
    b.add_argument("--dest", default="8.8.8.8")

    # scan subcommand (one port)
    c = sub.add_parser("scan", help="Quick SYN scan of one port (use responsibly)")
    c.add_argument("target")
    c.add_argument("--port", type=int, default=80)
    c.add_argument("--timeout", type=float, default=1.0)

    # sniff subcommand
    d = sub.add_parser("sniff", help="Capture a few packets and print summaries")
    d.add_argument("--count", type=int, default=5)
    d.add_argument("--filter", default=None)

    # trace subcommand
    e = sub.add_parser("trace", help="Tiny traceroute (ICMP)")
    e.add_argument("target")
    e.add_argument("--max-hops", type=int, default=10)
    e.add_argument("--timeout", type=float, default=1.0)

    return p

# main: parse args and dispatch to tiny functions above
def main(argv=None):
    # show a short permission note for beginners
    print("Note: some operations may need sudo/Administrator. Only test on allowed targets.\n")

    # parse command-line arguments
    parser = build_parser()
    args = parser.parse_args(argv)

    # dispatch based on subcommand name
    if args.cmd == "ping":
        ping_once(args.target, timeout=args.timeout)
    elif args.cmd == "show":
        show_packet_example(dest=args.dest)
    elif args.cmd == "scan":
        syn_scan_one(args.target, port=args.port, timeout=args.timeout)
    elif args.cmd == "sniff":
        sniff_count(n=args.count, filter_expr=args.filter)
    elif args.cmd == "trace":
        tiny_trace(args.target, max_hops=args.max_hops, timeout=args.timeout)
    else:
        # no subcommand provided: print help for the user
        parser.print_help()

# Python idiom: only run main() when the script is executed (not when imported)
if __name__ == "__main__":
    main()