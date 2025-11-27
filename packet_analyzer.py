"""
Network Packet Analyzer
- Modes: live sniffing or pcap file analysis
- Educational use only. Use on networks you own or where you have permission.
Dependencies: scapy
    pip install scapy
Run:
    python packet_analyzer.py --mode live --iface eth0
    python packet_analyzer.py --mode pcap --file capture.pcap
"""

import argparse
import sys
import time
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, IP, IPv6, TCP, UDP, ICMP, Raw, Ether
except Exception as e:
    print("Scapy not found. Install with: pip install scapy")
    raise

MAX_PAYLOAD_PREVIEW = 64  # bytes to show from payload


def format_payload(pkt):
    # return short hex + text preview
    raw = None
    if Raw in pkt:
        raw = bytes(pkt[Raw].load)
    elif pkt.payload and hasattr(pkt.payload, "load"):
        try:
            raw = bytes(pkt.payload.load)
        except Exception:
            raw = None

    if not raw:
        return ""

    # text preview (printable ascii) and hex fallback
    try:
        text = raw[:MAX_PAYLOAD_PREVIEW].decode("utf-8", errors="replace")
    except Exception:
        text = ""
    hex_preview = raw[:MAX_PAYLOAD_PREVIEW].hex()
    return f"HEX({hex_preview}) TEXT({text})"


def analyze_packet(pkt, verbose=False):
    ts = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    proto = "OTHER"
    src = dst = "-"
    sport = dport = "-"
    length = len(pkt)

    # Ethernet -> IP/IPv6
    if Ether in pkt and pkt[Ether].type:
        # keep for possible future use
        pass

    if IP in pkt:
        ip = pkt[IP]
        proto_num = ip.proto
        src = ip.src
        dst = ip.dst
        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"
        else:
            proto = f"IP(proto={proto_num})"
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        src = ip6.src
        dst = ip6.dst
        if TCP in pkt:
            proto = "TCP6"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP6"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            proto = "IPv6"
    else:
        # Not IP: show layer summary
        src = getattr(pkt.src, "src", "-")
        dst = getattr(pkt.dst, "dst", "-")
        proto = pkt.summary()

    payload_preview = format_payload(pkt)
    if verbose:
        print(f"{ts} | {proto:6} | {src:>21} -> {dst:<21} | sport:{sport} dport:{dport} | len:{length}")
        if payload_preview:
            print(f"    payload: {payload_preview}")
    else:
        print(f"{ts} | {proto:6} | {src} -> {dst} | sport:{sport} dport:{dport} | len:{length}")
        if payload_preview:
            # inline small preview
            print(f"    payload: {payload_preview}")


def live_sniff(iface, count, timeout, verbose=False, filter_expr=None):
    print(f"[+] Starting live capture on iface='{iface}' (count={count}, timeout={timeout})")
    pkts = []

    def _callback(pkt):
        pkts.append(pkt)
        analyze_packet(pkt, verbose=verbose)
        # flush output in some terminals
        sys.stdout.flush()
        if count and len(pkts) >= count:
            return True  # stop

    sniff_kwargs = {"prn": _callback, "store": False}
    if iface:
        sniff_kwargs["iface"] = iface
    if filter_expr:
        sniff_kwargs["filter"] = filter_expr
    if timeout:
        sniff_kwargs["timeout"] = timeout

    try:
        sniff(**sniff_kwargs)
    except PermissionError:
        print("Permission denied: try running with sudo/administrator privileges.")
    except Exception as e:
        print("Error while sniffing:", e)


def analyze_pcap(file_path, limit=None, verbose=False):
    print(f"[+] Loading pcap file: {file_path}")
    try:
        pkts = rdpcap(file_path)
    except FileNotFoundError:
        print("File not found:", file_path)
        return
    except Exception as e:
        print("Failed to read pcap:", e)
        return

    total = len(pkts)
    print(f"[+] Packets in file: {total}")
    n = 0
    for pkt in pkts:
        n += 1
        analyze_packet(pkt, verbose=verbose)
        if limit and n >= limit:
            break

    print(f"[+] Done. Processed {n} packets.")


def main():
    parser = argparse.ArgumentParser(description="Network Packet Analyzer (educational)")
    parser.add_argument("--mode", choices=["live", "pcap"], default="pcap", help="Operation mode")
    parser.add_argument("--iface", help="Interface for live capture (e.g., eth0, Wi-Fi).")
    parser.add_argument("--file", help="PCAP file path for analysis.")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0=unlimited).")
    parser.add_argument("--timeout", type=int, default=0, help="Timeout seconds for live capture (0=none).")
    parser.add_argument("--limit", type=int, default=0, help="Limit packets to read from pcap (0=all).")
    parser.add_argument("--filter", help="BPF filter expression (e.g., 'tcp and port 80') for live mode.")
    parser.add_argument("--verbose", action="store_true", help="Verbose output with more details.")
    args = parser.parse_args()

    if args.mode == "pcap":
        if not args.file:
            print("PCAP mode requires --file <path_to_pcap>")
            sys.exit(1)
        analyze_pcap(args.file, limit=args.limit or None, verbose=args.verbose)
    else:
        # live mode
        if not args.iface:
            print("Live mode recommended with --iface. Example: --iface Wi-Fi or --iface eth0")
            print("Attempting to sniff on default interface (may require privileges).")
        live_sniff(args.iface, count=args.count or None, timeout=args.timeout or None, verbose=args.verbose, filter_expr=args.filter)


if __name__ == "__main__":
    main()
