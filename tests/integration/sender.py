import argparse
import sys

from scapy.all import *

# Default Configuration
DEFAULT_IFACE = "veth-ns"
DST_IP = "10.99.0.1"  # Send to Host
DST_PORT = 53


def send_dns_packet(domain, qtype, vlan_id=None, iface=DEFAULT_IFACE):
    print(f"[*] Preparing DNS query: {domain} ({qtype}) -> {DST_IP}")

    # 1. Construct DNS layer
    dns_layer = DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))

    # 2. Construct IP/UDP layers
    ip_layer = IP(dst=DST_IP) / UDP(sport=RandShort(), dport=DST_PORT)

    # 3. Construct Ethernet layer
    eth_layer = Ether()

    # 4. Assemble the packet
    if vlan_id:
        print(f"   [+] Adding VLAN Tag: {vlan_id}")
        # With VLAN: Ether -> Dot1Q -> IP -> ...
        pkt = eth_layer / Dot1Q(vlan=int(vlan_id)) / ip_layer / dns_layer
    else:
        # Standard packet: Ether -> IP -> ...
        pkt = eth_layer / ip_layer / dns_layer

    # 5. Send the packet
    # sendp() is used for Layer 2 sending; iface must be specified
    try:
        sendp(pkt, iface=iface, verbose=False)
        print(f"   [√] Packet sent via interface: {iface}")
        pkt.summary()
    except Exception as e:
        print(f"   [!] Send failed: {e}")
        print(
            "       Hint: Ensure this script is running in the correct netns (use 'ip netns exec ...')"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Construct and send DNS packets (VLAN support included)"
    )
    parser.add_argument(
        "--domain", "-d", default="www.google.com", help="Domain name to query"
    )
    parser.add_argument(
        "--type", "-t", default="A", help="DNS record type (e.g., A, AAAA, TXT)"
    )
    parser.add_argument("--vlan", "-v", type=int, help="VLAN ID (optional, e.g., 100)")
    parser.add_argument("--iface", "-i", default="veth-ns", help="Output interface")

    args = parser.parse_args()

    send_dns_packet(args.domain, args.type, args.vlan, args.iface)
