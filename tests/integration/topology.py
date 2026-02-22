import argparse
import sys
import time

from pyroute2 import IPRoute, NetNS

# Configuration Constants
NS_NAME = "dns-ns"
VETH_HOST = "veth-host"
VETH_NS = "veth-ns"
IP_HOST = "10.99.0.1/24"
IP_NS = "10.99.0.2/24"


def setup():
    """Create Network Namespace, Veth Pair, and configure IP addresses"""
    print(f"[*] Initializing network topology...")

    ip = IPRoute()

    # 1. Create Network Namespace
    # pyroute2 raises an exception if it already exists; simplified here by suggesting a teardown
    try:
        NetNS(NS_NAME)
        print(f"   [+] Netns '{NS_NAME}' created successfully")
    except OSError:
        print(f"   [!] Netns '{NS_NAME}' may already exist; please run teardown first")
        return

    # 2. Create Veth Pair
    # Equivalent to: ip link add veth-host type veth peer name veth-ns
    try:
        ip.link("add", ifname=VETH_HOST, kind="veth", peer=VETH_NS)
        print(f"   [+] Veth pair created successfully ({VETH_HOST} <-> {VETH_NS})")
    except Exception as e:
        print(f"   [!] Failed to create Veth pair: {e}")
        return

    # 3. Move veth-ns into the namespace
    idx_ns = ip.link_lookup(ifname=VETH_NS)[0]
    ip.link("set", index=idx_ns, net_ns_fd=NS_NAME)
    print(f"   [+] {VETH_NS} moved to {NS_NAME}")

    # 4. Configure Host-side IP and bring it up
    idx_host = ip.link_lookup(ifname=VETH_HOST)[0]
    ip.addr("add", index=idx_host, address=IP_HOST.split("/")[0], mask=24)
    ip.link("set", index=idx_host, state="up")
    print(f"   [+] Host-side IP configured: {IP_HOST}")

    # 5. Configure Namespace-side IP and bring it up (requires entering the Netns)
    ns = NetNS(NS_NAME)
    idx_ns_inner = ns.link_lookup(ifname=VETH_NS)[0]
    ns.addr("add", index=idx_ns_inner, address=IP_NS.split("/")[0], mask=24)
    ns.link("set", index=idx_ns_inner, state="up")

    # Enable the loopback interface (crucial for certain tests)
    idx_lo = ns.link_lookup(ifname="lo")[0]
    ns.link("set", index=idx_lo, state="up")

    ns.close()
    print(f"   [+] Namespace-side IP configured: {IP_NS}")
    print("[*] Topology setup complete!")


def teardown():
    """Clean up Netns and Veth interfaces"""
    print(f"[*] Tearing down network topology...")
    ip = IPRoute()

    # 1. Delete Veth (deleting the Host side automatically removes the peer)
    try:
        idx = ip.link_lookup(ifname=VETH_HOST)
        if idx:
            ip.link("del", index=idx[0])
            print(f"   [-] {VETH_HOST} deleted")
    except Exception:
        pass

    # 2. Delete Network Namespace
    # Equivalent to: ip netns del dns-ns
    try:
        ns = NetNS(NS_NAME)
        ns.close()
        ns.remove()
        print(f"   [-] Netns '{NS_NAME}' deleted")
    except FileNotFoundError:
        print(f"   [-] Netns '{NS_NAME}' does not exist")
    except Exception as e:
        print(f"   [!] Error deleting Netns: {e}")

    print("[*] Teardown complete!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage DNS testing network topology")
    parser.add_argument(
        "action", choices=["setup", "teardown"], help="Action to perform"
    )
    args = parser.parse_args()

    # Note: Requires root privileges
    if args.action == "setup":
        setup()
    elif args.action == "teardown":
        teardown()
