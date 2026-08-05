"""Manage DNS testing network topology using only subprocess + ip commands.

No external dependencies required — uses iproute2 CLI tools directly.
"""

import argparse
import subprocess
import sys
import os

# Configuration Constants
NS_NAME = "dns-ns"
VETH_HOST = "veth-host"
VETH_NS = "veth-ns"
IP_HOST = "10.99.0.1/24"
IP_NS = "10.99.0.2/24"

# Path to dummy XDP pass-through object (needed on veth peer for XDP_TX)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
XDP_PASS_OBJ = os.path.join(PROJECT_ROOT, "build", "xdp_pass.bpf.o")


def _run(cmd, check=True, quiet=False):
    """Run a command, optionally suppressing errors."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0 and not quiet:
        print(f"   [!] Command failed: {' '.join(cmd)}\n       {result.stderr.strip()}")
    return result


def _exists_in_current_namespace(name):
    return _run(["ip", "link", "show", name], check=False, quiet=True).returncode == 0


def _namespace_exists(name):
    return any(
        line.split()[0] == name
        for line in _run(["ip", "netns", "list"], check=False, quiet=True).stdout.splitlines()
        if line
    )


def _cleanup_created_topology(*, namespace_created, host_veth_created):
    """Remove only resources created by the current setup call."""
    if host_veth_created:
        _run(["firewall-cmd", "--zone=trusted", "--remove-interface=" + VETH_HOST], check=False, quiet=True)
        _run(["ip", "link", "del", VETH_HOST], check=False, quiet=True)
    if namespace_created:
        _run(["ip", "netns", "del", NS_NAME], check=False, quiet=True)


def setup(xdp_pass_object=None):
    """Create Network Namespace, Veth Pair, and configure IP addresses."""
    print("[*] Initializing network topology...")

    xdp_pass_object = xdp_pass_object or XDP_PASS_OBJ
    if _namespace_exists(NS_NAME):
        print(f"   [!] Netns '{NS_NAME}' already exists; refusing to modify it")
        return 1
    if _exists_in_current_namespace(VETH_HOST) or _exists_in_current_namespace(VETH_NS):
        print(f"   [!] Topology interface already exists; refusing to modify it")
        return 1
    if not os.path.isfile(xdp_pass_object):
        print(f"   [!] XDP pass object does not exist: {xdp_pass_object}")
        return 1

    namespace_created = False
    host_veth_created = False

    # 1. Create Network Namespace
    r = _run(["ip", "netns", "add", NS_NAME], check=False)
    if r.returncode != 0:
        if "File exists" in r.stderr:
            print(f"   [!] Netns '{NS_NAME}' already exists; please run teardown first")
            return 1
        print(f"   [!] Failed to create netns: {r.stderr.strip()}")
        return 1
    namespace_created = True
    print(f"   [+] Netns '{NS_NAME}' created successfully")

    # 2. Create Veth Pair
    r = _run(["ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS])
    if r.returncode != 0:
        print(f"   [!] Failed to create veth pair: {r.stderr.strip()}")
        _cleanup_created_topology(namespace_created=namespace_created, host_veth_created=host_veth_created)
        return 1
    host_veth_created = True
    print(f"   [+] Veth pair created successfully ({VETH_HOST} <-> {VETH_NS})")

    # 3. Move veth-ns into the namespace
    r = _run(["ip", "link", "set", VETH_NS, "netns", NS_NAME])
    if r.returncode != 0:
        _cleanup_created_topology(namespace_created=namespace_created, host_veth_created=host_veth_created)
        return 1
    print(f"   [+] {VETH_NS} moved to {NS_NAME}")

    # 4. Configure Host-side IP and bring it up
    for command in (
        ["ip", "addr", "add", IP_HOST, "dev", VETH_HOST],
        ["ip", "link", "set", VETH_HOST, "up"],
    ):
        if _run(command).returncode != 0:
            _cleanup_created_topology(
                namespace_created=namespace_created,
                host_veth_created=host_veth_created,
            )
            return 1
    print(f"   [+] Host-side IP configured: {IP_HOST}")

    # 4b. Add veth-host to firewalld trusted zone (if firewalld is active)
    #     Without this, firewalld rejects traffic on interfaces not in any zone.
    r = _run(["firewall-cmd", "--zone=trusted", "--add-interface=" + VETH_HOST], check=False, quiet=True)
    if r.returncode == 0:
        print(f"   [+] {VETH_HOST} added to firewalld trusted zone")
    else:
        print(f"   [~] firewalld not available or failed (non-fatal)")

    # 5. Configure Namespace-side IP and bring it up
    for command in (
        ["ip", "netns", "exec", NS_NAME, "ip", "addr", "add", IP_NS, "dev", VETH_NS],
        ["ip", "netns", "exec", NS_NAME, "ip", "link", "set", VETH_NS, "up"],
        ["ip", "netns", "exec", NS_NAME, "ip", "link", "set", "lo", "up"],
    ):
        if _run(command).returncode != 0:
            _cleanup_created_topology(
                namespace_created=namespace_created,
                host_veth_created=host_veth_created,
            )
            return 1

    print(f"   [+] Namespace-side IP configured: {IP_NS}")

    # 6. Attach dummy XDP pass-through to veth-ns inside the namespace.
    #    Required for XDP_TX on veth-host to deliver packets to the peer.
    #    Without this, veth silently drops XDP_TX frames.
    r = _run(["ip", "netns", "exec", NS_NAME,
                  "ip", "link", "set", "dev", VETH_NS, "xdp", "obj", xdp_pass_object,
                  "sec", "xdp"], check=False)
    if r.returncode != 0:
        print(f"   [!] Failed to attach XDP to {VETH_NS}: {r.stderr.strip()}")
        _cleanup_created_topology(namespace_created=namespace_created, host_veth_created=host_veth_created)
        return 1
    print(f"   [+] XDP pass-through attached to {VETH_NS}")

    print("[*] Topology setup complete!")
    return 0


def teardown():
    """Clean up Netns and Veth interfaces."""
    print("[*] Tearing down network topology...")

    # 0. Remove veth-host from firewalld trusted zone (if firewalld is active)
    _run(["firewall-cmd", "--zone=trusted", "--remove-interface=" + VETH_HOST], check=False, quiet=True)

    # 1. Delete Veth (deleting the host side automatically removes the peer)
    link_exists = _run(["ip", "link", "show", VETH_HOST], check=False, quiet=True).returncode == 0
    if link_exists:
        if _run(["ip", "link", "del", VETH_HOST], check=False).returncode != 0:
            print(f"   [!] Failed to delete {VETH_HOST}")
            return 1
        print(f"   [-] {VETH_HOST} deleted")

    # 2. Delete Network Namespace
    if not _namespace_exists(NS_NAME):
        print(f"   [-] Netns '{NS_NAME}' does not exist (already clean)")
    elif _run(["ip", "netns", "del", NS_NAME], check=False).returncode != 0:
        print(f"   [!] Failed to delete netns '{NS_NAME}'")
        return 1
    else:
        print(f"   [-] Netns '{NS_NAME}' deleted")

    print("[*] Teardown complete!")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage DNS testing network topology")
    parser.add_argument(
        "action", choices=["setup", "teardown"], help="Action to perform"
    )
    parser.add_argument(
        "--xdp-pass-object",
        default=XDP_PASS_OBJ,
        help="XDP pass-through object for the namespace peer",
    )
    args = parser.parse_args()

    # Note: Requires root privileges
    if args.action == "setup":
        sys.exit(setup(args.xdp_pass_object))
    elif args.action == "teardown":
        sys.exit(teardown())
