#!/usr/bin/env bash

# Delete the veth pair (deleting veth0 automatically removes veth1)
if ip link show veth0 > /dev/null 2>&1; then
    echo "Removing veth0 and veth1..."
    sudo ip link delete veth0
    echo "Cleanup complete."
else
    echo "veth0 not found, nothing to clean."
fi
