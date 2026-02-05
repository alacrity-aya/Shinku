#!/usr/bin/bash

sudo ip link add veth0 type veth peer name veth1

sudo ip link set veth0 up
sudo ip link set veth1 up

sudo ip addr add 192.168.100.1/24 dev veth1

# dns gateway, attach xdp here
sudo ip addr add 192.168.100.2/24 dev veth0
