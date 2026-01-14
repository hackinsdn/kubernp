#!/bin/bash

# client id
ID=$1

###### eth1 ######
# no tagging
ip addr add 10.1.0.${ID}/30 dev eth1
ip link set dev eth1 address aa:c1:ab:00:00:0${ID}

# single tag VID 10
ip link add name eth1.10 link eth1 type vlan id 10
ip addr add 10.1.1.${ID}/30 dev eth1.10
ip link set dev eth1.10 address aa:c1:ab:00:01:0${ID}
ip link set dev eth1.10 up
