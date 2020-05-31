#!/bin/bash

echo "Configuration for tun running"
ip -4 addr a 192.168.1.1/24 dev tun0
ip -4 link set up dev tun0

