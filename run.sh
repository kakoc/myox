#!/bin/bash

# sudo ip addr flush dev tun0
# sudo ip link delete tun0

cargo build --release
sudo setcap cap_net_admin=eip /home/konstantin/study/rust/myox_tcp/target/release/myox_tcp
sudo /home/konstantin/study/rust/myox_tcp/target/release/myox_tcp &

pid=$!

# add 192.168.0.1 with a mask = 24 to tun0 device
sudo ip addr add 192.168.0.1/24 dev tun0
# sudo ip addr add 192.168.0.2/24 dev tun0
# sudo ip addr add 192.168.0.3/24 dev tun0

# bring tun0 online
sudo ip link set up dev tun0

trap "kill $pid; sudo ip link delete tun0" INT TERM
wait $pid

# sudo tshark -i tun0
# nc 192.168.0.2 80
