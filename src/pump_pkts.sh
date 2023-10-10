#!/bin/bash

for PCAP in tests/*.pcap; do
  ./pcap2zmq.exe --nodelay -P $PCAP -Z ipc:///tmp/pcap.ipc
done
