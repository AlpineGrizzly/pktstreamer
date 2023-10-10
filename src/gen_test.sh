#!/bin/bash
PCAP="$1"
./pcap2zmq.exe --nodelay -P $PCAP -Z ipc:///tmp/pcap.ipc

