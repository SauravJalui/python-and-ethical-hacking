#!/usr/bin/env python
import netfilterqueue

def process_packet(packet):
    print(packet)
    packet.accept()

queue = netfilterqueue.NetfiterQueue()
queue.bind(0, process_packet)
queue.run()
