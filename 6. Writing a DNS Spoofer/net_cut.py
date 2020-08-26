#!/usr/bin/env python
from netfilterqueue import NetfilterQueue


def process_packet(packet):
    print(packet)
    packet.drop()


queue = NetfilterQueue()
queue.bind(1, process_packet)
queue.run()
