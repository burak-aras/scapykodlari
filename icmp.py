from scapy.all import *

def send_arp_request(target_ip, target_mac, source_ip, source_mac, iface="eth0"):
    ether_header = Ether(src=source_mac, dst=target_mac)
    arp_header = ARP(hwdst=target_mac, hwsrc=source_mac, pdst=target_ip, psrc=source_ip, op=1)
    arp_packet = ether_header / arp_header
    sendp(arp_packet, iface=iface)

def send_icmp_request(target_ip, target_mac, source_ip, source_mac, iface="eth0"):
    ether_header = Ether(src=source_mac, dst=target_mac)
    ip_header = IP(dst=target_ip, src=source_ip, ttl=2)
    icmp_header = ICMP(type=8, code=0)
    icmp_packet = ether_header / ip_header / icmp_header
    sendp(icmp_packet, iface=iface)

def main():
    target_ip = "192.168.1.120"
    target_mac = "1C:CC:D6:83:EB:51"
    source_ip = "192.168.1.199"
    source_mac = "ff:21:21:21:21:21"
    iface = "eth0"

    send_arp_request(target_ip, target_mac, source_ip, source_mac, iface)
    send_icmp_request(target_ip, target_mac, source_ip, source_mac, iface)
    send_arp_request(target_ip, target_mac, source_ip, source_mac, iface)

if __name__ == "__main__":
    main()
