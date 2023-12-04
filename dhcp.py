from scapy.all import *

def build_dhcp_discover_packet(src_mac="00:00:00:00:00:00"):
    srcMacB = "\x00\x21\x32\x44\x21\x55"

    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac, type=0x800)
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=srcMacB, ciaddr="0.0.0.0", flags=1)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])

    packet = ethernet / ip / udp / bootp / dhcp
    return packet

def send_dhcp_discover_packet(packet, iface="eth0"):
    sendp(packet, iface=iface, verbose=False)

def main():
    src_mac_address = "00:21:32:44:21:55"  
    dhcp_discover_packet = build_dhcp_discover_packet(src_mac=src_mac_address)

    print("Sending DHCP Discover packet:")
    print(dhcp_discover_packet.show())

    send_dhcp_discover_packet(dhcp_discover_packet, iface="eth0")

if __name__ == "__main__":
    main()
