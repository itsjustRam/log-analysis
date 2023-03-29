import socket
import struct

# create a raw socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# receive packets
while True:
    packet, address = s.recvfrom(65535)

    # extract ethernet header
    eth_header = packet[:14]
    eth = struct.unpack('!6s6sH', eth_header)
    source_mac = ':'.join('%02x' % b for b in eth[0])
    dest_mac = ':'.join('%02x' % b for b in eth[1])
    eth_type = socket.ntohs(eth[2])

    # extract IP header
    if eth_type == 8:
        ip_header = packet[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        with open("/home/ram/PycharmProjects/pro/network/ips.txt", "a") as f:
            f.write(s_addr)
            f.write(" ")
            f.write(d_addr)
            f.write("\n")

        print('Source MAC:', source_mac)
        print('Destination MAC:', dest_mac)
        print('Source IP:', s_addr)
        print('Destination IP:', d_addr)
        print('Protocol:', protocol)
        print('TTL:', ttl)

