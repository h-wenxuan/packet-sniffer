import socket
import struct

# Get the local machine's IP address
HOST = socket.gethostbyname(socket.gethostname())

def main():
    # Create raw socket (AF_INET only capture IPv4 network traffic)
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((HOST, 0))

    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode (Windows only)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[*] Listening on {HOST}...")

    while True:
        raw_data, addr = conn.recvfrom(65535)
        version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)
        print(f"\nIPv4 Packet: {src} → {target} | Protocol: {proto} | TTL: {ttl}")

        # Check which protocol the packet carries
        if proto == 1:   # ICMP
            icmp_type, code, checksum, icmp_data = icmp_packet(data)
            print(f"   ICMP Packet: Type={icmp_type}, Code={code}, Checksum={checksum}")
            if icmp_data:
                print(f"   Data: {icmp_data}")

        elif proto == 6:  # TCP
            src_port, dest_port, sequence, acknowledgment, flags, tcp_data = tcp_segment(data)
            print(f"   TCP Segment: {src_port} → {dest_port}")
            print(f"   Sequence: {sequence}, Acknowledgment: {acknowledgment}")
            print(f"   Flags: URG={flags['URG']}, ACK={flags['ACK']}, PSH={flags['PSH']}, RST={flags['RST']}, SYN={flags['SYN']}, FIN={flags['FIN']}")
            if tcp_data:
                print(f"   Data: {tcp_data}")
                
        elif proto == 17:  # UDP
            src_port, dest_port, size, udp_data = udp_segment(data)
            print(f"   UDP Segment: {src_port} → {dest_port} | Length: {size}")

            # DNS usually uses port 53 (or 5353 for mDNS)
            if src_port == 53 or dest_port == 53 or dest_port == 5353:
                dns_info, remaining = dns_parse(udp_data)
                print("   DNS Packet:")
                for key, value in dns_info.items():
                    print(f"      {key}: {value}")
                print(f"      Raw Questions/Answers: {remaining}")
            elif udp_data:
                print(f"   Data: {udp_data}")


def ipv4_packet(data):
    """Unpack IPv4 packet"""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ip = '.'.join(map(str, src))
    dest_ip = '.'.join(map(str, target))

    return version, header_length, ttl, proto, src_ip, dest_ip, data[header_length:]

def icmp_packet(data):
    """Unpack ICMP packet"""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    """Unpack TCP segment"""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    flags = {'URG': flag_urg, 'ACK': flag_ack, 'PSH': flag_psh,
             'RST': flag_rst, 'SYN': flag_syn, 'FIN': flag_fin}

    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_segment(data):
    """Unpack UDP segment"""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def dns_parse(data):
    """Parse DNS query/response from raw data"""
    (transaction_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack('! H H H H H H', data[:12])
    dns_info = {
        "Transaction ID": hex(transaction_id),
        "Flags": hex(flags),
        "Questions": qdcount,
        "Answer RRs": ancount,
        "Authority RRs": nscount,
        "Additional RRs": arcount
    }
    return dns_info, data[12:]

main()
