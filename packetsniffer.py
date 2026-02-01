import socket
import struct
import queue

class PacketSniffer:
    def __init__(self):
        self.HOST = socket.gethostbyname(socket.gethostname()) # Local IP address
        self.conn = None
        
    def start_sniffing(self, packet_queue, is_sniffing_ref):
        """Start packet sniffing and put results in queue"""
        try:
            # Create raw socket (capture IPv4 network traffic)
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.conn.bind((self.HOST, 0))
            
            # Include IP headers
            self.conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Enable promiscuous mode (Windows only)
            self.conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            # Set socket timeout to allow graceful shutdown (is_sniffing_ref check)
            self.conn.settimeout(1.0)
            
            print(f"[*] Listening on {self.HOST}...")
            
            while is_sniffing_ref(): 
                try:
                    raw_data, addr = self.conn.recvfrom(65535)
                    packet_info = self.parse_packet(raw_data)
                    if packet_info:
                        # Store raw bytes for hex dump functionality
                        packet_info['raw_bytes'] = raw_data
                        packet_queue.put(packet_info)
                except socket.timeout:
                    continue  
                except Exception as e:
                    print(f"Error processing packet: {e}")
                    continue
                    
        except Exception as e:
            print(f"Socket error: {e}")
        finally:
            if self.conn:
                try:
                    self.conn.close()
                except:
                    pass
    
    def parse_packet(self, raw_data):
        """Parse raw packet data into structured format"""
        try:
            version, header_length, ttl, proto, src, target, data = self.ipv4_packet(raw_data)
            
            packet_info = {
                'src_ip': src,  # Source IP address
                'dest_ip': target,  # Destination IP address
                'protocol': proto,  # Protocol number
                'version': version,  # IP version
                'header_length': header_length,  # IP header length
                'ttl': ttl,  # Time to live
                'size': len(raw_data),  # Packet size
                'src_port': 0,  # Source port
                'dest_port': 0,  # Destination port
                'data': '',  # Payload data
                'summary': '',  # Summary of the packet
                'flags': {}  # Flags (for TCP)
            }
            
            # Check which protocol the packet carries
            if proto == 1:   # ICMP
                icmp_type, code, checksum, icmp_data = self.icmp_packet(data)
                packet_info.update({
                    'icmp_type': icmp_type,
                    'icmp_code': code,
                    'checksum': checksum,
                    'summary': f"ICMP {src} → {target} (Type: {icmp_type}, Code: {code})",
                    'data': str(icmp_data[:100]) if icmp_data else ''
                })
                
            elif proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, flags, tcp_data = self.tcp_segment(data)
                packet_info.update({
                    'src_port': src_port,
                    'dest_port': dest_port,
                    'sequence': sequence,
                    'acknowledgment': acknowledgment,
                    'flags': flags, 
                    'summary': f"TCP {src}:{src_port} → {target}:{dest_port} [Seq: {sequence}, Ack: {acknowledgment}]",
                    'data': str(tcp_data[:100]) if tcp_data else ''
                })
                
            elif proto == 17:  # UDP
                src_port, dest_port, size, udp_data = self.udp_segment(data)
                packet_info.update({
                    'src_port': src_port,
                    'dest_port': dest_port,
                    'summary': f"UDP {src}:{src_port} → {target}:{dest_port} (Len: {size})",
                    'data': str(udp_data[:100]) if udp_data else ''
                })
                
                # Check for DNS
                if src_port == 53 or dest_port == 53 or dest_port == 5353:
                    try:
                        dns_info, remaining = self.dns_parse(udp_data)
                        packet_info['summary'] += " [DNS]"
                    except:
                        pass
            else:
                packet_info['summary'] = f"Protocol {proto}: {src} → {target}"
                
            return packet_info
            
        except Exception as e:
            print(f"Packet parsing error: {e}")
            return None

    def ipv4_packet(self, data):
        """Unpack IPv4 packet"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4

        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        src_ip = '.'.join(map(str, src))
        dest_ip = '.'.join(map(str, target))

        return version, header_length, ttl, proto, src_ip, dest_ip, data[header_length:]

    def icmp_packet(self, data):
        """Unpack ICMP packet"""
        if len(data) < 4:
            return 0, 0, 0, b''
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def tcp_segment(self, data):
        """Unpack TCP segment"""
        if len(data) < 14:
            return 0, 0, 0, 0, {}, b''
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

    def udp_segment(self, data):
        """Unpack UDP segment"""
        if len(data) < 8:
            return 0, 0, 0, b''
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    def dns_parse(self, data):
        """Parse DNS query/response from raw data"""
        if len(data) < 12:
            return {}, b''
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

def main():
    """Standalone mode for testing"""
    sniffer = PacketSniffer()
    packet_queue = queue.Queue()
    is_sniffing = [True]  # Use list for reference
    
    try:
        sniffer.start_sniffing(packet_queue, lambda: is_sniffing[0])
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffer...")
        is_sniffing[0] = False

if __name__ == "__main__":
    main()