"""
Detailed packet view window
"""
import tkinter as tk
from tkinter import ttk, scrolledtext


class PacketDetailsWindow:
    """Window showing detailed packet information"""
    
    def __init__(self, parent, packet_data, packet_number):
        self.packet_data = packet_data
        self.packet_number = packet_number
        
        # Create new window
        self.window = tk.Toplevel(parent)
        self.window.title(f"Packet Details - #{packet_number}")
        self.window.geometry("800x600")
        
        self.setup_gui()
        self.populate_data()
        
    def setup_gui(self):
        """Setup the detailed view GUI."""
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with basic packet info
        header_frame = ttk.LabelFrame(main_frame, text="Packet Summary", padding="5")
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Summary text
        self.summary_label = ttk.Label(header_frame, text="", font=("Courier", 10))
        self.summary_label.pack(anchor=tk.W)
        
        # Create notebook for different views
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Protocol layers view
        self.create_protocol_view(notebook)
        
        # Raw data view
        self.create_raw_data_view(notebook)
        
        # Hexdump view
        self.create_hex_view(notebook)
        
        # Close button
        close_frame = ttk.Frame(main_frame)
        close_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(close_frame, text="Close", command=self.window.destroy).pack(side=tk.RIGHT)
        
    def create_protocol_view(self, notebook):
        """Create the protocol layers tree view."""
        protocol_frame = ttk.Frame(notebook)
        notebook.add(protocol_frame, text="Protocol Layers")
        
        # Create treeview
        tree_frame = ttk.Frame(protocol_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.protocol_tree = ttk.Treeview(tree_frame, show="tree")
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.protocol_tree.yview)
        self.protocol_tree.configure(yscrollcommand=scrollbar.set)
        
        self.protocol_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_raw_data_view(self, notebook):
        """Create the raw data view."""
        raw_frame = ttk.Frame(notebook)
        notebook.add(raw_frame, text="Raw Data")
        
        self.raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.NONE, font=("Courier", 9))
        self.raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def create_hex_view(self, notebook):
        """Create the hexadecimal dump view."""
        hex_frame = ttk.Frame(notebook)
        notebook.add(hex_frame, text="Hex Dump")
        
        self.hex_text = scrolledtext.ScrolledText(hex_frame, wrap=tk.NONE, font=("Courier", 9))
        self.hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def populate_data(self):
        """Populate the window with packet data."""
        packet = self.packet_data
        
        # Update summary
        summary = packet.get('summary', 'Unknown packet')
        self.summary_label.config(text=f"Packet #{self.packet_number}: {summary}")
        
        # Populate protocol tree
        self.populate_protocol_tree()
        
        # Populate raw data
        self.populate_raw_data()
        
        # Populate hex dump
        self.populate_hex_dump()
        
    def populate_protocol_tree(self):
        """Populate the protocol layers tree."""
        packet = self.packet_data
        
        # Clear existing items
        for item in self.protocol_tree.get_children():
            self.protocol_tree.delete(item)
            
        # Frame info
        frame_info = f"Frame {self.packet_number}: {packet.get('size', 0)} bytes"
        frame_node = self.protocol_tree.insert("", "end", text=frame_info)
        self.protocol_tree.insert(frame_node, "end", text=f"Frame Length: {packet.get('size', 0)} bytes")
        
        # Ethernet/IP Layer
        ip_info = f"Internet Protocol Version 4, Src: {packet.get('src_ip', 'Unknown')}, Dst: {packet.get('dest_ip', 'Unknown')}"
        ip_node = self.protocol_tree.insert("", "end", text=ip_info)
        self.protocol_tree.insert(ip_node, "end", text=f"Source: {packet.get('src_ip', 'Unknown')}")
        self.protocol_tree.insert(ip_node, "end", text=f"Destination: {packet.get('dest_ip', 'Unknown')}")
        self.protocol_tree.insert(ip_node, "end", text=f"Protocol: {self.get_protocol_name(packet.get('protocol', 0))}")
        self.protocol_tree.insert(ip_node, "end", text=f"TTL: {packet.get('ttl', 'Unknown')}")
        
        # Transport Layer
        protocol = packet.get('protocol', 0)
        if protocol == 6:  # TCP
            self.add_tcp_details(ip_node, packet)
        elif protocol == 17:  # UDP
            self.add_udp_details(ip_node, packet)
        elif protocol == 1:  # ICMP
            self.add_icmp_details(ip_node, packet)
            
        # Expand all nodes
        self.expand_all_nodes()
        
    def add_tcp_details(self, parent, packet):
        """Add TCP-specific details to the tree."""
        tcp_info = f"Transmission Control Protocol, Src Port: {packet.get('src_port', 0)}, Dst Port: {packet.get('dest_port', 0)}"
        tcp_node = self.protocol_tree.insert(parent, "end", text=tcp_info)  # Use parent instead of ""
        
        self.protocol_tree.insert(tcp_node, "end", text=f"Source Port: {packet.get('src_port', 0)}")
        self.protocol_tree.insert(tcp_node, "end", text=f"Destination Port: {packet.get('dest_port', 0)}")
        
        flags = packet.get('flags', {})
        if flags:
            flags_str = ", ".join([flag for flag, value in flags.items() if value])
            self.protocol_tree.insert(tcp_node, "end", text=f"Flags: {flags_str}")
            
            # Individual flag details
            flag_node = self.protocol_tree.insert(tcp_node, "end", text="Flag Details:")
            for flag, value in flags.items():
                self.protocol_tree.insert(flag_node, "end", text=f"{flag}: {'Set' if value else 'Not set'}")
                
    def add_udp_details(self, parent, packet):
        """Add UDP-specific details to the tree."""
        udp_info = f"User Datagram Protocol, Src Port: {packet.get('src_port', 0)}, Dst Port: {packet.get('dest_port', 0)}"
        udp_node = self.protocol_tree.insert(parent, "end", text=udp_info)  # Use parent instead of ""
        
        self.protocol_tree.insert(udp_node, "end", text=f"Source Port: {packet.get('src_port', 0)}")
        self.protocol_tree.insert(udp_node, "end", text=f"Destination Port: {packet.get('dest_port', 0)}")
        
        # Check if it's DNS
        if packet.get('src_port') == 53 or packet.get('dest_port') == 53:
            self.protocol_tree.insert(udp_node, "end", text="Application: Domain Name System (DNS)")
            
    def add_icmp_details(self, parent, packet):
        """Add ICMP-specific details to the tree."""
        icmp_info = f"Internet Control Message Protocol"
        icmp_node = self.protocol_tree.insert(parent, "end", text=icmp_info)  # Use parent instead of ""
        
        # Add more ICMP details
        if packet.get('icmp_type') is not None:
            self.protocol_tree.insert(icmp_node, "end", text=f"Type: {packet.get('icmp_type')}")
        if packet.get('icmp_code') is not None:
            self.protocol_tree.insert(icmp_node, "end", text=f"Code: {packet.get('icmp_code')}")
        if packet.get('checksum') is not None:
            self.protocol_tree.insert(icmp_node, "end", text=f"Checksum: {packet.get('checksum')}")
        
    def expand_all_nodes(self):
        """Expand all nodes in the tree."""
        def expand_item(item):
            self.protocol_tree.item(item, open=True)
            for child in self.protocol_tree.get_children(item):
                expand_item(child)
                
        for item in self.protocol_tree.get_children():
            expand_item(item)
            
    def populate_raw_data(self):
        """Populate the raw data view."""
        packet = self.packet_data
        
        # Create a formatted display of packet data
        raw_data = []
        raw_data.append(f"Packet #{self.packet_number} Raw Data")
        raw_data.append("=" * 50)
        raw_data.append(f"Timestamp: {packet.get('timestamp', 'Unknown')}")
        raw_data.append(f"Size: {packet.get('size', 0)} bytes")
        raw_data.append(f"Source: {packet.get('src_ip', 'Unknown')}:{packet.get('src_port', 'N/A')}")
        raw_data.append(f"Destination: {packet.get('dest_ip', 'Unknown')}:{packet.get('dest_port', 'N/A')}")
        raw_data.append(f"Protocol: {self.get_protocol_name(packet.get('protocol', 0))}")
        raw_data.append(f"TTL: {packet.get('ttl', 'Unknown')}")
        raw_data.append("")
        
        # Flags (for TCP)
        flags = packet.get('flags', {})
        if flags:
            raw_data.append("TCP Flags:")
            for flag, value in flags.items():
                raw_data.append(f"  {flag}: {'Set' if value else 'Not set'}")
            raw_data.append("")
        
        # Data payload
        data = packet.get('data', '')
        if data:
            raw_data.append("Data Payload:")
            raw_data.append("-" * 20)
            raw_data.append(str(data))
        else:
            raw_data.append("No data payload available")
            
        self.raw_text.insert("1.0", "\n".join(raw_data))
        
    def populate_hex_dump(self):
        """Populate the hex dump view with actual packet bytes."""
        raw_bytes = self.packet_data.get('raw_bytes')
        
        if not raw_bytes:
            # Professional error handling - no fallbacks like Wireshark
            error_msg = [
                f"ERROR: Raw packet data not available for packet #{self.packet_number}",
                "",
                "Possible causes:",
                "• Packet capture failed to store raw bytes",
                "• Memory allocation error during capture",
                "• Socket read error",
                "",
                "Professional packet analyzers require complete raw packet data.",
                "Please restart packet capture to ensure proper data collection."
            ]
            self.hex_text.insert("1.0", "\n".join(error_msg))
            return
            
        # Always show real hex dump - no simulations or fallbacks
        hex_lines = []
        hex_lines.append(f"Hex dump for packet #{self.packet_number}")
        hex_lines.append("=" * 70)
        hex_lines.append("Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII")
        hex_lines.append("-" * 70)
        
        for i in range(0, len(raw_bytes), 16):
            offset = f"{i:04X}  "
            hex_part = ""
            ascii_part = ""
            
            for j in range(16):
                if i + j < len(raw_bytes):
                    byte_val = raw_bytes[i + j]
                    hex_part += f"{byte_val:02X} "
                    ascii_part += chr(byte_val) if 32 <= byte_val <= 126 else "."
                else:
                    hex_part += "   "
                    
            hex_lines.append(f"{offset}{hex_part.ljust(48)} {ascii_part}")
            
        self.hex_text.insert("1.0", "\n".join(hex_lines))
        
    def get_protocol_name(self, protocol_num):
        """Convert protocol number to name."""
        protocol_names = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP"
        }
        return protocol_names.get(protocol_num, f"Protocol {protocol_num}")


def show_packet_details(parent, packet_data, packet_number):
    """Show packet details in a new window."""
    return PacketDetailsWindow(parent, packet_data, packet_number)