"""
Main GUI for the AI Network Packet Sniffer
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import time
import random
from datetime import datetime
import numpy as np

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Import our modules
from packetsniffer import PacketSniffer
from anomaly_detector import AnomalyDetector, WindowAggregator
from packet_details import show_packet_details


class PacketSnifferGUI:
    
    def __init__(self, root):
        self.root = root
        self.root.title("AI Network Packet Sniffer")
        self.root.geometry("1400x900")

        # Application state
        self.is_sniffing = False
        self.collecting_baseline = False
        
        # Packet handling
        self.packet_queue = queue.Queue()
        self.sniffer = PacketSniffer() # Real packet sniffer
        self.packet_list = []  # Store all captured packets
        self.packet_counter = 0
        
        # AI components
        self.aggregator = WindowAggregator(window_seconds=0.5)
        self.anomaly_detector = AnomalyDetector() # AI-based anomaly detector
        self.anomaly_count = 0
        self.total_packets = 0

        self.setup_gui()

    def setup_gui(self):
        """Setup the main GUI interface."""
        main = ttk.Frame(self.root, padding="10")
        main.pack(fill=tk.BOTH, expand=True)

        # Control buttons
        self.setup_controls(main)
        
        # Status bar
        self.setup_status_bar(main)

        # Main content area
        self.setup_main_content(main)
        
        # Plot area
        self.setup_plot_area(main)

    def setup_controls(self, parent):
        """Setup control buttons"""
        controls = ttk.Frame(parent)
        controls.pack(fill=tk.X, pady=(0, 5))

        self.btn_start = ttk.Button(controls, text="Start Capture", command=self.start_sniffing)
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(controls, text="Stop Capture", command=self.stop_sniffing, state="disabled")
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        ttk.Separator(controls, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.btn_baseline = ttk.Button(controls, text="Collect Baseline", command=self.start_baseline)
        self.btn_baseline.pack(side=tk.LEFT, padx=5)

        self.btn_train = ttk.Button(controls, text="Train AI Model", command=self.train_model)
        self.btn_train.pack(side=tk.LEFT, padx=5)

        ttk.Separator(controls, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.btn_clear = ttk.Button(controls, text="Clear Packets", command=self.clear_packets)
        self.btn_clear.pack(side=tk.LEFT, padx=5)

        ttk.Separator(controls, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        """Setup simulation buttons"""
        self.btn_scan = ttk.Button(controls, text="Simulate Port Scan", command=self.simulate_port_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_flood = ttk.Button(controls, text="Simulate DDoS", command=self.simulate_flood)
        self.btn_flood.pack(side=tk.LEFT, padx=5)

    def setup_status_bar(self, parent):
        """Setup status information bar"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: Ready to capture")
        self.status_label.pack(side=tk.LEFT)
        
        self.stats_label = ttk.Label(status_frame, text="Packets: 0 | Anomalies: 0 | Queue: 0 | Model: Not Trained")
        self.stats_label.pack(side=tk.RIGHT)

    def setup_main_content(self, parent):
        """Setup the main content area with packet list and anomaly panel."""
        # Create horizontal paned window (resizable)
        panes = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, pady=10)

        # Left panel - Packet list
        left_panel = ttk.Frame(panes)
        panes.add(left_panel, weight=3)
        
        # Right panel - Anomaly detection
        right_panel = ttk.Frame(panes)
        panes.add(right_panel, weight=1)

        self.setup_packet_list(left_panel)
        self.setup_anomaly_panel(right_panel)
        
        # Store panes reference for potential future use
        self.main_panes = panes

    def setup_packet_list(self, parent):
        """Setup packet list with columns"""
        ttk.Label(parent, text="Network Packets", font=("Arial", 12, "bold")).pack(pady=(0, 5))
        
        # Create frame for treeview and scrollbars
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Define columns
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        
        # Create treeview
        self.packet_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        # Configure column headings and widths
        column_widths = {
            "No.": 60,
            "Time": 100,
            "Source": 120,
            "Destination": 120,
            "Protocol": 80,
            "Length": 70,
            "Info": 300
        }
        
        for col in columns:
            self.packet_tree.heading(col, text=col, command=lambda c=col: self.sort_packets(c))
            self.packet_tree.column(col, width=column_widths[col], minwidth=50)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind double-click event
        self.packet_tree.bind("<Double-1>", self.on_packet_double_click)
        
        # Add right-click context menu
        self.setup_context_menu()

    def setup_context_menu(self):
        """Setup right-click context menu for packet list."""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.view_packet_details)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Source IP", command=self.copy_source_ip)
        self.context_menu.add_command(label="Copy Destination IP", command=self.copy_dest_ip)
        
        self.packet_tree.bind("<Button-3>", self.show_context_menu)

    def setup_anomaly_panel(self, parent):
        """Setup anomaly detection panel."""
        ttk.Label(parent, text="Anomaly Detection", font=("Arial", 12, "bold")).pack(pady=(0, 5))
        
        # Anomaly log
        self.anomaly_text = scrolledtext.ScrolledText(parent, height=15, width=40)
        self.anomaly_text.pack(fill=tk.BOTH, expand=True)
        
        # Add initial message
        welcome_msg = "AI Anomaly Detection\n"
        welcome_msg += "=" * 30 + "\n"
        welcome_msg += "1. Start packet capture\n"
        welcome_msg += "2. Collect baseline data\n"
        welcome_msg += "3. Train AI model\n"
        welcome_msg += "4. Monitor for anomalies\n\n"
        welcome_msg += "Anomalies will appear here...\n"
        self.anomaly_text.insert("1.0", welcome_msg)

    def setup_plot_area(self, parent):
        """Setup matplotlib plot for training progress"""
        # Create matplotlib figure with better layout
        self.fig = Figure(figsize=(12, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("AI Training Progress")
        self.ax.set_xlabel("Training Step")
        self.ax.set_ylabel("Anomaly Score")
        
        # Adjust layout to prevent label cutoff
        self.fig.tight_layout(pad=2.0)

        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=False, pady=10)

    # ================= Control Functions =================

    def start_sniffing(self):
        """Start packet capture"""
        self.is_sniffing = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status_label.config(text="Status: Capturing network packets...")

        # Start real packet sniffer thread
        self.sniffer_thread = threading.Thread(target=self.packet_capture_worker, daemon=True)
        self.sniffer_thread.start()

        # Start GUI update loop
        self.update_gui()

    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_sniffing = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_label.config(text="Status: Capture stopped")

    def clear_packets(self):
        """Clear all captured packets"""
        # Clear packet list and tree
        self.packet_list.clear()
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Reset counters
        self.packet_counter = 0
        self.total_packets = 0
        
        # Update status
        self.update_stats()
        
        print(f"[INFO] Cleared all packets - ready to capture fresh data")
        messagebox.showinfo("Cleared", "All captured packets have been cleared.\nPacket numbering will restart from #1.")

    def start_baseline(self):
        """Start baseline data collection for anomaly detection."""
        if not self.is_sniffing:
            messagebox.showwarning("Warning", "Start packet capture first to collect baseline data.")
            return
        
        self.collecting_baseline = True
        self.anomaly_detector.clear_baseline()
        self.anomaly_count = 0
        self.status_label.config(text="Status: Collecting baseline data...")
        
        # Update anomaly panel
        self.anomaly_text.delete("1.0", tk.END)
        
        # Insert baseline collection message
        header = "*** COLLECTING BASELINE DATA ***\n"
        baseline_msg = "Learning normal network behavior...\n"
        baseline_msg += "Let normal traffic flow for 30+ windows\n"
        baseline_msg += "Then click 'Train AI Model'\n"
        baseline_msg += "=" * 50 + "\n\n"
        self.anomaly_text.insert(tk.END, header + baseline_msg)
        
        messagebox.showinfo("Baseline Collection", "Now collecting baseline data. Let normal traffic flow for 30+ windows, then click 'Train AI Model'.")

    def train_model(self):
        """Train the anomaly detection model."""
        progress = self.anomaly_detector.get_training_progress()
        
        if progress['baseline_count'] < 30:
            messagebox.showwarning(
                "Insufficient Data", 
                f"Need at least 30 windows for baseline training.\n"
                f"Currently have {progress['baseline_count']} windows.\n\n"
                f"Let the system collect more data first."
            )
            return

        try:
            result = self.anomaly_detector.train_model()
            
            self.collecting_baseline = False
            self.status_label.config(text="Status: AI model trained - Detecting anomalies")

            # Update anomaly panel
            self.anomaly_text.delete("1.0", tk.END)
            
            # Insert training success message
            header = "*** AI MODEL TRAINED SUCCESSFULLY ***\n"
            trained_msg = f"Threshold: {result['threshold']:.3f}\n"
            trained_msg += f"Trained on {result['baseline_windows']} windows\n"
            trained_msg += "Real-time anomaly detection is now active!\n"
            trained_msg += "=" * 50 + "\n\n"
            self.anomaly_text.insert(tk.END, header + trained_msg)

            # Update plot
            self.update_training_plot(result['training_scores'], result['threshold'])
            
            messagebox.showinfo(
                "Training Complete", 
                f"AI model successfully trained!\n\n"
                f"• Trained on {result['baseline_windows']} windows\n"
                f"• Anomaly threshold: {result['threshold']:.3f}\n"
                f"• Expected false positive rate: ~10%\n\n"
                f"Anomaly detection is now active."
            )
        
        except Exception as e:
            messagebox.showerror("Training Error", f"Failed to train model: {e}")
            import traceback
            traceback.print_exc()

    # ================= Packet Handling =================

    def packet_capture_worker(self):
        """Worker thread for packet capture"""
        try:
            self.sniffer.start_sniffing(self.packet_queue, lambda: self.is_sniffing)
        except Exception as e:
            print(f"Error in packet sniffer: {e}")
            messagebox.showerror("Capture Error", f"Failed to start packet capture: {e}")
            self.stop_sniffing()

    def update_gui(self):
        """Main GUI update loop"""
        if not self.is_sniffing:
            return

        # Process queued packets
        packets_processed = 0
        try:
            while True:
                packet = self.packet_queue.get_nowait()
                self.process_packet(packet)
                packets_processed += 1
        except queue.Empty:
            pass

        # Update statistics
        self.update_stats()

        # Schedule next update
        self.root.after(100, self.update_gui)

    def process_packet(self, packet):
        """Process a single captured packet"""
        self.total_packets += 1
        self.packet_counter += 1
        
        # Add timestamp
        packet['timestamp'] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        packet['packet_number'] = self.packet_counter
        
        # Store packet (keep last 2000 for memory management)
        self.packet_list.append(packet)
        if len(self.packet_list) > 2000:
            self.packet_list.pop(0)  # Remove oldest packet
        
        # Always add to packet tree, but manage tree size
        self.add_packet_to_tree(packet)
        
        # Keep tree manageable - remove oldest entries if too many
        tree_items = self.packet_tree.get_children()
        if len(tree_items) > 1000:
            # Remove oldest 100 entries to make room
            for i in range(100):
                if tree_items:
                    self.packet_tree.delete(tree_items[i])
        
        # Process for anomaly detection
        self.aggregator.add_packet(packet)
        
        # Check if window is ready
        if self.aggregator.window_ready():
            features = self.aggregator.extract_features()
            ip_context = self.aggregator.get_ip_context()
            self.aggregator.reset()

            if self.collecting_baseline:
                self.anomaly_detector.add_baseline_features(features)
                if self.anomaly_detector.get_training_progress()['baseline_count'] % 10 == 0:
                    count = self.anomaly_detector.get_training_progress()['baseline_count']
                    self.status_label.config(text=f"Status: Collected {count} baseline windows")

            elif self.anomaly_detector.is_trained:
                self.detect_anomaly_window(features, ip_context)

    def add_packet_to_tree(self, packet):
        """Add packet to the treeview display"""
        # Format packet data for display
        packet_no = str(packet['packet_number'])
        timestamp = packet['timestamp']
        source = f"{packet.get('src_ip', 'Unknown')}:{packet.get('src_port', '')}" if packet.get('src_port') else packet.get('src_ip', 'Unknown')
        dest = f"{packet.get('dest_ip', 'Unknown')}:{packet.get('dest_port', '')}" if packet.get('dest_port') else packet.get('dest_ip', 'Unknown')
        protocol = self.get_protocol_name(packet.get('protocol', 0))
        length = str(packet.get('size', 0))
        
        # Create concise info without redundant data
        info = ""
        if packet.get('protocol') == 6:  # TCP
            flags = packet.get('flags', {})
            active_flags = [flag for flag, value in flags.items() if value]
            if active_flags:
                info = f"[{', '.join(active_flags)}]"
            else:
                info = "TCP packet"
        elif packet.get('protocol') == 17:  # UDP 
            if packet.get('src_port') == 53 or packet.get('dest_port') == 53:
                info = "DNS Query/Response"
            else:
                info = f"UDP datagram"
        elif packet.get('protocol') == 1:  # ICMP
            info = "ICMP message"
        else:
            info = f"Protocol {packet.get('protocol', 'Unknown')}"
        
        # Insert into tree
        item = self.packet_tree.insert("", "end", values=(packet_no, timestamp, source, dest, protocol, length, info))
        
        # Auto-scroll to bottom
        self.packet_tree.see(item)
        
        # Color coding based on protocol
        if packet.get('protocol') == 6:  # TCP
            self.packet_tree.set(item, "Protocol", "TCP")
        elif packet.get('protocol') == 17:  # UDP
            self.packet_tree.set(item, "Protocol", "UDP")
        elif packet.get('protocol') == 1:  # ICMP
            self.packet_tree.set(item, "Protocol", "ICMP")

    def detect_anomaly_window(self, features, ip_context):
        """Detect anomalies in the current window."""
        try:
            result = self.anomaly_detector.detect_anomaly(features)
            
            if result['is_anomaly']:
                self.anomaly_count += 1
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                
                # Create detailed anomaly message
                header_text = f"[{timestamp}] *** ANOMALY DETECTED ***\n"
                score_text = f"Score: {result['score']:.3f} (threshold: {result['threshold']:.3f})\n"
                divider = "=" * 50 + "\n"
                
                # Insert header and score text normally
                self.anomaly_text.insert(tk.END, header_text + score_text + divider)
                
                # Add IP context if available
                if ip_context:
                    recent_packets = ip_context.get('recent_packets', [])
                    
                    # Analyze source -> destination flows
                    if recent_packets:
                        flow_counts = {}
                        port_info = {}
                        
                        # Count flows and gather port information
                        for pkt in recent_packets:
                            src = pkt.get('src_ip', 'Unknown')
                            dst = pkt.get('dst_ip', 'Unknown')
                            src_port = pkt.get('src_port')
                            dst_port = pkt.get('dest_port')
                            proto = pkt.get('protocol', 0)
                            
                            flow_key = f"{src} → {dst}"
                            flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1
                            
                            # Store port and protocol info for this flow
                            if flow_key not in port_info:
                                port_info[flow_key] = {
                                    'dst_ports': set(),
                                    'protocols': set(),
                                    'src_ports': set()
                                }
                            
                            if dst_port:
                                port_info[flow_key]['dst_ports'].add(dst_port)
                            if src_port:
                                port_info[flow_key]['src_ports'].add(src_port)
                            port_info[flow_key]['protocols'].add(self.get_protocol_name(proto))
                        
                        # Sort flows by frequency (most active first)
                        sorted_flows = sorted(flow_counts.items(), key=lambda x: x[1], reverse=True)
                        
                        flow_msg = "SUSPICIOUS TRAFFIC FLOWS:\n"
                        for i, (flow, count) in enumerate(sorted_flows[:5], 1):  # Show top 5 flows
                            info = port_info[flow]
                            protocols = ", ".join(info['protocols'])
                            
                            # Show port information
                            port_details = ""
                            if info['dst_ports']:
                                if len(info['dst_ports']) > 3:
                                    port_list = list(info['dst_ports'])[:3]
                                    port_details = f" → ports {', '.join(map(str, port_list))} (+{len(info['dst_ports'])-3} more)"
                                else:
                                    port_details = f" → ports {', '.join(map(str, info['dst_ports']))}"
                            
                            flow_msg += f"  {i}. {flow}{port_details}\n"
                            flow_msg += f"     {count} packets, {protocols}\n"
                        
                        if len(sorted_flows) > 5:
                            flow_msg += f"  ... and {len(sorted_flows)-5} more flows\n"
                        
                        flow_msg += "\n"
                        self.anomaly_text.insert(tk.END, flow_msg)
                    else:
                        self.anomaly_text.insert(tk.END, "SUSPICIOUS ACTIVITY DETECTED\nNo detailed flow information available\n\n")
                
                # Add traffic details
                feature_names = ["pkt/sec", "bytes/sec", "tcp%", "udp%", "icmp%", "syn_cnt", "src_ips", "dst_ports", "dns_cnt"]
                traffic_details = []
                for i, (name, value) in enumerate(zip(feature_names, features)):
                    if i < 2:  # Rate features
                        traffic_details.append(f"{name}={value:.1f}")
                    elif i < 5:  # Ratio features  
                        traffic_details.append(f"{name}={value:.2f}")
                    else:  # Count features
                        traffic_details.append(f"{name}={int(value)}")
                
                traffic_msg = f"Traffic: {', '.join(traffic_details[:3])}\n"
                traffic_msg += f"Patterns: {', '.join(traffic_details[5:8])}\n"
                traffic_msg += "=" * 50 + "\n\n"
                
                self.anomaly_text.insert(tk.END, traffic_msg)
                self.anomaly_text.see(tk.END)
                
                # Keep manageable length
                if self.anomaly_text.get("1.0", tk.END).count('\n') > 150:
                    self.anomaly_text.delete("1.0", "30.0")
                
        except Exception as e:
            print(f"[ERROR] Anomaly detection failed: {e}")
            import traceback
            traceback.print_exc()

    # ================= Event Handlers =================

    def on_packet_double_click(self, event):
        """Handle double-click on packet list."""
        self.view_packet_details()

    def view_packet_details(self):
        """Show detailed packet information."""
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a packet to view details.")
            return
        
        # Get selected packet data
        item = selection[0]
        packet_values = self.packet_tree.item(item, 'values')
        if not packet_values or len(packet_values) < 1:
            messagebox.showerror("Error", "Could not retrieve packet information.")
            return
            
        packet_no = int(packet_values[0])
        
        # Find packet data - search from most recent first
        packet_data = None
        for packet in reversed(self.packet_list):
            if packet['packet_number'] == packet_no:
                packet_data = packet
                break
        
        if packet_data:
            show_packet_details(self.root, packet_data, packet_no)
        else:
            messagebox.showwarning("Packet Not Found", 
                f"Packet #{packet_no} is no longer in memory.\n"
                f"The system keeps the most recent 2000 packets in memory for details view.")

    def show_context_menu(self, event):
        """Show right-click context menu."""
        # Select the item under cursor
        item = self.packet_tree.identify_row(event.y)
        if item:
            self.packet_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_source_ip(self):
        """Copy source IP to clipboard."""
        selection = self.packet_tree.selection()
        if selection:
            item = selection[0]
            source = self.packet_tree.item(item, 'values')[2]
            source_ip = source.split(':')[0] if ':' in source else source
            self.root.clipboard_clear()
            self.root.clipboard_append(source_ip)
            messagebox.showinfo("Copied", f"Source IP '{source_ip}' copied to clipboard.")

    def copy_dest_ip(self):
        """Copy destination IP to clipboard."""
        selection = self.packet_tree.selection()
        if selection:
            item = selection[0]
            dest = self.packet_tree.item(item, 'values')[3]
            dest_ip = dest.split(':')[0] if ':' in dest else dest
            self.root.clipboard_clear()
            self.root.clipboard_append(dest_ip)
            messagebox.showinfo("Copied", f"Destination IP '{dest_ip}' copied to clipboard.")

    def sort_packets(self, column):
        """Sort packets by column (placeholder for future implementation)."""
        print(f"Sorting by {column} - Not implemented yet")

    # ================= Simulation Functions =================

    def simulate_port_scan(self):
        """Simulate a port scanning attack."""
        if not self.is_sniffing:
            messagebox.showwarning("Not Capturing", "Start packet capture first.")
            return

        if not self.anomaly_detector.is_trained:
            messagebox.showwarning("Model Not Ready", "Train the AI model first before testing.")
            return

        self.status_label.config(text="Status: Simulating port scan attack...")

        def worker():
            src_ip = "10.0.0.99"
            print(f"[SIMULATION] Starting port scan from {src_ip}")
            
            # Generate rapid port scan packets
            for i in range(100):
                for port in range(1000 + i*10, 1000 + i*10 + 10):
                    packet = {
                        "size": 64,
                        "protocol": 6,  # TCP
                        "src_ip": src_ip,
                        "dest_ip": "192.168.1.10",
                        "src_port": random.randint(40000, 60000),
                        "dest_port": port,
                        "ttl": 64,
                        "flags": {"SYN": 1, "ACK": 0, "PSH": 0, "RST": 0, "URG": 0, "FIN": 0},
                        "data": "",
                        "summary": f"TCP {src_ip}:{random.randint(40000, 60000)} → 192.168.1.10:{port} [SYN SCAN]"
                    }
                    self.packet_queue.put(packet)
                
                time.sleep(0.005)
                    
            print(f"[SIMULATION] Port scan completed - 1000 SYN packets")
            self.status_label.config(text="Status: Capture active - AI model detecting anomalies")

        threading.Thread(target=worker, daemon=True).start()

    def simulate_flood(self):
        """Simulate a DDoS flood attack."""
        if not self.is_sniffing:
            messagebox.showwarning("Not Capturing", "Start packet capture first.")
            return
            
        if not self.anomaly_detector.is_trained:
            messagebox.showwarning("Model Not Ready", "Train the AI model first before testing.")
            return

        self.status_label.config(text="Status: Simulating DDoS flood attack...")

        def worker():
            src_ip = "10.0.0.200"
            print(f"[SIMULATION] Starting DDoS flood from {src_ip}")
            
            # Generate massive flood attack
            for i in range(1000):
                packet = {
                    "size": random.randint(1200, 1500),
                    "protocol": 6,  # TCP
                    "src_ip": src_ip,
                    "dest_ip": "192.168.1.10",
                    "src_port": random.randint(1000, 65000),
                    "dest_port": 80,
                    "ttl": 64,
                    "flags": {"SYN": 1, "ACK": 0, "PSH": 0, "RST": 0, "URG": 0, "FIN": 0},
                    "data": "A" * 100,
                    "summary": f"TCP {src_ip}:{random.randint(1000, 65000)} → 192.168.1.10:80 [FLOOD]"
                }
                self.packet_queue.put(packet)
                
                if i % 100 == 0:
                    time.sleep(0.01)
                    
            print(f"[SIMULATION] Flood completed - 1000 large packets")
            self.status_label.config(text="Status: Capture active - AI model detecting anomalies")

        threading.Thread(target=worker, daemon=True).start()

    # ================= Utility Functions =================

    def update_stats(self):
        """Update statistics display."""
        model_status = "Not Trained"
        if self.anomaly_detector.is_trained:
            progress = self.anomaly_detector.get_training_progress()
            model_status = f"Trained on {progress['baseline_count']} windows"
        elif self.collecting_baseline:
            progress = self.anomaly_detector.get_training_progress()
            model_status = f"Collecting baseline ({progress['baseline_count']} windows)"
        
        queue_size = self.packet_queue.qsize()
        
        self.stats_label.config(
            text=f"Packets: {self.total_packets} | "
                 f"Anomalies: {self.anomaly_count} | "
                 f"Queue: {queue_size} | "
                 f"Model: {model_status}"
        )

    def update_training_plot(self, training_scores, threshold):
        """Update the training progress plot."""
        self.ax.clear()
        self.ax.set_title("AI Training Progress: Anomaly Score Evolution")
        self.ax.set_xlabel("Training Step")
        self.ax.set_ylabel("Mean Anomaly Score")
        
        if training_scores:
            self.ax.plot(training_scores, marker="o", linewidth=2, markersize=4)
            self.ax.grid(True, alpha=0.3)
            self.ax.axhline(y=threshold, color='r', linestyle='--', alpha=0.7, 
                          label=f'Anomaly Threshold ({threshold:.3f})')
            self.ax.legend()
        
        # Ensure proper layout and prevent label cutoff
        self.fig.tight_layout(pad=2.0)
        self.canvas.draw()

    def get_protocol_name(self, protocol_num):
        """Convert protocol number to readable name."""
        protocol_names = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP"
        }
        return protocol_names.get(protocol_num, f"Proto {protocol_num}")


def main():
    """Main entry point."""
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()