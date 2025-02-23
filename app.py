import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.arch.common import compile_filter
import pandas as pd
import threading
import joblib
import numpy as np
from datetime import datetime
import os
from collections import defaultdict
import time

class FlowFeatures:
    def __init__(self):
        self.start_time = time.time()
        self.last_forward_time = self.start_time
        self.last_backward_time = self.start_time
        self.forward_packets = []
        self.backward_packets = []
        self.forward_iat = []
        self.backward_iat = []
        self.active_start = None
        self.last_active = None
        self.idle_start = None
        self.active_times = []
        self.idle_times = []
        self.init_win_bytes_forward = None
        self.init_win_bytes_backward = None

class PacketFeatureExtractor:
    def __init__(self):
        self.flows = defaultdict(FlowFeatures)
        self.feature_columns = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets',
            'Total Backward Packets', 'Total Length of Fwd Packets',
            'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max',
            'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
            'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
            'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
            'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
            'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
            'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
            'Idle Std', 'Idle Max', 'Idle Min'
        ]

    def get_flow_key(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            proto = 'TCP' if TCP in packet else 'UDP'
            forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            backward_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
            return forward_key, backward_key
        return None, None

    def is_forward_flow(self, packet, forward_key):
        if IP in packet and (TCP in packet or UDP in packet):
            current_key = f"{packet[IP].src}:{packet[TCP if TCP in packet else UDP].sport}-{packet[IP].dst}:{packet[TCP if TCP in packet else UDP].dport}-{'TCP' if TCP in packet else 'UDP'}"
            return current_key == forward_key
        return True

    def extract_features(self, packet, flow_key):
        current_time = time.time()
        flow = self.flows[flow_key]
        features = {}

        # Basic packet info
        packet_length = len(packet)
        if TCP in packet:
            header_length = len(packet[IP]) + len(packet[TCP])
            flags = packet[TCP].flags
            if flow.init_win_bytes_forward is None:
                flow.init_win_bytes_forward = packet[TCP].window
        elif UDP in packet:
            header_length = len(packet[IP]) + len(packet[UDP])
            flags = 0
        else:
            header_length = len(packet[IP])
            flags = 0

        # Update flow statistics
        is_forward = self.is_forward_flow(packet, flow_key)
        if is_forward:
            flow.forward_packets.append({
                'length': packet_length,
                'header_length': header_length,
                'time': current_time,
                'flags': flags
            })
            if len(flow.forward_packets) > 1:
                iat = current_time - flow.last_forward_time
                flow.forward_iat.append(iat)
            flow.last_forward_time = current_time
        else:
            flow.backward_packets.append({
                'length': packet_length,
                'header_length': header_length,
                'time': current_time,
                'flags': flags
            })
            if len(flow.backward_packets) > 1:
                iat = current_time - flow.last_backward_time
                flow.backward_iat.append(iat)
            flow.last_backward_time = current_time

        # Calculate all features
        features['Destination Port'] = packet[TCP].dport if TCP in packet else packet[UDP].dport
        features['Flow Duration'] = (current_time - flow.start_time) * 1000  # milliseconds
        features['Total Fwd Packets'] = len(flow.forward_packets)
        features['Total Backward Packets'] = len(flow.backward_packets)
        
        # Packet lengths
        fwd_lengths = [p['length'] for p in flow.forward_packets]
        bwd_lengths = [p['length'] for p in flow.backward_packets]
        
        features['Total Length of Fwd Packets'] = sum(fwd_lengths)
        features['Total Length of Bwd Packets'] = sum(bwd_lengths)
        
        # Forward packet length statistics
        if fwd_lengths:
            features['Fwd Packet Length Max'] = max(fwd_lengths)
            features['Fwd Packet Length Min'] = min(fwd_lengths)
            features['Fwd Packet Length Mean'] = np.mean(fwd_lengths)
            features['Fwd Packet Length Std'] = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
        else:
            features['Fwd Packet Length Max'] = 0
            features['Fwd Packet Length Min'] = 0
            features['Fwd Packet Length Mean'] = 0
            features['Fwd Packet Length Std'] = 0

        # Backward packet length statistics
        if bwd_lengths:
            features['Bwd Packet Length Max'] = max(bwd_lengths)
            features['Bwd Packet Length Min'] = min(bwd_lengths)
            features['Bwd Packet Length Mean'] = np.mean(bwd_lengths)
            features['Bwd Packet Length Std'] = np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0
        else:
            features['Bwd Packet Length Max'] = 0
            features['Bwd Packet Length Min'] = 0
            features['Bwd Packet Length Mean'] = 0
            features['Bwd Packet Length Std'] = 0

        # Flow rates
        duration_sec = features['Flow Duration'] / 1000
        if duration_sec > 0:
            features['Flow Bytes/s'] = (features['Total Length of Fwd Packets'] + 
                                      features['Total Length of Bwd Packets']) / duration_sec
            features['Flow Packets/s'] = (features['Total Fwd Packets'] + 
                                        features['Total Backward Packets']) / duration_sec
            features['Fwd Packets/s'] = features['Total Fwd Packets'] / duration_sec
            features['Bwd Packets/s'] = features['Total Backward Packets'] / duration_sec
        else:
            features['Flow Bytes/s'] = 0
            features['Flow Packets/s'] = 0
            features['Fwd Packets/s'] = 0
            features['Bwd Packets/s'] = 0

        # IAT features
        all_iat = flow.forward_iat + flow.backward_iat
        if all_iat:
            features['Flow IAT Mean'] = np.mean(all_iat)
            features['Flow IAT Std'] = np.std(all_iat) if len(all_iat) > 1 else 0
            features['Flow IAT Max'] = max(all_iat)
            features['Flow IAT Min'] = min(all_iat)
        else:
            features['Flow IAT Mean'] = 0
            features['Flow IAT Std'] = 0
            features['Flow IAT Max'] = 0
            features['Flow IAT Min'] = 0

        # Forward IAT
        if flow.forward_iat:
            features['Fwd IAT Total'] = sum(flow.forward_iat)
            features['Fwd IAT Mean'] = np.mean(flow.forward_iat)
            features['Fwd IAT Std'] = np.std(flow.forward_iat) if len(flow.forward_iat) > 1 else 0
            features['Fwd IAT Max'] = max(flow.forward_iat)
            features['Fwd IAT Min'] = min(flow.forward_iat)
        else:
            features['Fwd IAT Total'] = 0
            features['Fwd IAT Mean'] = 0
            features['Fwd IAT Std'] = 0
            features['Fwd IAT Max'] = 0
            features['Fwd IAT Min'] = 0

        # Backward IAT
        if flow.backward_iat:
            features['Bwd IAT Total'] = sum(flow.backward_iat)
            features['Bwd IAT Mean'] = np.mean(flow.backward_iat)
            features['Bwd IAT Std'] = np.std(flow.backward_iat) if len(flow.backward_iat) > 1 else 0
            features['Bwd IAT Max'] = max(flow.backward_iat)
            features['Bwd IAT Min'] = min(flow.backward_iat)
        else:
            features['Bwd IAT Total'] = 0
            features['Bwd IAT Mean'] = 0
            features['Bwd IAT Std'] = 0
            features['Bwd IAT Max'] = 0
            features['Bwd IAT Min'] = 0

        # Flag counts
        if TCP in packet:
            features['Fwd PSH Flags'] = 1 if flags & 0x08 else 0
            features['Bwd PSH Flags'] = 0
            features['Fwd URG Flags'] = 1 if flags & 0x20 else 0
            features['Bwd URG Flags'] = 0
            features['FIN Flag Count'] = 1 if flags & 0x01 else 0
            features['SYN Flag Count'] = 1 if flags & 0x02 else 0
            features['RST Flag Count'] = 1 if flags & 0x04 else 0
            features['PSH Flag Count'] = 1 if flags & 0x08 else 0
            features['ACK Flag Count'] = 1 if flags & 0x10 else 0
            features['URG Flag Count'] = 1 if flags & 0x20 else 0
            features['CWE Flag Count'] = 1 if flags & 0x40 else 0
            features['ECE Flag Count'] = 1 if flags & 0x80 else 0
        else:
            features.update({
                'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0,
                'Bwd URG Flags': 0, 'FIN Flag Count': 0, 'SYN Flag Count': 0,
                'RST Flag Count': 0, 'PSH Flag Count': 0, 'ACK Flag Count': 0,
                'URG Flag Count': 0, 'CWE Flag Count': 0, 'ECE Flag Count': 0
            })

        # Header lengths
        features['Fwd Header Length'] = header_length if is_forward else 0
        features['Bwd Header Length'] = header_length if not is_forward else 0
        features['Fwd Header Length.1'] = features['Fwd Header Length']

        # Additional features
        features['Down/Up Ratio'] = (features['Total Backward Packets'] / 
                                   features['Total Fwd Packets'] if features['Total Fwd Packets'] > 0 else 0)
        
        all_lengths = fwd_lengths + bwd_lengths
        if all_lengths:
            features['Average Packet Size'] = np.mean(all_lengths)
            features['Min Packet Length'] = min(all_lengths)
            features['Max Packet Length'] = max(all_lengths)
            features['Packet Length Mean'] = np.mean(all_lengths)
            features['Packet Length Std'] = np.std(all_lengths) if len(all_lengths) > 1 else 0
            features['Packet Length Variance'] = np.var(all_lengths) if len(all_lengths) > 1 else 0
        else:
            features.update({
                'Average Packet Size': 0, 'Min Packet Length': 0,
                'Max Packet Length': 0, 'Packet Length Mean': 0,
                'Packet Length Std': 0, 'Packet Length Variance': 0
            })

        features['Avg Fwd Segment Size'] = (features['Total Length of Fwd Packets'] / 
                                          features['Total Fwd Packets'] if features['Total Fwd Packets'] > 0 else 0)
        features['Avg Bwd Segment Size'] = (features['Total Length of Bwd Packets'] / 
                                          features['Total Backward Packets'] if features['Total Backward Packets'] > 0 else 0)

        # Bulk features (set to 0 as in test data)
        bulk_features = [
            'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate'
        ]
        for feature in bulk_features:
            features[feature] = 0

        # Subflow features
        features['Subflow Fwd Packets'] = features['Total Fwd Packets']
        features['Subflow Fwd Bytes'] = features['Total Length of Fwd Packets']
        features['Subflow Bwd Packets'] = features['Total Backward Packets']
        features['Subflow Bwd Bytes'] = features['Total Length of Bwd Packets']

        # Window features
        if TCP in packet:
            features['Init_Win_bytes_forward'] = flow.init_win_bytes_forward if flow.init_win_bytes_forward is not None else 0
            features['Init_Win_bytes_backward'] = packet[TCP].window
        else:
            features['Init_Win_bytes_forward'] = 0
            features['Init_Win_bytes_backward'] = 0

        # Active and idle features (set to 0 as in test data)
        active_idle_features = [
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
        for feature in active_idle_features:
            features[feature] = 0

        # Additional TCP-specific features
        features['act_data_pkt_fwd'] = 1 if TCP in packet and is_forward else 0
        features['min_seg_size_forward'] = header_length if is_forward else 0

        # Ensure all features are present and in correct order
        ordered_features = {}
        for column in self.feature_columns:
            ordered_features[column] = features.get(column, 0)

        return ordered_features

class NetworkMonitor:
    def __init__(self):
        # Load the trained models from models folder
        models_dir = os.path.join(os.getcwd(), 'models')
        self.rf_model = joblib.load(os.path.join(models_dir, 'random_forest_model.pkl'))
        self.scaler = joblib.load(os.path.join(models_dir, 'scaler.pkl'))
        self.label_encoder = joblib.load(os.path.join(models_dir, 'label_encoder.pkl'))
        
        # Initialize feature extractor
        self.feature_extractor = PacketFeatureExtractor()
        
        # Capture control variables
        self.is_capturing = False
        self.capture_thread = None
        self.capture_filter = "ip"  # Default filter
        
        # Initialize the UI
        self.root = tk.Tk()
        self.root.title("Network Intrusion Detection System")
        self.root.geometry("1200x800")
        
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill="both", expand=True)
        
        # Create control panel
        self.create_control_panel()
        
        # Create search panel
        self.create_search_panel()
        
        # Create table
        self.create_table()
        
        # Initialize packet counter and storage
        self.packet_count = 0
        self.max_packets = 1000
        self.captured_packets = []  # Store packet data for export
        
    def create_control_panel(self):
        """Create the control panel with buttons and filter options"""
        control_frame = ttk.Frame(self.main_container)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # Capture control buttons
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.toggle_capture)
        self.start_button.pack(side="left", padx=5)
        
        # Export button
        self.export_button = ttk.Button(control_frame, text="Export Data", command=self.export_data)
        self.export_button.pack(side="left", padx=5)
        
        # Filter frame
        filter_frame = ttk.LabelFrame(control_frame, text="Capture Filter")
        filter_frame.pack(side="left", padx=20)
        
        # Filter type dropdown
        self.filter_var = tk.StringVar(value="all")
        filter_options = ["all", "tcp", "udp", "tcp port 80", "tcp port 443"]
        filter_dropdown = ttk.Combobox(filter_frame, textvariable=self.filter_var, values=filter_options)
        filter_dropdown.pack(side="left", padx=5)
        
        # Custom filter entry
        self.custom_filter = ttk.Entry(filter_frame, width=30)
        self.custom_filter.pack(side="left", padx=5)
        
        # Apply filter button
        apply_filter = ttk.Button(filter_frame, text="Apply Filter", command=self.apply_capture_filter)
        apply_filter.pack(side="left", padx=5)
        
    def create_search_panel(self):
        """Create the search and filter panel"""
        search_frame = ttk.Frame(self.main_container)
        search_frame.pack(fill="x", padx=5, pady=5)
        
        # Search entry
        ttk.Label(search_frame, text="Search:").pack(side="left", padx=5)
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.pack(side="left", padx=5)
        
        # Search type dropdown
        self.search_type = tk.StringVar(value="source_ip")
        search_options = ["source_ip", "dest_ip", "protocol", "prediction"]
        search_dropdown = ttk.Combobox(search_frame, textvariable=self.search_type, values=search_options)
        search_dropdown.pack(side="left", padx=5)
        
        # Search button
        search_button = ttk.Button(search_frame, text="Search", command=self.search_packets)
        search_button.pack(side="left", padx=5)
        
        # Clear search button
        clear_button = ttk.Button(search_frame, text="Clear Search", command=self.clear_search)
        clear_button.pack(side="left", padx=5)
        
    def create_table(self):
        """Create the packet display table"""
        table_frame = ttk.Frame(self.main_container)
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create table
        self.tree = ttk.Treeview(table_frame)
        self.tree["columns"] = ("timestamp", "source_ip", "dest_ip", "protocol", 
                              "src_port", "dst_port", "prediction", "confidence", "flow_duration")
        
        # Configure columns
        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.column("timestamp", width=150)
        self.tree.column("source_ip", width=120)
        self.tree.column("dest_ip", width=120)
        self.tree.column("protocol", width=80)
        self.tree.column("src_port", width=80)
        self.tree.column("dst_port", width=80)
        self.tree.column("prediction", width=200)
        self.tree.column("confidence", width=100)
        self.tree.column("flow_duration", width=100)
        
        # Create headings
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("source_ip", text="Source IP")
        self.tree.heading("dest_ip", text="Destination IP")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("src_port", text="Src Port")
        self.tree.heading("dst_port", text="Dst Port")
        self.tree.heading("prediction", text="Prediction")
        self.tree.heading("confidence", text="Confidence")
        self.tree.heading("flow_duration", text="Flow Duration (ms)")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def toggle_capture(self):
        """Toggle packet capture on/off"""
        if not self.is_capturing:
            self.start_capture()
            self.start_button.configure(text="Stop Capture")
        else:
            self.stop_capture()
            self.start_button.configure(text="Start Capture")
        
    def start_capture(self):
        """Start packet capture in a separate thread"""
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=1.0)
            
    def _capture_packets(self):
        """Packet capture thread function"""
        try:
            scapy.sniff(
                prn=self.packet_callback,
                store=False,
                filter=self.capture_filter,
                stop_filter=lambda _: not self.is_capturing
            )
        except Exception as e:
            self.root.after(0, tk.messagebox.showerror, "Error", f"Capture error: {str(e)}")
            self.is_capturing = False
            self.root.after(0, self.start_button.configure, {"text": "Start Capture"})
            
    def apply_capture_filter(self):
        """Apply new capture filter"""
        new_filter = self.custom_filter.get() if self.custom_filter.get() else self.filter_var.get()
        if new_filter == "all":
            new_filter = "ip"

        try:
            # Test if filter is valid
            compile_filter(new_filter)
            self.capture_filter = new_filter  # Update the filter

            # Restart capture if currently running
            if self.is_capturing:
                self.stop_capture()
                self.start_capture()  # Restart with new filter

            messagebox.showinfo("Success", "Filter applied successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid filter: {e}")

            
    def export_data(self):
        """Export captured data to CSV"""
        if not self.captured_packets:
            tk.messagebox.showwarning("Warning", "No packets to export")
            return
            
        try:
            filename = tk.filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if filename:
                df = pd.DataFrame(self.captured_packets)
                df.to_csv(filename, index=False)
                tk.messagebox.showinfo("Success", "Data exported successfully")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Export failed: {str(e)}")
            
    def search_packets(self):
        """Search and filter displayed packets"""
        search_text = self.search_entry.get().lower()
        search_column = self.search_type.get()
        
        # Clear current selection
        for item in self.tree.selection():
            self.tree.selection_remove(item)
            
        # Search through items
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            column_index = self.tree["columns"].index(search_column)
            if search_text in str(values[column_index]).lower():
                self.tree.selection_add(item)
                self.tree.see(item)
                
    def clear_search(self):
        """Clear search results"""
        self.search_entry.delete(0, tk.END)
        for item in self.tree.selection():
            self.tree.selection_remove(item)
            
    def packet_callback(self, packet):
        """Process captured packet and update UI"""
        if IP in packet and (TCP in packet or UDP in packet):
            # Get flow key
            forward_key, backward_key = self.feature_extractor.get_flow_key(packet)
            if forward_key:
                # Extract features
                features = self.feature_extractor.extract_features(packet, forward_key)
                
                # Convert to DataFrame with exact column order
                df = pd.DataFrame([features])
                
                # Scale features
                scaled_features = self.scaler.transform(df)
                
                # Make prediction
                pred_proba = self.rf_model.predict_proba(scaled_features)
                prediction = self.rf_model.predict(scaled_features)
                confidence = np.max(pred_proba) * 100
                
                # Get packet info
                packet_info = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": packet[IP].src,
                    "dest_ip": packet[IP].dst,
                    "protocol": "TCP" if TCP in packet else "UDP",
                    "src_port": packet[TCP].sport if TCP in packet else packet[UDP].sport,
                    "dst_port": packet[TCP].dport if TCP in packet else packet[UDP].dport,
                    "prediction": self.label_encoder.inverse_transform(prediction)[0],
                    "confidence": f"{confidence:.2f}%",
                    "flow_duration": f"{features['Flow Duration']:.1f}"
                }
                
                # Store packet info
                self.captured_packets.append(packet_info)
                
                # Update UI
                self.root.after(0, self.update_ui, *packet_info.values())
    
    def update_ui(self, timestamp, source_ip, dest_ip, protocol, 
                  src_port, dst_port, prediction, confidence, flow_duration):
        """Update the UI with new packet information"""
        self.tree.insert("", 0, values=(timestamp, source_ip, dest_ip, 
                                      protocol, src_port, dst_port,
                                      prediction, confidence, flow_duration))
        self.packet_count += 1
        
        # Remove oldest entry if maximum is reached
        if self.packet_count > self.max_packets:
            self.tree.delete(self.tree.get_children()[-1])
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.run()