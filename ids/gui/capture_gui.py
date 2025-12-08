#!/usr/bin/env python3
"""GUI module for IDS capture.

This module provides `run()` which launches the Tk GUI. It is separated
from the `scripts/` launcher so the GUI can be imported and tested.
"""

import os
import sys
import signal
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import logging

from ids.capture.live_listener import LiveListener
from ids.detection.engine import DetectionEngine
from ids.gui.ui_helpers import (
    create_treeview_with_scrollbar, get_finding_color, apply_row_color,
    show_error, show_info
)
from ids.gui.rules_manager import (
    load_rules_from_file, save_rules_to_file, validate_rule,
    AVAILABLE_FIELDS, AVAILABLE_OPERATORS, AVAILABLE_ACTIONS
)

logger = logging.getLogger(__name__)


# Add the project root directory to PYTHONPATH
def _add_project_root_to_path():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

_add_project_root_to_path()


class RedesignedCaptureGUI:
    def __init__(self, root):
        self.root = root
        root.title("IDS Redesigned GUI")
        self.listener = None
        self.detection_engine = DetectionEngine()
        
        # Grouping system: store grouped detections by key
        # Key format: "attack_type|protocol|src_ip|dst_ip"
        self.detection_groups = {}  # Maps group_key -> {data, count, timestamps, item_id}
        
        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        # Build tabs
        self.capture_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.capture_tab, text="Packet Capture")
        self._build_capture_tab()

        self.detections_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.detections_tab, text="Detections")
        self._build_detections_tab()

        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        self._build_settings_tab()

        self.rules_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.rules_tab, text="Custom Rules")
        self._build_rules_tab()

        # Refresh interfaces
        self.refresh_interfaces()

    def _build_capture_tab(self):
        """Build the packet capture tab."""
        ttk.Label(self.capture_tab, text="Interface:").grid(column=0, row=0, sticky="w")
        self.iface_var = tk.StringVar(value="lo")
        self.iface_combo = ttk.Combobox(self.capture_tab, textvariable=self.iface_var, state="readonly")
        self.iface_combo.grid(column=1, row=0, sticky="we")

        ttk.Button(self.capture_tab, text="Start Capture", command=self.start_capture).grid(
            column=0, row=1, sticky="we"
        )
        ttk.Button(self.capture_tab, text="Stop Capture", command=self.stop_capture).grid(
            column=1, row=1, sticky="we"
        )

        # Attack scanners checkboxes with detector mapping
        # Map display names to detector class names
        self.detector_name_map = {
            "ARP Spoof": "ArpSpoofDetector",
            "SYN Flood": "SynFloodDetector",
            "UDP Flood": "UdpFloodDetector",
            "XMAS Scan": "XmasNullScanDetector",
            "Null Scan": "XmasNullScanDetector",
            "Rate Detection": "SimpleRateDetector"
        }
        
        # Create a frame for checkboxes in one line
        checkbox_frame = ttk.Frame(self.capture_tab)
        checkbox_frame.grid(column=0, row=2, columnspan=3, sticky="ew", padx=5, pady=5)
        
        self.attack_scanners = {}
        attacks = ["ARP Spoof", "SYN Flood", "UDP Flood", "XMAS Scan", "Null Scan", "Rate Detection"]
        for col, attack in enumerate(attacks):
            var = tk.BooleanVar(value=True)
            # Create callback that passes the attack name (trace_add passes 3 args: varname, index, mode)
            callback = lambda varname, index, mode, attack_name=attack: self._on_detector_checkbox_changed(attack_name)
            var.trace_add("write", callback)
            chk = ttk.Checkbutton(checkbox_frame, text=attack, variable=var)
            chk.grid(column=col, row=0, sticky="w", padx=5)
            self.attack_scanners[attack] = var

        # Packet list
        self.packet_list = tk.Listbox(self.capture_tab, width=80, height=20)
        self.packet_list.grid(column=0, row=3, columnspan=3, sticky="nsew")

    def _build_detections_tab(self):
        """Build the detections display tab."""
        for widget in self.detections_tab.winfo_children():
            widget.destroy()

        # Header with title and delete button
        header_frame = ttk.Frame(self.detections_tab)
        header_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(header_frame, text="Detections:", font=("Arial", 14, "bold")).pack(
            side="left", anchor="w"
        )
        
        ttk.Button(
            header_frame, text="🗑️  Delete", width=12,
            command=self._delete_detection
        ).pack(side="right", padx=5)
        
        ttk.Button(
            header_frame, text="Clear All", width=12,
            command=self._clear_all_detections
        ).pack(side="right", padx=2)

        columns = ("Time", "Type", "Protocol", "Source IP", "Destination IP", "Count", "Details")
        column_definitions = [
            ("Time", 150, "Time"),
            ("Type", 150, "Attack Type"),
            ("Protocol", 100, "Protocol"),
            ("Source IP", 150, "Source IP"),
            ("Destination IP", 150, "Destination IP"),
            ("Count", 100, "Packet Count"),
            ("Details", 300, "Details")
        ]

        self.detections_tree, scrollbar = create_treeview_with_scrollbar(
            self.detections_tab, columns, column_definitions
        )
        
        self.detections_tree.pack(fill="both", expand=True, padx=10, pady=5)
        scrollbar.pack(side="right", fill="y")

        self.detections_tree.bind("<Double-1>", self._on_detection_double_click)
        self.detections_tree.bind("<Delete>", self._on_delete_key)

    def _build_settings_tab(self):
        """Build the settings tab."""
        from ids.utils import config as cfg
        
        ttk.Label(self.settings_tab, text="Settings: Detection Configuration", font=("Arial", 12, "bold")).pack(
            anchor="w", padx=10, pady=10
        )

        # Info frame
        info_text = "Adjust detection thresholds below. Changes take effect immediately."
        ttk.Label(self.settings_tab, text=info_text, font=("Arial", 9), foreground="gray").pack(
            anchor="w", padx=10, pady=5
        )

        # Create scrollable frame for settings
        canvas = tk.Canvas(self.settings_tab)
        scrollbar = ttk.Scrollbar(self.settings_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        self.attack_settings = {}
        
        # SYN Flood settings
        syn_cfg = cfg.get('syn_flood') or {}
        frame = ttk.LabelFrame(scrollable_frame, text="SYN Flood Detection", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="Time Window (seconds):").grid(row=0, column=0, sticky="w", pady=5)
        syn_window_var = tk.DoubleVar(value=float(syn_cfg.get('window', 0.5)))
        ttk.Entry(frame, textvariable=syn_window_var, width=10).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(Detection window in seconds)", font=("Arial", 8), foreground="gray").grid(row=0, column=2, sticky="w")
        
        ttk.Label(frame, text="Packet Threshold:").grid(row=1, column=0, sticky="w", pady=5)
        syn_threshold_var = tk.IntVar(value=int(syn_cfg.get('threshold', 50)))
        ttk.Entry(frame, textvariable=syn_threshold_var, width=10).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(TCP packets per window)", font=("Arial", 8), foreground="gray").grid(row=1, column=2, sticky="w")
        
        self.attack_settings["syn_flood"] = {
            "window": syn_window_var,
            "threshold": syn_threshold_var
        }

        # UDP Flood settings
        udp_cfg = cfg.get('udp_flood') or {}
        frame = ttk.LabelFrame(scrollable_frame, text="UDP Flood Detection", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="Time Window (seconds):").grid(row=0, column=0, sticky="w", pady=5)
        udp_window_var = tk.DoubleVar(value=float(udp_cfg.get('window', 0.5)))
        ttk.Entry(frame, textvariable=udp_window_var, width=10).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(Detection window in seconds)", font=("Arial", 8), foreground="gray").grid(row=0, column=2, sticky="w")
        
        ttk.Label(frame, text="Packet Threshold:").grid(row=1, column=0, sticky="w", pady=5)
        udp_threshold_var = tk.IntVar(value=int(udp_cfg.get('threshold', 50)))
        ttk.Entry(frame, textvariable=udp_threshold_var, width=10).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(UDP packets per window)", font=("Arial", 8), foreground="gray").grid(row=1, column=2, sticky="w")
        
        self.attack_settings["udp_flood"] = {
            "window": udp_window_var,
            "threshold": udp_threshold_var
        }

        # Generic Rate Detection (fallback)
        simple_cfg = cfg.get('simple_rate') or {}
        frame = ttk.LabelFrame(scrollable_frame, text="Generic Rate Detection (Fallback)", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="Time Window (seconds):").grid(row=0, column=0, sticky="w", pady=5)
        simple_window_var = tk.DoubleVar(value=float(simple_cfg.get('window', 0.5)))
        ttk.Entry(frame, textvariable=simple_window_var, width=10).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(For all other protocols)", font=("Arial", 8), foreground="gray").grid(row=0, column=2, sticky="w")
        
        ttk.Label(frame, text="Packet Threshold:").grid(row=1, column=0, sticky="w", pady=5)
        simple_threshold_var = tk.IntVar(value=int(simple_cfg.get('threshold', 10)))
        ttk.Entry(frame, textvariable=simple_threshold_var, width=10).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(Packets per window)", font=("Arial", 8), foreground="gray").grid(row=1, column=2, sticky="w")
        
        self.attack_settings["simple_rate"] = {
            "window": simple_window_var,
            "threshold": simple_threshold_var
        }

        # Info about non-configurable detectors
        frame = ttk.LabelFrame(scrollable_frame, text="Fixed Detection Methods", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        
        info = """ARP Spoofing: Detected when same IP seen from different MAC
XMAS Scan: Detected when TCP flags are FIN+PSH+URG
NULL Scan: Detected when TCP packet has no flags set
Port Scan: Configured via Custom Rules tab
Large Packet: Detected when packet > 3000 bytes (configurable in rules)
External Access: Blocked CIDR ranges (configurable in rules)
DNS Anomaly: Detected from known DNS IPs (configurable in rules)"""
        
        ttk.Label(frame, text=info, font=("Arial", 8), justify="left").pack(anchor="w", padx=5, pady=5)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Button frame
        btn_frame = ttk.Frame(self.settings_tab)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Save Settings", command=self.save_settings).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Reset to Defaults", command=self.reset_settings).pack(side="left", padx=5)

    def _build_rules_tab(self):
        """Build the custom rules tab."""
        ttk.Label(self.rules_tab, text="Manage Custom Rules:").pack(anchor="w")

        # Rules tree
        self.rules_tree = ttk.Treeview(
            self.rules_tab,
            columns=("Name", "Field", "Operator", "Value", "Action"),
            show="headings"
        )
        
        for col, width in [("Name", 200), ("Field", 150), ("Operator", 150), ("Value", 150), ("Action", 150)]:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=width, anchor="center")

        self.rules_tree.pack(fill="both", expand=True)

        # Rule management buttons
        btn_frame = ttk.Frame(self.rules_tab)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="Add Rule", command=self._add_rule).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Edit Rule", command=self._edit_rule).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Delete Rule", command=self._delete_rule).pack(side="left", padx=5)

        self._load_rules()

    def _on_detection_double_click(self, event):
        """Handle double-click on detection row to show grouped details in formatted window."""
        try:
            selected_item = self.detections_tree.selection()[0]
            
            # Find group data for this item
            group_data = None
            for group_key, data in self.detection_groups.items():
                if data['item_id'] == selected_item:
                    group_data = data
                    break
            
            if not group_data:
                messagebox.showwarning("Error", "Could not find details for this detection.")
                return
            
            # Create a custom Toplevel window for better formatting
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Detection Details - {group_data['attack_type'].replace('_', ' ').title()}")
            details_window.geometry("750x650")
            details_window.resizable(True, True)
            
            # Main frame with padding
            main_frame = ttk.Frame(details_window, padding="15")
            main_frame.pack(fill="both", expand=True)
            
            # Title
            title_label = ttk.Label(main_frame, text="Grouped Detection Details", 
                                   font=("Arial", 14, "bold"))
            title_label.pack(anchor="w", pady=(0, 15))
            
            # Create text widget with scrollbar
            text_frame = ttk.Frame(main_frame)
            text_frame.pack(fill="both", expand=True)
            
            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side="right", fill="y")
            
            text_widget = tk.Text(text_frame, height=28, width=90, wrap="word", 
                                 yscrollcommand=scrollbar.set, font=("Courier", 10))
            text_widget.pack(side="left", fill="both", expand=True)
            scrollbar.config(command=text_widget.yview)
            
            # Build and insert formatted content
            content = self._format_detection_details(group_data)
            text_widget.insert("1.0", content)
            text_widget.config(state="disabled")  # Make read-only
            
            # Close button
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill="x", pady=(10, 0))
            
            ttk.Button(button_frame, text="Close", command=details_window.destroy).pack(side="right")
            ttk.Button(button_frame, text="Copy Details", 
                      command=lambda: self._copy_to_clipboard(content)).pack(side="right", padx=5)
            
        except IndexError:
            messagebox.showwarning("No Selection", "Please select a detection to view details.")
    
    def _format_detection_details(self, group_data):
        """Format detection details for display."""
        timestamps_str = "\n".join(f"  {i+1}. {ts}" for i, ts in enumerate(group_data['timestamps'][-20:]))
        
        content = f"""═══════════════════════════════════════════════════════════════════
                      DETECTION GROUP DETAILS
═══════════════════════════════════════════════════════════════════

━━━ ATTACK INFORMATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attack Type:              {group_data['attack_type'].replace('_', ' ').title()}
Protocol:                 {group_data['protocol']}
Source IP:                {group_data['src_ip']}
Destination IP:           {group_data['dst_ip']}

━━━ GROUPING STATISTICS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Packets Grouped:    {group_data['count']}
First Detected:           {group_data['first_time']}
Last Detected:            {group_data['last_time']}
Time Span:                Multiple packets over time period

━━━ RECENT DETECTION TIMESTAMPS (Last {len(group_data['timestamps'])} Events) ━━━
{timestamps_str}

━━━ ATTACK MESSAGE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{group_data['finding'].get('message', 'No details available')}

━━━ ADDITIONAL INFORMATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action:                   {group_data.get('action', 'ALERT').upper() if group_data.get('action') else 'ALERT'}
Detection Method:         Automatic Group-based Detection
Grouping Key:             {group_data['attack_type']} | {group_data['protocol']} | {group_data['src_ip']} | {group_data['dst_ip']}

═══════════════════════════════════════════════════════════════════

💡 INFO: This detection represents {group_data['count']} identical packets
   that have been automatically grouped to maintain a clean display.
   The timestamps show the complete timeline of detected packets.
   You can copy these details to clipboard for further analysis.

═══════════════════════════════════════════════════════════════════"""
        return content
    
    def _copy_to_clipboard(self, text):
        """Copy text to clipboard."""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Success", "Details copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")


    def _on_delete_key(self, event):
        """Handle Delete key press on detection tree."""
        self._delete_detection()

    def _delete_detection(self):
        """Delete selected detection(s) from the tree and grouping dict."""
        selected_items = self.detections_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a detection to delete.")
            return
        
        for item in selected_items:
            # Find and remove from grouping dictionary
            for group_key, group_data in list(self.detection_groups.items()):
                if group_data['item_id'] == item:
                    del self.detection_groups[group_key]
                    break
            
            self.detections_tree.delete(item)

    def _clear_all_detections(self):
        """Clear all detections from the tree and reset grouping dict."""
        if messagebox.askyesno("Clear All", "Are you sure you want to clear all detections?"):
            self.detection_groups.clear()
            for item in self.detections_tree.get_children():
                self.detections_tree.delete(item)

    def _on_detector_checkbox_changed(self, attack_name):
        """Callback when a detector checkbox is changed.
        
        Syncs the checkbox state with the detection engine.
        """
        detector_class_name = self.detector_name_map.get(attack_name)
        if not detector_class_name:
            return
        
        is_enabled = self.attack_scanners[attack_name].get()
        self.detection_engine.set_detector_enabled(detector_class_name, is_enabled)
        status = "enabled" if is_enabled else "disabled"
        self.packet_list.insert("end", f"[INFO] Detector '{attack_name}' ({detector_class_name}) {status}")
        self.packet_list.yview_moveto(1)
        logger.debug("Detector %s set to %s", detector_class_name, status)

    def start_capture(self):
        """Start packet capture on selected interface."""
        selected_iface = self.iface_var.get()
        if not selected_iface:
            show_error("Error", "No interface selected.")
            return

        self.listener = LiveListener(interface=selected_iface, filter_exp="ip")

        def gui_callback(packet):
            self.root.after(0, self._process_packet, packet)

        threading.Thread(target=self.listener.listen, args=(gui_callback,), daemon=True).start()
        self.packet_list.insert("end", f"[INFO] Capture started on {selected_iface}")

    def _process_packet(self, packet):
        """Process and display a captured packet."""
        try:
            # Display packet in list
            packet_summary = (
                f"{packet['timestamp']} | {packet['src_ip']} -> {packet['dst_ip']} | "
                f"{packet['protocol']} | {packet['length']} bytes"
            )
            self.packet_list.insert("end", packet_summary)
            self.packet_list.yview_moveto(1)

            # Apply rules
            packet_after_rules = self.detection_engine._apply_rules_to_packet(packet)
            
            # Display rule findings from the packet after rules were applied
            if packet_after_rules is not None and "rule_findings" in packet_after_rules:
                for finding in packet_after_rules["rule_findings"]:
                    self._display_finding(finding)
            
            if packet_after_rules is None:
                self.packet_list.insert("end", "  [DROPPED] Packet filtered by rule")
                self.packet_list.yview_moveto(1)
                return

            # Analyze with detectors
            findings = self.detection_engine.analyze(packet_after_rules)
            for finding in findings:
                self._display_finding(finding)
        except Exception as e:
            logger.exception("Error processing packet: %s", e)

    def _get_group_key(self, finding):
        """Generate a group key for detection grouping.
        
        Groups detections by: attack_type | protocol | src_ip | dst_ip
        This prevents 300 identical packets from flooding the screen.
        """
        attack_type = finding.get('attack_type', finding.get('type', 'Unknown'))
        protocol = finding.get('protocol', 'Unknown')
        src_ip = finding.get('src_ip', 'Unknown')
        dst_ip = finding.get('dst_ip', 'Unknown')
        return f"{attack_type}|{protocol}|{src_ip}|{dst_ip}"

    def _display_finding(self, finding):
        """Display a detection finding in the detections tree with grouping.
        
        Groups identical detections and shows count instead of individual rows.
        """
        try:
            time = finding.get('time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            finding_type = finding.get('attack_type', finding.get('type', 'Unknown')).replace('_', ' ').title()
            protocol = finding.get('protocol', 'Unknown Protocol')
            src_ip = finding.get('src_ip', 'Unknown Source')
            dst_ip = finding.get('dst_ip', 'Unknown Destination')
            message = finding.get('message', 'No details available')
            action = finding.get('action', None)

            # Get grouping key
            group_key = self._get_group_key(finding)

            # Get row color based on action
            row_color = get_finding_color(action)

            if group_key in self.detection_groups:
                # Group already exists: increment count
                group_data = self.detection_groups[group_key]
                group_data['count'] += 1
                group_data['last_time'] = time
                group_data['timestamps'].append(time)
                
                # Keep only last 50 timestamps to avoid memory issues
                if len(group_data['timestamps']) > 50:
                    group_data['timestamps'] = group_data['timestamps'][-50:]
                
                # Update the tree item
                item_id = group_data['item_id']
                count_text = f"[{group_data['count']}x]"
                
                # Update values in tree
                self.detections_tree.item(item_id, values=(
                    group_data['first_time'],
                    finding_type,
                    protocol,
                    src_ip,
                    dst_ip,
                    count_text,
                    f"{message} (Last: {time})"
                ))
            else:
                # New group: create entry
                item_id = self.detections_tree.insert("", "end", values=(
                    time, finding_type, protocol, src_ip, dst_ip, "[1x]", message
                ))
                
                # Store group data
                self.detection_groups[group_key] = {
                    'first_time': time,
                    'last_time': time,
                    'attack_type': finding_type,
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'count': 1,
                    'timestamps': [time],
                    'item_id': item_id,
                    'action': action,
                    'finding': finding,
                }

            # Apply or update color
            apply_row_color(self.detections_tree, item_id, row_color)
        except Exception as e:
            logger.exception("Error displaying finding: %s", e)

    def stop_capture(self):
        """Stop packet capture."""
        if self.listener:
            self.listener.stop()
            self.packet_list.insert("end", "[INFO] Capture stopped.")

    def save_settings(self):
        """Save settings to configuration file."""
        try:
            from ids.utils import config as cfg
            
            # Validate inputs
            try:
                syn_window = float(self.attack_settings["syn_flood"]["window"].get())
                syn_threshold = int(self.attack_settings["syn_flood"]["threshold"].get())
                
                udp_window = float(self.attack_settings["udp_flood"]["window"].get())
                udp_threshold = int(self.attack_settings["udp_flood"]["threshold"].get())
                
                simple_window = float(self.attack_settings["simple_rate"]["window"].get())
                simple_threshold = int(self.attack_settings["simple_rate"]["threshold"].get())
                
                # Validate values
                if syn_window <= 0 or syn_threshold <= 0:
                    show_error("Invalid Input", "SYN Flood: Window and threshold must be > 0")
                    return
                if udp_window <= 0 or udp_threshold <= 0:
                    show_error("Invalid Input", "UDP Flood: Window and threshold must be > 0")
                    return
                if simple_window <= 0 or simple_threshold <= 0:
                    show_error("Invalid Input", "Generic Rate: Window and threshold must be > 0")
                    return
                    
            except ValueError:
                show_error("Invalid Input", "Please enter valid numbers for all fields")
                return
            
            # Update config
            cfg.set_section("syn_flood", {"window": syn_window, "threshold": syn_threshold})
            cfg.set_section("udp_flood", {"window": udp_window, "threshold": udp_threshold})
            cfg.set_section("simple_rate", {"window": simple_window, "threshold": simple_threshold})
            cfg.save()
            
            show_info("Success", "Settings saved successfully!\nDetectors will use new values immediately.")
            logger.info("Settings updated: syn_flood=%s, udp_flood=%s, simple_rate=%s", 
                       {"window": syn_window, "threshold": syn_threshold},
                       {"window": udp_window, "threshold": udp_threshold},
                       {"window": simple_window, "threshold": simple_threshold})
        except Exception as e:
            show_error("Error", f"Failed to save settings: {e}")
            logger.exception("Error saving settings")

    def reset_settings(self):
        """Reset settings to default values."""
        if messagebox.askyesno("Reset to Defaults", "Are you sure you want to reset all settings to defaults?"):
            try:
                from ids.utils import config as cfg
                
                # Reset to defaults
                cfg.set_section("syn_flood", {"window": 0.5, "threshold": 10})
                cfg.set_section("udp_flood", {"window": 0.5, "threshold": 10})
                cfg.set_section("simple_rate", {"window": 0.5, "threshold": 10})
                cfg.save()
                
                # Rebuild settings tab
                self._build_settings_tab()
                show_info("Reset Complete", "Settings have been reset to defaults.")
                logger.info("Settings reset to defaults")
            except Exception as e:
                show_error("Error", f"Failed to reset settings: {e}")
                logger.exception("Error resetting settings")

    def refresh_interfaces(self):
        """Refresh list of available network interfaces."""
        try:
            import socket
            interfaces = [name for _idx, name in socket.if_nameindex()]
        except Exception as e:
            logger.error("Error fetching interfaces: %s", e)
            interfaces = ['lo']

        if not interfaces:
            interfaces = ['lo']

        self.iface_combo['values'] = interfaces
        current_iface = self.iface_var.get()
        if current_iface not in interfaces:
            self.iface_var.set('lo' if 'lo' in interfaces else interfaces[0])

    def _add_rule(self):
        """Open dialog to add a new rule."""
        self._show_rule_dialog(None, "Add Rule")

    def _edit_rule(self):
        """Open dialog to edit selected rule."""
        selected_item = self.rules_tree.selection()
        if not selected_item:
            show_error("Error", "No rule selected.")
            return

        item = self.rules_tree.item(selected_item)
        values = item["values"]
        self._show_rule_dialog(values, "Edit Rule")

    def _delete_rule(self):
        """Delete the selected rule."""
        selected_item = self.rules_tree.selection()
        if not selected_item:
            show_error("Error", "No rule selected.")
            return

        self.rules_tree.delete(selected_item)
        self._on_rule_change()

    def _show_rule_dialog(self, rule_values, title):
        """Show rule creation/editing dialog."""
        rule_window = tk.Toplevel(self.root)
        rule_window.title(title)

        # Fields
        fields = [
            ("Rule Name:", "name"),
            ("Field:", "field"),
            ("Operator:", "operator"),
            ("Value:", "value"),
            ("Action:", "action")
        ]

        vars_dict = {}

        for i, (label_text, var_name) in enumerate(fields):
            ttk.Label(rule_window, text=label_text).grid(row=i, column=0, sticky="w", padx=5, pady=5)

            var = tk.StringVar()
            if rule_values:
                var.set(rule_values[i])

            if var_name == "field":
                combo = ttk.Combobox(rule_window, textvariable=var, state="readonly")
                combo["values"] = AVAILABLE_FIELDS
                combo.grid(row=i, column=1, sticky="we", padx=5, pady=5)
            elif var_name == "operator":
                combo = ttk.Combobox(rule_window, textvariable=var, state="readonly")
                combo["values"] = AVAILABLE_OPERATORS
                combo.grid(row=i, column=1, sticky="we", padx=5, pady=5)
            elif var_name == "action":
                combo = ttk.Combobox(rule_window, textvariable=var, state="readonly")
                combo["values"] = AVAILABLE_ACTIONS
                combo.grid(row=i, column=1, sticky="we", padx=5, pady=5)
            else:
                ttk.Entry(rule_window, textvariable=var).grid(row=i, column=1, sticky="we", padx=5, pady=5)

            vars_dict[var_name] = var

        def save_rule():
            rule = {
                "name": vars_dict["name"].get(),
                "field": vars_dict["field"].get(),
                "operator": vars_dict["operator"].get(),
                "value": vars_dict["value"].get(),
                "action": vars_dict["action"].get()
            }

            # Validate
            is_valid, error_msg = validate_rule(rule)
            if not is_valid:
                show_error("Error", error_msg)
                return

            # Update tree and file
            if rule_values:
                # Edit mode
                selected = self.rules_tree.selection()[0]
                self.rules_tree.item(selected, values=(
                    rule["name"], rule["field"], rule["operator"], rule["value"], rule["action"]
                ))
            else:
                # Add mode
                self.rules_tree.insert("", "end", values=(
                    rule["name"], rule["field"], rule["operator"], rule["value"], rule["action"]
                ))

            self._on_rule_change()
            rule_window.destroy()

        ttk.Button(rule_window, text="Save", command=save_rule).grid(row=len(fields), column=0, columnspan=2, pady=10)

    def _load_rules(self):
        """Load rules from file and populate tree."""
        try:
            rules = load_rules_from_file()
            for rule in rules:
                self.rules_tree.insert("", "end", values=(
                    rule.get("name", ""),
                    rule.get("field", ""),
                    rule.get("operator", ""),
                    rule.get("value", ""),
                    rule.get("action", "")
                ))
        except FileNotFoundError:
            logger.warning("rules.json not found")
        except Exception as e:
            logger.error("Failed to load rules: %s", e)

    def _on_rule_change(self):
        """Save rules and reload in detection engine."""
        # Collect rules from tree
        rules = []
        for item in self.rules_tree.get_children():
            values = self.rules_tree.item(item, "values")
            rules.append({
                "name": values[0],
                "field": values[1],
                "operator": values[2],
                "value": values[3],
                "action": values[4]
            })

        # Save to file
        if save_rules_to_file(rules):
            # Reload in detection engine
            self.detection_engine.reload_rules()


def run():
    """Run the IDS GUI."""
    root = tk.Tk()
    app = RedesignedCaptureGUI(root)

    def _handle_sigint(signum, frame):
        try:
            root.quit()
        except Exception:
            pass

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        try:
            root.quit()
        except Exception:
            pass


if __name__ == '__main__':
    run()
