#!/usr/bin/env python3
"""
OSSEC Parser - Real-Time Queue-Based Version
Captures packets and sends flows to queue every 30s
"""

from scapy.all import *
from collections import defaultdict
import time
import math
import numpy as np
from multiprocessing import Queue
import signal
import sys

# Configuration
FLOW_TIMEOUT = 15
FLOW_MAX_AGE = 30  # Export every 30s
FLOW_MEMORY_LIMIT = 10

class FlowBuilderRealtime:
    def __init__(self, output_queue, shutdown_event):
        self.output_queue = output_queue
        self.shutdown_event = shutdown_event
        
        self.active_flows = {}
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'exported_flows': 0,
            'queue_sends': 0
        }
        
        self.start_time = time.time()
        self.last_cleanup = time.time()
        self.last_export = time.time()
        
        print(f"[Parser] 🚀 Started (Queue-based)")
    
    def process_packet(self, packet):
        """Process each packet"""
        if self.shutdown_event.is_set():
            return
        
        try:
            self.stats['total_packets'] += 1
            
            flow_key, direction, metadata = self._extract_flow_key(packet)
            if flow_key is None:
                return
            
            if flow_key in self.active_flows:
                self._update_flow(flow_key, packet, direction, metadata)
            else:
                self._create_flow(flow_key, packet, direction, metadata)
            
            current_time = time.time()
            
            # Periodic cleanup (every 10s)
            if current_time - self.last_cleanup > 10:
                self._cleanup_old_flows()
                self.last_cleanup = current_time
            
            # Export to queue every 30s
            if current_time - self.last_export > FLOW_MAX_AGE:
                self._export_active_flows()
                self.last_export = current_time
            
            # Progress
            if self.stats['total_packets'] % 1000 == 0:
                self._print_progress()
        
        except Exception as e:
            print(f"[Parser] ⚠️  Error: {e}")
    
    def _extract_flow_key(self, packet):
        """Extract 5-tuple from packet"""
        metadata = {'tos': 0, 'ttl': 0, 'ip_version': 0, 'has_payload': False}
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            metadata['tos'] = packet[IP].tos
            metadata['ttl'] = packet[IP].ttl
            metadata['ip_version'] = 4
            
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto_name = 'TCP'
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                proto_name = 'UDP'
            else:
                src_port = 0
                dst_port = 0
                proto_name = f'IP_{packet[IP].proto}'
        
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            metadata['ttl'] = packet[IPv6].hlim
            metadata['ip_version'] = 6
            
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto_name = 'TCP'
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                proto_name = 'UDP'
            else:
                return None, None, None
        
        else:
            return None, None, None
        
        if packet.haslayer(Raw):
            metadata['has_payload'] = True
        
        # Normalize bidirectional flow
        if (src_ip, src_port) < (dst_ip, dst_port):
            flow_key = (src_ip, dst_ip, src_port, dst_port, proto_name)
            direction = 0
        else:
            flow_key = (dst_ip, src_ip, dst_port, src_port, proto_name)
            direction = 1
        
        return flow_key, direction, metadata
    
    def _create_flow(self, flow_key, packet, direction, metadata):
        """Create new flow"""
        current_time = time.time()
        packet_size = len(packet)
        tcp_flags = self._get_tcp_flags(packet) if packet.haslayer(TCP) else 0
        
        self.active_flows[flow_key] = {
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
            'src_port': flow_key[2],
            'dst_port': flow_key[3],
            'protocol': flow_key[4],
            'start_time': current_time,
            'last_seen': current_time,
            'fwd_packets': 1 if direction == 0 else 0,
            'fwd_bytes': packet_size if direction == 0 else 0,
            'fwd_tcp_flags': tcp_flags if direction == 0 else 0,
            'fwd_packet_sizes': [packet_size] if direction == 0 else [],
            'fwd_iat': [],
            'fwd_last_time': current_time if direction == 0 else None,
            'bwd_packets': 1 if direction == 1 else 0,
            'bwd_bytes': packet_size if direction == 1 else 0,
            'bwd_tcp_flags': tcp_flags if direction == 1 else 0,
            'bwd_packet_sizes': [packet_size] if direction == 1 else [],
            'bwd_iat': [],
            'bwd_last_time': current_time if direction == 1 else None,
            'tos': metadata['tos'],
            'ttl': metadata['ttl'],
            'ip_version': metadata['ip_version'],
            'payload_entropy_samples': []
        }
        
        if metadata['has_payload']:
            entropy = self._calculate_entropy(packet[Raw].load)
            self.active_flows[flow_key]['payload_entropy_samples'].append(entropy)
        
        self.stats['total_flows'] += 1
    
    def _update_flow(self, flow_key, packet, direction, metadata):
        """Update existing flow"""
        flow = self.active_flows[flow_key]
        current_time = time.time()
        packet_size = len(packet)
        
        flow['last_seen'] = current_time
        
        if direction == 0:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_size
            flow['fwd_packet_sizes'].append(packet_size)
            
            if flow['fwd_last_time']:
                iat = current_time - flow['fwd_last_time']
                flow['fwd_iat'].append(iat)
            
            flow['fwd_last_time'] = current_time
            
            if packet.haslayer(TCP):
                flow['fwd_tcp_flags'] |= self._get_tcp_flags(packet)
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_size
            flow['bwd_packet_sizes'].append(packet_size)
            
            if flow['bwd_last_time']:
                iat = current_time - flow['bwd_last_time']
                flow['bwd_iat'].append(iat)
            
            flow['bwd_last_time'] = current_time
            
            if packet.haslayer(TCP):
                flow['bwd_tcp_flags'] |= self._get_tcp_flags(packet)
        
        if metadata['has_payload'] and len(flow['payload_entropy_samples']) < 10:
            entropy = self._calculate_entropy(packet[Raw].load)
            flow['payload_entropy_samples'].append(entropy)
    
    def _get_tcp_flags(self, packet):
        """Get TCP flags as bitmask"""
        if not packet.haslayer(TCP):
            return 0
        
        flags = packet[TCP].flags
        flag_map = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32}
        result = 0
        
        for flag_char, flag_val in flag_map.items():
            if flag_char in str(flags):
                result |= flag_val
        
        return result
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data or len(data) == 0:
            return 0.0
        
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _cleanup_old_flows(self):
        """Remove flows with no activity for FLOW_TIMEOUT seconds"""
        current_time = time.time()
        expired_flows = []
        
        for flow_key, flow_data in self.active_flows.items():
            if current_time - flow_data['last_seen'] > FLOW_TIMEOUT:
                # Finalize and send to queue
                completed_flow = self._finalize_flow(flow_data)
                self._send_to_queue([completed_flow])
                expired_flows.append(flow_key)
        
        for flow_key in expired_flows:
            del self.active_flows[flow_key]
        
        if expired_flows:
            print(f"[Parser] 🔄 Cleaned {len(expired_flows)} expired flows")
    
    def _export_active_flows(self):
        """Export all active flows (snapshots)"""
        if not self.active_flows:
            return
        
        current_time = time.time()
        flows_to_export = []
        
        for flow_key, flow_data in list(self.active_flows.items()):
            flow_age = current_time - flow_data['start_time']
            
            if flow_age > FLOW_MAX_AGE:
                # Create snapshot
                completed_flow = self._finalize_flow(flow_data)
                flows_to_export.append(completed_flow)
                
                # Clean RAM
                flow_data['fwd_packet_sizes'] = flow_data['fwd_packet_sizes'][-FLOW_MEMORY_LIMIT:]
                flow_data['bwd_packet_sizes'] = flow_data['bwd_packet_sizes'][-FLOW_MEMORY_LIMIT:]
                flow_data['fwd_iat'] = flow_data['fwd_iat'][-FLOW_MEMORY_LIMIT:]
                flow_data['bwd_iat'] = flow_data['bwd_iat'][-FLOW_MEMORY_LIMIT:]
                
                # Reset for next snapshot
                flow_data['start_time'] = current_time
                flow_data['fwd_packets'] = 0
                flow_data['bwd_packets'] = 0
                flow_data['fwd_bytes'] = 0
                flow_data['bwd_bytes'] = 0
        
        if flows_to_export:
            self._send_to_queue(flows_to_export)
            print(f"[Parser] 📸 Exported {len(flows_to_export)} active flow snapshots")
    
    def _finalize_flow(self, flow_data):
        """Compute final features"""
        duration = flow_data['last_seen'] - flow_data['start_time']
        total_packets = flow_data['fwd_packets'] + flow_data['bwd_packets']
        total_bytes = flow_data['fwd_bytes'] + flow_data['bwd_bytes']
        
        return {
            'src_ip': flow_data['src_ip'],
            'dst_ip': flow_data['dst_ip'],
            'src_port': flow_data['src_port'],
            'dst_port': flow_data['dst_port'],
            'protocol': flow_data['protocol'],
            'duration': duration,
            'start_timestamp': flow_data['start_time'],
            'total_fwd_packets': flow_data['fwd_packets'],
            'total_bwd_packets': flow_data['bwd_packets'],
            'total_fwd_bytes': flow_data['fwd_bytes'],
            'total_bwd_bytes': flow_data['bwd_bytes'],
            'fwd_packets_per_sec': flow_data['fwd_packets'] / duration if duration > 0 else 0,
            'bwd_packets_per_sec': flow_data['bwd_packets'] / duration if duration > 0 else 0,
            'flow_bytes_per_sec': total_bytes / duration if duration > 0 else 0,
            'tos': flow_data['tos'],
            'ttl': flow_data['ttl'],
            'ip_version': flow_data['ip_version'],
            'fwd_packet_length_mean': np.mean(flow_data['fwd_packet_sizes']) if flow_data['fwd_packet_sizes'] else 0,
            'fwd_packet_length_std': np.std(flow_data['fwd_packet_sizes']) if flow_data['fwd_packet_sizes'] else 0,
            'fwd_packet_length_max': max(flow_data['fwd_packet_sizes']) if flow_data['fwd_packet_sizes'] else 0,
            'fwd_packet_length_min': min(flow_data['fwd_packet_sizes']) if flow_data['fwd_packet_sizes'] else 0,
            'bwd_packet_length_mean': np.mean(flow_data['bwd_packet_sizes']) if flow_data['bwd_packet_sizes'] else 0,
            'bwd_packet_length_std': np.std(flow_data['bwd_packet_sizes']) if flow_data['bwd_packet_sizes'] else 0,
            'bwd_packet_length_max': max(flow_data['bwd_packet_sizes']) if flow_data['bwd_packet_sizes'] else 0,
            'bwd_packet_length_min': min(flow_data['bwd_packet_sizes']) if flow_data['bwd_packet_sizes'] else 0,
            'fwd_iat_mean': np.mean(flow_data['fwd_iat']) if flow_data['fwd_iat'] else 0,
            'fwd_iat_std': np.std(flow_data['fwd_iat']) if flow_data['fwd_iat'] else 0,
            'fwd_iat_max': max(flow_data['fwd_iat']) if flow_data['fwd_iat'] else 0,
            'fwd_iat_min': min(flow_data['fwd_iat']) if flow_data['fwd_iat'] else 0,
            'bwd_iat_mean': np.mean(flow_data['bwd_iat']) if flow_data['bwd_iat'] else 0,
            'bwd_iat_std': np.std(flow_data['bwd_iat']) if flow_data['bwd_iat'] else 0,
            'bwd_to_fwd_packet_ratio': flow_data['bwd_packets'] / flow_data['fwd_packets'] if flow_data['fwd_packets'] > 0 else 0,
            'bwd_to_fwd_byte_ratio': flow_data['bwd_bytes'] / flow_data['fwd_bytes'] if flow_data['fwd_bytes'] > 0 else 0,
            'fwd_psh_flags': 1 if (flow_data['fwd_tcp_flags'] & 8) else 0,
            'fwd_urg_flags': 1 if (flow_data['fwd_tcp_flags'] & 32) else 0,
            'fwd_fin_flags': 1 if (flow_data['fwd_tcp_flags'] & 1) else 0,
            'fwd_syn_flags': 1 if (flow_data['fwd_tcp_flags'] & 2) else 0,
            'fwd_rst_flags': 1 if (flow_data['fwd_tcp_flags'] & 4) else 0,
            'fwd_ack_flags': 1 if (flow_data['fwd_tcp_flags'] & 16) else 0,
            'bwd_psh_flags': 1 if (flow_data['bwd_tcp_flags'] & 8) else 0,
            'bwd_urg_flags': 1 if (flow_data['bwd_tcp_flags'] & 32) else 0,
            'bwd_fin_flags': 1 if (flow_data['bwd_tcp_flags'] & 1) else 0,
            'bwd_syn_flags': 1 if (flow_data['bwd_tcp_flags'] & 2) else 0,
            'bwd_rst_flags': 1 if (flow_data['bwd_tcp_flags'] & 4) else 0,
            'bwd_ack_flags': 1 if (flow_data['bwd_tcp_flags'] & 16) else 0,
            'is_tcp': 1 if 'TCP' in flow_data['protocol'] else 0,
            'is_udp': 1 if 'UDP' in flow_data['protocol'] else 0,
            'is_arp': 1 if 'ARP' in flow_data['protocol'] else 0,
            'is_icmp': 1 if 'IP_1' in flow_data['protocol'] else 0,
            'is_ipv6': 1 if flow_data['ip_version'] == 6 else 0,
            'avg_payload_entropy': np.mean(flow_data['payload_entropy_samples']) if flow_data['payload_entropy_samples'] else 0,
            'max_payload_entropy': max(flow_data['payload_entropy_samples']) if flow_data['payload_entropy_samples'] else 0,
            'min_payload_entropy': min(flow_data['payload_entropy_samples']) if flow_data['payload_entropy_samples'] else 0,
        }
    
    def _send_to_queue(self, flows):
        """Send flows to queue for features process"""
        try:
            self.output_queue.put({
                'flows': flows,
                'timestamp': time.time()
            }, block=False)
            
            self.stats['exported_flows'] += len(flows)
            self.stats['queue_sends'] += 1
        
        except:
            print(f"[Parser] ⚠️  Queue full! Dropping {len(flows)} flows")
    
    def _print_progress(self):
        """Print progress"""
        elapsed = time.time() - self.start_time
        pps = self.stats['total_packets'] / elapsed if elapsed > 0 else 0
        
        print(f"[Parser] 📈 Packets: {self.stats['total_packets']:,} | "
              f"Active: {len(self.active_flows)} | "
              f"Exported: {self.stats['exported_flows']} | "
              f"Queue sends: {self.stats['queue_sends']} | "
              f"Rate: {pps:.1f} pkt/s")
    
    def finalize(self):
        """Export all remaining flows"""
        print(f"[Parser] 🛑 Finalizing...")
        
        remaining = []
        for flow_key, flow_data in self.active_flows.items():
            completed_flow = self._finalize_flow(flow_data)
            remaining.append(completed_flow)
        
        if remaining:
            self._send_to_queue(remaining)
            print(f"[Parser] 📤 Exported {len(remaining)} remaining flows")
        
        elapsed = time.time() - self.start_time
        print(f"[Parser] ✅ Total packets: {self.stats['total_packets']:,}")
        print(f"[Parser] ✅ Total flows exported: {self.stats['exported_flows']}")
        print(f"[Parser] ✅ Duration: {elapsed:.1f}s")

def run_parser(output_queue, shutdown_event):
    """Main parser process"""
    builder = FlowBuilderRealtime(output_queue, shutdown_event)
    
    try:
        print(f"[Parser] 🎯 Starting packet capture...")
        sniff(prn=builder.process_packet, store=False,
              stop_filter=lambda x: shutdown_event.is_set())
    
    except Exception as e:
        print(f"[Parser] 💥 Error: {e}")
    
    finally:
        builder.finalize()
