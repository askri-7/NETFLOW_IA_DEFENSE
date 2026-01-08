

"""
OSSEC Network Traffic Anomaly Defender - Phase 1: Flow Builder
Optimized for ML analysis with entropy-based suspicion scoring
Multi-protocol support: IPv4, IPv6, ARP, Layer 2
"""

from scapy.all import *
from collections import defaultdict
import time
import math
import pandas as pd
import numpy as np
import os

# --- Configuration ---
FLOW_TIMEOUT = 60  # seconds - close inactive flows
FLOW_EXPORT_BATCH = 1000  # Export every N flows
OUTPUT_FILE = "flows.csv"

class FlowBuilder:
    def __init__(self):
        # Active flows: key = 5-tuple, value = flow stats
        self.active_flows = {}
        
        # Completed flows buffer for batch export
        self.completed_flows = []
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'exported_flows': 0,
            'ipv4_packets': 0,
            'ipv6_packets': 0,
            'arp_packets': 0,
            'other_packets': 0
        }
        
        self.start_time = time.time()
        self.last_cleanup = time.time()
        
        print("🚀 Flow Builder initialized (IPv4 + IPv6 + ARP)")
        print(f"📊 Flow timeout: {FLOW_TIMEOUT}s")
        print(f"💾 Export batch size: {FLOW_EXPORT_BATCH} flows\n")
    
    def process_packet(self, packet):
        """Process each packet in real-time and build flows"""
        try:
            self.stats['total_packets'] += 1
            
            # Extract 5-tuple and create flow key
            flow_key, direction, metadata = self._extract_flow_key(packet)
            
            if flow_key is None:
                return
            
            # Update or create flow
            if flow_key in self.active_flows:
                self._update_flow(flow_key, packet, direction, metadata)
            else:
                self._create_flow(flow_key, packet, direction, metadata)
            
            # Periodic cleanup of old flows
            if time.time() - self.last_cleanup > 10:
                self._cleanup_old_flows()
                self.last_cleanup = time.time()
            
            # Show progress
            if self.stats['total_packets'] % 1000 == 0:
                self._print_progress()
                
        except Exception as e:
            print(f"⚠️ Error processing packet: {e}")
    
    def _extract_flow_key(self, packet):
        """
        Extract flow key for ANY packet type
        Returns: (flow_key, direction, metadata)
        """
        metadata = {
            'tos': 0,
            'ttl': 0,
            'ip_version': 0,
            'has_payload': False
        }
        
        # === Handle IPv4 traffic (TCP/UDP/ICMP) ===
        if packet.haslayer(IP):
            self.stats['ipv4_packets'] += 1
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            metadata['tos'] = packet[IP].tos
            metadata['ttl'] = packet[IP].ttl
            metadata['ip_version'] = 4
            
            # Get ports for TCP/UDP
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
                proto_name = f'IP_{proto}'  # e.g., IP_1 for ICMP
        
        # === Handle IPv6 traffic ===
        elif packet.haslayer(IPv6):
            self.stats['ipv6_packets'] += 1
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            proto = packet[IPv6].nh  # Next Header
            
            metadata['tos'] = packet[IPv6].tc  # Traffic Class
            metadata['ttl'] = packet[IPv6].hlim  # Hop Limit
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
                src_port = 0
                dst_port = 0
                proto_name = f'IPv6_{proto}'
        
        # === Handle ARP traffic ===
        elif packet.haslayer(ARP):
            self.stats['arp_packets'] += 1
            src_ip = packet[ARP].psrc  # Protocol source (IP)
            dst_ip = packet[ARP].pdst  # Protocol destination (IP)
            src_port = 0
            dst_port = 0
            proto_name = f'ARP_{packet[ARP].op}'  # ARP_1 (request) or ARP_2 (reply)
            metadata['ip_version'] = 0
        
        # === Handle Ethernet-only (Layer 2) ===
        elif packet.haslayer(Ether):
            self.stats['other_packets'] += 1
            src_ip = packet[Ether].src
            dst_ip = packet[Ether].dst
            src_port = 0
            dst_port = 0
            proto_name = f'L2_{packet[Ether].type}'
            metadata['ip_version'] = 0
        
        # === Unknown packet type ===
        else:
            self.stats['other_packets'] += 1
            return None, None, None
        
        # Check for payload
        if packet.haslayer(Raw):
            metadata['has_payload'] = True
        
        # Normalize flow (bidirectional)
        if (src_ip, src_port) < (dst_ip, dst_port):
            flow_key = (src_ip, dst_ip, src_port, dst_port, proto_name)
            direction = 0
        else:
            flow_key = (dst_ip, src_ip, dst_port, src_port, proto_name)
            direction = 1
        
        return flow_key, direction, metadata

    def _create_flow(self, flow_key, packet, direction, metadata):
        """Create a new flow from first packet"""
        current_time = time.time()
        packet_size = len(packet)
        
        # Extract TCP flags if present
        tcp_flags = self._get_tcp_flags(packet) if packet.haslayer(TCP) else 0
        
        # Initialize bidirectional flow
        self.active_flows[flow_key] = {
            # 5-tuple
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
            'src_port': flow_key[2],
            'dst_port': flow_key[3],
            'protocol': flow_key[4],
            
            # Timing
            'start_time': current_time,
            'last_seen': current_time,
            
            # Forward direction (0)
            'fwd_packets': 1 if direction == 0 else 0,
            'fwd_bytes': packet_size if direction == 0 else 0,
            'fwd_tcp_flags': tcp_flags if direction == 0 else 0,
            'fwd_packet_sizes': [packet_size] if direction == 0 else [],
            'fwd_iat': [],  # Inter-arrival times
            'fwd_last_time': current_time if direction == 0 else None,
            
            # Reverse direction (1)
            'bwd_packets': 1 if direction == 1 else 0,
            'bwd_bytes': packet_size if direction == 1 else 0,
            'bwd_tcp_flags': tcp_flags if direction == 1 else 0,
            'bwd_packet_sizes': [packet_size] if direction == 1 else [],
            'bwd_iat': [],
            'bwd_last_time': current_time if direction == 1 else None,
            
            # Protocol-specific metadata
            'tos': metadata['tos'],
            'ttl': metadata['ttl'],
            'ip_version': metadata['ip_version'],
            
            # Payload entropy tracking
            'payload_entropy_samples': []
        }
        
        # Calculate entropy for first packet if it has payload
        if metadata['has_payload']:
            entropy = self._calculate_entropy(packet[Raw].load)
            self.active_flows[flow_key]['payload_entropy_samples'].append(entropy)
        
        self.stats['total_flows'] += 1
    
    def _update_flow(self, flow_key, packet, direction, metadata):
        """Update existing flow with new packet"""
        flow = self.active_flows[flow_key]
        current_time = time.time()
        packet_size = len(packet)
        
        # Update timing
        flow['last_seen'] = current_time
        
        if direction == 0:  # Forward
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_size
            flow['fwd_packet_sizes'].append(packet_size)
            
            # Inter-arrival time
            if flow['fwd_last_time']:
                iat = current_time - flow['fwd_last_time']
                flow['fwd_iat'].append(iat)
            flow['fwd_last_time'] = current_time
            
            # TCP flags
            if packet.haslayer(TCP):
                flow['fwd_tcp_flags'] |= self._get_tcp_flags(packet)
                
        else:  # Reverse
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_size
            flow['bwd_packet_sizes'].append(packet_size)
            
            if flow['bwd_last_time']:
                iat = current_time - flow['bwd_last_time']
                flow['bwd_iat'].append(iat)
            flow['bwd_last_time'] = current_time
            
            if packet.haslayer(TCP):
                flow['bwd_tcp_flags'] |= self._get_tcp_flags(packet)
        
        # Sample entropy (max 10 samples to save memory)
        if metadata['has_payload'] and len(flow['payload_entropy_samples']) < 10:
            entropy = self._calculate_entropy(packet[Raw].load)
            flow['payload_entropy_samples'].append(entropy)
    
    def _get_tcp_flags(self, packet):
        """Convert TCP flags to integer bitmask"""
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
        """
        Calculate Shannon entropy of payload data
        High entropy (>7.0) = encrypted/compressed/random
        Low entropy (<3.0) = plain text/patterns
        """
        if not data or len(data) == 0:
            return 0.0
        
        # Count byte frequencies
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _cleanup_old_flows(self):
        """Export and remove flows that haven't seen packets in FLOW_TIMEOUT seconds"""
        current_time = time.time()
        expired_flows = []
        
        for flow_key, flow_data in self.active_flows.items():
            if current_time - flow_data['last_seen'] > FLOW_TIMEOUT:
                # Flow is complete - prepare for export
                completed_flow = self._finalize_flow(flow_data)
                self.completed_flows.append(completed_flow)
                expired_flows.append(flow_key)
        
        # Remove expired flows
        for flow_key in expired_flows:
            del self.active_flows[flow_key]
        
        # Export batch if needed
        if len(self.completed_flows) >= FLOW_EXPORT_BATCH:
            self._export_flows()
        
        if expired_flows:
            print(f"🔄 Cleaned up {len(expired_flows)} flows | Active: {len(self.active_flows)}")
    
    def _finalize_flow(self, flow_data):
        """
        Compute final features from flow data
        This is what your ML model will use
        """
        duration = flow_data['last_seen'] - flow_data['start_time']
        total_packets = flow_data['fwd_packets'] + flow_data['bwd_packets']
        total_bytes = flow_data['fwd_bytes'] + flow_data['bwd_bytes']
        
        # Compute statistics
        finalized = {
            # === Basic Flow Info ===
            'src_ip': flow_data['src_ip'],
            'dst_ip': flow_data['dst_ip'],
            'src_port': flow_data['src_port'],
            'dst_port': flow_data['dst_port'],
            'protocol': flow_data['protocol'],
            
            # === Temporal Features ===
            'duration': duration,
            'start_timestamp': flow_data['start_time'],
            
            # === Volume Features ===
            'total_fwd_packets': flow_data['fwd_packets'],
            'total_bwd_packets': flow_data['bwd_packets'],
            'total_fwd_bytes': flow_data['fwd_bytes'],
            'total_bwd_bytes': flow_data['bwd_bytes'],
            
            # === Rate Features ===
            'fwd_packets_per_sec': flow_data['fwd_packets'] / duration if duration > 0 else 0,
            'bwd_packets_per_sec': flow_data['bwd_packets'] / duration if duration > 0 else 0,
            'flow_bytes_per_sec': total_bytes / duration if duration > 0 else 0,
            
            # === Packet Size Features ===
            'fwd_packet_length_mean': np.mean(flow_data['fwd_packet_sizes']) if flow_data['fwd_packet_sizes'] else 0,
            'fwd_packet_length_std': np.std(flow_data['fwd_packet_sizes']) if flow_data['fwd_packet_sizes'] else 0,
            'fwd_packet_length_max': max(flow_data['fwd_packet_sizes']) if flow_data['fwd_packet_sizes'] else 0,
            'fwd_packet_length_min': min(flow_data['fwd_packet_sizes']) if flow_data['fwd_packet_sizes'] else 0,
            
            'bwd_packet_length_mean': np.mean(flow_data['bwd_packet_sizes']) if flow_data['bwd_packet_sizes'] else 0,
            'bwd_packet_length_std': np.std(flow_data['bwd_packet_sizes']) if flow_data['bwd_packet_sizes'] else 0,
            'bwd_packet_length_max': max(flow_data['bwd_packet_sizes']) if flow_data['bwd_packet_sizes'] else 0,
            'bwd_packet_length_min': min(flow_data['bwd_packet_sizes']) if flow_data['bwd_packet_sizes'] else 0,
            
            # === Inter-Arrival Time Features ===
            'fwd_iat_mean': np.mean(flow_data['fwd_iat']) if flow_data['fwd_iat'] else 0,
            'fwd_iat_std': np.std(flow_data['fwd_iat']) if flow_data['fwd_iat'] else 0,
            'fwd_iat_max': max(flow_data['fwd_iat']) if flow_data['fwd_iat'] else 0,
            'fwd_iat_min': min(flow_data['fwd_iat']) if flow_data['fwd_iat'] else 0,
            
            'bwd_iat_mean': np.mean(flow_data['bwd_iat']) if flow_data['bwd_iat'] else 0,
            'bwd_iat_std': np.std(flow_data['bwd_iat']) if flow_data['bwd_iat'] else 0,
            
            # === TCP Flags ===
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
            
            # === Entropy Features (Suspicion Score) ===
            'avg_payload_entropy': np.mean(flow_data['payload_entropy_samples']) if flow_data['payload_entropy_samples'] else 0,
            'max_payload_entropy': max(flow_data['payload_entropy_samples']) if flow_data['payload_entropy_samples'] else 0,
            'min_payload_entropy': min(flow_data['payload_entropy_samples']) if flow_data['payload_entropy_samples'] else 0,
            
            # === Additional Features ===
            'tos': flow_data['tos'],
            'ttl': flow_data['ttl'],
            'ip_version': flow_data['ip_version'],
            
            # === Behavioral Ratios ===
            'bwd_to_fwd_packet_ratio': flow_data['bwd_packets'] / flow_data['fwd_packets'] if flow_data['fwd_packets'] > 0 else 0,
            'bwd_to_fwd_byte_ratio': flow_data['bwd_bytes'] / flow_data['fwd_bytes'] if flow_data['fwd_bytes'] > 0 else 0,
            
            # === Protocol Indicators ===
            'is_tcp': 1 if 'TCP' in flow_data['protocol'] else 0,
            'is_udp': 1 if 'UDP' in flow_data['protocol'] else 0,
            'is_arp': 1 if 'ARP' in flow_data['protocol'] else 0,
            'is_icmp': 1 if 'IP_1' in flow_data['protocol'] else 0,
            'is_ipv6': 1 if flow_data['ip_version'] == 6 else 0,
        }
        
        return finalized
    
    def _export_flows(self):
        """Export completed flows to CSV"""
        if not self.completed_flows:
            return
        
        df = pd.DataFrame(self.completed_flows)
        
        # Append to CSV (create with header first time)
        file_exists = os.path.isfile(OUTPUT_FILE)
        df.to_csv(OUTPUT_FILE, mode='a', header=not file_exists, index=False)
        
        self.stats['exported_flows'] += len(self.completed_flows)
        print(f"💾 Exported {len(self.completed_flows)} flows to {OUTPUT_FILE}")
        print(f"📊 Total exported: {self.stats['exported_flows']} flows")
        
        # Clear buffer
        self.completed_flows = []
    
    def _print_progress(self):
        """Print current progress"""
        elapsed = time.time() - self.start_time
        pps = self.stats['total_packets'] / elapsed if elapsed > 0 else 0
        
        print(f"📈 Packets: {self.stats['total_packets']:,} | "
              f"Active Flows: {len(self.active_flows):,} | "
              f"Exported: {self.stats['exported_flows']:,} | "
              f"Rate: {pps:.1f} pkt/s")
        print(f"   IPv4: {self.stats['ipv4_packets']} | "
              f"IPv6: {self.stats['ipv6_packets']} | "
              f"ARP: {self.stats['arp_packets']} | "
              f"Other: {self.stats['other_packets']}")
    
    def finalize(self):
        """Export all remaining flows on shutdown"""
        print("\n🛑 Finalizing capture...")
        
        # Export all active flows
        for flow_key, flow_data in self.active_flows.items():
            completed_flow = self._finalize_flow(flow_data)
            self.completed_flows.append(completed_flow)
        
        # Final export
        if self.completed_flows:
            self._export_flows()
        
        # Final stats
        elapsed = time.time() - self.start_time
        print(f"\n{'='*70}")
        print(f"📊 FINAL STATISTICS")
        print(f"{'='*70}")
        print(f"⏱️  Duration: {elapsed:.1f}s")
        print(f"📦 Total Packets: {self.stats['total_packets']:,}")
        print(f"   - IPv4: {self.stats['ipv4_packets']:,}")
        print(f"   - IPv6: {self.stats['ipv6_packets']:,}")
        print(f"   - ARP: {self.stats['arp_packets']:,}")
        print(f"   - Other: {self.stats['other_packets']:,}")
        print(f"🌊 Total Flows: {self.stats['total_flows']:,}")
        print(f"💾 Exported Flows: {self.stats['exported_flows']:,}")
        print(f"📈 Avg Packet Rate: {self.stats['total_packets']/elapsed:.1f} pkt/s")
        print(f"📁 Output File: {OUTPUT_FILE}")
        print(f"{'='*70}\n")


def main():
    """Main execution"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║     OSSEC Network Traffic Anomaly Defender - Flow Builder     ║
║          Phase 1: Parser (IPv4/IPv6/ARP Support)              ║
╚═══════════════════════════════════════════════════════════════╝
""")
    
    builder = FlowBuilder()
    
    try:
        print("🎯 Starting packet capture...")
        print("📡 Press Ctrl+C to stop\n")
        
        # Start capture with store=False for memory efficiency
        sniff(prn=builder.process_packet, store=False)
        
    except KeyboardInterrupt:
        print("\n\n⏸️  Capture interrupted by user")
    except PermissionError:
        print("\n❌ Permission denied! Run with: sudo python3 flow_builder.py")
    except Exception as e:
        print(f"\n💥 Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        builder.finalize()


if __name__ == "__main__":
    main()
