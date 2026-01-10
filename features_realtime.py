#!/usr/bin/env python3

"""
OSSEC Network Traffic Anomaly Defender - Phase 2: Feature Engineering (Real-Time)
Reads flows from Queue, engineers features, sends to next Queue
Continuous processing for real-time detection
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import time
from multiprocessing import Queue
import queue

# Configuration
NORMALIZATION_METHOD = 'minmax'
OUTLIER_CLIP_PERCENTILE = 99

# Metadata columns
METADATA_COLS = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'start_timestamp']

# Suspicious ports (from network analyzer)
SUSPICIOUS_PORTS = {
    4444, 31337, 1337, 9999, 666, 54320, 12345, 2323,
    20, 21, 22, 23, 3389, 25, 110, 143, 445, 139
}

class FeaturesEngineering:
    def __init__(self, input_queue, output_queue, shutdown_event):
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.shutdown_event = shutdown_event
        
        # Scaler (incrementally fitted)
        self.scaler = MinMaxScaler()
        self.scaler_fitted = False
        
        # Stats
        self.stats = {
            'batches_processed': 0,
            'total_flows': 0,
            'features_sent': 0
        }
        
        print(f"[Features] 🚀 Started (Queue-based)")
    
    def run(self):
        """Main processing loop"""
        print(f"[Features] 👂 Waiting for flows from parser...")
        
        while not self.shutdown_event.is_set():
            try:
                # Get flows from parser (timeout 1s)
                data = self.input_queue.get(timeout=1)
                
                flows = data['flows']
                timestamp = data['timestamp']
                
                print(f"\n[Features] 📥 Received {len(flows)} flows")
                
                # Convert to DataFrame
                df = pd.DataFrame(flows)
                
                if len(df) == 0:
                    continue
                
                # Step 1: Clean data
                df = self._clean_data(df)
                
                # Step 2: Engineer features
                df = self._engineer_features(df)
                
                # Step 3: Normalize
                df = self._normalize_features(df)
                
                # Step 4: Send to ML detector
                self._send_to_queue(df, timestamp)
                
                self.stats['batches_processed'] += 1
                self.stats['total_flows'] += len(df)
                
                print(f"[Features] ✅ Processed {len(df)} flows → Sent to ML")
            
            except queue.Empty:
                continue
            
            except Exception as e:
                if not self.shutdown_event.is_set():
                    print(f"[Features] ⚠️  Error: {e}")
                time.sleep(0.1)
        
        print(f"[Features] 🛑 Shutting down...")
        print(f"[Features] ✅ Processed {self.stats['batches_processed']} batches, {self.stats['total_flows']} flows")
    
    def _clean_data(self, df):
        """Clean missing/infinite values"""
        # Replace inf with NaN
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Fill NaN with 0
        df = df.fillna(0)
        
        return df
    
    def _engineer_features(self, df):
        """Create aggregation features"""
        
        # ===== Port Scan Detection =====
        port_scan_features = df.groupby('src_ip').agg({
            'dst_port': lambda x: x.nunique(),
            'dst_ip': lambda x: x.nunique(),
            'duration': 'sum',
            'total_fwd_packets': 'sum'
        }).rename(columns={
            'dst_port': 'unique_dst_ports_per_src',
            'dst_ip': 'unique_dst_ips_per_src',
            'duration': 'total_src_duration',
            'total_fwd_packets': 'total_src_packets'
        })
        
        df = df.merge(port_scan_features, left_on='src_ip', right_index=True, how='left')
        
        # ===== DDoS Detection =====
        ddos_features = df.groupby('dst_ip').agg({
            'src_ip': lambda x: x.nunique(),
            'total_bwd_packets': 'sum'
        }).rename(columns={
            'src_ip': 'unique_src_ips_per_dst',
            'total_bwd_packets': 'total_dst_packets'
        })
        
        df = df.merge(ddos_features, left_on='dst_ip', right_index=True, how='left')
        
        # ===== Protocol Diversity =====
        protocol_diversity = df.groupby('src_ip')['protocol'].nunique().rename('unique_protocols_per_src')
        df = df.merge(protocol_diversity, left_on='src_ip', right_index=True, how='left')
        
        # ===== SYN Flood Detection =====
        syn_flows = df[df['fwd_syn_flags'] == 1].groupby('src_ip').agg({
            'fwd_syn_flags': 'count',
            'duration': 'sum'
        }).rename(columns={
            'fwd_syn_flags': 'syn_count_per_src',
            'duration': 'syn_duration_per_src'
        })
        
        df = df.merge(syn_flows, left_on='src_ip', right_index=True, how='left')
        df['syn_rate_per_src'] = df['syn_count_per_src'] / (df['syn_duration_per_src'] + 0.001)
        
        # ===== Suspicious Port Detection =====
        df['contacts_suspicious_port'] = df['dst_port'].isin(SUSPICIOUS_PORTS).astype(int)
        
        suspicious_port_count = df[df['contacts_suspicious_port'] == 1].groupby('src_ip').size().rename('suspicious_ports_contacted')
        df = df.merge(suspicious_port_count, left_on='src_ip', right_index=True, how='left')
        
        # ===== Service-Specific Features =====
        
        # SSH brute force (port 22)
        ssh_flows = df[df['dst_port'] == 22].groupby('src_ip').agg({
            'dst_port': 'count',
            'dst_ip': lambda x: x.nunique()
        }).rename(columns={
            'dst_port': 'ssh_attempts_per_src',
            'dst_ip': 'unique_ssh_targets'
        })
        df = df.merge(ssh_flows, left_on='src_ip', right_index=True, how='left')
        
        # DNS activity (port 53)
        dns_flows = df[(df['dst_port'] == 53) | (df['src_port'] == 53)].groupby('src_ip').agg({
            'dst_port': 'count',
            'avg_payload_entropy': 'mean'
        }).rename(columns={
            'dst_port': 'dns_queries_per_src',
            'avg_payload_entropy': 'dns_entropy_per_src'
        })
        df = df.merge(dns_flows, left_on='src_ip', right_index=True, how='left')
        
        # HTTP/HTTPS (ports 80, 443, 8080)
        http_flows = df[df['dst_port'].isin([80, 443, 8080])].groupby('src_ip').agg({
            'dst_port': 'count',
            'dst_ip': lambda x: x.nunique()
        }).rename(columns={
            'dst_port': 'http_connections_per_src',
            'dst_ip': 'unique_http_targets'
        })
        df = df.merge(http_flows, left_on='src_ip', right_index=True, how='left')
        
        # RDP (port 3389)
        rdp_flows = df[df['dst_port'] == 3389].groupby('src_ip').size().rename('rdp_attempts_per_src')
        df = df.merge(rdp_flows, left_on='src_ip', right_index=True, how='left')
        
        # Telnet (port 23)
        telnet_flows = df[df['dst_port'] == 23].groupby('src_ip').size().rename('telnet_attempts_per_src')
        df = df.merge(telnet_flows, left_on='src_ip', right_index=True, how='left')
        
        # FTP (ports 20, 21)
        ftp_flows = df[df['dst_port'].isin([20, 21])].groupby('src_ip').size().rename('ftp_attempts_per_src')
        df = df.merge(ftp_flows, left_on='src_ip', right_index=True, how='left')
        
        # SMB (ports 445, 139)
        smb_flows = df[df['dst_port'].isin([445, 139])].groupby('src_ip').size().rename('smb_attempts_per_src')
        df = df.merge(smb_flows, left_on='src_ip', right_index=True, how='left')
        
        # ===== ICMP Flood Detection =====
        icmp_flows = df[df['is_icmp'] == 1].groupby('src_ip').agg({
            'is_icmp': 'count',
            'duration': 'sum'
        }).rename(columns={
            'is_icmp': 'icmp_count_per_src',
            'duration': 'icmp_duration_per_src'
        })
        df = df.merge(icmp_flows, left_on='src_ip', right_index=True, how='left')
        df['icmp_rate_per_src'] = df['icmp_count_per_src'] / (df['icmp_duration_per_src'] + 0.001)
        
        # ===== Connection Patterns =====
        
        # Short connections (< 1s)
        df['is_short_connection'] = (df['duration'] < 1.0).astype(int)
        short_conn = df[df['is_short_connection'] == 1].groupby('src_ip').size().rename('short_connections_per_src')
        df = df.merge(short_conn, left_on='src_ip', right_index=True, how='left')
        
        # Long connections (> 300s)
        df['is_long_connection'] = (df['duration'] > 300.0).astype(int)
        long_conn = df[df['is_long_connection'] == 1].groupby('src_ip').size().rename('long_connections_per_src')
        df = df.merge(long_conn, left_on='src_ip', right_index=True, how='left')
        
        # High byte rate (> 10000 bytes/s)
        df['high_byte_rate'] = (df['flow_bytes_per_sec'] > 10000).astype(int)
        high_rate = df[df['high_byte_rate'] == 1].groupby('src_ip').size().rename('high_rate_connections_per_src')
        df = df.merge(high_rate, left_on='src_ip', right_index=True, how='left')
        
        # ===== Failed Connections =====
        
        # RST flags
        rst_flows = df[df['fwd_rst_flags'] == 1].groupby('src_ip').size().rename('rst_count_per_src')
        df = df.merge(rst_flows, left_on='src_ip', right_index=True, how='left')
        
        # Failed handshakes (SYN without ACK)
        failed_handshake = df[(df['fwd_syn_flags'] == 1) & (df['fwd_ack_flags'] == 0)].groupby('src_ip').size().rename('failed_handshakes_per_src')
        df = df.merge(failed_handshake, left_on='src_ip', right_index=True, how='left')
        
        # ===== Data Exfiltration =====
        
        # Upload ratio (more data sent than received)
        df['upload_ratio'] = df['total_fwd_bytes'] / (df['total_bwd_bytes'] + 1)
        high_upload = df[df['upload_ratio'] > 10].groupby('src_ip').size().rename('high_upload_flows_per_src')
        df = df.merge(high_upload, left_on='src_ip', right_index=True, how='left')
        
        # Fill NaN from merges
        df = df.fillna(0)
        
        return df
    
    def _normalize_features(self, df):
        """Normalize features using MinMax scaler"""
        
        # Separate metadata from features
        metadata_df = df[METADATA_COLS].copy()
        feature_cols = [col for col in df.columns if col not in METADATA_COLS]
        
        X = df[feature_cols].copy()
        
        # Fit scaler on first batch, then reuse
        if not self.scaler_fitted:
            X_normalized = self.scaler.fit_transform(X)
            self.scaler_fitted = True
            print(f"[Features] 🎯 Scaler fitted on {len(X)} samples")
        else:
            X_normalized = self.scaler.transform(X)
        
        # Rebuild DataFrame
        df_normalized = pd.DataFrame(X_normalized, columns=feature_cols)
        final_df = pd.concat([metadata_df.reset_index(drop=True), df_normalized], axis=1)
        
        return final_df
    
    def _send_to_queue(self, df, timestamp):
        """Send engineered features to ML detector queue"""
        try:
            # Convert to dict for queue transmission
            features_data = {
                'features': df.to_dict('records'),
                'timestamp': timestamp,
                'count': len(df)
            }
            
            self.output_queue.put(features_data, block=False)
            self.stats['features_sent'] += len(df)
        
        except:
            print(f"[Features] ⚠️  Output queue full! Dropping {len(df)} features")

def run_features(input_queue, output_queue, shutdown_event):
    """Main features process entry point"""
    processor = FeaturesEngineering(input_queue, output_queue, shutdown_event)
    processor.run()
